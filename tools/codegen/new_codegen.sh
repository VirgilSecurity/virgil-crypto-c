#!/usr/bin/env bash
# ---------------------------------------------------------------------------
#  new_codegen.sh — Run the new Python codegen pipeline for a project
#
#  Usage:
#    bash tools/codegen/new_codegen.sh [OPTIONS] [PROJECT]
#
#  Arguments:
#    PROJECT           Project to generate (common, foundation). Default: common
#
#  Options:
#    --apply           Write generated code into the repo source tree
#                      (default: write to build/new-codegen/)
#    --build           Build the project after generation (implies --apply)
#    --verify          Full validation: codegen → clang-format → build → diff
#                      check → test. Restores generated files afterward.
#                      This is the CI/gate mode.
#    --out DIR         Output directory (default: build/new-codegen)
#    --legacy          Include legacy resolved-XML fallback modules
#    --dry-run         Show what would be generated without writing
#    --help            Show this help
#
#  Validation flow (--verify):
#    1. Apply codegen into source tree
#    2. Run clang-format on the project target
#    3. Build the project
#    4. Check diff — flag if handwritten/implementation code changed
#       (generated blocks are expected to change, but code outside
#       generated markers should not)
#    5. Run cmake tests for the project
#    6. Restore all generated files via git checkout
#
#  Examples:
#    bash tools/codegen/new_codegen.sh                     # generate common to build/new-codegen/
#    bash tools/codegen/new_codegen.sh foundation           # generate foundation to build/new-codegen/
#    bash tools/codegen/new_codegen.sh --build common       # generate + build common
#    bash tools/codegen/new_codegen.sh --verify common      # full validation (CI mode)
#    bash tools/codegen/new_codegen.sh --verify foundation  # full validation for foundation
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"

# --- Defaults ---
PROJECT="common"
OUT_DIR=""
APPLY=false
BUILD=false
VERIFY=false
LEGACY=false
DRY_RUN=false

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)   APPLY=true; shift ;;
    --build)   BUILD=true; APPLY=true; shift ;;
    --verify)  VERIFY=true; BUILD=true; APPLY=true; shift ;;
    --out)     OUT_DIR="$2"; shift 2 ;;
    --legacy)  LEGACY=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    --help|-h)
      sed -n '/^#  new_codegen/,/^# ---/{/^# ---/d; /^#$/d; s/^#  \{0,1\}//; p;}' "$0"
      exit 0
      ;;
    -*)
      echo "unknown option: $1" >&2; exit 1 ;;
    *)
      PROJECT="$1"; shift ;;
  esac
done

# --- Resolve project paths ---
case "${PROJECT}" in
  common)
    LIB_RESTORE_PATHS=(
      "library/common/include/virgil/crypto/common"
      "library/common/src"
    )
    CMAKE_TARGET="common"
    CMAKE_TEST_TARGET="test_common"
    ;;
  foundation)
    LIB_RESTORE_PATHS=(
      "library/foundation/include/virgil/crypto/foundation"
      "library/foundation/src"
    )
    CMAKE_TARGET="foundation"
    CMAKE_TEST_TARGET="test_foundation"
    ;;
  *)
    echo "error: unsupported project '${PROJECT}'" >&2
    echo "supported projects: common, foundation" >&2
    exit 1
    ;;
esac

# --- Verify mode: restore generated files on exit ---
if ${VERIFY}; then
  cleanup() {
    local exit_code=$?
    echo ""
    echo "--- Restoring generated files ---"
    for restore_path in "${LIB_RESTORE_PATHS[@]}"; do
      git -C "${ROOT_DIR}" checkout -- "${restore_path}" >/dev/null 2>&1 || true
    done
    echo "restored ${PROJECT} generated files"
    exit ${exit_code}
  }
  trap cleanup EXIT
fi

# --- Build codegen arguments ---
CODEGEN_ARGS=(
  --repo-root "${ROOT_DIR}"
  --project "${PROJECT}"
)

if ${APPLY}; then
  CODEGEN_ARGS+=(--apply)
elif [[ -n "${OUT_DIR}" ]]; then
  CODEGEN_ARGS+=(--out "${OUT_DIR}")
fi

if ${LEGACY}; then
  CODEGEN_ARGS+=(--legacy-c-modules)
fi

# --- Run ---
echo "=== New Codegen: ${PROJECT} ==="
echo "  apply:  ${APPLY}"
echo "  build:  ${BUILD}"
echo "  verify: ${VERIFY}"
echo ""

if ${DRY_RUN}; then
  echo "[dry-run] would run: python3 ${ROOT_DIR}/tools/codegen/common_bootstrap.py ${CODEGEN_ARGS[*]}"
  exit 0
fi

# ── Step 1: Codegen ──────────────────────────────────────────────────────────
echo "--- Step 1: Codegen ---"
python3 "${ROOT_DIR}/tools/codegen/common_bootstrap.py" "${CODEGEN_ARGS[@]}"

if ! ${BUILD}; then
  exit 0
fi

# ── Ensure cmake is configured ───────────────────────────────────────────────
mkdir -p "${BUILD_DIR}"
if [ ! -f "${BUILD_DIR}/CMakeCache.txt" ]; then
  echo ""
  echo "--- Configuring cmake ---"
  cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}"
fi

# ── Step 2: Clang-format ─────────────────────────────────────────────────────
echo ""
echo "--- Step 2: Clang-format ---"
if cmake --build "${BUILD_DIR}" --target "${CMAKE_TARGET}_clangformat" -- -j4 2>/dev/null; then
  echo "clang-format applied"
else
  echo "clang-format target not available, skipping"
fi

# ── Step 3: Build ────────────────────────────────────────────────────────────
echo ""
echo "--- Step 3: Build ---"
cmake --build "${BUILD_DIR}" --target "${CMAKE_TARGET}" -- -j4
echo "${PROJECT} built successfully"

if ! ${VERIFY}; then
  exit 0
fi

# ── Step 4: Diff check ───────────────────────────────────────────────────────
echo ""
echo "--- Step 4: Diff check ---"
DIFF_EXIT=0
IMPL_CHANGES=""

for restore_path in "${LIB_RESTORE_PATHS[@]}"; do
  # Get list of changed files
  changed_files=$(git -C "${ROOT_DIR}" diff --name-only -- "${restore_path}" 2>/dev/null || true)
  if [ -z "${changed_files}" ]; then
    continue
  fi

  for file in ${changed_files}; do
    # Check if changes are only within generated blocks
    # Generated blocks are between @generated and @end markers
    full_diff=$(git -C "${ROOT_DIR}" diff -- "${file}" 2>/dev/null || true)

    # Check for changes outside generated blocks by looking at diff context
    # Lines starting with - or + that are NOT within generated sections
    outside_generated=$(echo "${full_diff}" | awk '
      /^@@/ { in_hunk=1; next }
      !in_hunk { next }
      /^[-+].*@generated/ { in_gen=1; next }
      /^[-+].*@end/ { in_gen=0; next }
      in_gen { next }
      /^[-+][^-+]/ { print }
    ')

    if [ -n "${outside_generated}" ]; then
      IMPL_CHANGES="${IMPL_CHANGES}\n⚠️  ${file} — changes OUTSIDE generated blocks:\n${outside_generated}\n"
      DIFF_EXIT=1
    fi
  done
done

changed_count=$(git -C "${ROOT_DIR}" diff --name-only -- "${LIB_RESTORE_PATHS[@]}" 2>/dev/null | wc -l | tr -d ' ')
echo "${changed_count} file(s) changed by codegen"

if [ ${DIFF_EXIT} -ne 0 ]; then
  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║  ⚠️  WARNING: Changes detected OUTSIDE generated blocks     ║"
  echo "║  This may indicate codegen is modifying handwritten code.   ║"
  echo "║  Review carefully before accepting.                         ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  printf "${IMPL_CHANGES}"
  echo ""
  echo "Continuing with tests despite warnings..."
fi

# ── Step 5: Tests ────────────────────────────────────────────────────────────
echo ""
echo "--- Step 5: Tests ---"
if cmake --build "${BUILD_DIR}" --target "${CMAKE_TEST_TARGET}" -- -j4 2>/dev/null; then
  echo "test target built"
  ctest --test-dir "${BUILD_DIR}" -R "${PROJECT}" --output-on-failure -j4 2>&1 || {
    echo ""
    echo "❌ Tests FAILED for ${PROJECT}"
    exit 1
  }
  echo "✅ All ${PROJECT} tests passed"
else
  echo "test target '${CMAKE_TEST_TARGET}' not available, running ctest with project filter"
  ctest --test-dir "${BUILD_DIR}" -R "${PROJECT}" --output-on-failure -j4 2>&1 || {
    echo ""
    echo "❌ Tests FAILED for ${PROJECT}"
    exit 1
  }
  echo "✅ All ${PROJECT} tests passed"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════"
echo "  ✅ ${PROJECT} codegen verification complete"
echo "     Files changed: ${changed_count}"
if [ ${DIFF_EXIT} -ne 0 ]; then
  echo "     ⚠️  Non-generated changes detected (review above)"
fi
echo "═══════════════════════════════════════"
