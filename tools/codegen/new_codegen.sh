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
ALL_PROJECTS="common foundation phe pythia ratchet"

resolve_project_paths() {
  local proj="$1"
  case "${proj}" in
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
    phe)
      LIB_RESTORE_PATHS=(
        "library/phe/include/virgil/crypto/phe"
        "library/phe/src"
      )
      CMAKE_TARGET="phe"
      CMAKE_TEST_TARGET="test_phe"
      ;;
    pythia)
      LIB_RESTORE_PATHS=(
        "library/pythia/include/virgil/crypto/pythia"
        "library/pythia/src"
      )
      CMAKE_TARGET="pythia"
      CMAKE_TEST_TARGET="test_pythia"
      ;;
    ratchet)
      LIB_RESTORE_PATHS=(
        "library/ratchet/include/virgil/crypto/ratchet"
        "library/ratchet/src"
      )
      CMAKE_TARGET="ratchet"
      CMAKE_TEST_TARGET="test_ratchet"
      ;;
    *)
      echo "error: unsupported project '${proj}'" >&2
      echo "supported projects: ${ALL_PROJECTS} all" >&2
      exit 1
      ;;
  esac
}

if [ "${PROJECT}" = "all" ]; then
  PROJECTS="${ALL_PROJECTS}"
else
  PROJECTS="${PROJECT}"
fi

# Resolve paths for the first (or only) project — used by single-project mode.
# For 'all' mode, paths are re-resolved per project in the loop below.
for _p in ${PROJECTS}; do
  resolve_project_paths "${_p}"
  break
done

# --- Verify mode: restore generated files on exit ---
if ${VERIFY}; then
  cleanup() {
    local exit_code=$?
    echo ""
    echo "--- Restoring generated files ---"
    for _proj in ${PROJECTS}; do
      resolve_project_paths "${_proj}"
      for restore_path in "${LIB_RESTORE_PATHS[@]}"; do
        git -C "${ROOT_DIR}" checkout -- "${restore_path}" >/dev/null 2>&1 || true
        git -C "${ROOT_DIR}" clean -fd -- "${restore_path}" >/dev/null 2>&1 || true
      done
    done
    echo "restored generated files"
    exit ${exit_code}
  }
  trap cleanup EXIT
fi

# --- Inline diff checker (used by step 4) ---
check_outside_generated() {
  local root_dir="$1" file="$2"
  python3 - <<'PY' "${root_dir}" "${file}"
from __future__ import annotations
import difflib
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
file = sys.argv[2]

START_MARKERS = {"//  @generated", "//  @generated_header_includes"}
END = "//  @end"


def strip_generated_blocks(text: str) -> str:
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    in_generated = False
    for line in lines:
        stripped = line.rstrip("\n")
        if stripped in START_MARKERS:
            in_generated = True
            continue
        if in_generated:
            if stripped == END:
                in_generated = False
            continue
        out.append(line)
    text = "".join(out)
    while "\n\n\n" in text:
        text = text.replace("\n\n\n", "\n\n")
    return text

old_res = subprocess.run(
    ["git", "-C", str(root), "show", f"HEAD:{file}"],
    capture_output=True,
    text=True,
)
if old_res.returncode != 0:
    sys.exit(0)

new_path = root / file
if not new_path.exists():
    sys.exit(0)

old_text = strip_generated_blocks(old_res.stdout)
new_text = strip_generated_blocks(new_path.read_text())

if old_text == new_text:
    sys.exit(0)

for line in difflib.unified_diff(
    old_text.splitlines(),
    new_text.splitlines(),
    fromfile=file,
    tofile=file,
    lineterm="",
):
    if line.startswith(("---", "+++", "@@")):
        continue
    if line.startswith(("-", "+")) and not line.startswith(("---", "+++")):
        print(line)
PY
}

# --- Run one project through the full pipeline ---
run_project() {
  local proj="$1"
  resolve_project_paths "${proj}"

  # ── Build codegen arguments ──
  local CODEGEN_ARGS=(
    --repo-root "${ROOT_DIR}"
    --project "${proj}"
  )
  if ${APPLY}; then
    CODEGEN_ARGS+=(--apply)
  elif [[ -n "${OUT_DIR}" ]]; then
    CODEGEN_ARGS+=(--out "${OUT_DIR}")
  fi
  if ${LEGACY}; then
    CODEGEN_ARGS+=(--legacy-c-modules)
  fi

  echo ""
  echo "=== New Codegen: ${proj} ==="

  if ${DRY_RUN}; then
    echo "[dry-run] would run: python3 ${ROOT_DIR}/tools/codegen/common_bootstrap.py ${CODEGEN_ARGS[*]}"
    return 0
  fi

  # ── Step 1: Codegen ──
  echo "--- Step 1: Codegen ---"
  python3 "${ROOT_DIR}/tools/codegen/common_bootstrap.py" "${CODEGEN_ARGS[@]}"

  if ! ${BUILD}; then
    return 0
  fi

  # ── Ensure cmake is configured ──
  mkdir -p "${BUILD_DIR}"
  if [ ! -f "${BUILD_DIR}/CMakeCache.txt" ]; then
    echo ""
    echo "--- Configuring cmake ---"
    cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}"
  fi

  # ── Step 2: Clang-format ──
  echo ""
  echo "--- Step 2: Clang-format ---"
  if cmake --build "${BUILD_DIR}" --target "${CMAKE_TARGET}_clangformat" -- -j4 2>/dev/null; then
    echo "clang-format applied"
  else
    echo "clang-format target not available, skipping"
  fi

  # ── Step 3: Build ──
  echo ""
  echo "--- Step 3: Build ---"
  cmake --build "${BUILD_DIR}" --target "${CMAKE_TARGET}" -- -j4
  echo "${proj} built successfully"

  if ! ${VERIFY}; then
    return 0
  fi

  # ── Step 4: Diff check ──
  echo ""
  echo "--- Step 4: Diff check ---"
  local DIFF_EXIT=0
  local IMPL_CHANGES=""

  for restore_path in "${LIB_RESTORE_PATHS[@]}"; do
    local changed_files
    changed_files=$(git -C "${ROOT_DIR}" diff --name-only -- "${restore_path}" 2>/dev/null || true)
    if [ -z "${changed_files}" ]; then
      continue
    fi

    for file in ${changed_files}; do
      local outside_generated
      outside_generated=$(check_outside_generated "${ROOT_DIR}" "${file}")
      if [ -n "${outside_generated}" ]; then
        IMPL_CHANGES="${IMPL_CHANGES}\n⚠️  ${file} — changes OUTSIDE generated blocks:\n${outside_generated}\n"
        DIFF_EXIT=1
      fi
    done
  done

  local changed_count
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

  # ── Step 5: Tests ──
  echo ""
  echo "--- Step 5: Tests ---"
  if cmake --build "${BUILD_DIR}" --target "${CMAKE_TEST_TARGET}" -- -j4 2>/dev/null; then
    echo "test target built"
    ctest --test-dir "${BUILD_DIR}" -R "${proj}" --output-on-failure -j4 2>&1 || {
      echo ""
      echo "❌ Tests FAILED for ${proj}"
      return 1
    }
    echo "✅ All ${proj} tests passed"
  else
    echo "test target '${CMAKE_TEST_TARGET}' not available, running ctest with project filter"
    ctest --test-dir "${BUILD_DIR}" -R "${proj}" --output-on-failure -j4 2>&1 || {
      echo ""
      echo "❌ Tests FAILED for ${proj}"
      return 1
    }
    echo "✅ All ${proj} tests passed"
  fi

  # ── Project summary ──
  echo ""
  echo "═══════════════════════════════════════"
  echo "  ✅ ${proj} codegen verification complete"
  echo "     Files changed: ${changed_count}"
  if [ ${DIFF_EXIT} -ne 0 ]; then
    echo "     ⚠️  Non-generated changes detected (review above)"
  fi
  echo "═══════════════════════════════════════"
  return 0
}

# --- Main execution ---
echo "=== New Codegen ==="
echo "  projects: ${PROJECTS}"
echo "  apply:    ${APPLY}"
echo "  build:    ${BUILD}"
echo "  verify:   ${VERIFY}"

FAILED_PROJECTS=""
for _proj in ${PROJECTS}; do
  if ! run_project "${_proj}"; then
    FAILED_PROJECTS="${FAILED_PROJECTS} ${_proj}"
  fi
done

if [ -n "${FAILED_PROJECTS}" ]; then
  echo ""
  echo "❌ FAILED projects:${FAILED_PROJECTS}"
  exit 1
fi
