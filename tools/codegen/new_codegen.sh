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
#    --verify          Build + restore generated files afterward (implies --build)
#                      This is the "safe" mode: proves the codegen output compiles
#                      without leaving generated files in the tree
#    --out DIR         Output directory (default: build/new-codegen)
#    --legacy          Include legacy resolved-XML fallback modules
#    --dry-run         Show what would be generated without writing
#    --help            Show this help
#
#  Examples:
#    bash tools/codegen/new_codegen.sh                     # generate common to build/new-codegen/
#    bash tools/codegen/new_codegen.sh foundation           # generate foundation to build/new-codegen/
#    bash tools/codegen/new_codegen.sh --build common       # generate + build common
#    bash tools/codegen/new_codegen.sh --verify common      # generate + build + restore (CI mode)
#    bash tools/codegen/new_codegen.sh --verify foundation  # generate + build + restore foundation
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

# --- Resolve library paths for restore ---
case "${PROJECT}" in
  common)
    LIB_RESTORE_PATHS=(
      "library/common/include/virgil/crypto/common"
      "library/common/src"
    )
    CMAKE_TARGET="common"
    ;;
  foundation)
    LIB_RESTORE_PATHS=(
      "library/foundation/include/virgil/crypto/foundation"
      "library/foundation/src"
    )
    CMAKE_TARGET="foundation"
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
    echo ""
    echo "--- Restoring generated files ---"
    for restore_path in "${LIB_RESTORE_PATHS[@]}"; do
      git -C "${ROOT_DIR}" checkout -- "${restore_path}" >/dev/null 2>&1 || true
    done
    echo "restored ${PROJECT} generated files"
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

# --- Run codegen ---
echo "=== New Codegen: ${PROJECT} ==="
echo "  apply: ${APPLY}"
echo "  build: ${BUILD}"
echo "  verify: ${VERIFY}"
echo ""

if ${DRY_RUN}; then
  echo "[dry-run] would run: python3 ${ROOT_DIR}/tools/codegen/common_bootstrap.py ${CODEGEN_ARGS[*]}"
  exit 0
fi

python3 "${ROOT_DIR}/tools/codegen/common_bootstrap.py" "${CODEGEN_ARGS[@]}"

# --- Build if requested ---
if ${BUILD}; then
  echo ""
  echo "--- Building ${PROJECT} ---"

  # Ensure cmake is configured
  if [ ! -f "${BUILD_DIR}/CMakeCache.txt" ]; then
    cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}"
  fi

  # Format first (if clangformat target exists)
  if cmake --build "${BUILD_DIR}" --target "${CMAKE_TARGET}_clangformat" -- -j4 2>/dev/null; then
    echo "clangformat applied"
  fi

  # Build
  cmake --build "${BUILD_DIR}" --target "${CMAKE_TARGET}" -- -j4

  echo ""
  echo "${PROJECT} built successfully using new codegen outputs"
fi
