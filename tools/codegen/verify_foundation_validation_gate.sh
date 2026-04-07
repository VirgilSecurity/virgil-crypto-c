#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
JOBS_DEFAULT="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
BUILD_DIR=""
BUILD_ONLY=0
POST_QUANTUM_OFF=0
JOBS="${JOBS:-$JOBS_DEFAULT}"

usage() {
  cat <<'EOF'
Usage: bash tools/codegen/verify_foundation_validation_gate.sh [options]

Options:
  --build-dir <path>     Explicit CMake build directory.
  --build-only           Configure and build, but skip CTest.
  --post-quantum-off     Configure with -DVIRGIL_POST_QUANTUM=OFF.
  --jobs <n>             Parallel build jobs (default: detected CPU count or 4).
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --build-dir)
      BUILD_DIR="$2"
      shift 2
      ;;
    --build-only)
      BUILD_ONLY=1
      shift
      ;;
    --post-quantum-off)
      POST_QUANTUM_OFF=1
      shift
      ;;
    --jobs)
      JOBS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [ -z "$BUILD_DIR" ]; then
  if [ "$POST_QUANTUM_OFF" -eq 1 ]; then
    BUILD_DIR="${ROOT_DIR}/build/foundation-gate-pq-off"
  else
    BUILD_DIR="${ROOT_DIR}/build/foundation-gate"
  fi
fi

mkdir -p "$BUILD_DIR"

CMAKE_ARGS=(
  -S "$ROOT_DIR"
  -B "$BUILD_DIR"
  -DCMAKE_BUILD_TYPE=Release
  -DENABLE_CLANGFORMAT=OFF
  -DVIRGIL_PROGRAMS=OFF
  -DVIRGIL_WRAP_GO=OFF
  -DVIRGIL_WRAP_PHP=OFF
  -DVIRGIL_WRAP_JAVA=OFF
  -DVIRGIL_WRAP_WASM=OFF
  -DVIRGIL_LIB_PYTHIA=OFF
  -DVIRGIL_LIB_RATCHET=OFF
  -DVIRGIL_LIB_PHE=OFF
)

if [ "$POST_QUANTUM_OFF" -eq 1 ]; then
  CMAKE_ARGS+=("-DVIRGIL_POST_QUANTUM=OFF")
fi

cmake "${CMAKE_ARGS[@]}"
cmake --build "$BUILD_DIR" --target foundation -j"$JOBS"

if [ "$BUILD_ONLY" -eq 0 ]; then
  ctest --test-dir "$BUILD_DIR" --output-on-failure -L foundation
fi

echo "foundation validation gate completed successfully"
