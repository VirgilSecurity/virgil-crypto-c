#!/usr/bin/env bash
set -euo pipefail

# Validation-only helper for foundation build/test gates.
# This task does not take ownership of generation/apply/restore flows yet.

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
  --post-quantum-off     Configure with -DVSCF_POST_QUANTUM=OFF.
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
)

if [ "$POST_QUANTUM_OFF" -eq 1 ]; then
  CMAKE_ARGS+=("-DVSCF_POST_QUANTUM=OFF")
fi

cmake "${CMAKE_ARGS[@]}"
cmake --build "$BUILD_DIR" --target foundation -j"$JOBS"

if [ "$BUILD_ONLY" -eq 0 ]; then
  FOUNDATION_TEST_TARGETS=()
  while IFS= read -r test_target; do
    FOUNDATION_TEST_TARGETS+=("$test_target")
  done < <(
    ctest --test-dir "$BUILD_DIR" -N -L foundation 2>/dev/null \
      | sed -E -n 's/^[[:space:]]*Test[[:space:]]*#[0-9]+:[[:space:]]*//p'
  )

  if [ "${#FOUNDATION_TEST_TARGETS[@]}" -eq 0 ]; then
    echo "No foundation-labeled tests were discovered in $BUILD_DIR" >&2
    exit 1
  fi

  cmake --build "$BUILD_DIR" --target "${FOUNDATION_TEST_TARGETS[@]}" -j"$JOBS"
  ctest --test-dir "$BUILD_DIR" --output-on-failure -L foundation
fi

echo "foundation validation gate completed successfully"
