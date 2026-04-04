#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build"
RESTORE_LOG="${BUILD_DIR}/new-codegen-common-restored.txt"

cleanup() {
  git -C "${ROOT_DIR}" checkout -- library/common/include/virgil/crypto/common library/common/src >/dev/null 2>&1 || true
  mkdir -p "${BUILD_DIR}"
  printf 'restored library/common generated files\n' > "${RESTORE_LOG}"
}
trap cleanup EXIT

mkdir -p "${BUILD_DIR}"
if [ ! -f "${BUILD_DIR}/CMakeCache.txt" ]; then
  cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}"
fi

python3 "${ROOT_DIR}/tools/codegen/common_bootstrap.py" --repo-root "${ROOT_DIR}" --project common --apply
cmake --build "${BUILD_DIR}" --target common -j4

echo "common built successfully using new codegen outputs"
