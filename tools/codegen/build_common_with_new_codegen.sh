#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
RESTORE_LOG="${ROOT_DIR}/build/new-codegen-common-restored.txt"

cleanup() {
  git -C "${ROOT_DIR}" checkout -- library/common/include/virgil/crypto/common library/common/src >/dev/null 2>&1 || true
  printf 'restored library/common generated files\n' > "${RESTORE_LOG}"
}
trap cleanup EXIT

python3 "${ROOT_DIR}/tools/codegen/common_bootstrap.py" --repo-root "${ROOT_DIR}" --project common --apply
cmake --build "${ROOT_DIR}/build" --target common -j4

echo "common built successfully using new codegen outputs"
