#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/build/new-codegen-common"

python3 "${ROOT_DIR}/tools/codegen/common_bootstrap.py" --repo-root "${ROOT_DIR}" --project common --out build/new-codegen-common

echo
echo "Diff summary against library/common:"
diff -ru "${ROOT_DIR}/library/common" "${OUT_DIR}/library/common" > "${ROOT_DIR}/build/new-codegen-common.diff" || true
wc -l "${ROOT_DIR}/build/new-codegen-common.diff"
echo "Saved full diff to build/new-codegen-common.diff"
