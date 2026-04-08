#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/build/new-codegen-foundation-enums"
LIST_FILE="${ROOT_DIR}/build/new-codegen-foundation-enums.txt"
EXPECTED_FILE="${ROOT_DIR}/build/new-codegen-foundation-enums.expected"
DIFF_FILE="${ROOT_DIR}/build/new-codegen-foundation-enums.diff"

rm -rf "${OUT_DIR}"
mkdir -p "${ROOT_DIR}/build"

python3 "${ROOT_DIR}/tools/codegen/common_bootstrap.py" \
  --repo-root "${ROOT_DIR}" \
  --project foundation \
  --out build/new-codegen-foundation-enums

cat > "${EXPECTED_FILE}" <<'EOF'
library/foundation/include/virgil/crypto/foundation/private/vscf_recipient_cipher_decryption_state.h
library/foundation/include/virgil/crypto/foundation/vscf_alg_id.h
library/foundation/include/virgil/crypto/foundation/vscf_asn1_tag.h
library/foundation/include/virgil/crypto/foundation/vscf_cipher_state.h
library/foundation/include/virgil/crypto/foundation/vscf_group_msg_type.h
library/foundation/include/virgil/crypto/foundation/vscf_oid_id.h
library/foundation/include/virgil/crypto/foundation/vscf_status.h
library/foundation/src/vscf_alg_id.c
library/foundation/src/vscf_asn1_tag.c
library/foundation/src/vscf_cipher_state.c
library/foundation/src/vscf_group_msg_type.c
library/foundation/src/vscf_oid_id.c
library/foundation/src/vscf_recipient_cipher_decryption_state.c
library/foundation/src/vscf_status.c
EOF

find "${OUT_DIR}" -type f | sed "s#${OUT_DIR}/##" | sort > "${LIST_FILE}"
diff -u "${EXPECTED_FILE}" "${LIST_FILE}" > "${DIFF_FILE}" || {
  cat "${DIFF_FILE}"
  echo
  echo "Unexpected foundation enum slice outputs."
  exit 1
}

rm -f "${DIFF_FILE}"

echo
echo "Foundation enum slice generated the expected 14 files into build/new-codegen-foundation-enums"
