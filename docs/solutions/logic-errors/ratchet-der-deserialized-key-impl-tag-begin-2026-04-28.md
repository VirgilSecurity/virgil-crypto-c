---
title: "vscf_raw_public_key_new_with_data leaves impl_tag as BEGIN, breaking create_from_key after DER deserialization"
date: 2026-04-28
category: docs/solutions/logic-errors
module: ratchet
problem_type: logic_error
component: service_object
severity: high
symptoms:
  - "Ratchet PQC integration tests fail at first encrypt after session initiation: TEST_ASSERT_FALSE(vscr_error_has_error) fails"
  - "vscf_key_alg_factory_create_from_key returns ERROR_UNSUPPORTED_ALGORITHM for a DER-deserialized ML-KEM public key"
  - "vscf_raw_public_key_t from the ASN.1 deserializer has impl_tag == vscf_impl_tag_BEGIN (0) even though alg_info is correctly populated"
root_cause: wrong_api
resolution_type: code_fix
tags:
  - ratchet
  - post-quantum
  - ml-kem
  - key-deserialization
  - impl-tag
  - asn1
  - der
  - key-alg-factory
---

# vscf_raw_public_key_new_with_data leaves impl_tag as BEGIN, breaking create_from_key after DER deserialization

## Problem

After switching `vscr_ratchet_pb_utils.c` to DER/ASN.1 serialization for PQ keys, ratchet decryption fails with `ERROR_UNSUPPORTED_ALGORITHM` even though `vscf_key_alg_factory.c` has correct `case` labels for ML-KEM. The root cause is that `vscf_raw_public_key_new_with_data` (called internally by the ASN.1 deserializer) never sets `impl_tag` — it stays at its zero-initialized value `vscf_impl_tag_BEGIN`. Callers that pass the deserialized key to `vscf_key_alg_factory_create_from_key` (which dispatches on `impl_tag`) fall through to `default:` and get `ERROR_UNSUPPORTED_ALGORITHM`.

## Symptoms

- `test__encrypt_decrypt_back_and_forth` and similar ratchet PQC integration tests fail at `TEST_ASSERT_FALSE(vscr_error_has_error(&error))` immediately after Bob's first `vscr_ratchet_session_encrypt`
- `vscf_key_alg_factory_create_from_key` returns `NULL` with `error.status = vscf_status_ERROR_UNSUPPORTED_ALGORITHM` for a key that was just produced by `vscf_key_asn1_deserializer_deserialize_public_key`
- The `vscf_raw_public_key_t` has a valid `alg_info` (OID parsed correctly from the DER blob) but `impl_tag == vscf_impl_tag_BEGIN` (value 0)

## What Didn't Work

- **Re-checking factory cases** — `vscf_key_alg_factory.c` already had correct `case vscf_impl_tag_ML_KEM:` labels (added in a prior fix). The switch cannot match them when `impl_tag` is `BEGIN`, regardless of how many cases exist.
- **Inspecting the DER round-trip in isolation** — the bytes encoded and decoded cleanly; `alg_info` inside the deserialized key correctly identified ML-KEM-768. The bug only surfaces when the key is subsequently passed to factory functions that dispatch on `impl_tag` rather than `alg_info`.

## Solution

After ASN.1 deserialization, pass the `vscf_raw_public_key_t` through a full import pipeline that resolves `impl_tag` from `alg_info`:

```c
// After vscf_key_asn1_deserializer_deserialize_public_key():
vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_raw_public_key(raw_key, NULL, &error_ctx);
if (vscf_error_has_error(&error_ctx)) {
    vscf_raw_public_key_destroy(&raw_key);
    return vscr_status_ERROR_KEY_DESERIALIZATION_FAILED;
}
*public_key_ref = vscf_key_alg_import_public_key(key_alg, raw_key, &error_ctx);
vscf_raw_public_key_destroy(&raw_key);
vscf_impl_destroy(&key_alg);
```

`vscf_key_alg_factory_create_from_raw_public_key` dispatches on `raw_key->alg_info` (not `raw_key->impl_tag`), returning the correct algorithm implementation. `import_public_key` then produces a key object with a properly initialized `impl_tag` — identical to what `vscf_key_provider_import_public_key` would return.

The same pattern applies for private keys: `create_from_raw_private_key` + `import_private_key`.

**Files changed:** `library/ratchet/src/vscr_ratchet_pb_utils.c` — functions `vscr_ratchet_pb_utils_deserialize_public_key` and `vscr_ratchet_pb_utils_deserialize_private_key`. Added includes `vscf_key_alg_factory.h` and `vscf_key_alg.h`.

## Why This Works

`vscf_raw_public_key_t` is a transport container, not a live key object. `vscf_raw_public_key_new_with_data` intentionally leaves `impl_tag` unset — the raw key just holds bytes and `alg_info`; the algorithm-specific implementation that sets `impl_tag` is only attached after an `import_public_key` call. Two factory functions exist for different inputs:

- `create_from_key(key, ...)` — reads `key->impl_tag`; requires a fully-imported key with `impl_tag` resolved
- `create_from_raw_public_key(raw_key, ...)` — reads `raw_key->alg_info`; works on transport-layer raw keys where `impl_tag` may be `BEGIN`

The `create_from_raw_public_key` + `import_public_key` pipeline is exactly the path `vscf_key_provider_import_public_key` takes internally. It produces a key where `impl_tag` is set to the correct algorithm tag, so all subsequent `create_from_key` calls succeed.

## Prevention

- After `vscf_key_asn1_deserializer_deserialize_public_key` (or `_deserialize_private_key`), never pass the returned `vscf_raw_*_key_t` directly to `vscf_key_alg_factory_create_from_key`. The raw key's `impl_tag` is `vscf_impl_tag_BEGIN` at this point.
- Always complete the import pipeline: `create_from_raw_public_key` → `import_public_key` (or `create_from_raw_private_key` → `import_private_key`).
- When debugging `ERROR_UNSUPPORTED_ALGORITHM` from `create_from_key`: check whether the key came from the ASN.1 deserializer. If so, the likely cause is `impl_tag_BEGIN`, not missing factory cases.

## Related Issues

- Factory cases missing for ML-KEM/ML-DSA (a different root cause with the same symptom): [`docs/solutions/logic-errors/key-alg-factory-missing-pq-cases-2026-04-27.md`](key-alg-factory-missing-pq-cases-2026-04-27.md) — in that case the factory switch was missing `case` labels for the new algorithms; here all cases are correct but `impl_tag` is never set by the deserializer.
- Algorithm-agnostic ratchet API pattern (the refactor during which this bug was encountered): [`docs/solutions/best-practices/ratchet-algorithm-agnostic-api-2026-04-28.md`](../best-practices/ratchet-algorithm-agnostic-api-2026-04-28.md)
