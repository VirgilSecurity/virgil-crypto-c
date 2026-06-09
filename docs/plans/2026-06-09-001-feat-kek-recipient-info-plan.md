---
title: "feat: Add KEKRecipientInfo (AES Key Wrap) to CMS EnvelopedData"
type: feat
status: active
date: 2026-06-09
---

# feat: Add KEKRecipientInfo (AES Key Wrap) to CMS EnvelopedData

## Overview

Extend the CMS EnvelopedData implementation with `KEKRecipientInfo` support (RFC 5652 §6.2.3 + RFC 3565). This allows a sender to encrypt the content-encryption key (CEK) using a pre-shared symmetric key via AES Key Wrap (RFC 3394), rather than an asymmetric public key or a password.

The design introduces a new `interface_key_wrap` so that future KEK algorithms (AES-128-KW, SM4-KW, Camellia-KW, etc.) slot in without touching `recipient_cipher` or the serializer. `vscf_aes256_kw` is the first concrete implementation. The work follows the codegen-first pattern established for all existing algorithm classes.

## Problem Frame

The existing `vscf_message_info_der_serializer.c` explicitly marks `kekri [2] KEKRecipientInfo` as "not supported" in three dispatch points. The library supports `ktri` (public-key transport) and `pwri` (password) recipients. KEKRecipientInfo adds the pre-shared symmetric key path. AES Key Wrap via mbedTLS (`mbedtls_nist_kw_*`) is already compiled into the `mbed::crypto` target; no new library dependency is needed.

## Requirements Trace

- R1. A caller can add one or more KEK recipients by passing a `key_wrap` algorithm implementation, a caller-supplied `keyIdentifier`, and the raw KEK bytes.
- R2. Encryption wraps the CEK using the provided `key_wrap` algorithm and encodes the result as `KEKRecipientInfo` with context tag `[2]` per RFC 5652 §6.1.
- R3. Decryption locates the matching KEK recipient by `keyIdentifier`, unwraps the CEK, and proceeds to decrypt the content.
- R4. The DER serializer round-trips `KEKRecipientInfo` correctly (serialize → deserialize → same bytes).
- R5. `KEKRecipientInfo.version` is always `4`; `EnvelopedData.version` is `3` whenever a KEK recipient is present.
- R6. All three AES key sizes (128, 192, 256-bit) are supported: `id-aes128-wrap`, `id-aes192-wrap`, and `id-aes256-wrap` OIDs are registered; separate `vscf_aes{128,256}_kw` implementation classes exist (192-bit is rare — OID registered but implementation class is out of scope for this PR).
- R7. The `AlgorithmIdentifier` for AES wrap encodes the OID only — parameters field is absent (not NULL).
- R8. `KEKIdentifier` encodes only `keyIdentifier OCTET STRING`; `date` and `other` are omitted for interoperability.
- R9. Adding a new KEK algorithm in future requires only: (a) a new implementation of `interface_key_wrap`, (b) a new OID + alg_id entry. No changes to `recipient_cipher` or the serializer are needed.

## Scope Boundaries

- No `KeyAgreeRecipientInfo` (`kari [1]`) — remains out of scope.
- No `OtherRecipientInfo` (`ori [4]`) — remains out of scope.
- No RFC 5649 KWP (key wrap with padding) — KW mode only; CMS CEKs are always multiples of 8 bytes.
- `vscf_aes192_kw` implementation class is out of scope (OID is registered for round-trip, but no cipher class).
- Language wrapper codegen (Go, Java, Swift) regenerates stubs automatically but is not wired or tested in this PR.

### Deferred to Separate Tasks

- Language wrapper smoke tests (Go, Java, Swift): separate PR after the C layer is verified.
- `vscf_aes192_kw` implementation class: can be added in a follow-up with no design changes.

## Context & Research

### Relevant Code and Patterns

- `codegen/models/project_foundation/interface_cipher.xml` — interface pattern to mirror for `interface_key_wrap`.
- `codegen/models/project_foundation/interface_kdf.xml` — minimal interface example (no `inherit`).
- `codegen/models/project_foundation/interface_alg.xml` — `alg_id` + `produce_alg_info` + `restore_alg_info`.
- `codegen/models/project_foundation/interface_key_cipher.xml` — keyed operation interface pattern.
- `library/foundation/src/vscf_aes256_cbc.c` — algorithm implementation class pattern: `init_ctx`/`cleanup_ctx`, `alg_id`, `produce_alg_info` returning `vscf_simple_alg_info_t`, `restore_alg_info`.
- `codegen/models/project_foundation/class_key_recipient_info.xml` — data class model to mirror.
- `codegen/models/project_foundation/class_message_info.xml` — add `kek_recipients` property.
- `codegen/models/project_foundation/class_recipient_cipher.xml` — add new public methods.
- `library/foundation/src/vscf_message_info_der_serializer.c:1011–1057` — serialize loop.
- `library/foundation/src/vscf_message_info_der_serializer.c:1772–1813` — deserialize dispatch.
- `library/foundation/src/vscf_recipient_cipher.c` — `encrypt_cipher_key_for_recipients` and `decrypt_data_encryption_key` dispatcher.
- `library/foundation/src/vscf_oid.c` — OID constant table.
- `library/foundation/src/vscf_alg_info_der_serializer.c` — `serialize_simple_alg_info` for OID-only AlgorithmIdentifiers.
- `library/foundation/features.cmake` + `sources.cmake` — CMake registration.
- `tests/fuzzy/foundation/src/fuzzy_test__message_info_der_serializer__der_serializer_deserialize_info.c` — existing fuzzer to extend.
- `tests/fuzzy/foundation/src/fuzzy_test__recipient_cipher__ed25519_decrypt_message.c` — fuzzer template for new KEK decrypt fuzzer.

### Institutional Learnings

- Codegen files are partially generated: run `python3 -m tools.codegen.common_bootstrap --project foundation --apply` (the new Python-based codegen in `tools/codegen/`, not the legacy GSL pipeline) to regenerate boilerplate, then hand-fill business logic inside `@end` / `@<tag>` guarded regions.
- In-source CMake builds are forbidden. Always use `-B<builddir> -S.`.
- mbedTLS `nist_kw.h` is already compiled into `mbed::crypto`; no new link target needed.
- Fuzzy tests require LLVM Clang and use `LLVMFuzzerTestOneInput`. They live in `tests/fuzzy/foundation/`.

### External References

- RFC 5652 §6.1–6.2.3 — KEKRecipientInfo structure and version rules
- RFC 3394 — AES Key Wrap algorithm (input must be multiple of 8 bytes; output = input + 8 bytes)
- RFC 3565 — AES Key Wrap usage in CMS; OID assignments
- mbedTLS `mbedtls_nist_kw_*` API: `init`, `setkey(is_wrap=1/0)`, `wrap`, `unwrap`, `free`
- `MBEDTLS_KW_MODE_KW` for RFC 3394 (not KWP/RFC 5649)

## Key Technical Decisions

- **Define `interface_key_wrap`** (new interface inheriting `interface_alg`): exposes `wrap(kek, data, out)`, `unwrap(kek, data, out)`, and buffer-sizing methods. `recipient_cipher` calls only through this interface — adding SM4-KW or Camellia-KW in future requires no changes to the cipher or serializer.
- **`vscf_aes256_kw` as the first implementation** (plus `vscf_aes128_kw`): each is a stateless implementation class. `produce_alg_info` returns `vscf_simple_alg_info_t(vscf_alg_id_AES256_KW)` (OID only, no parameters). `restore_alg_info` is a no-op (no state to restore). The key size is fixed by the class, not inferred from the KEK byte length at call time — this makes the algorithm explicit and avoids silent mis-sizing.
- **`add_kek_recipient(cipher, kek_id, key_wrap_impl, kek)` API**: the caller constructs the algorithm implementation explicitly (e.g. `vscf_aes256_kw_new()`) and passes it alongside the raw KEK bytes. The cipher obtains the `AlgorithmIdentifier` for `KEKRecipientInfo` via `vscf_alg_produce_alg_info(key_wrap_impl)`.
- **Three OIDs registered (128/192/256), three `alg_id` values**: all three are needed for correct round-trip deserialization of any incoming message. The serializer uses the alg_id from the stored `alg_info` to select the correct OID — it does not inspect the wrapped key length.
- **`KEKIdentifier` with `keyIdentifier` only**: `date` and `other` are omitted for maximum interoperability. On deserialize, skip any OPTIONAL fields that may be present in foreign messages.
- **`EnvelopedData.version` = 3 when kekri present**: RFC 5652 §6.1 — version 3 covers kari, kekri, and pwri. Version 4 is only for `originatorInfo` (not supported). The existing check `version != 2 && version != 3` already covers the valid range; only the serializer's version-selection logic needs updating.
- **`KEKRecipientInfo.version` always 4**: hardcoded in serializer per RFC 5652 §6.2.3.
- **Codegen-first, then fill guarded regions**: run `python3 -m tools.codegen.common_bootstrap --project foundation --apply` after each XML model change. Hand-fill only `init_ctx`/`cleanup_ctx` and the wrap/unwrap business logic inside guarded markers.
- **Deserialize dispatch: probe `[2]` before `[3]`**: extend the existing speculative tag-probe loop. If `read_context_tag(2)` returns non-zero → kekri; else if `read_context_tag(3)` returns non-zero → pwri; else → ktri SEQUENCE.

## Open Questions

### Resolved During Planning

- **Does `interface_key_wrap` exist already?** No — grep over all `codegen/models/project_foundation/interface_*.xml` confirms no key-wrap interface. Creating it is required.
- **Does mbedTLS support all three AES key sizes for KW?** Yes — `mbedtls_nist_kw_setkey` accepts `keybits` 128/192/256.
- **OID parameters: truly absent or NULL?** Truly absent — RFC 3394; `serialize_simple_alg_info` already handles this correctly.
- **EnvelopedData version when kekri present?** Version 3 per RFC 5652 §6.1 (not 4).
- **Which codegen system?** New Python codegen at `tools/codegen/` — `python3 -m tools.codegen.common_bootstrap --project foundation --apply`.
- **Are fuzzy tests available?** Yes — `tests/fuzzy/foundation/`. Existing `fuzzy_test__message_info_der_serializer` covers KEK DER deserialization automatically once the code is in. A new `fuzzy_test__recipient_cipher__kek_decrypt_message` is needed for the cipher path.

### Deferred to Implementation

- **Whether `vscf_asn1_reader_peek_tag` exists**: If no non-consuming peek is available, the `[2]`-before-`[3]` probe order works because `read_context_tag` returns 0 without advancing on mismatch — verify this before committing.
- **Exact guarded-region names in generated files**: visible only after running codegen.
- **Whether `vscf_aes256_kw` is modeled as `<class>` or `<implementation>`**: examine how `vscf_aes256_cbc` is modeled (likely `<implementor>`) and mirror that pattern exactly.

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

```
New interface hierarchy:

  interface_alg
       └── interface_key_wrap          (new)
                └── vscf_aes128_kw     (new implementation)
                └── vscf_aes256_kw     (new implementation)
                └── [future: vscf_sm4_kw, vscf_camellia_kw, ...]

Encrypt path:
  caller:  kw = vscf_aes256_kw_new()
           add_kek_recipient(cipher, kek_id, vscf_aes256_kw_impl(kw), kek_bytes)
               → stores (kek_id, key_wrap_impl, kek_bytes) in cipher->kek_recipients

  cipher:  encrypt_cipher_key_for_kek_recipients()
               for each kek_recipient:
                 vscf_key_wrap_wrap(key_wrap_impl, kek_bytes, master_key, out)  → wrapped_cek
                 alg_info = vscf_alg_produce_alg_info(key_wrap_impl)           → simple_alg_info(AES256_KW)
                 kek_recipient_info_new(kek_id, alg_info, wrapped_cek)
                 message_info_add_kek_recipient(message_info, info)

  serializer: serialize_recipient_infos()
               for each kek_recipient_info:
                 serialize_kek_recipient_info()  →  SEQUENCE { v=4, kekid, alg, encKey }
                 write_context_tag(2, len)        →  [2] IMPLICIT wrapping

Decrypt path:
  caller:  kw = vscf_aes256_kw_new()
           start_decryption_with_kek(cipher, kek_id, vscf_aes256_kw_impl(kw), kek_bytes, message_info)

  cipher:  decrypt_data_encryption_key() dispatcher
               if decryption_kek != NULL → decrypt_data_encryption_key_with_kek()
                 find matching kek_id in message_info->kek_recipients
                 determine alg from recipient_info->key_encryption_algorithm
                 vscf_key_wrap_unwrap(key_wrap_impl, kek_bytes, encrypted_key, out) → master_key
                 configure_decryption_cipher(master_key)

DER: kekri [2] IMPLICIT KEKRecipientInfo ::= SEQUENCE {
       version   INTEGER (4),
       kekid     SEQUENCE { keyIdentifier OCTET STRING },
       keyEncAlg AlgorithmIdentifier { OID id-aes256-wrap },   -- no parameters
       encKey    OCTET STRING (cek_len + 8 bytes)
     }
```

## Implementation Units

- [ ] **Unit 1: OID and alg_id infrastructure**

**Goal:** Register `id-aes{128,192,256}-wrap` OIDs and three corresponding `alg_id` enum values; wire them through the OID ↔ alg_id conversion functions and the alg_info DER serializer/deserializer.

**Requirements:** R6, R7

**Dependencies:** None

**Files:**
- Modify: `codegen/models/project_foundation/enum_alg_id.xml`
- Modify: `library/foundation/include/virgil/crypto/foundation/vscf_alg_id.h`
- Modify: `library/foundation/include/virgil/crypto/foundation/vscf_oid_id.h`
- Modify: `library/foundation/src/vscf_oid.c`
- Modify: `library/foundation/src/vscf_alg_info_der_serializer.c`
- Modify: `library/foundation/src/vscf_alg_info_der_deserializer.c`

**Approach:**
- Add `vscf_alg_id_AES128_KW`, `vscf_alg_id_AES192_KW`, `vscf_alg_id_AES256_KW` to `enum_alg_id.xml` and the generated header.
- Add `vscf_oid_id_AES128_KW`, `vscf_oid_id_AES192_KW`, `vscf_oid_id_AES256_KW` to `vscf_oid_id.h`.
- Add three OID byte constants in `vscf_oid.c` (NIST arc `2.16.840.1.101.3.4.1`, last bytes: 5, 25, 45).
- Extend `vscf_oid_from_id`, `vscf_oid_to_id`, `vscf_oid_to_alg_id` switch statements with all three.
- `vscf_alg_info_der_serializer.c`: map `vscf_alg_id_AES{128,192,256}_KW` → `serialize_simple_alg_info` (OID only, no parameters element).
- `vscf_alg_info_der_deserializer.c`: recognize the three KW OIDs and return `vscf_simple_alg_info_t` with the matching `alg_id`.
- Run `python3 -m tools.codegen.common_bootstrap --project foundation --apply` after editing `enum_alg_id.xml`.

**Patterns to follow:**
- `vscf_oid_id_AES256_GCM` / `vscf_oid_id_AES256_CBC` entries in `vscf_oid.c`.
- `serialize_simple_alg_info` already used for `KDF1`, `SHA256`, `ED25519`, etc.

**Test scenarios:**
- Happy path: `vscf_oid_from_id(vscf_oid_id_AES256_KW)` → bytes `{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2D}` (9 bytes).
- Happy path: `vscf_oid_to_id(oid_aes256_kw)` → `vscf_oid_id_AES256_KW`.
- Happy path: `vscf_oid_to_alg_id(oid_aes128_kw)` → `vscf_alg_id_AES128_KW` (verify all three OIDs independently).
- Happy path: Serialize `vscf_simple_alg_info_t(AES256_KW)` → DER `30 0B 06 09 60 86 48 01 65 03 04 01 2D` (11 bytes, no trailing `05 00`).
- Happy path: Deserialize those 11 bytes → `alg_id == vscf_alg_id_AES256_KW`.
- Error path: Unknown OID → `vscf_oid_to_alg_id` returns `vscf_alg_id_NONE`.

**Verification:** OID byte sequences serialize and deserialize without data corruption. AlgInfo round-trip produces identical `alg_id`.

---

- [ ] **Unit 2: `interface_key_wrap` codegen model and generated files**

**Goal:** Define the `interface_key_wrap` XML model and run codegen to produce the generated interface headers and source. This is the extensibility seam — all KEK algorithm classes implement this interface.

**Requirements:** R9

**Dependencies:** Unit 1

**Files:**
- Create: `codegen/models/project_foundation/interface_key_wrap.xml`
- Create (generated): `library/foundation/include/virgil/crypto/foundation/vscf_key_wrap.h`
- Create (generated): `library/foundation/src/vscf_key_wrap.c`
- Create (generated): `library/foundation/include/virgil/crypto/foundation/vscf_key_wrap_api.h`
- Create (generated): `library/foundation/src/vscf_key_wrap_api.c`
- Modify: `library/foundation/features.cmake`
- Modify: `library/foundation/sources.cmake`

**Approach:**
- `interface_key_wrap` inherits `interface_alg` (for `alg_id`, `produce_alg_info`, `restore_alg_info` — allows the cipher to obtain the AlgorithmIdentifier for the KEKRecipientInfo and potentially restore a KW algorithm from stored alg info in future).
- Methods: `wrap(kek vsc_data_t, data vsc_data_t, out vsc_buffer_t*) → status`, `unwrap(kek, data, out) → status`, `wrapped_len(data_len) → size`, `unwrapped_len(data_len) → size`.
- `wrapped_len` is deterministic: `data_len + 8` for KW mode. `unwrapped_len` is `data_len - 8`.
- Buffer length annotations on `out` arguments reference the corresponding `wrapped_len`/`unwrapped_len` methods (same pattern as `interface_cipher`'s `out_len` reference).
- After writing the XML, run `python3 -m tools.codegen.common_bootstrap --project foundation --apply`.
- `features.cmake`: add `VSCF_KEY_WRAP` option (default ON); `sources.cmake`: register generated files.

**Patterns to follow:**
- `codegen/models/project_foundation/interface_cipher.xml` — method + buffer-length annotation pattern.
- `codegen/models/project_foundation/interface_kdf.xml` — minimal interface with a single operation.
- `codegen/models/project_foundation/interface_alg.xml` — `inherit` pattern.

**Test scenarios:**
- Test expectation: none — this unit produces only generated interface scaffolding with no business logic. Functional tests appear in Units 3, 6, and 7.

**Verification:** `cmake --build build` succeeds. Generated `vscf_key_wrap.h` declares `vscf_key_wrap_wrap` and `vscf_key_wrap_unwrap` with the expected signatures.

---

- [ ] **Unit 3: `vscf_aes128_kw` and `vscf_aes256_kw` implementation classes**

**Goal:** Create two stateless implementation classes that implement `interface_key_wrap` using `mbedtls_nist_kw_*`. These are the only concrete classes needed to expose AES-128-KW and AES-256-KW as selectable KEK algorithms.

**Requirements:** R1, R6, R7

**Dependencies:** Units 1, 2

**Files:**
- Create: `codegen/models/project_foundation/implementor_aes256_kw.xml` (or `class_aes256_kw.xml` — follow the convention used by `vscf_aes256_cbc`)
- Create (generated + manual): `library/foundation/include/virgil/crypto/foundation/vscf_aes256_kw.h`
- Create (generated + manual): `library/foundation/src/vscf_aes256_kw.c`
- Create (generated): `library/foundation/include/virgil/crypto/foundation/private/vscf_aes256_kw_defs.h`
- Create (generated): `library/foundation/src/vscf_aes256_kw_defs.c`
- Mirror all of the above for `vscf_aes128_kw`
- Modify: `library/foundation/features.cmake`
- Modify: `library/foundation/sources.cmake`
- Test: `tests/foundation/test_aes256_kw.c`
- Modify: `tests/foundation/CMakeLists.txt`

**Approach:**
- **Struct**: no stored state beyond the `impl_info` + `refcnt` vtable header (both classes are stateless; keys are passed in at call time, not stored). No `kek` buffer stored in the struct.
- **`alg_id`**: returns `vscf_alg_id_AES256_KW` / `vscf_alg_id_AES128_KW`.
- **`produce_alg_info`**: returns `vscf_simple_alg_info_new_with_alg_id(alg_id)`. No IV, no parameters.
- **`restore_alg_info`**: no-op (returns `vscf_status_SUCCESS`). No state to restore from alg_info.
- **`wrapped_len(data_len)`**: returns `data_len + 8`.
- **`unwrapped_len(data_len)`**: returns `data_len - 8`.
- **`wrap(kek, data, out)`**:
  - `mbedtls_nist_kw_init(&kw)`
  - `mbedtls_nist_kw_setkey(&kw, MBEDTLS_CIPHER_ID_AES, kek.bytes, kek.len * 8, 1)`
  - `mbedtls_nist_kw_wrap(&kw, MBEDTLS_KW_MODE_KW, data.bytes, data.len, out->bytes, &out_len, out->capacity)`
  - `mbedtls_nist_kw_free(&kw)` — always, even on error
  - Map `MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA` → `vscf_status_ERROR_BAD_ARGUMENTS`; other errors → `vscf_status_ERROR_UNHANDLED_THIRDPARTY_ERROR`
- **`unwrap(kek, data, out)`**: same lifecycle with `is_wrap=0` and `_unwrap`; map `MBEDTLS_ERR_CIPHER_AUTH_FAILED` → `vscf_status_ERROR_BAD_ENCRYPTED_DATA`.
- Include `mbedtls/nist_kw.h` directly — already compiled into `mbed::crypto`.
- After XML model creation, run `python3 -m tools.codegen.common_bootstrap --project foundation --apply`, then fill guarded regions.

**Execution note:** Run codegen after XML models are written; fill business logic in the guarded `init_ctx`/`cleanup_ctx`/`wrap`/`unwrap` regions.

**Patterns to follow:**
- `library/foundation/src/vscf_aes256_cbc.c` — `init_ctx`, `cleanup_ctx`, `alg_id`, `produce_alg_info`, `restore_alg_info`.
- `library/foundation/src/vscf_aes256_gcm.c` — stateless-ish cipher pattern.
- mbedTLS `nist_kw` lifetime: `init` → `setkey` → `wrap/unwrap` → `free` in every code path.

**Test scenarios:**
- Happy path: `vscf_aes256_kw_wrap(kek_32, cek_32, out)` → `out.len == 40`; `vscf_aes256_kw_unwrap(kek_32, out, recovered)` → `recovered == cek_32`.
- Happy path: AES-128-KW with 16-byte kek, 16-byte cek → wrapped is 24 bytes; unwrap recovers original.
- Happy path: `produce_alg_info` → `alg_id == vscf_alg_id_AES256_KW`; `restore_alg_info(that)` → `vscf_status_SUCCESS`.
- Happy path: `wrapped_len(32) == 40`; `unwrapped_len(40) == 32`.
- Error path: `wrap` with kek length not a valid AES key size (e.g. 10 bytes) → `vscf_status_ERROR_BAD_ARGUMENTS`.
- Error path: `unwrap` with correct kek but tampered wrapped data → `vscf_status_ERROR_BAD_ENCRYPTED_DATA`.
- Error path: `unwrap` with wrong kek → `vscf_status_ERROR_BAD_ENCRYPTED_DATA` (HMAC-check fail from mbedTLS).

**Verification:** All test cases green. `vscf_aes256_kw_impl(vscf_aes256_kw_new())` satisfies `vscf_key_wrap_t *` and can be passed to `vscf_key_wrap_wrap`.

---

- [ ] **Unit 4: `vscf_kek_recipient_info` data class + build registration**

**Goal:** Create the `vscf_kek_recipient_info_t` (and `_list_t`) plain data class holding `key_identifier`, `key_encryption_algorithm` (`vscf_impl_t *`), and `encrypted_key`. Register in CMake.

**Requirements:** R1, R2, R3, R8

**Dependencies:** Units 1, 2

**Files:**
- Create: `codegen/models/project_foundation/class_kek_recipient_info.xml`
- Create: `codegen/models/project_foundation/class_kek_recipient_info_list.xml`
- Create (generated + manual): `library/foundation/include/virgil/crypto/foundation/vscf_kek_recipient_info.h`
- Create (generated): `library/foundation/include/virgil/crypto/foundation/private/vscf_kek_recipient_info_defs.h`
- Create (generated + manual): `library/foundation/src/vscf_kek_recipient_info.c`
- Create (generated): `library/foundation/src/vscf_kek_recipient_info_defs.c`
- Create (generated): `library/foundation/include/virgil/crypto/foundation/vscf_kek_recipient_info_list.h`
- Create (generated): `library/foundation/include/virgil/crypto/foundation/private/vscf_kek_recipient_info_list_defs.h`
- Create (generated): `library/foundation/src/vscf_kek_recipient_info_list.c`
- Create (generated): `library/foundation/src/vscf_kek_recipient_info_list_defs.c`
- Modify: `library/foundation/features.cmake`
- Modify: `library/foundation/sources.cmake`
- Test: `tests/foundation/test_kek_recipient_info.c`
- Modify: `tests/foundation/CMakeLists.txt`

**Approach:**
- Properties: `key_identifier` (buffer), `key_encryption_algorithm` (interface `alg_info`, access `readonly`), `encrypted_key` (buffer).
- Constructors: `new_with_data(key_identifier, key_encryption_algorithm, encrypted_key)` (public), `new_with_buffer(key_identifier, key_encryption_algorithm, &encrypted_key_ref)` (private, disowns buffer).
- List class: singly-linked, identical structure to `class_key_recipient_info_list.xml`.
- `features.cmake`: `VSCF_KEK_RECIPIENT_INFO`, `VSCF_KEK_RECIPIENT_INFO_LIST` options (default ON); add both as dependencies of `VSCF_RECIPIENT_CIPHER`.
- Run `python3 -m tools.codegen.common_bootstrap --project foundation --apply` after writing XML.

**Patterns to follow:**
- `codegen/models/project_foundation/class_key_recipient_info.xml` — exact structural mirror.
- `codegen/models/project_foundation/class_key_recipient_info_list.xml` — list class mirror.

**Test scenarios:**
- Happy path: `new_with_data(id, alg_info, key)` → accessors return identical values.
- Happy path: `shallow_copy` increments refcount; double-`destroy` does not crash; second pointer nullified.
- Happy path: List `add` → `has_item` true → `item` returns added object → `next` is NULL for a single-item list.
- Edge case: `new_with_data` with zero-length `key_identifier` → does not crash; accessor returns empty `vsc_data_t`.

**Verification:** Build succeeds. Test binary runs green. `VSCF_KEK_RECIPIENT_INFO` CMake option defaults ON and the library builds with the new sources.

---

- [ ] **Unit 5: Add `kek_recipients` to `vscf_message_info`**

**Goal:** Extend `vscf_message_info_t` with a `kek_recipients` list property, private `add_kek_recipient`, and public `kek_recipient_info_list` accessor — matching the `key_recipients` pattern exactly.

**Requirements:** R1, R2, R3

**Dependencies:** Unit 4

**Files:**
- Modify: `codegen/models/project_foundation/class_message_info.xml`
- Modify: `library/foundation/include/virgil/crypto/foundation/private/vscf_message_info_defs.h`
- Modify: `library/foundation/src/vscf_message_info.c`
- Modify: `library/foundation/include/virgil/crypto/foundation/vscf_message_info.h`

**Approach:**
- Add `<property name="kek recipients" class="kek recipient info list"/>` to the class model.
- Add private `add_kek_recipient` (disowns ref) and `kek_recipient_info_list_modifiable`.
- Add public `kek_recipient_info_list` (read-only).
- Extend `vscf_message_info_clear_recipients` to also clear `kek_recipients`.
- `init_ctx` allocates; `cleanup_ctx` destroys — same as key/password recipients.
- Run codegen; hand-fill alloc/dealloc guarded sections.

**Patterns to follow:** `add_key_recipient` / `key_recipient_info_list` in `vscf_message_info.c`.

**Test scenarios:**
- Happy path: `add_kek_recipient` → `kek_recipient_info_list` has `has_item` true.
- Happy path: `clear_recipients` clears the kek list alongside key and password lists.
- Edge case: fresh `message_info` with no kek recipients → `kek_recipient_info_list` is non-NULL, `has_item` false.

**Verification:** Build succeeds. Existing key and password recipient tests pass (no regression).

---

- [ ] **Unit 6: DER serializer / deserializer for KEKRecipientInfo**

**Goal:** Implement `serialize_kek_recipient_info` and `deserialize_kek_recipient_info`; extend the dispatch loops; fix `EnvelopedData.version` logic for kekri.

**Requirements:** R2, R3, R4, R5, R7, R8

**Dependencies:** Units 1, 2, 4, 5

**Files:**
- Modify: `library/foundation/src/vscf_message_info_der_serializer.c`

**Approach:**
- **`serialize_kek_recipient_info`** (static, mirrors `serialize_password_recipient_info`):
  Write in reverse DER order: `encryptedKey` OCTET STRING, `keyEncryptionAlgorithm` (via `alg_info_der_serializer_serialize_inplace`), `kekid` SEQUENCE { `keyIdentifier` OCTET STRING }, `version` INTEGER (4). Wrap in SEQUENCE; caller adds context tag `[2]`.
- **Serialize loop**: add kek_recipients loop between key and password loops; wrap each with `write_context_tag(2, len)`.
- **`deserialize_kek_recipient_info`** (static): read SEQUENCE forward: version (assert == 4), kekid SEQUENCE → OCTET STRING (skip optional OPTIONAL fields if present), `keyEncryptionAlgorithm` via `alg_info_der_deserializer`, `encryptedKey` OCTET STRING. Construct `vscf_kek_recipient_info_t` and add to `message_info`.
- **Deserialize dispatch**: probe `[2]` first, then `[3]`, then fall through to ktri SEQUENCE. Remove all `-- not supported` comments.
- **`EnvelopedData.version`**: in `serialize_enveloped_data`/`serialize_cms_content_info`, bump to `3` when `vscf_message_info_kek_recipient_info_list(info)` is non-empty (same logic as existing pwri bump).
- **`deserialize_enveloped_data` version check**: existing `!= 2 && != 3` already covers version 3 — update surrounding comment to document that kekri is a reason for version 3.

**Patterns to follow:**
- `serialize_password_recipient_info` / `deserialize_password_recipient_info` — direct structural mirror.
- `pwri [3]` context-tag wrapping in the serialize loop — mirror with tag `2`.

**Test scenarios:**
- Happy path: Serialize `message_info` with one KEK recipient (AES-256-KW, 8-byte keyId, 40-byte encryptedKey) → DER outer tag is `[2]`, inner `SEQUENCE` first element is `INTEGER 4`.
- Happy path: Deserialize that DER → `kek_recipient_info_list` has one item with matching `key_identifier` and `encrypted_key`.
- Happy path: Round-trip with both ktri and kekri present → both are in the deserialized info.
- Happy path: `EnvelopedData.version` == 3 when only kekri present; == 3 when both ktri and kekri present.
- Edge case: Input `KEKIdentifier` with `date` field present → deserializer skips without error.
- Error path: `KEKRecipientInfo.version` ≠ 4 in input → `vscf_status_ERROR_BAD_ENCRYPTED_DATA`.

**Verification:** DER round-trip test passes. Existing ktri and pwri DER tests pass (no regression in dispatch).

---

- [ ] **Unit 7: `vscf_recipient_cipher` KEK encrypt/decrypt API**

**Goal:** Add `vscf_recipient_cipher_add_kek_recipient` and `vscf_recipient_cipher_start_decryption_with_kek`; call through `vscf_key_wrap_*` for all wrap/unwrap operations.

**Requirements:** R1, R2, R3, R9

**Dependencies:** Units 1, 2, 3, 4, 5, 6

**Files:**
- Modify: `codegen/models/project_foundation/class_recipient_cipher.xml`
- Modify: `library/foundation/include/virgil/crypto/foundation/vscf_recipient_cipher.h`
- Modify: `library/foundation/include/virgil/crypto/foundation/private/vscf_recipient_cipher_defs.h`
- Modify: `library/foundation/src/vscf_recipient_cipher.c`

**Approach:**
- **New struct fields** (`_defs.h`, via model): `kek_recipients` list (stores `(kek_id, key_wrap_impl, kek_bytes)` triples for encrypt-time use — define a thin private struct or reuse a pattern from existing `key_recipients`); `decryption_kek_id` buffer; `decryption_kek` buffer; `decryption_kek_wrap_impl` (`vscf_impl_t *`).
- **`add_kek_recipient(self, kek_id, key_wrap_impl, kek)`** (public): copies `kek_id` and `kek` into secure buffers; shallow-copies `key_wrap_impl`. Stores all three in `self->kek_recipients` list. Mirror of `add_key_recipient`.
- **`start_decryption_with_kek(self, kek_id, key_wrap_impl, kek, message_info)`** (public): stores `kek_id`, `key_wrap_impl`, `kek` for use during `decrypt_data_encryption_key`. Mirror of `start_decryption_with_key`.
- **`encrypt_cipher_key_for_kek_recipients`** (new static): for each entry in `self->kek_recipients`:
  - `vscf_key_wrap_wrap(key_wrap_impl, kek, master_key, wrapped_buf)`
  - `alg_info = vscf_alg_produce_alg_info(key_wrap_impl)` → `vscf_simple_alg_info_t`
  - `vscf_kek_recipient_info_new_with_buffer(kek_id, alg_info, &wrapped_buf)`
  - `vscf_message_info_add_kek_recipient(message_info, &info)`
  Called from `update_message_info_for_encryption` (or equivalent) alongside existing key-recipient loop.
- **`decrypt_data_encryption_key_with_kek`** (new static):
  - Search `message_info->kek_recipients` for `key_identifier == self->decryption_kek_id`.
  - If not found: return `vscf_status_ERROR_KEY_RECIPIENT_IS_NOT_FOUND`.
  - `vscf_key_wrap_unwrap(decryption_kek_wrap_impl, decryption_kek, recipient_info->encrypted_key, out)` → master key.
  - On success: `configure_decryption_cipher(master_key)`.
- **`decrypt_data_encryption_key` dispatcher**: add third branch `else if (self->decryption_kek != NULL)` → call `decrypt_data_encryption_key_with_kek`.
- **Cleanup**: zero and free all new buffers; `vscf_impl_destroy` the `key_wrap_impl` refs.

**Patterns to follow:**
- `encrypt_cipher_key_for_recipients` (key-transport path).
- `decrypt_data_encryption_key_with_private_key`.
- `add_key_recipient` / `start_decryption_with_key` — exact API shape mirror.

**Test scenarios:**
- Happy path: Encrypt with AES-256-KW KEK recipient → decrypt with matching KEK and keyId → plaintext matches.
- Happy path: Encrypt with both KEK recipient (AES-256) and key-transport recipient → decrypt with each independently → same plaintext.
- Happy path: Encrypt with AES-128-KW (16-byte KEK) → decrypt succeeds.
- Error path: Decrypt with wrong KEK (same keyId, different bytes) → `vscf_status_ERROR_BAD_ENCRYPTED_DATA`.
- Error path: Decrypt with correct KEK but wrong keyId → `vscf_status_ERROR_KEY_RECIPIENT_IS_NOT_FOUND`.
- Error path: KEK length not a valid AES size (e.g. 10 bytes) → error returned before wrapping starts.
- Integration: `start_decryption_with_kek` on a message with no kek recipients → error, no crash.

**Verification:** Full encrypt/decrypt round-trip passes. Existing key-transport and password-recipient tests pass. No memory leaks on the new buffers.

---

- [ ] **Unit 8: Tests and fuzzy test extension**

**Goal:** Write unit tests for all new code paths; add a KEK-decrypt fuzzy test; register everything with CTest.

**Requirements:** R1–R9

**Dependencies:** Units 1–7

**Files:**
- Create: `tests/foundation/test_kek_recipient_info.c`
- Create: `tests/foundation/test_aes256_kw.c` (unit tests for the wrap/unwrap primitive — already listed in Unit 3, registered here)
- Modify: `tests/foundation/test_message_info_der_serializer.c`
- Modify: `tests/foundation/test_recipient_cipher.c`
- Modify: `tests/foundation/data/src/test_data_recipient_cipher.c` + `.h` (add KEK test vectors)
- Modify: `tests/foundation/CMakeLists.txt`
- Create: `tests/fuzzy/foundation/src/fuzzy_test__recipient_cipher__kek_decrypt_message.c`
- Modify: `tests/fuzzy/foundation/CMakeLists.txt`

**Approach:**
- **`test_kek_recipient_info.c`**: data class unit tests (constructors, accessors, list operations) — mirrors `test_key_recipient_info.c`.
- **`test_message_info_der_serializer.c`**: add one test with a hard-coded known-good DER blob generated by OpenSSL (`openssl cms -EncryptedKey -secretkey <hex> -secretkeyid <hex>`) and verify deserialized fields match; add one serialize test that produces the same blob programmatically.
- **`test_recipient_cipher.c`**: add `test__encrypt_decrypt__with_kek_recipient__success`, `test__encrypt_decrypt__with_kek_and_key_recipients__success`, and key error-path cases.
- **`test_data_recipient_cipher.c`**: add KEK test vector constants (fixed 32-byte KEK, 8-byte keyId, known plaintext, expected wrapped key bytes — generate with OpenSSL against a fixed CEK for determinism).
- **`fuzzy_test__recipient_cipher__kek_decrypt_message.c`**: loads a known-valid KEK-encrypted message (serialized in test data) and calls `start_decryption_with_kek` + `process_decryption` + `finish_decryption` with the valid KEK and keyId. The fuzzer feeds arbitrary bytes as the message body. Pattern mirrors `fuzzy_test__recipient_cipher__ed25519_decrypt_message.c` exactly.
- The existing `fuzzy_test__message_info_der_serializer__der_serializer_deserialize_info` already exercises the kekri `[2]` deserialize branch once it is wired in — no new fuzzer needed for the serializer itself.
- `tests/fuzzy/foundation/CMakeLists.txt`: `_add_test(fuzzy_test__recipient_cipher__kek_decrypt_message)`.

**Patterns to follow:**
- `tests/fuzzy/foundation/src/fuzzy_test__recipient_cipher__ed25519_decrypt_message.c` — fuzzer structure.
- `tests/foundation/test_key_recipient_info.c` — data class unit test template.
- `tests/foundation/test_recipient_cipher.c` — cipher test structure.

**Test scenarios:** (covered by Units 3–7; this unit wires them into named runnable binaries)

**Verification:**
- `cd build && ctest --output-on-failure -R kek` — all new tests green.
- `ctest --output-on-failure` (full suite) — no regressions.
- The fuzzy binary builds without error (requires Clang; document the build flag needed, e.g. `-DVIRGIL_BUILD_FUZZY=ON`).

## System-Wide Impact

- **Interaction graph:** `vscf_recipient_cipher` calls `vscf_key_wrap_wrap/unwrap` (new interface) and `vscf_message_info_add_kek_recipient` (new method). No callbacks or observers affected. The `message_info_der_serializer` dispatch is extended additively.
- **Error propagation:** `mbedtls_nist_kw_*` errors are mapped to `vscf_status_t` inside the `vscf_aes{128,256}_kw` classes before surfacing to the cipher — the cipher never sees raw mbedTLS codes.
- **State lifecycle risks:** `kek_recipients` list (encrypt-time) and `decryption_kek`/`decryption_kek_id`/`decryption_kek_wrap_impl` (decrypt-time) must be zeroed and freed in `cleanup_ctx`. Wrapped key buffer is transferred via `new_with_buffer` (disown semantics) — the cipher holds no dangling copy.
- **API surface parity:** `add_kek_recipient` / `start_decryption_with_kek` are new public C API. Language wrappers regenerate stubs automatically from codegen but are not wired in this PR.
- **Integration coverage:** DER round-trip (Unit 6) + end-to-end cipher test (Unit 7) + KEK fuzzer (Unit 8) together prove correctness of the full stack.
- **Unchanged invariants:** `KeyTransRecipientInfo` and `PasswordRecipientInfo` serialize/deserialize paths are not modified. `EnvelopedData.version` for messages with only ktri or pwri recipients is unchanged.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| `deserialize_recipient_infos` tag dispatch order is fragile | Verify `read_context_tag` returns 0 without advancing on mismatch. If a non-consuming peek exists, prefer it. |
| `mbedtls_nist_kw.h` not compiled in all CMake configs | After `cmake --build`, verify `mbedtls_nist_kw_init` links. If missing, add `MBEDTLS_NIST_KW_C=ON` to the mbedTLS config in `thirdparty/`. |
| Codegen overwrites hand-edited regions | Run codegen first, fill guarded regions second; never edit outside `@end` / `@<tag>` markers. |
| New codegen (`tools/codegen/`) may not yet support `interface` XML models in the same way as the legacy pipeline | Check `tools/codegen/ARCHITECTURE.md` and `test_interface_rendering.py` tests before writing the XML model. |
| Feature branch diverges from `develop` mid-implementation | Rebase onto `develop` before opening PR. |
| Fuzzy tests require Clang | Document the CMake flag (e.g. `-DVIRGIL_BUILD_FUZZY=ON -DCMAKE_C_COMPILER=clang`) in the test binary's CMake guard. |

## Documentation / Operational Notes

- Feature branch: `feat/kek-recipient-info`, branched from `develop`.
- Before pushing: run `cmake --build build -j$(nproc)` and `cd build && ctest --output-on-failure`. Per project policy, do not push without a clean local build and test run.
- Codegen command: `python3 -m tools.codegen.common_bootstrap --project foundation --apply` (from repo root). Run after every XML model change.

## Sources & References

- Related code: `library/foundation/src/vscf_message_info_der_serializer.c`
- Related code: `library/foundation/src/vscf_recipient_cipher.c`
- Related code: `library/foundation/src/vscf_oid.c`
- Related code: `library/foundation/src/vscf_aes256_cbc.c` — algorithm implementation pattern
- Related code: `codegen/models/project_foundation/interface_cipher.xml` — interface model pattern
- Related code: `tests/fuzzy/foundation/src/fuzzy_test__recipient_cipher__ed25519_decrypt_message.c`
- External docs: RFC 5652 §6.1–6.2.3
- External docs: RFC 3394 (AES Key Wrap)
- External docs: RFC 3565 (AES in CMS)
- mbedTLS API: `thirdparty/mbedtls/.../include/mbedtls/nist_kw.h`
- New codegen: `tools/codegen/ARCHITECTURE.md`
