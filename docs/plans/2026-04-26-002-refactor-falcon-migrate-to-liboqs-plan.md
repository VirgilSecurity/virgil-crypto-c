---
title: "refactor: Migrate Falcon implementation from standalone thirdparty to liboqs OQS API"
type: refactor
status: active
date: 2026-04-26
---

# refactor: Migrate Falcon implementation from standalone thirdparty to liboqs OQS API

## Overview

`thirdparty/liboqs` is already built with `OQS_ENABLE_SIG_FALCON=ON` (default), so the Falcon
algorithm is compiled into `liboqs.a`. The standalone `thirdparty/falcon` is redundant. This
plan removes it and rewrites `vscf_falcon.c` to call the liboqs OQS generic signature API
instead of the standalone Falcon C API.

## Problem Frame

Two Falcon implementations are currently linked into `libvsc_foundation`: the standalone
`thirdparty/falcon` (downloaded from falcon-sign.info) and the Falcon bundled inside liboqs
0.15.0. Only the standalone one is actually called from C code. The liboqs Falcon is dormant
but adds build time and binary size. The standalone library required a symbol-collision patch
(`patch_shake256.cmake`) that renames all `shake256_*` symbols to `falcon_shake256_*` to avoid
conflict with round5 — a fragile workaround that disappears when the standalone library is removed.

## Requirements Trace

- R1. `vscf_falcon_*` public API is preserved (generate key, sign, verify, export/import)
- R2. C tests pass: `test_falcon` (wrapper API), `test_post_quantum_library_falcon` (low-level)
- R3. `thirdparty/falcon/` directory and its CMake target are fully removed from the build
- R4. CGO link entries in Go wrapper XML models replace `-lfalcon` with `-loqs`
- R5. The `FALCON_LIBRARY` compile-time macro remains defined (test guards unchanged)

## Scope Boundaries

- No changes to the public `vscf_falcon_*` function signatures or the `vscf_alg_id_t` values
- No changes to the serialization format of Falcon-512 public keys
- The Falcon private key blob format changes slightly (see Key Technical Decisions)
- No changes to `vscf_round5_*` or any other post-quantum adapter

### Deferred to Separate Tasks

- Rebuild Go pre-built static libs in `wrappers/go/pkg/` (need `liboqs.a`, remove `libfalcon.a`): separate task requiring a macOS + Linux build environment
- Fix `BUILD_BYPRODUCTS` path bug in `thirdparty/liboqs/CMakeLists.txt` (`libliboqs.a` vs `liboqs.a`): separate housekeeping PR
- Liboqs description strings (`OQS_ENABLE_KEM_ML_KEM`, `OQS_ENABLE_SIG_ML_DSA` options currently say "Falcon"): can be fixed in this branch or separately

## Context & Research

### Relevant Code and Patterns

- `thirdparty/falcon/CMakeLists.txt` — ExternalProject, downloads tarball, applies 3 patches
- `thirdparty/liboqs/CMakeLists.txt` — ExternalProject, clones OQS tag 0.15.0, passes `OQS_ENABLE_SIG_FALCON=${OQS_ENABLE_SIG_FALCON}` to the sub-build
- `library/foundation/src/vscf_falcon.c` — 615-line partially-generated file; hand-written functions are keygen, extract_public_key, signature_len, sign_hash, verify_hash
- `library/foundation/CMakeLists.txt` line 109 — `FALCON_LIBRARY=$<BOOL:${FALCON_LIBRARY}>` compile def (must be rewired to `OQS_ENABLE_SIG_FALCON`)
- `library/foundation/features.cmake` line 168 — `option(VSCF_FALCON "..." ON)` — **generated** from `implementor_post_quantum.xml`, default currently `${FALCON_LIBRARY}`
- `codegen/models/project_foundation/implementor_post_quantum.xml` lines 7-10 — `<feature name="falcon" default="${FALCON_LIBRARY}"/>`, `<require library="falcon" feature="library"/>`, `<require header="falcon/falcon.h"/>`
- `codegen/models/project_foundation/project_foundation.xml` and `project_ratchet/project_ratchet.xml` — 8 `<cgo_link>` entries include `-lfalcon`, none include `-loqs`
- `tests/foundation/test_post_quantum_library_falcon.c` — tests standalone C API directly, includes `<falcon/falcon.h>`
- `tests/foundation/test_falcon.c` — tests `vscf_falcon_*` wrapper API, includes `<falcon/falcon.h>`

### Institutional Learnings

- `docs/solutions/best-practices/external-library-cmake-codegen-2026-04-26.md` — `thirdparty/*/features.cmake` is generated from `codegen/models/external/library_*.xml`; deleting `library_falcon.xml` and running `--apply` removes the generated file. Do not hand-edit generated cmake files.

### External References

- liboqs 0.15.0 OQS signature API: `OQS_SIG_new`, `OQS_SIG_keypair`, `OQS_SIG_sign`, `OQS_SIG_verify`, `OQS_SIG_free` — all in `<oqs/oqs.h>`
- liboqs Falcon-512 constants: two variants exist — `OQS_SIG_alg_falcon_512` (variable-length signature, max 752 bytes) and `OQS_SIG_alg_falcon_padded_512` (fixed 666-byte signatures). Public key (897) and secret key (1281) sizes are identical for both variants. The 666 value in the standalone `FALCON_SIG_CT_SIZE(9)` (constant-time format) matches the padded variant.

## Key Technical Decisions

- **Keep the `FALCON_LIBRARY` compile-time macro name** — test guards throughout the codebase use `#if FALCON_LIBRARY`; renaming them is unnecessary churn. Wire `FALCON_LIBRARY` to `OQS_ENABLE_SIG_FALCON` in `library/foundation/CMakeLists.txt`. Update `implementor_post_quantum.xml` to default the falcon feature on `${OQS_ENABLE_SIG_FALCON}`.

- **Do not route through Virgil's `vscf_random` for OQS operations** — the standalone falcon accepted a seeded SHAKE256 DRBG; liboqs uses `OQS_randombytes` (OpenSSL RAND_bytes or OS PRNG) globally. The `random` parameter in `vscf_falcon_generate_key` and `vscf_falcon_sign_hash` will be accepted but not used; liboqs handles randomness internally. This simplifies the implementation significantly and is sound for production.

- **Embed the OQS public key in the private key blob** — liboqs has no `extract_public_key_from_secret_key` API equivalent to `falcon_make_public`. To preserve `vscf_falcon_extract_public_key`, the private key representation in Virgil stores `[OQS_secret_key | OQS_public_key]` concatenated. The first 1281 bytes are the OQS secret key; the following 897 bytes are the public key. `extract_public_key` reads the embedded bytes. This changes the private key serialization format — keys generated by the old standalone implementation are incompatible.

- **Use `OQS_SIG_alg_falcon_padded_512` throughout** — the standalone library used `FALCON_SIG_CT_SIZE(9)` which is the constant-time fixed-length format (666 bytes). The closest liboqs equivalent is `OQS_SIG_alg_falcon_padded_512` (fixed 666-byte signatures), not `OQS_SIG_alg_falcon_512` (variable-length, up to 752 bytes). Use `OQS_SIG_alg_falcon_padded_512` in `OQS_SIG_new()`, `vscf_falcon_signature_len`, and all size constants. Note: `OQS_SIG_falcon_512_length_public_key` (897) and `OQS_SIG_falcon_512_length_secret_key` (1281) are shared by both variants. The `_padded_512_length_signature` constant is 666. Falcon-1024 support is out of scope.

- **Remove test vectors that relied on a seeded DRBG** — `test_data_falcon.c`/`test_data_falcon.h` contain keys/signatures generated from deterministic seeds via the standalone SHAKE256 DRBG. Those vectors are invalid after migration. Tests should be rewritten to use generate-then-verify round trips without comparing exact bytes.

## Open Questions

### Resolved During Planning

- *Can liboqs Falcon replace standalone Falcon for signing and verification?* — Yes. liboqs 0.15.0 implements Falcon-512/1024 with the same NIST specification. Key and signature byte formats are compatible with the reference implementation.
- *Is `OQS_ENABLE_SIG_FALCON=ON` the default?* — Yes, confirmed in `thirdparty/liboqs/features.cmake`.
- *Does `vscf_falcon.c` use CTR_DRBG directly?* — The include `vscf_ctr_drbg.h` is generated from the `<require feature="ctr drbg"/>` in the IR. The hand-written keygen/sign functions use `vscf_random_random()` (the generic random interface, not CTR_DRBG-specific). The CTR_DRBG dependency in the IR can be removed after migration since OQS handles randomness internally.

### Deferred to Implementation

- *Does removing `vscf_ctr_drbg.h` from the generated includes break any other generated code in `vscf_falcon_internal.c` or `vscf_falcon_defs.c`?* — Check at implementation time; remove only if unused.
- *Are there any tests in `test_falcon.c` that do NOT use fixed-seed test vectors?* — Audit at implementation time; preserve round-trip tests, remove or regenerate vector-comparison tests.
- *Does the codegen emit `${OQS_ENABLE_SIG_FALCON}` as a CMake variable reference or resolve it to its literal value at generation time?* — The codegen resolves external library feature defaults as CMake variable references (confirmed: `${VIRGIL_POST_QUANTUM}` is emitted verbatim). However, project-level implementation feature defaults (in `implementor_post_quantum.xml`) may be resolved differently. Verify at implementation time: after running `--apply`, check whether `library/foundation/features.cmake` contains `${OQS_ENABLE_SIG_FALCON}` or just `ON`. If it resolves to `ON`, add an explicit `if(NOT OQS_ENABLE_SIG_FALCON) ... set(VSCF_FALCON OFF ...) endif()` block in `library/foundation/CMakeLists.txt` to enforce the dependency at CMake configure time.

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

```
Before:
  vscf_falcon.c --[#include falcon/falcon.h]--> thirdparty/falcon (ExternalProject)
  foundation --[link]--> falcon + liboqs (liboqs: unused)

After:
  vscf_falcon.c --[#include oqs/oqs.h]--> thirdparty/liboqs (OQS_ENABLE_SIG_FALCON=ON)
  foundation --[link]--> liboqs only

Key mapping (standalone → OQS):
  OQS_SIG_new(OQS_SIG_alg_falcon_padded_512)  // constant-time, fixed 666-byte signatures

  falcon_keygen_make(rng, logn, ...)          → OQS_SIG_keypair(sig, pk, sk)
  falcon_sign_dyn(rng, sig_buf, &len, ...)    → OQS_SIG_sign(sig, sig_buf, &len, msg, mlen, sk)
  falcon_verify(sig, slen, pk, pklen, ...)    → OQS_SIG_verify(sig, msg, mlen, sig_buf, slen, pk)
  falcon_make_public(pk, pklen, sk, sklen)    → read embedded pk from [sk_blob | pk_blob]
  FALCON_PRIVKEY_SIZE(9)                      → OQS_SIG_falcon_512_length_secret_key (1281)
  FALCON_PUBKEY_SIZE(9)                       → OQS_SIG_falcon_512_length_public_key (897)
  FALCON_SIG_CT_SIZE(9)                       → OQS_SIG_falcon_padded_512_length_signature (666)
  falcon_get_logn(key_buf, len) > 0           → len == expected_size check (2178 for sk, 897 for pk)
```

## Implementation Units

- [ ] **Unit 1: Update codegen IR and regenerate**

**Goal:** Remove the standalone falcon from the codegen model; rewire the foundation falcon feature to OQS; update CGO link entries to use `-loqs` instead of `-lfalcon`.

**Requirements:** R4, R5

**Dependencies:** None

**Files:**
- Delete: `codegen/models/external/library_falcon.xml`
- Modify: `codegen/models/project_foundation/implementor_post_quantum.xml`
- Modify: `codegen/models/project_foundation/project_foundation.xml` (post-quantum feature block line ~33 + cgo_link entries)
- Modify: `codegen/models/project_ratchet/project_ratchet.xml` (cgo_link entries)
- Generated (via `--apply`): `library/foundation/features.cmake`, `wrappers/go/foundation/platform.go`, `wrappers/go/ratchet/platform.go`
- Partially regenerated (generated sections only, hand-written sections preserved): `library/foundation/src/vscf_falcon.c`, `library/foundation/include/virgil/crypto/foundation/vscf_falcon.h`
- Delete (post-regenerate): `thirdparty/falcon/features.cmake` (no longer produced by codegen)

**Approach:**
- In `implementor_post_quantum.xml`: change `<feature name="falcon" default="${FALCON_LIBRARY}"/>` → `default="${OQS_ENABLE_SIG_FALCON}"`; change `<require library="falcon" feature="library"/>` → `<require library="liboqs" feature="ENABLE SIG FALCON"/>` (or remove since liboqs is already required at the project level); change `<require header="falcon/falcon.h"/>` → `<require header="oqs/oqs.h"/>`; remove `<constant name="seed len" value="48"/>`, `<constant name="logn 512" value="9"/>`, `<constant name="logn 1024" value="10"/>` if present (they become dead after migration)
- In `project_foundation.xml`: remove `<require library="falcon" feature="library"/>` from the `<feature name="post quantum">` block (line 33); also update every `<cgo_link>` entry to replace `-lfalcon` with `-loqs`
- In `project_ratchet.xml`: in every `<cgo_link>` entry, replace `-lfalcon` with `-loqs`
- Delete `library_falcon.xml` — codegen will stop producing `thirdparty/falcon/features.cmake`
- Run `python3 -m tools.codegen.common_bootstrap --project all --apply` to regenerate
- Manually delete the now-orphaned `thirdparty/falcon/features.cmake`

**Patterns to follow:**
- `codegen/models/project_foundation/implementor_post_quantum.xml` — existing IR pattern
- `codegen/models/external/library_liboqs.xml` — sibling library model with OQS feature names

**Test scenarios:**
- Happy path: After regeneration, `library/foundation/features.cmake` has `option(VSCF_FALCON "..." ${OQS_ENABLE_SIG_FALCON})` (not `${FALCON_LIBRARY}`)
- Happy path: `wrappers/go/foundation/platform.go` CGO LDFLAGS contain `-loqs` and do not contain `-lfalcon`
- Happy path: `thirdparty/falcon/features.cmake` no longer exists
- Edge case: Running `--apply` twice produces identical output (idempotency)

**Verification:**
- `grep -r "FALCON_LIBRARY" library/foundation/features.cmake` returns no matches
- `grep -r "\-lfalcon" wrappers/go/` returns no matches
- `grep -r "\-loqs" wrappers/go/` matches all platforms in foundation and ratchet

---

- [ ] **Unit 2: Remove standalone falcon from the CMake build**

**Goal:** Delete `thirdparty/falcon/` and wire `FALCON_LIBRARY` compile def to `OQS_ENABLE_SIG_FALCON`.

**Requirements:** R3, R5

**Dependencies:** Unit 1 (codegen regeneration removes the generated features.cmake first)

**Files:**
- Modify: `CMakeLists.txt` (root)
- Modify: `library/foundation/CMakeLists.txt`
- Delete: `thirdparty/falcon/` (entire directory: CMakeLists.txt, falcon.CMakeLists.txt, patch_shake256.cmake, config.h, features.cmake)

**Approach:**
- Root `CMakeLists.txt`: remove the `add_subdirectory("thirdparty/falcon")` line inside the `if(VIRGIL_POST_QUANTUM)` block
- `library/foundation/CMakeLists.txt`: remove `$<$<BOOL:${VSCF_POST_QUANTUM}>:falcon>` from `target_link_libraries`; change the `FALCON_LIBRARY` compile definition from `$<BOOL:${FALCON_LIBRARY}>` to `$<BOOL:${OQS_ENABLE_SIG_FALCON}>`
- Delete `thirdparty/falcon/` via `git rm -r thirdparty/falcon/`
- No changes needed to `library/foundation/sources.cmake` — `$<$<BOOL:${VSCF_FALCON}>:...>` guards are still valid; `VSCF_FALCON` now defaults to `${OQS_ENABLE_SIG_FALCON}` via Unit 1

**Patterns to follow:**
- Root `CMakeLists.txt` lines 218-221 — existing post-quantum subdirectory pattern
- `library/foundation/CMakeLists.txt` lines 94-96, 109 — existing generator expression patterns

**Test scenarios:**
- Happy path: `cmake -Bbuild -S. -DVIRGIL_POST_QUANTUM=ON` configures without errors (no reference to `falcon` target)
- Happy path: `cmake -Bbuild -S. -DVIRGIL_POST_QUANTUM=OFF` configures cleanly (falcon was already gated; liboqs also gated)
- Error path: Configuring with `-DVIRGIL_POST_QUANTUM=ON -DOQS_ENABLE_SIG_FALCON=OFF` should build and `FALCON_LIBRARY=0` propagates correctly

**Verification:**
- `cmake -Bbuild -S.` succeeds with no warnings about missing falcon target
- `grep -r "falcon" CMakeLists.txt` (root) shows no remaining falcon references

---

- [ ] **Unit 3: Rewrite `vscf_falcon.c` hand-written functions for OQS API**

**Goal:** Replace all standalone Falcon API calls in the hand-written sections of `vscf_falcon.c` with liboqs `OQS_SIG_*` calls. Public API and error-code semantics are preserved.

**Requirements:** R1, R2

**Dependencies:** Units 1 and 2 (build must compile against liboqs include path)

**Files:**
- Modify: `library/foundation/src/vscf_falcon.c`

**Approach:**
- Replace `#include <falcon/falcon.h>` with `#include <oqs/oqs.h>` (in the user-code section, not the generated section — the generated section gets its includes from the IR; after Unit 1's regeneration, `<oqs/oqs.h>` will be in the generated includes)
- `vscf_falcon_generate_key`: allocate private key buffer as `OQS_SIG_falcon_512_length_secret_key + OQS_SIG_falcon_512_length_public_key` bytes (concatenated). Call `OQS_SIG_new(OQS_SIG_alg_falcon_512)`, then `OQS_SIG_keypair`. Write secret key bytes, then append public key bytes. Return error on `OQS_ERROR`. Free the OQS_SIG object with `OQS_SIG_free`.
- `vscf_falcon_extract_public_key`: validate private key length equals `OQS_SIG_falcon_512_length_secret_key + OQS_SIG_falcon_512_length_public_key`; read the trailing `OQS_SIG_falcon_512_length_public_key` bytes as the public key.
- `vscf_falcon_exported_public_key_data_len`: return `OQS_SIG_falcon_512_length_public_key` (897)
- `vscf_falcon_exported_private_key_data_len`: return combined size
- `vscf_falcon_can_import_public_key` / `vscf_falcon_can_import_private_key`: validate against OQS sizes
- `vscf_falcon_can_sign`: replace `falcon_get_logn(key, len) > 0` with `key_data.len == OQS_SIG_falcon_512_length_secret_key + OQS_SIG_falcon_512_length_public_key` (2178 bytes — combined blob format)
- `vscf_falcon_can_verify`: replace `falcon_get_logn(key, len) > 0` with `key_data.len == OQS_SIG_falcon_512_length_public_key` (897 bytes)
- `vscf_falcon_signature_len`: return `OQS_SIG_falcon_padded_512_length_signature` (666); remove `falcon_get_logn` call entirely — we always use padded Falcon-512
- `vscf_falcon_sign_hash`: `OQS_SIG_new(OQS_SIG_alg_falcon_padded_512)` + `OQS_SIG_sign`. Extract OQS secret key from the first 1281 bytes of the private key blob. Ensure `OQS_SIG_free` is called on every exit path including error returns. Map `OQS_ERROR` to the same status code the old code returned on `FALCON_ERR_FORMAT`.
- `vscf_falcon_verify_hash`: `OQS_SIG_new(OQS_SIG_alg_falcon_padded_512)` + `OQS_SIG_verify`. Call `OQS_SIG_free` on every exit path. Map `OQS_ERROR` to the appropriate Virgil status.
- Remove all `falcon_shake256_*`, `FALCON_TMPSIZE_*`, `falcon_get_logn` usage. The `random` parameter is accepted but unused — do not assert on it.
- Ensure `vscf_falcon_exported_private_key_data_len` returns `OQS_SIG_falcon_512_length_secret_key + OQS_SIG_falcon_512_length_public_key` (2178), and `vscf_falcon_import_private_key_data` validates `key_data.len == 2178`. Both must be updated atomically.

**Patterns to follow:**
- liboqs 0.15.0 public API in `<oqs/oqs.h>` — this is the first OQS API consumer in the codebase; there is no existing local pattern to follow. Use the OQS signature API as documented at `thirdparty/liboqs/liboqs/src/sig/` or the upstream OQS README.
- Existing error mapping in `vscf_falcon.c` — keep the same `vscf_status_t` return values

**Test scenarios:**
- Happy path: `vscf_falcon_generate_key` produces a key pair; both private and public key blobs have the expected lengths
- Happy path: `vscf_falcon_sign_hash` + `vscf_falcon_verify_hash` round trip succeeds with generated keys
- Happy path: `vscf_falcon_extract_public_key` returns the same public key bytes as generated during keygen
- Edge case: `vscf_falcon_verify_hash` with wrong public key returns `vscf_status_ERROR_BAD_SIGNATURE` (or equivalent)
- Edge case: `vscf_falcon_verify_hash` with truncated signature returns error
- Edge case: `vscf_falcon_can_import_public_key` with wrong-length blob returns false
- Edge case: `vscf_falcon_can_import_private_key` with old-format private key (standalone falcon size = 1281 bytes without embedded public key) returns false

**Verification:**
- `cmake --build build` succeeds with no compilation errors or new warnings in `vscf_falcon.c`
- No remaining references to `falcon_shake256`, `FALCON_TMPSIZE_*`, `falcon_get_logn` in `vscf_falcon.c`

---

- [ ] **Unit 4: Fix C tests and verify all tests pass**

**Goal:** Update the two test files that include `<falcon/falcon.h>` directly; replace seeded-DRBG test vectors with round-trip tests; run CTest and confirm all falcon tests pass.

**Requirements:** R2

**Dependencies:** Unit 3

**Files:**
- Modify: `tests/foundation/test_post_quantum_library_falcon.c`
- Modify: `tests/foundation/test_falcon.c`
- Modify (possibly delete): `tests/foundation/data/src/test_data_falcon.c`, `tests/foundation/data/include/test_data_falcon.h`

**Approach:**
- `test_post_quantum_library_falcon.c`: Replace standalone Falcon API usage with liboqs OQS API. The test guard `TEST_DEPENDENCIES_AVAILABLE FALCON_LIBRARY` is fine (the macro is still defined). Rewrite the body to call `OQS_SIG_new(OQS_SIG_alg_falcon_512)`, `OQS_SIG_keypair`, `OQS_SIG_sign`, `OQS_SIG_verify`, `OQS_SIG_free`. Validate success codes and output lengths. Remove `#include <falcon/falcon.h>`.
- `test_falcon.c`: Remove `#include <falcon/falcon.h>`. Audit each test case: tests that compare against fixed byte vectors from `test_data_falcon.h` will fail because liboqs uses a different RNG path. Rewrite these as generate-then-export-import-sign-verify round trips. Preserve tests that do not check exact byte values. If `test_data_falcon.c`/`.h` are no longer needed, remove them from the build target in `tests/foundation/CMakeLists.txt`.
- After changes, run `ctest --output-on-failure -R falcon` to confirm falcon-specific tests pass, then run the full test suite to check for regressions in hybrid-key, key-provider, and ratchet tests that exercise Falcon indirectly.

**Patterns to follow:**
- `tests/foundation/test_falcon.c` existing round-trip tests (generate → sign → verify) — keep this structure
- `tests/foundation/test_hybrid_key_alg.c` — example of tests that exercise falcon indirectly; these should need no changes if the `vscf_falcon_*` API is preserved

**Test scenarios:**
- Happy path: `test_post_quantum_library_falcon` passes with OQS API
- Happy path: `test_falcon` key generation + sign + verify round trip passes
- Happy path: `test_falcon` key export/import round trip preserves key bytes
- Error path: `test_falcon` verify with wrong key or wrong signature returns false
- Integration: `test_hybrid_key_alg`, `test_key_provider`, `test_recipient_cipher`, `test_signer_verifier` all pass (Falcon exercised via hybrid path)
- Integration: `test_ratchet_xxdh` passes (ratchet links foundation which links liboqs)

**Verification:**
- `ctest --output-on-failure` reports 0 failures
- No test skips or newly-disabled tests beyond what was already skipped before this change

---

## System-Wide Impact

- **Interaction graph:** `library/foundation` → `liboqs` (was: `library/foundation` → `falcon` + `liboqs`). The `vscf_falcon.c` hand-written sections are the only callers of OQS Falcon API. No other module calls Falcon directly.
- **Error propagation:** OQS returns `OQS_SUCCESS`/`OQS_ERROR` (int 0/-1). These map to Virgil status codes in the same place as the old `falcon_status == 0` / `FALCON_ERR_FORMAT` checks.
- **Private key serialization change:** Private keys generated by the new code embed both the OQS secret key and public key. Keys generated by the old standalone code have a different layout. There is no migration path for existing serialized Falcon private keys. If this is a concern, the exported format could add a version byte, but that is out of scope.
- **API surface parity:** The `vscf_falcon_*` function signatures are unchanged. Language wrappers (Go, Java, Python, Swift, PHP) generated from the IR are unaffected.
- **Go CGO link change:** `-lfalcon` becomes `-loqs` in generated `platform.go`. The Go wrapper tests will not pass until the pre-built `liboqs.a` is placed in `wrappers/go/pkg/` (deferred task).
- **Unchanged invariants:** All `vscf_falcon_*` public function signatures, `vscf_alg_id_FALCON` enum value, Falcon-512 public key serialization format, and all tests not directly touching the private-key blob format remain unchanged.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Private key format break: existing Falcon private keys cannot be imported | Document the incompatibility; the `vscf_falcon_can_import_private_key` check rejects old blobs cleanly. Production impact is minimal (private keys are not long-lived in Virgil's usage pattern). |
| liboqs RNG non-determinism: tests using `fake_random` no longer control Falcon RNG | Remove seeded-DRBG test vectors (Unit 4). Round-trip tests pass regardless of which bytes the RNG produces. |
| Go wrapper CGO tests broken until pre-built libs rebuilt | Known; go tests are excluded from CTest scope. Document in the PR. |
| `OQS_ENABLE_SIG_FALCON=OFF` builds: if a user explicitly disables Falcon in liboqs, `FALCON_LIBRARY=0` propagates correctly | Covered by the compile-def wiring in Unit 2; `VSCF_FALCON` follows `OQS_ENABLE_SIG_FALCON`. |
| Codegen may resolve `${OQS_ENABLE_SIG_FALCON}` to literal `ON` in `library/foundation/features.cmake` | Verify after `--apply`; if resolved to literal, add explicit `if(NOT OQS_ENABLE_SIG_FALCON)` override in `library/foundation/CMakeLists.txt`. |

## Sources & References

- Related code: `thirdparty/liboqs/CMakeLists.txt` — liboqs ExternalProject definition
- Related code: `library/foundation/src/vscf_falcon.c` — 615-line adapter to rewrite
- Related code: `codegen/models/project_foundation/implementor_post_quantum.xml` — IR source
- Related doc: `docs/solutions/best-practices/external-library-cmake-codegen-2026-04-26.md`
- liboqs 0.15.0 tag: https://github.com/open-quantum-safe/liboqs/tree/0.15.0
