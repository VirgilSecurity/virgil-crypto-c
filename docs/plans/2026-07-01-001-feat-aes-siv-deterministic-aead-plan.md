---
title: "feat: Add AES-256-SIV deterministic AEAD via a dedicated deterministic-cipher API"
type: feat
status: active
date: 2026-07-01
origin: docs/brainstorms/aes-siv-deterministic-aead-requirements.md
---

# feat: Add AES-256-SIV deterministic AEAD via a dedicated deterministic-cipher API

## Overview

Add **AES-256-SIV** (RFC 5297) to the `foundation` library as the first algorithm behind a new,
**algorithm-agnostic deterministic-encryption API** (`vscf_deterministic_cipher`). Deterministic
encryption produces ciphertext that is a function of `(key, associated data, plaintext)` — equal inputs
give equal ciphertext — for use cases like searchable/indexable encrypted values and dedup, while still
authenticating.

The primitive is implemented as a `cipher_auth` class on the vendored mbedTLS 3.6.5 building blocks
(AES-CMAC for the S2V synthetic-IV derivation, AES-CTR for the keystream), and is **deliberately excluded
from the CMS/envelope path** (`recipient_cipher`/`ecies`/`pbes2`) — those flows assume a probabilistic
(IND-CPA) cipher, and their agility lives in the CMS `AlgorithmIdentifier`. Deterministic output is a bare
RFC 5297 `V‖C` blob with no envelope; agility for deterministic values is application-owned (out-of-band)
and, at the API layer, provided by the facade's `alg_id` selection.

## Problem Frame

The library has no deterministic AEAD. AES-256-GCM is probabilistic and fails catastrophically on nonce
reuse, so it is unsafe for deterministic/searchable use. See origin:
`docs/brainstorms/aes-siv-deterministic-aead-requirements.md`. The brainstorm resolved the product shape
(dedicated API, AES-256-SIV first, out of the envelope path); this plan resolves the technical approach.

## Requirements Trace

- **R1** — AES-256-SIV implemented as a `cipher_auth` foundation class on mbedTLS primitives (origin FR1).
- **R2** — `auth_encrypt`/`auth_decrypt` compute/verify the synthetic IV per RFC 5297; tag (synthetic IV) = 16 bytes (origin FR2).
- **R3** — Associated data supported (single buffer for v1); determinism holds, differing AD → differing ciphertext (origin FR3).
- **R4a** — Reachability: deterministic encryption is available through the dedicated `vscf_deterministic_cipher` API, emitting bare `V‖C` (not CMS) (origin FR4). *(owned by Unit 4)*
- **R4b** — Exclusion: AES-256-SIV is not selectable as a data cipher in `recipient_cipher`/`ecies`/`pbes2` (origin FR4). *(owned by Unit 5)*
- **R5** — Decrypt fails closed (auth error, zero plaintext) on tampered tag/ciphertext/AD (origin FR5).
- **R6** — Propagated to all wrappers (Swift, Java/Android, Python, Go, PHP, WASM) via codegen (origin FR6).
- **R7** — Nonce-free: `NONCE_LEN=0`, `set_nonce` errors/no-ops and never feeds the SIV (origin FR7).
- **R8** — Security: constant-time tag compare, secret-state zeroization, key-length enforcement, no MSVC VLAs (origin Security section).
- **R9** — Algorithm-agnostic facade so future deterministic AEADs slot in without a new API (origin Decision 3).
- **R10** — Deterministic-leakage / cross-domain-key misuse warning is authored in the IR class/method doc-comments (impl **and** facade) so it propagates to all 6 wrappers, and its presence in generated docs is verified (origin Security "Deterministic-leakage caveat").

## Scope Boundaries

- No AES-128-SIV or other key sizes (origin non-goal).
- No standalone public CMAC/S2V class — CMAC is used internally via mbedTLS.
- SIV is not a selectable data cipher in the CMS/envelope flows.
- No in-band algorithm/version metadata on deterministic ciphertext (agility is application-owned).

### Deferred to Separate Tasks

- **Multi-component AD vector** (full RFC 5297 `S1..Sn, P` ordered list): future API variant. v1 uses a single AD component `S2V(K1, AD, P)`.
- **A second deterministic algorithm** (e.g. AES-GCM-SIV / RFC 8452): the facade is built to accept one, but only AES-256-SIV ships now.
- **OID / `enum_oid_id` mapping**: add only if a deterministic value must ever be embedded in a CMS `AlgorithmIdentifier`.

## Context & Research

### Relevant Code and Patterns

- **AEAD cipher_auth template:** `codegen/models/project_foundation/implementor_mbedtls.xml` (the `aes256 gcm` `<implementation>` block, ~lines 77-141) and generated `library/foundation/src/vscf_aes256_gcm.c`.
- **Facade/standalone class template:** `codegen/models/project_foundation/class_shamir.xml` (`context="public"`, `<require impl=...>`, `setup defaults`, `<dependency>`, `is_const` length methods with `<proxy>`). Also `class_recipient_cipher.xml` for a facade that instantiates a concrete impl internally (`vscf_recipient_cipher.c` hard-codes `vscf_aes256_gcm_impl(...)` at ~line 2124).
- **alg_id enum:** `codegen/models/project_foundation/enum_alg_id.xml` (flat `<constant name="aes256 gcm"/>` list; append `aes256 siv`). Generated `library/foundation/include/virgil/crypto/foundation/vscf_alg_id.h`.
- **Exclusion gate:** `vscf_alg_factory_create_cipher_from_alg_id` in `library/foundation/src/vscf_alg_factory.c` (~lines 268-287) and its IR `class_alg_factory.xml` `<require impl=...>` list. Not adding SIV here excludes it from CMS, `recipient_cipher` decryption (`vscf_recipient_cipher.c:1416`), and `vscf_pkcs5_pbes2.c:166` by construction.
- **mbedTLS feature model:** `codegen/models/external/library_mbedtls.xml` (`<feature name="...">` list) → generates `thirdparty/mbedtls/features.cmake` via `codegen/cmake_files_codegen.gsl`. Vendored template `thirdparty/mbedtls/config.h.in` uses `#cmakedefine`.
- **Constant-time compare (already exists):** `vsc_memory_secure_equal` (`library/common/src/vsc_memory.c:216`, header `vsc_memory.h:129`) — the byte-pointer form to use for the raw 16-byte tag compare. The MAC-verify precedent at `vscf_ecies.c:799` uses the buffer-level wrapper `vsc_buffer_secure_equal` (which delegates to the same constant-time core). Zeroize: `vsc_zeroize`/`vsc_erase`, and `vsc_buffer_make_secure` for secret scratch.
- **Status:** reuse `vscf_status_ERROR_AUTH_FAILED` (`vscf_status.h:115`) for verification failure — no new status enum needed.
- **Tests:** `tests/foundation/test_aes256_gcm.c` (vectors, constant checks, `TEST_ASSERT_EQUAL_DATA_AND_BUFFER`), `tests/foundation/test_shamir.c` (tamper/negative pattern), data in `tests/foundation/data/`, registered via `_add_test(...)` in `tests/foundation/CMakeLists.txt` + `RUN_TEST(...)` in each test's `main()`.

### Institutional Learnings

- `docs/solutions/best-practices/codegen-class-context-and-const-length-methods-2026-06-18.md` — set `context="public"`; length methods sizing buffer outputs must be `is_const="1"` (not `is_static`, which breaks the Swift wrapper at Apple-framework build time).
- `docs/solutions/build-errors/go-cgo-stale-committed-pkg-headers-2026-06-18.md` — the Go wrapper compiles cgo against **committed** `wrappers/go/pkg/<target>/include` headers; `cmake install` skips "up-to-date" ones. Adding a symbol to an existing header (`vscf_alg_id.h`, `vscf_foundation_public.h`) requires force-committing the refreshed platform-independent headers across all 5 Go targets.
- `docs/solutions/build-errors/msvc-no-c99-vla-vendored-c-2026-06-18.md` — no C99 VLAs anywhere under `library/`; size stack buffers with compile-time `#define` bounds (SIV is all fixed 16-byte blocks, so this is natural). The MSVC `Build JVM (Windows x86_64)` job is the late gate.
- `docs/solutions/best-practices/vsc-buffer-ownership-and-secure-erasure-2026-06-18.md` — secret scratch via `vsc_buffer_new_with_capacity` + `vsc_buffer_make_secure` + `vsc_buffer_destroy`; `vsc_buffer_use` only for non-owning views.
- `docs/solutions/best-practices/external-library-cmake-codegen-2026-04-26.md` — enable mbedTLS features by editing `library_mbedtls.xml` then regenerating; never hand-edit `features.cmake`.
- `docs/solutions/best-practices/codegen-test-stale-assertions-2026-05-12.md` — a new class shifts generated counts and breaks snapshot/parity assertions across the `tools/codegen` pytest backends; re-baseline before the change, then update counts. This is expected churn.
- `docs/solutions/logic-errors/oid-enum-missing-from-codegen-model-2026-04-26.md` — never hand-edit `@generated` blocks; register enum/alg-id constants in model XML or codegen reverts them across all wrappers.

### External References

- RFC 5297 (AES-SIV): S2V, `dbl`, `pad`, `xorend`, CTR IV masking, Appendix A test vectors.
- Reference C impl `dfoxfranke/libaes_siv`; interop suites: `miscreant`, Go `github.com/aead/siv`, BoringSSL `e_aessiv.c`, Java `cryptomator/siv-mode`.

## Key Technical Decisions

- **mbedTLS primitives.** CMAC via the cipher layer: `mbedtls_cipher_cmac_starts/update/finish` with an **AES-256-ECB** `mbedtls_cipher_info_t`; key length passed in **bits**. There is no `mbedtls_cmac_*` family. **CMAC context reuse — verify first:** the plan intends to reuse one K1 CMAC context across S2V's several CMACs via `mbedtls_cipher_cmac_reset`. Confirm against the vendored v3.6.5 source that the `finish → reset → update → finish` cycle is supported and fully clears the MAC accumulator (keeping the K1 schedule); **if not, call `mbedtls_cipher_cmac_starts` fresh per CMAC.** CTR via `mbedtls_aes_crypt_ctr` with `nc_off=0` and K2's **encrypt** schedule.
- **Key split (RFC 5297).** 64-byte key → **K1 = leftmost 256 bits** (S2V/CMAC), **K2 = rightmost 256 bits** (CTR). Never swap or derive one from the other. `cipher_info` advertises `key len = 64`, `key bitlen = 512` — this is safe **only because SIV is excluded from the generic key-derivation path**; `vscf_recipient_cipher.c` derives key material as `2·key_len + 2·nonce_len` from `cipher_info`, so a SIV cipher reaching that path would miscompute. The exclusion (below) is the load-bearing invariant, not merely "its own class."
- **S2V correctness invariants.** `dbl` is **big-endian** 1-bit left shift with `0x87` XORed into the least-significant byte on MSB-carry. Final block: `len(Sn) ≥ 16` → `xorend` (XOR D onto the trailing 16 bytes); `len(Sn) < 16` → `dbl(D) xor pad(Sn)`, where `pad(empty) = 0x80 ‖ 0^15`. **AD string-count (pin this):** for AEAD the S2V string list is `(AD, plaintext)` with plaintext **last** — i.e. **v1 always runs S2V over exactly n=2 strings**, where a supplied-but-empty AD is a present zero-length string `S1` (contributing `dbl(D) ⊕ CMAC(K1, empty)`), **not** an absent string. This differs byte-for-byte from an `n=1` (no-AD) construction; the two must not be conflated, and the chosen behavior must be anchored to a reference-library vector (see Unit 3). Empty plaintext takes the `len<16` branch (`dbl(D) ⊕ pad(empty)`), producing a valid `V` with empty `C`.
- **CTR IV masking + counter semantics.** Counter `Q = V` with `q[8] &= 0x7f; q[12] &= 0x7f` (clear top bit of bytes 8 and 12). Masking applies **only to the CTR counter**; the stored/verified tag is the **unmasked** `V`. Both RFC 5297 and `mbedtls_aes_crypt_ctr` increment the **full 128-bit block** after masking, so they are equivalent for all practical lengths; a theoretical divergence exists only above ~2^31 blocks (byte-12 rollover into the cleared bit). Confirm mbedTLS's increment is full-block (not 64-bit-limited) in the vendored source, and cover it with a **multi-block (>16-block) plaintext** vector cross-checked against a reference impl (there is no existing CTR usage in-repo — this is net-new primitive behavior).
- **Wire format + length semantics.** The impl's `cipher_auth` uses the separate-tag form internally (`tag = V`, `enc = C`). The **facade** composes the RFC-canonical bare **`V‖C`** (synthetic IV prepended) on encrypt and splits it on decrypt — this is the interop format. **Disambiguate the two length functions:** the *facade* `encrypted_len = plaintext_len + 16` and `decrypted_len = V‖C_len − 16` (guard `< 16` → error, no `size_t` underflow); the *impl* `auth_encrypted_len = data_len + 16` and `auth_decrypted_len = data_len` **operate on `C` alone** (already stripped of `V` by the facade) — the impl must **not** subtract 16 again, or a 16-byte input (empty-plaintext ciphertext) double-subtracts/underflows. Note the GCM `auth_encrypted_len` formula (`+ BLOCK_LEN + AUTH_TAG_LEN`) is **wrong** for SIV (CTR has no block expansion). A dedicated exactly-16-byte-input test (empty plaintext) must assert `decrypted_len == 0` and no underflow, distinct from the `< 16` error test.
- **Constant-time + zeroize.** Tag verify uses `vsc_memory_secure_equal(V, T, 16)` (never `memcmp`); all secret scratch (D, T, CMAC subkeys, keystream block, key halves) zeroized on every exit path via secure buffers / `vsc_zeroize`.
- **Exclusion + public-surface scope.** SIV is *not* added to `vscf_alg_factory_create_cipher_from_alg_id` / `class_alg_factory.xml`, which keeps it out of CMS, `recipient_cipher` decryption, and `pbes2` by construction. **However, this is not a total public-surface guarantee:** the generated `vscf_aes256_siv` impl class is itself public in every wrapper (like `Aes256Gcm`), so `auth_encrypt`/`auth_decrypt` on the raw impl are directly callable, bypassing the facade's `V‖C` canonicalization and leakage docs. Two consequences shape the design: (1) the impl's inherited **streaming `cipher` methods (`update`/`finish`/`start_encryption`/`start_decryption`) are marked `declaration="private"`/`scope="internal"`** — SIV, unlike GCM, needs no CMS streaming, so this shrinks the surface and removes the unbounded-buffering path; (2) the deterministic-leakage warning (R10) is authored on **both** the impl and facade doc-comments. The prior "facade is the only public path" framing is inaccurate and is corrected here: the facade is the *recommended* path; the raw impl remains callable and carries the same warnings.
- **No `random` dependency.** SIV encryption is deterministic — unlike GCM/`recipient_cipher`, the class wires no `ctr_drbg`.

## Open Questions

### Resolved During Planning

- Ciphertext layout → facade emits RFC-canonical `V‖C`; impl uses separate `(enc=C, tag=V)` internally.
- 64-byte key vs `cipher_info` key_len → SIV is its own class; advertise `key len = 64` / `key bitlen = 512`.
- Streaming/DoS bound → the impl's inherited streaming `cipher` methods are marked `private`/`internal` for SIV (it needs no CMS streaming), so there is no public streaming entry point and no unbounded-buffering path; the public surface is the one-shot facade plus the raw impl's one-shot `auth_encrypt`/`auth_decrypt`.
- Constant-time comparator availability → `vsc_memory_secure_equal` already exists (resolves the brainstorm's open security item).
- OID → none for v1 (bare path needs no in-band alg id).
- API shape → algorithm-agnostic facade now (`vscf_deterministic_cipher`), AES-256-SIV as impl #1.
- Associated data → single AD buffer for v1.

### Deferred to Implementation

- Exact generated method/property names in the codegen skeleton (fill bodies into whatever codegen emits).
- Whether the facade stores the selected `alg_id` as an enum property vs instantiates the impl in `setup defaults` — mirror `class_shamir.xml` once the skeleton exists.
- Final codegen pytest count/parity numbers (re-baseline before the change, then update to the new counts).
- Whether to add a defensive guard in `vscf_ecies_use_cipher` rejecting a deterministic/`nonce_len==0` cipher (see risk below). Because the impl is publicly injectable, prefer adding the guard + a test over prose-only mitigation; if the guard is deferred, soften the "exclusion by construction" claim to "exclusion from the factory/automatic path; injection remains a documented, tested-or-accepted residual."
- `mbedtls_cipher_cmac_reset` availability/semantics and full-block CTR increment in the vendored v3.6.5 tag — confirm in Unit 1/3 before relying on them (see Key Technical Decisions).

## Output Structure

    library/foundation/
      include/virgil/crypto/foundation/
        vscf_aes256_siv.h                      (generated)
        vscf_deterministic_cipher.h            (generated)
        private/
          vscf_aes256_siv_defs.h               (generated)
          vscf_aes256_siv_internal.h           (generated)
          vscf_deterministic_cipher_defs.h     (generated)
          vscf_deterministic_cipher_internal.h (generated)
      src/
        vscf_aes256_siv.c                       (generated stub → fill S2V+CTR)
        vscf_aes256_siv_internal.c              (generated)
        vscf_aes256_siv_defs.c                  (generated)
        vscf_deterministic_cipher.c             (generated stub → fill facade)
        vscf_deterministic_cipher_internal.c    (generated)
        vscf_deterministic_cipher_defs.c        (generated)
    tests/foundation/
      test_aes256_siv.c
      test_deterministic_cipher.c
      data/test_data_aes256_siv.h

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

```
Public deterministic API (facade)                 Concrete algorithm (cipher_auth impl)
─────────────────────────────────                 ─────────────────────────────────────
vscf_deterministic_cipher                          vscf_aes256_siv
  set_alg_id(AES256_SIV) ── selects ──▶ instantiates vscf_aes256_siv
  set_key(64B) ─────────────────────────────────▶ split K1(left256)|K2(right256)
  set_auth_data(AD)                                set_auth_data(AD)
  encrypt(P) ─▶ impl.auth_encrypt(P) → (C, V) ─▶ return  V ‖ C     (RFC canonical)
  decrypt(V‖C) ─▶ split → impl.auth_decrypt(C, tag=V, AD)
                       │
                       ▼
        S2V(K1, AD, P) = V   (CMAC(zero)→D; D=dbl(D)⊕CMAC(AD);
                              final: len(P)≥16 ? xorend : dbl+pad; V=CMAC(T))
        Q = V with q[8]&=0x7f, q[12]&=0x7f
        C = AES-CTR(K2, Q, P)
        decrypt: recompute V' from recovered P; secure_equal(V',V)? P : AUTH_FAILED

Envelope path (recipient_cipher / ecies / pbes2)  ── AES256_SIV NOT registered in
  vscf_alg_factory_create_cipher_from_alg_id ──▶ returns NULL  (exclusion by construction)
```

## Implementation Units

- [ ] **Unit 1: Enable mbedTLS CMAC + CTR features**

**Goal:** Make `MBEDTLS_CMAC_C` and `MBEDTLS_CIPHER_MODE_CTR` available in the compiled mbedTLS so the SIV impl can link `mbedtls_cipher_cmac_*` and `mbedtls_aes_crypt_ctr`.

**Requirements:** R1 (prerequisite)

**Dependencies:** None (must land first)

**Files:**
- Modify: `codegen/models/external/library_mbedtls.xml` (add `<feature name="CMAC C"><require feature="AES C"/></feature>` and `<feature name="CIPHER MODE CTR"/>`)
- Modify (generated, via codegen): `thirdparty/mbedtls/features.cmake`
- Modify: `thirdparty/mbedtls/config.h.in` (add `#cmakedefine MBEDTLS_CMAC_C`, `#cmakedefine MBEDTLS_CIPHER_MODE_CTR`)

**Approach:**
- Add the two features to the mbedTLS IR model; regenerate with `python3 -m tools.codegen.common_bootstrap --project all --apply` so `features.cmake` gets the `option(... ON)` lines and dependency checks.
- `config.h.in` is intentionally **hand-maintained** (it is the vendored mbedTLS template, *not* codegen-driven, unlike `features.cmake`). Add the two `#cmakedefine MBEDTLS_CMAC_C` / `#cmakedefine MBEDTLS_CIPHER_MODE_CTR` lines by hand, each with a comment referencing the `library_mbedtls.xml` feature entry so the two halves stay in sync. Regenerating `features.cmake` does not disturb `config.h.in`, so the split is stable — but the pairing must be maintained together (a `features.cmake` option without the matching `#cmakedefine` = silently enabled in CMake, undefined in the compiled header).
- Also confirm in the vendored v3.6.5 source that `mbedtls_cipher_cmac_reset` and full-block `mbedtls_aes_crypt_ctr` are present/exported (fetched via ExternalProject `GIT_TAG v3.6.5`) before Unit 3 relies on them.
- Reconfigure/rebuild; verify the generated `build/thirdparty/mbedtls/config.h` now contains both `#define`s (watch for stale CMake cache — force a clean configure if a derived flag doesn't take).

**Patterns to follow:** existing `<feature name="NIST KW C"><require feature="AES C"/></feature>` in `library_mbedtls.xml`; `external-library-cmake-codegen` learning.

**Test scenarios:**
- Test expectation: none (build-config change) — verified by Unit 3's crypto tests linking and passing. Verification is the presence of both macros in the generated config header and a clean mbedTLS build.

**Verification:**
- `build/thirdparty/mbedtls/config.h` defines `MBEDTLS_CMAC_C` and `MBEDTLS_CIPHER_MODE_CTR`; full C build succeeds.
- WASM size delta measured before/after enabling the two features; the increase is recorded and confirmed within the WASM/mobile size budget (or explicitly accepted). This is Unit 1's owning check for the global-config size concern noted in System-Wide Impact.

---

- [ ] **Unit 2: Declare the AES-256-SIV cipher_auth impl + alg_id; generate skeleton**

**Goal:** Add the `aes256 siv` implementation and its `alg_id` to the IR and generate the class scaffold (headers, defs, internal, `.c` stub, factory-independent).

**Requirements:** R1, R2, R7, R9 (alg_id selectability), R10 (impl doc-comment)

**Dependencies:** Unit 1 (the `<require feature>` entries must resolve)

**Files:**
- Modify: `codegen/models/project_foundation/implementor_mbedtls.xml` (new `<implementation name="aes256 siv">`)
- Modify: `codegen/models/project_foundation/enum_alg_id.xml` (append `<constant name="aes256 siv"/>`)
- Generated: `library/foundation/src/vscf_aes256_siv.{c,internal.c,defs.c}`, `include/.../vscf_aes256_siv.h`, `private/vscf_aes256_siv_{defs,internal}.h`, updated `vscf_alg_id.h`

**Approach:**
- Model on the `aes256 gcm` block: interfaces `alg, encrypt, decrypt, cipher info, cipher, cipher auth info, auth encrypt, auth decrypt, cipher auth`.
- **Restrict the public surface:** mark the inherited streaming `cipher` methods (`update`, `finish`, `start_encryption`, `start_decryption`) as `declaration="private"`/`scope="internal"` — SIV needs no CMS streaming, and this removes the unbounded-buffering path. The public methods are `auth_encrypt`/`auth_decrypt` (+ `set_key`/`set_auth_data`).
- **Author the R10 deterministic-leakage warning** in the class doc-comment (and on `auth_encrypt`) directly in the IR so it propagates to all wrappers.
- `cipher info` constants: `nonce len = 0`, `key len = 64`, `key bitlen = 512`, `block len = 16`; `cipher auth info` `auth tag len = 16`.
- `<require library="mbedtls" feature="CMAC C"/>`, `<require library="mbedtls" feature="CIPHER MODE CTR"/>`, `<require header="mbedtls/cmac.h" scope="context"/>`, `<require header="mbedtls/aes.h" scope="context"/>`.
- Properties: mbedTLS cipher context(s) for CMAC + an `mbedtls_aes_context` for CTR, `key` byte array sized `length_constant=".(class_aes256_siv_constant_key_len)"` (64), `auth data` buffer. **Do NOT copy GCM's `state` enum or `is_nonce_used` fields** — SIV is one-shot and nonce-free; a simple "key-set" boolean guard (reject `auth_encrypt`/`auth_decrypt` before `set_key`) is all that's needed. No `random` dependency.
- Append the alg_id constant at the **end** of the enum (serialized values must not shift).

**Patterns to follow:** `implementor_mbedtls.xml` `aes256 gcm` (structure only — strip its streaming state machine); `enum_alg_id.xml`; `oid-enum-missing-from-codegen-model` (edit model, not generated files).

**Test scenarios:**
- Test expectation: none (scaffolding/codegen). Behavioral coverage lands in Unit 3. Re-baseline `tools/codegen` pytest counts here so later churn is attributable.

**Verification:**
- Codegen produces the `vscf_aes256_siv` files with empty method bodies and `vscf_alg_id_AES256_SIV` in `vscf_alg_id.h`; project still builds (stubs compile).

---

- [ ] **Unit 3: Implement RFC 5297 S2V + CTR core, with regression tests**

**Goal:** Fill the generated stub with correct, constant-time AES-256-SIV, and land the RFC 5297 regression tests in the same commit.

**Requirements:** R2, R3, R5, R7, R8

**Dependencies:** Unit 2

**Files:**
- Modify: `library/foundation/src/vscf_aes256_siv.c`, `library/foundation/src/vscf_aes256_siv_internal.c`
- Create: `tests/foundation/test_aes256_siv.c`, `tests/foundation/data/test_data_aes256_siv.h`
- Modify: `tests/foundation/CMakeLists.txt` (`_add_test(test_aes256_siv)`)

**Approach:**
- The impl produces the **separate-tag** form: `auth_encrypt` returns `(enc = C, tag = V)`; the RFC-canonical `V‖C` composition is the facade's job (Unit 4), **not** here. `auth_encrypted_len`/`auth_decrypted_len` operate on `C` alone (facade strips/prepends `V`): `auth_encrypted_len = data_len + 16`, `auth_decrypted_len = data_len` — **no −16 in the impl** (the facade already removed `V`).
- `set_key`: enforce 64-byte length (else `vscf_status_ERROR_BAD_ARGUMENTS`); split K1=left 32B, K2=right 32B.
- `set_nonce`: **return `vscf_status_ERROR_BAD_ARGUMENTS`** (not a silent no-op — surface misuse); never used in the construction (R7). Remove the GCM template's `is_nonce_used` guard so `auth_encrypt` works without a `set_nonce` call.
- S2V helper (v1, exactly **n=2** strings — `S1 = AD` (possibly empty), `S2 = P`): `D = CMAC(K1, zero16)`; `D = dbl(D) ⊕ CMAC(K1, AD)` (AD present, possibly zero-length); final plaintext block via `xorend` (len≥16) or `dbl(D) ⊕ pad(P)` (len<16, where `pad(empty) = 0x80‖0^15`); `V = CMAC(K1, T)`. Reuse the K1 CMAC context via `mbedtls_cipher_cmac_reset` **only if** Unit 1 confirmed the reset cycle; else `mbedtls_cipher_cmac_starts` fresh per CMAC.
- `dbl`: big-endian left shift + `0x87` reduction; **no VLAs**, fixed 16-byte blocks.
- CTR: `Q = V` with `q[8]&=0x7f; q[12]&=0x7f`; `C = mbedtls_aes_crypt_ctr(K2, Q, P)`. Store unmasked `V` as the tag. **Zeroize the mbedTLS `stream_block[16]` scratch** (it holds K2-derived keystream — mbedTLS docs mark it sensitive) with `vsc_zeroize(stream_block, 16)` on every exit path; it is a fixed API array, not a secure buffer.
- `auth_decrypt`: CTR-decrypt with `Q` from the supplied `V`, recompute `V'` over recovered plaintext + AD, `vsc_memory_secure_equal(V', V, 16)`; on mismatch return `vscf_status_ERROR_AUTH_FAILED` and emit **zero** plaintext.
- Zeroize D, T, CMAC subkeys, `stream_block`, `nonce_counter`, key halves on all exit paths (secure buffers / `vsc_zeroize`).

**Execution note:** Implement test-first against the RFC 5297 Appendix A.1 vector, then the fresh single-AD ≥16-byte vector (below) — wire the failing vectors before filling S2V, since the `dbl`/`xorend`/masking details are the high-risk area.

**Patterns to follow:** constant-time tag compare via `vsc_memory_secure_equal(v_prime, v, 16)` on the two raw 16-byte arrays (note: `vscf_ecies.c:799` uses the buffer-level `vsc_buffer_secure_equal` — different signature; use the byte-pointer form here); `vscf_shamir.c` (secure-buffer idioms); `dfoxfranke/libaes_siv` (dbl / byte-8,12 masking / final-block branches).

**Test scenarios:**
- Happy path: RFC 5297 **Appendix A.1** vector (14-byte plaintext, single AD) — exercises the `dbl+pad` branch; assert `V‖C` equals the RFC output `85632d07…fe5c`.
- Happy path (**xorend branch** — the highest-risk path): a **single-AD, ≥16-byte-plaintext** vector **generated from a reference impl** (`libaes_siv`/miscreant/`aead/siv`) run with exactly one AD string, committed as the cross-library anchor. **Do NOT use RFC A.2** — it is a *multi-component* (AD+nonce+P) vector that the v1 single-AD API cannot reproduce; asserting against it would either fail or tempt an AD-concatenation that proves nothing.
- Happy path (**multi-block CTR**): a plaintext spanning **>16 AES blocks** (>256 bytes), cross-checked against the reference impl, to exercise CTR counter carry behavior (net-new primitive; no in-repo precedent).
- Happy path: constants — `TEST_ASSERT_EQUAL(64, vscf_aes256_siv_KEY_LEN)`, `16 == AUTH_TAG_LEN`, `0 == NONCE_LEN`, `16 == BLOCK_LEN`.
- Determinism: same `(key, AD, plaintext)` twice → identical output; changing one AD byte → different output.
- Edge case: **empty plaintext** (len<16 / `pad(empty)` branch) with **empty AD**, asserted against a **reference-generated** expected `V‖C` (not just round-trip — a wrong empty-branch still round-trips). Pins the supplied-empty-AD = present-empty-string (n=2) convention.
- Intermediate-value check: assert `CMAC(K1, zero16)` equals the known `D` intermediate, so a CMAC-reset bug is localized rather than surfacing only as a full-vector mismatch.
- Error path: tampered tag byte → `ERROR_AUTH_FAILED`, zero plaintext out.
- Error path: tampered ciphertext byte → `ERROR_AUTH_FAILED`.
- Error path: AD mismatch between encrypt and decrypt → `ERROR_AUTH_FAILED`.
- Error path: `set_key` with 32/48/63/65 bytes → `ERROR_BAD_ARGUMENTS`; `set_nonce(anything)` → `ERROR_BAD_ARGUMENTS`.

**Verification:**
- `ctest -R test_aes256_siv` green; both S2V branches covered by reference-anchored vectors (not just self-round-trip); multi-block CTR verified; negative cases fail closed.

---

- [ ] **Unit 4: Algorithm-agnostic deterministic-cipher facade**

**Goal:** Add `vscf_deterministic_cipher` — the public API that selects the algorithm by `alg_id`, drives the SIV impl, and emits/consumes the bare RFC-canonical `V‖C`.

**Requirements:** R4a, R9, R10 (facade doc-comment)

**Dependencies:** Unit 3

**Files:**
- Create: `codegen/models/project_foundation/class_deterministic_cipher.xml`
- Modify: `codegen/models/project_foundation/project_foundation.xml` (register the class in the `<class>` list)
- Generated: `library/foundation/src/vscf_deterministic_cipher.{c,internal.c,defs.c}`, `include/.../vscf_deterministic_cipher.h`, `private/*`
- Create: `tests/foundation/test_deterministic_cipher.c`
- Modify: `tests/foundation/CMakeLists.txt`

**Approach:**
- `context="public"`, `<require impl="aes256 siv"/>`; model on `class_shamir.xml`. Author the R10 deterministic-leakage + cross-domain-key warning in the class doc-comment.
- API: `set_alg_id(alg_id)` (only `AES256_SIV`; reject unsupported → error). **`set_alg_id` is required before `encrypt`/`decrypt` — no implicit default**; calling `encrypt` without it returns an error (prevents accidentally producing output under an unintended algorithm). Plus `set_key`, `set_auth_data`, `encrypt(data) → V‖C`, `decrypt(V‖C) → plaintext`.
- **Length methods:** `encrypted_len`/`decrypted_len` as `is_const="1"` (never `is_static` — Swift), each with an explicit `<length method=...>`/`<proxy>` mapping mirroring `class_shamir.xml` verbatim, e.g. `<length method="encrypted len"><proxy argument="data" to="data len" cast="data_length"/></length>` on the `encrypt` output buffer and the equivalent on `decrypt`. Omitting the `<proxy>` leaves the buffer-sizing call unwired and breaks codegen.
- `encrypted_len(data_len) = data_len + 16`; `decrypted_len(v_c_len) = v_c_len − 16` with a `< 16` guard (no `size_t` underflow). This subtraction happens **only in the facade** (the impl's own `auth_decrypted_len` receives `C` and does not subtract again).
- Internally instantiate `vscf_aes256_siv_impl(vscf_aes256_siv_new())` (as `recipient_cipher` does for GCM), call `auth_encrypt` to get `(C, V)`, then write `V‖C`; on decrypt split first 16 bytes as `V`, remainder as `C`, call `auth_decrypt`. **The facade owns the impl's lifetime — call `vscf_aes256_siv_destroy` in its cleanup path** to release the mbedTLS CMAC/AES contexts.
- Deliberately NOT registered in `alg_factory` / `recipient_cipher`.

**Patterns to follow:** `class_shamir.xml` (facade shape, `setup defaults`, `is_const` length methods with `<proxy>`), `class_recipient_cipher.xml` (internal impl instantiation + `destroy` in cleanup).

**Test scenarios:**
- Happy path: `set_alg_id(AES256_SIV)` + `set_key` + `encrypt`/`decrypt` round-trip returns the original plaintext.
- Happy path: encrypt output layout is exactly `V(16) ‖ C` and byte-matches the RFC A.1 vector produced through the facade.
- Determinism: identical inputs → identical facade output.
- Edge case: exactly-16-byte input to `decrypt` (empty-plaintext ciphertext) → `decrypted_len == 0`, decrypt succeeds with empty output, **no `size_t` underflow**.
- Error path: `decrypt` of a blob `< 16` bytes → error (no under-read).
- Error path: `encrypt`/`decrypt` without `set_alg_id` → error; unsupported `alg_id` → error from `set_alg_id`.
- Error path: tampered `V‖C` → `ERROR_AUTH_FAILED`.

**Verification:**
- `ctest -R test_deterministic_cipher` green; facade output is RFC-canonical and round-trips.

---

- [ ] **Unit 5: Envelope-path exclusion guard + regression test**

**Goal:** Lock in that AES-256-SIV is unreachable through the CMS/envelope cipher selection — both the automatic factory path and the ECIES injection path.

**Requirements:** R4b

**Dependencies:** Unit 2 (alg_id exists)

**Files:**
- Modify: `tests/foundation/test_aes256_siv.c` — add the exclusion assertions here (the file `tests/foundation/test_alg_factory.c` does **not** exist; do not create a new test file just for this)
- Modify: `library/foundation/src/vscf_ecies.c` (+ its IR if guarded) — add the injection guard (see approach)
- (No change to `class_alg_factory.xml` / `vscf_alg_factory.c` — factory exclusion is by omission; verify nothing was added)

**Approach:**
- Confirm SIV is absent from `vscf_alg_factory_create_cipher_from_alg_id` and `class_alg_factory.xml`.
- Add a regression test (`test_aes256_siv__not_accessible_via_alg_factory`) asserting `vscf_alg_factory_create_cipher_from_alg_id(vscf_alg_id_AES256_SIV)` returns `NULL` — pins intent so a future edit can't silently wire SIV into CMS.
- **ECIES injection guard (resolved — do the guard, not prose-only):** three reviewers flagged that `vscf_ecies_use_cipher`/`take_cipher` accepts any `cipher` impl, so a caller could inject SIV and silently make ECIES deterministic (breaking its IND-CPA guarantee). Add a guard in `vscf_ecies_use_cipher`/`take_cipher` rejecting a deterministic cipher (e.g. `vscf_cipher_info_nonce_len(cipher) == 0`, or an explicit SIV alg_id check) — surface `vscf_status_ERROR_UNSUPPORTED_ALGORITHM` / assert per the codebase convention — with a test. This makes the "exclusion by construction" claim true for *all* paths, not just the factory.

**Patterns to follow:** existing alg-factory tests; ECIES `use_cipher`/`take_cipher` guards.

**Test scenarios:**
- Negative-by-design: factory returns `NULL` for `vscf_alg_id_AES256_SIV`; still returns non-NULL for `AES256_GCM`/`AES256_CBC`.
- Error path: injecting a SIV impl into ECIES via `vscf_ecies_use_cipher` is rejected with a clear status/assert.

**Verification:**
- Exclusion tests green; neither the factory nor ECIES can end up using a SIV cipher; `recipient_cipher`/`pbes2` cannot obtain one.

---

- [ ] **Unit 6: Wrapper propagation, committed Go headers, codegen-test re-baseline**

**Goal:** Propagate both new classes to all wrappers, refresh committed Go pkg headers, and update codegen snapshot assertions.

**Requirements:** R6

**Dependencies:** Units 2-5 (all IR changes complete)

**Files:**
- Generated: `wrappers/{go,java,swift,python,php,wasm}/…` (new `Aes256Siv`/`DeterministicCipher` classes + edits to shared error/registry/export files per wrapper)
- Modify: committed `wrappers/go/pkg/<os>_<arch>/include/virgil/crypto/foundation/` headers (platform-independent only: new class headers + `private/*_defs.h`, updated `vscf_alg_id.h`, `vscf_foundation_public.h`) across all 5 Go targets
- Modify: `tools/codegen` backend test count/parity assertions (`test_swift_backend.py`, `test_php_backend.py`, `test_python_backend.py`, `test_wasm_backend.py`, `test_impl_rendering.py`, etc.)

**Approach:**
- Run `python3 -m tools.codegen.common_bootstrap --project all --apply`; commit generated wrapper source.
- Re-baseline `python3 -m pytest tools/codegen/ -q` before the change, then update the count/parity assertions to the new expected numbers (a new class predictably shifts them).
- Build once and force-commit refreshed platform-independent Go headers across the 5 targets; do NOT commit per-target `*_platform.h` drift or `.a` files.
- Verify Go: `go build ./...` + `go test ./...` from `wrappers/go/` (ignore the benign duplicate-library linker warning).
- Verify Swift: flip `useLocalBinaries=true`, `swift build`, `swift test`, restore the flag.

**Execution note:** Watch the `Build JVM (Windows x86_64)` CI job specifically after push — MSVC is the VLA gate local builds miss.

**Test scenarios:**
- Integration: `go test ./...` deterministic-cipher round-trip passes in the Go wrapper.
- Integration: `swift test` passes with local binaries.
- Regression: `tools/codegen` pytest green after count updates; no unexpected parity failures.
- Doc propagation (R10): confirm the deterministic-leakage warning text appears in the generated class docs for each wrapper (Swift/Java/Go/Python/PHP/WASM), not just the C header.

**Verification:**
- All wrappers generate and build; Go + Swift test suites green; codegen pytest green; R10 warning present in all wrapper docs.

## System-Wide Impact

- **Interaction graph:** `vscf_deterministic_cipher` → `vscf_aes256_siv` → mbedTLS CMAC/CTR. No new callback/observer paths. The envelope classes (`recipient_cipher`/`ecies`/`pbes2`) are intentionally *not* connected.
- **Error propagation:** verification failures surface as `vscf_status_ERROR_AUTH_FAILED`; length/format errors as `ERROR_BAD_ARGUMENTS`. No plaintext emitted before auth succeeds.
- **State lifecycle risks:** secret scratch (S2V D/T, subkeys, keystream, key halves) must be zeroized on every exit including error paths; SIV holds no RNG state (deterministic).
- **API surface parity:** enabling `MBEDTLS_CMAC_C`/`MBEDTLS_CIPHER_MODE_CTR` compiles into **every** target linking mbed::crypto (foundation/phe/ratchet, all wrapper prebuilts, WASM) — a global size increase; check the WASM/mobile size budget.
- **Integration coverage:** Go and Swift wrapper round-trips prove the cgo/Apple-framework boundaries that C unit tests don't.
- **Unchanged invariants:** `recipient_cipher`/`ecies`/`pbes2` behavior and the CMS wire format are unchanged; the alg-factory cipher set gains no new entry. Existing AES-256-GCM/CBC selection is untouched.

## Risk Analysis & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| S2V/`dbl`/masking implemented incorrectly (silent non-interop or weak IV) | Med | High | Test-first against **reference-anchored** vectors for both branches (A.1 dbl+pad; a fresh single-AD ≥16B xorend vector — *not* RFC A.2); intermediate `D` check; mirror `libaes_siv` |
| xorend branch only self-consistent, not interop-verified (RFC A.2 unusable with single-AD API) | Med | High | Generate the ≥16B vector from a reference lib run with one AD string; commit as the anchor (Unit 3) |
| CTR counter carry differs from RFC for very long inputs | Low | Med | Confirm mbedTLS full-block increment; multi-block (>16 block) vector cross-checked vs reference |
| CMAC `finish→reset→update` unsupported in vendored 3.6.5 | Low | High | Confirm in Unit 1; fall back to fresh `cmac_starts` per CMAC; intermediate-value test localizes a reset bug |
| Raw `vscf_aes256_siv` impl is public → callers bypass facade / leakage docs | Med | Med | Streaming `cipher` methods marked private/internal; R10 warning on impl **and** facade; framing corrected (facade is *recommended*, not *only*, path) |
| MSVC VLA rejection in hand-written C (late Windows JVM failure) | Med | Med | Fixed `#define`-bounded 16-byte buffers, no VLAs; watch the Windows JVM CI job |
| Go cgo build breaks on stale committed pkg headers | Med | Med | Force-commit refreshed platform-independent Go headers across 5 targets in the same PR; `go build/test` |
| Swift build fails on `is_static` length methods | Med | Med | Use `is_const="1"` length methods (per learning); verify with local Swift build/test |
| Codegen snapshot/parity assertions break | High | Low | Expected; re-baseline first, then update counts |
| mbedTLS config change → binary-size regression (esp. WASM) | Med | Med | Unit 1 measures WASM size delta against budget; features are small (CMAC/CTR) |
| Non-constant-time tag compare → forgery timing oracle | Low | High | Use existing `vsc_memory_secure_equal` (byte-pointer form); `stream_block`/scratch zeroized on all paths |
| ECIES accepts an injected SIV cipher → silent deterministic envelope | Low | Med | Add a guard in `vscf_ecies_use_cipher`/`take_cipher` rejecting a deterministic cipher, with a test (Unit 5) |
| Stale CMake cache hides the new mbedTLS defines on reconfigure | Low | Med | Verify generated `config.h`; clean-configure if a derived flag doesn't take |

## Documentation / Operational Notes

- Public API docs for **both** `vscf_deterministic_cipher` and the raw `vscf_aes256_siv` impl **must** state the deterministic-leakage property (equal `(key, AD, plaintext)` → equal ciphertext) and that a key shared across isolation domains leaks plaintext equality across them — use a unique key per domain and/or a domain-specific AD. This warning is authored in the IR doc-comments (R10) so it propagates to all 6 wrappers; **verify it appears in the generated Swift/Java/Go/Python/PHP/WASM class docs** (part of Unit 6), not just the C header.
- Document that deterministic ciphertext is bare (no in-band alg id); callers track algorithm/key/version out-of-band for rotation. Warn that during rotation an `ERROR_AUTH_FAILED` cannot be distinguished from a wrong-key / wrong-algorithm / tampered-ciphertext case — recommend callers wrap `V‖C` in an application envelope carrying at least a key/alg-version byte and validate it before decrypting.
- **Permanent public surface (one-way door):** the `vscf_deterministic_cipher` name, its method shape (`set_alg_id`/`set_auth_data`/`encrypt`→`V‖C`), and the bare versionless `V‖C` wire format become immutable public API across Maven Central / SPM / PyPI / Go modules / etc. once shipped. The name was chosen deliberately over `deterministic_aead`; confirm before Unit 6 (wrapper propagation), since renaming after is a breaking change in every ecosystem. The versionless-wire-format trade-off (recurring per-adopter out-of-band versioning cost vs. a minimal in-band version prefix) is accepted for v1 given a second algorithm is already anticipated — recorded here so it reads as chosen, not overlooked.
- No new release mechanics — codegen + `release.yml` handle wrapper prebuilts as usual.

## Sources & References

- **Origin document:** [docs/brainstorms/aes-siv-deterministic-aead-requirements.md](../brainstorms/aes-siv-deterministic-aead-requirements.md)
- Reference impl to mirror: `vscf_shamir` (PR #207) — `codegen/models/project_foundation/class_shamir.xml`, `library/foundation/src/vscf_shamir.c`
- AEAD template: `library/foundation/src/vscf_aes256_gcm.c`, `implementor_mbedtls.xml` (`aes256 gcm`)
- Constant-time verify precedent: `library/foundation/src/vscf_ecies.c:799`
- RFC 5297; `dfoxfranke/libaes_siv`; miscreant; Go `github.com/aead/siv`
