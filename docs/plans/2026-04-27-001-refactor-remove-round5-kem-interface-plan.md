---
title: "refactor: Remove round5, migrate ratchet KEM to interface, expand PQ test coverage"
type: refactor
status: done
date: 2026-04-27
deepened: 2026-04-27
---

# refactor: Remove round5, migrate ratchet KEM to interface, expand PQ test coverage

## Overview

Round5 is a post-quantum KEM that was added experimentally and is now superseded by the standardised
ML-KEM-768 (FIPS 203). This refactor removes round5 completely from the codebase, migrates the
ratchet XXDH module from a hardcoded `vscf_round5_t` dependency to the generic `vscf_kem` interface
(injecting `vscf_ml_kem_t` as the default), and ensures all unit tests cover the new ML-KEM-768
and ML-DSA-65 algorithms in the same depth that round5 and falcon tests provided.

## Problem Frame

Round5 was a NIST PQC Round 2 candidate that was not selected for standardisation. ML-KEM (FIPS 203)
is the final standard replacing it. Continuing to ship round5 means maintaining an abandoned
thirdparty library and mapping an unstandardised algorithm to the wire. Removing it:
- Reduces the thirdparty surface by one ExternalProject dependency.
- Eliminates the only remaining PQC library that has no path to FIPS certification.
- Forces the ratchet module to depend only on the `vscf_kem` interface, making future KEM
  substitution a configuration decision rather than a code change.

The user also noted that ratchet's current design (`self->round5 = vscf_round5_new()`) hard-codes
a specific algorithm type where the `vscf_kem` interface is sufficient — this plan fixes that.

## Requirements Trace

- R1. `thirdparty/round5/` directory and all associated build artifacts are removed from the repo.
- R2. The foundation library builds and links cleanly with `VIRGIL_POST_QUANTUM=ON` and `ROUND5_LIBRARY` absent.
- R3. `vscr_ratchet_xxdh_t` holds a `vscf_impl_t *kem` property (interface) instead of `vscf_round5_t *round5`.
- R4. Ratchet hidden constants are updated: `ROUND5_ENCAPSULATED_KEY_LEN=620→1088`, `ROUND5_SHARED_KEY_LEN=16→32`, `ROUND5_PUBLIC_KEY_LEN=461→1184` to match ML-KEM-768.
- R5. Protobuf `.options` files updated: `max_size` removed from all `FT_POINTER` PQ key fields (encapsulated keys, public keys) — making them algorithm-agnostic. Size validation moves entirely to the application layer.
- R6. All unit tests that previously tested round5 are either deleted (algorithm-specific) or migrated to ML-KEM equivalents.
- R7. Integration tests (key_provider, hybrid_key_alg, recipient_cipher) test ML-KEM-768 hybrid keys in place of round5 hybrid keys.
- R8. A multi-threading test for ML-KEM (`test_mt_ml_kem.c`) exists, mirroring `test_mt_round5.c`.
- R9. `ctest` passes for all targets (foundation, ratchet) with `VIRGIL_POST_QUANTUM=ON`.

## Scope Boundaries

- Round5 is removed; **Falcon is kept** (it was upgraded to 2021 in the preceding plan).
- Only ratchet's KEM dependency migrates to the interface; ratchet's signer dependency (`self->falcon`) is out of scope and stays as-is.
- No changes to ML-KEM-768 or ML-DSA-65 algorithm implementations (`vscf_ml_kem.c`, `vscf_ml_dsa.c`) — those are complete per the previous plan.
- The codegen extension (Unit 7) generates only the `exported_functions.json` symbol list; it does not change any `.js` wrapper logic or `CMakeLists.txt`.
- No changes to language wrapper higher-level SDKs (virgil-crypto-go, virgil-crypto-python) beyond what codegen and `platform.go` / `keytype.go` cover.

### Deferred to Separate Tasks

- Updating pre-built Go static libs in `wrappers/go/pkg/*/` (removing round5 from the pre-built `.a` archives): separate build job.
- Hybrid ML-DSA + ML-KEM ratchet key type (`Curve25519MlKem768Ed25519MlDsa65` in Go keytype): separate plan once ML-DSA integration in ratchet is designed.
- **`virgil-ratchet-x` Swift repo** (`/Users/ssiroshtan/projects/virgil-security/virgil-ratchet-x`): `SecureChat.swift:164` and `KeysRotator.swift:106` both select `.curve25519Round5` when `enablePostQuantum=true`. After round5 removal these two lines must be updated to `.curve25519MlKem768`. Since `virgil-e3kit-x` ships with `enableRatchetPqc = false` (off by default), non-PQC deployments are unaffected at runtime. PQC-enabled deployments will break until this repo is updated — coordinate as a separate PR in that repo.

## Context & Research

### Relevant Code and Patterns

**Round5 thirdparty:**
- `thirdparty/round5/CMakeLists.txt` — ExternalProject definition to delete.
- `thirdparty/round5/features.cmake` — `ROUND5_LIBRARY` option to delete.

**Foundation codegen models:**
- `codegen/models/external/library_round5.xml` — library XML to delete.
- `codegen/models/project_foundation/implementor_post_quantum.xml` — round5 implementor block (lines ~51–96) to remove; ML-KEM and ML-DSA blocks already present.
- `codegen/models/project_foundation/enum_alg_id.xml` — `ROUND5_ND_1CCA_5D` constant to remove; `ML_KEM_768` and `ML_DSA_65` already present.
- `codegen/models/project_foundation/enum_oid_id.xml` — round5 OID constant to remove.
- `codegen/models/project_foundation/enum_status.xml` — `ERROR_ROUND5`, `ERROR_BAD_ROUND5_PUBLIC_KEY`, `ERROR_BAD_ROUND5_PRIVATE_KEY` to remove.
- `codegen/models/project_foundation/class_key_alg_factory.xml` — round5 factory entry to remove.
- `codegen/models/project_foundation/class_key_provider.xml` — round5 provider entry to remove.
- `codegen/models/project_foundation/project_foundation.xml` — `<require library="round5"/>` to remove.

**Ratchet codegen models (all round5 references — five models reference the class directly):**
- `codegen/models/project_ratchet/class_ratchet_xxdh.xml` line 15: `<property name="round5" class="round5" project="foundation"/>` → change to `<property name="kem" interface="kem" project="foundation"/>`.
- `codegen/models/project_ratchet/class_ratchet.xml` line 30: same `<property name="round5" .../>` — change to kem interface.
- `codegen/models/project_ratchet/class_ratchet_keys.xml` line 29: same — change to kem interface.
- `codegen/models/project_ratchet/class_ratchet_sender_chain.xml` line 27: `<argument name="round5" class="round5" .../>` — change to kem interface argument.
- `codegen/models/project_ratchet/class_ratchet_receiver_chain.xml` line 27: same — change to kem interface argument.
- `codegen/models/project_ratchet/class_ratchet_pb_utils.xml` lines 38 and 51: two method arguments taking `round5` — change to kem interface.
- `codegen/models/project_ratchet/class_ratchet_common_hidden.xml` — `<constant name="round5 encapsulated key len" value="620"/>` → 1088, `<constant name="round5 public key len" value="461"/>` → 1184, `<constant name="round5 shared key len" value="16"/>` → 32. Rename constants to `kem encapsulated key len`, `kem public key len`, `kem shared key len`. **This file is codegen-managed — do NOT hand-edit the generated header; update this XML model and let codegen regenerate it.**
- `codegen/models/project_ratchet/enum_status.xml` — `ERROR_ROUND5` to remove.
- `codegen/models/project_ratchet/project_ratchet.xml` — four `<cgo_link>` entries each containing `-lround5`: remove from all platform variants.

**Ratchet protobuf options (hand-maintained, not codegen-driven):**
- `library/ratchet/protobuf/vscr_RatchetMessage.options` — PQ key fields already use `type:FT_POINTER` (heap-allocated). The `max_size:620` and `max_size:461` constraints are decode-time length guards, NOT static buffer sizes. Remove `max_size` entirely from all `FT_POINTER` PQ fields, making the protobuf layer algorithm-agnostic. Application-layer validation in `vscr_ratchet_key_utils.c` enforces correct algorithm-specific sizes.
- `library/ratchet/protobuf/vscr_RatchetSession.options` — same: remove `max_size` from `encapsulated_key1/2/3`, `public_key_second`, `private_key_second`, and `encapsulated_key` fields that carry PQ key material. Fields with fixed classical key sizes (`max_size:32 fixed_length:true`) are untouched.

**Ratchet hand-written sources (broader than xxdh):**
- `library/ratchet/src/vscr_ratchet_xxdh.c` — round5 field + KEM calls (encapsulate/decapsulate).
- `library/ratchet/src/vscr_ratchet_keys.c` — uses `ROUND5_ENCAPSULATED_KEY_LEN` / `ROUND5_SHARED_KEY_LEN`.
- `library/ratchet/src/vscr_ratchet_session.c` — references `ROUND5_ENCAPSULATED_KEY_LEN` for message parsing.
- `library/ratchet/src/vscr_ratchet_sender_chain.c` — same constant in serialization check.
- `library/ratchet/src/vscr_ratchet_key_utils.c` — validates second key alg_id as `vscf_alg_id_ROUND5_ND_1CCA_5D` (lines ~341, 362, 488, 509); must be updated to `vscf_alg_id_ML_KEM_768`.
- `library/ratchet/src/vscr_ratchet.c` — calls `vscf_round5_generate_key(self->round5, vscf_alg_id_ROUND5_ND_1CCA_5D, ...)` for ephemeral PQ key generation during session init; must be updated to use the kem interface.
- `library/ratchet/src/vscr_ratchet_pb_utils.c` — calls `vscf_round5_import_public_key_data` / `vscf_round5_import_private_key_data` to reconstruct keys from protobuf bytes; the vscf_kem interface does not include key import — see Key Technical Decisions for the design approach.

**Integration tests that must be migrated:**
- `tests/foundation/test_key_provider.c` — `test__generate_private_key__round5`, import/export tests for `curve25519_round5_*` hybrid keys.
- `tests/foundation/test_hybrid_key_alg.c` — `curve25519_round5` hybrid key tests, `encrypt_decrypt__with_curve25519_and_round5_keys`.
- `tests/foundation/test_recipient_cipher.c` — `pqc_curve25519_round5_falcon` and `curve25519_round5_ed25519_falcon` cipher tests.
- `tests/foundation/test_key_info.c` — key info for round5 hybrid types.
- `tests/foundation/test_key_asn1_deserializer.c`, `test_pkcs8_serializer.c` — round5 key serialization tests.
- `tests/ratchet/test_ratchet_xxdh.c` — injects `vscf_round5_t`; must be updated to inject `vscf_ml_kem_t`.

**Go non-generated wrapper code:**
- `wrappers/go/foundation/platform.go` — CGo LDFLAGS include `-lround5` (to remove); `-lmlkem768` is already present. Note: `platform.go` is generated from `project_foundation.xml` cgo_link entries — remove `-lround5` from the XML model in Unit 2; do not hand-edit this file.
- `wrappers/go/crypto/keytype.go` — `Curve25519Round5Ed25519Falcon` and `Curve25519Round5` enums reference `AlgIdRound5Nd1cca5d`; rename to `Curve25519MlKem768Ed25519Falcon` / `Curve25519MlKem768`.

**WASM non-generated files:**
- `wrappers/wasm/foundation/exported_functions.json` — lists `_vscf_round5_new`, `_vscf_round5_*` as Emscripten EXPORTED_FUNCTIONS. This file appears to be hand-maintained (not emitted by the Python codegen backend). Round5 symbols must be manually removed; if they remain after the C symbols are deleted, the Emscripten link step will fail with undefined symbol errors.
- `wrappers/wasm/ratchet/exported_functions.json` — similarly may reference round5 ratchet symbols.

### Institutional Learnings

- `docs/solutions/` — check for any solution documents related to PQ algorithm wiring before editing `vscf_key_alg_factory.c` and `vscf_key_provider.c`.
- The previous plan (`docs/plans/2026-04-26-003-feat-pqc-upgrade-falcon-mlkem-mldsa-plan.md`) documents ML-KEM key structure details (public key offset extraction from secret key, derand API, etc.). Reference it when writing ratchet injection code.

## Key Technical Decisions

- **Ratchet KEM via interface, not concrete type:** `class_ratchet_xxdh.xml` changes `<property name="round5" class="round5"/>` to `<property name="kem" interface="kem"/>`. The codegen generates `vscr_ratchet_xxdh_use_kem(vscf_impl_t*)` instead of `vscr_ratchet_xxdh_use_round5(vscf_round5_t*)`. Callers (including `vscr_ratchet_t` setup defaults) inject `vscf_ml_kem_t` as the concrete implementation. This matches the user's feedback that the ratchet should depend on abstract KEM interface keys, not a specific algorithm type.

- **Wire-format break accepted:** Ratchet sessions created with round5 keys (620-byte encapsulated key, 16-byte shared secret) are incompatible with ML-KEM-768 (1088-byte encapsulated key, 32-byte shared secret). Since round5 is being removed entirely, there is no backwards-compatible migration path — this is a clean break. Document this in `vscr_ratchet_common_hidden.h`.

- **Rename ratchet constants:** `ROUND5_ENCAPSULATED_KEY_LEN` → `KEM_ENCAPSULATED_KEY_LEN`, `ROUND5_SHARED_KEY_LEN` → `KEM_SHARED_KEY_LEN`. Using algorithm-neutral names aligns with the kem-interface decision. Values become 1088 and 32 respectively (ML-KEM-768 sizes). `FALCON_SIGNATURE_LEN=809` is kept unchanged (falcon stays).

- **Integration test data for ML-KEM hybrids:** Test vectors for `curve25519_ml_kem_768` hybrid keys (used in test_key_provider, test_hybrid_key_alg, test_recipient_cipher) must be generated from the real ML-KEM implementation. Generate from a deterministic RNG seed using the existing `test_data_ml_kem` infrastructure.

- **pb_utils key import: use vscf_key_alg_factory, not a concrete kem reference:** `vscr_ratchet_pb_utils.c` currently calls `vscf_round5_import_public_key_data(self->round5, ...)` — the `vscf_kem` interface does not expose key import. The correct approach is to call `vscf_key_alg_factory_create_alg(vscf_alg_id_ML_KEM_768)` to obtain a `vscf_impl_t*` key-alg object, use it to import the raw key bytes, then discard it. This avoids threading a concrete `vscf_ml_kem_t*` into pb_utils and keeps pb_utils algorithm-agnostic: it reads the alg_id from the protobuf `simple_alg_info` field and constructs the right importer. The codegen model for `class_ratchet_pb_utils.xml` should drop the `round5` argument entirely; pb_utils creates its importer on demand using the factory.

- **Go keytype rename is a breaking API change for Go wrapper consumers:** `Curve25519Round5` → `Curve25519MlKem768`, `Curve25519Round5Ed25519Falcon` → `Curve25519MlKem768Ed25519Falcon`. This is intentional and unavoidable given round5 removal. The rename is a Go public API break; flag it for a major version bump consideration in the Go wrapper.

## Open Questions

### Resolved During Planning

- **Does ratchet setup_defaults need to create a ml_kem instance?** Yes. Whoever previously called `setup_defaults` on `vscr_ratchet_t` (or equivalent) relied on the ratchet creating `vscf_round5_t` internally. With the kem interface, the ratchet or its init code must create `vscf_ml_kem_t` and pass it via `use_kem`. Verify in `library/ratchet/src/` which function currently does `vscf_round5_new()` (likely `vscr_ratchet_xxdh.c:vscr_ratchet_xxdh_init_ctx`) and replace it with the equivalent ML-KEM creation + injection.
- **Is `vscr_ratchet_common_hidden.h` generated or hand-written?** Generated from `codegen/models/project_ratchet/class_ratchet_common_hidden.xml`. The XML model contains `<constant name="round5 encapsulated key len" value="620"/>` etc. Update the model in Unit 2; codegen emits the updated header. Do not hand-edit the generated file.
- **Do Java JNI and PHP C extension bindings for round5 get auto-removed by codegen?** Yes — these files (`wrappers/java/foundation/jni/FoundationJNI.c`, `wrappers/php/VirgilCryptoWrapper/extensions/foundation/vscf_foundation_php.c`) are generated by codegen. Running `--project all` removes round5 bindings automatically.

### Deferred to Implementation

- Whether `vscf_key_alg_factory.c` and `vscf_key_provider.c` are generated or hand-written: verify before editing. If codegen-managed, the model changes in Unit 2 are sufficient; if hand-written, manual removal of round5 switch cases is needed.
- Exact constant name used in the Go library for `AlgIdMlKem768` (check generated `foundation.go` after codegen run) to replace the `AlgIdRound5Nd1cca5d` reference in `keytype.go`.
- Whether any `test_data_hybrid_round5_falcon.c` (or similar) file contains hybrid key test vectors that need new ML-KEM counterparts — verify during test audit in Unit 5.

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

```
Before:
  vscr_ratchet_xxdh_t
    → round5: vscf_round5_t *     (concrete type, created internally)
    → vscf_round5_kem_encapsulate(self->round5, ...)
    → ROUND5_ENCAPSULATED_KEY_LEN = 620
    → ROUND5_SHARED_KEY_LEN = 16

After:
  vscr_ratchet_xxdh_t
    → kem: vscf_impl_t *           (interface, injected by caller)
    → vscf_kem_encapsulate(self->kem, ...)
    → KEM_ENCAPSULATED_KEY_LEN = 1088   ← ML-KEM-768
    → KEM_SHARED_KEY_LEN = 32           ← ML-KEM-768

Injection point (in vscr_ratchet or its setup_defaults):
  vscf_ml_kem_t *ml_kem = vscf_ml_kem_new();
  vscf_ml_kem_use_random(ml_kem, rng);
  vscr_ratchet_xxdh_use_kem(xxdh, vscf_ml_kem_impl(ml_kem));

Codegen delta:
  class_ratchet_xxdh.xml:
    <property name="round5" class="round5" project="foundation"/>
    →
    <property name="kem" interface="kem" project="foundation"/>

  Generated API change (vscr_ratchet_xxdh.h):
    vscr_ratchet_xxdh_use_round5(vscf_round5_t*)  →  vscr_ratchet_xxdh_use_kem(vscf_impl_t*)
    vscr_ratchet_xxdh_take_round5(vscf_round5_t*) →  vscr_ratchet_xxdh_take_kem(vscf_impl_t*)
```

## Implementation Units

---

- [x] **Unit 1: Remove round5 from CMake build system and thirdparty**

**Goal:** The build system no longer defines, finds, or links round5. The thirdparty directory is deleted.

**Requirements:** R1, R2

**Dependencies:** None

**Files:**
- Modify: `CMakeLists.txt` (remove `add_subdirectory("thirdparty/round5")`)
- Modify: `library/foundation/CMakeLists.txt` (remove round5 link target, remove `ROUND5_LIBRARY` compile definition)
- Modify: `library/foundation/features.cmake` (remove `ROUND5_LIBRARY` option)
- Delete: `thirdparty/round5/` (entire directory, `git rm -r`)

**Approach:**
- In root `CMakeLists.txt`, remove the `add_subdirectory("thirdparty/round5")` line from the `if(VIRGIL_POST_QUANTUM)` block (line ~219).
- In `library/foundation/CMakeLists.txt`, remove the `if(ROUND5_LIBRARY) ... target_link_libraries(foundation ... round5 ...) ... endif()` block and the `ROUND5_LIBRARY=...` entry in `target_compile_definitions`.
- In `library/foundation/features.cmake`, remove the `option(ROUND5_LIBRARY ...)` declaration.
- `git rm -r thirdparty/round5/` to remove the thirdparty directory from tracking.

**Patterns to follow:** Mirror how `thirdparty/falcon/` is wired in the same files (as the surviving PQ library to keep).

**Test scenarios:**
- Test expectation: none — this unit changes only build wiring with no behavioural change to test independently. Verification is by successful cmake configure.

**Verification:**
- `cmake -B build -S . -DVIRGIL_POST_QUANTUM=ON` configures without errors or warnings about round5.
- `cmake -B build -S . -DVIRGIL_POST_QUANTUM=OFF` also configures cleanly.

---

- [x] **Unit 2: Update codegen models and regenerate all language wrappers**

**Goal:** All codegen IR models no longer reference round5; ratchet XXDH model uses `kem` interface instead of `round5` class. Running codegen produces a clean foundation and ratchet with round5 types removed.

**Requirements:** R2, R3

**Dependencies:** Unit 1 (build system must not attempt to link round5)

**Files:**
- Delete: `codegen/models/external/library_round5.xml`
- Modify: `codegen/models/project_foundation/implementor_post_quantum.xml` (remove `<implementation name="round5">` block)
- Modify: `codegen/models/project_foundation/enum_alg_id.xml` (remove `<constant name="round5 nd 1cca 5d"/>`)
- Modify: `codegen/models/project_foundation/enum_oid_id.xml` (remove round5 OID constant)
- Modify: `codegen/models/project_foundation/enum_status.xml` (remove 3 ERROR_ROUND5* codes)
- Modify: `codegen/models/project_foundation/class_key_alg_factory.xml` (remove round5 factory entry)
- Modify: `codegen/models/project_foundation/class_key_provider.xml` (remove round5 provider entry)
- Modify: `codegen/models/project_foundation/project_foundation.xml` (remove `<require library="round5" .../>`)
- Modify: `codegen/models/project_ratchet/class_ratchet_xxdh.xml` (change round5 property → kem interface)
- Modify: `codegen/models/project_ratchet/class_ratchet.xml` (change round5 property → kem interface)
- Modify: `codegen/models/project_ratchet/class_ratchet_keys.xml` (change round5 property → kem interface)
- Modify: `codegen/models/project_ratchet/class_ratchet_sender_chain.xml` (change round5 argument → kem interface)
- Modify: `codegen/models/project_ratchet/class_ratchet_receiver_chain.xml` (change round5 argument → kem interface)
- Modify: `codegen/models/project_ratchet/class_ratchet_pb_utils.xml` (remove both round5 method arguments; pb_utils will use key_alg_factory internally)
- Modify: `codegen/models/project_ratchet/class_ratchet_common_hidden.xml` (rename and revalue the three ROUND5 constants to KEM_*)
- Modify: `codegen/models/project_ratchet/project_ratchet.xml` (remove `-lround5` from all four cgo_link entries)
- Modify: `codegen/models/project_ratchet/enum_status.xml` (remove `ERROR_ROUND5`)
- Generated (removed by codegen): `library/foundation/src/vscf_round5_internal.c`, `library/foundation/src/vscf_round5_defs.c`, `library/foundation/include/virgil/crypto/foundation/vscf_round5.h`, `library/foundation/include/virgil/crypto/foundation/private/vscf_round5_defs.h`, `library/foundation/include/virgil/crypto/foundation/vscf_foundation_public.h` (round5 include removed), `vscf_alg_id.h` (ROUND5 constant removed), `vscf_oid_id.h` (round5 OID removed), `vscf_status.h` (round5 errors removed)
- Generated (removed by codegen): all language wrapper round5 files — `wrappers/go/foundation/round5.go`, `wrappers/python/virgil_crypto_lib/foundation/round5.py`, `wrappers/python/virgil_crypto_lib/foundation/_c_bridge/_vscf_round5.py`, `wrappers/java/foundation/src/main/java/com/virgilsecurity/crypto/foundation/Round5.java`, `wrappers/php/VirgilCryptoWrapper/src/Foundation/Round5.php`, `wrappers/swift/VirgilCrypto/VirgilCryptoFoundation/Round5.swift`
- Generated (updated by codegen): `library/ratchet/include/virgil/crypto/ratchet/vscr_ratchet_xxdh.h` (use_kem/take_kem instead of use_round5), `library/ratchet/src/vscr_ratchet_xxdh_internal.c`, `library/ratchet/src/vscr_ratchet_xxdh_defs.c`, Java/PHP/Go/Python/Swift ratchet wrappers

**Approach:**
- **All six ratchet class models that reference `class="round5" project="foundation"` must be updated before codegen runs.** Running codegen with any unresolved `class="round5"` reference causes codegen to abort or emit broken output. The six models are: `class_ratchet_xxdh.xml`, `class_ratchet.xml`, `class_ratchet_keys.xml`, `class_ratchet_sender_chain.xml`, `class_ratchet_receiver_chain.xml`, `class_ratchet_pb_utils.xml`.
- For `class_ratchet_pb_utils.xml`: remove the `round5` method arguments entirely (both method declarations). The updated implementation will use `vscf_key_alg_factory_create_alg` internally — no interface argument needed.
- In `class_ratchet_common_hidden.xml`: rename `round5 encapsulated key len` → `kem encapsulated key len` (value 1088), `round5 public key len` → `kem public key len` (value 1184), `round5 shared key len` → `kem shared key len` (value 32).
- In `project_ratchet.xml` cgo_link: remove `-lround5` from the four platform entries (darwin, linux, linux-legacy, windows). These drive `wrappers/go/ratchet/platform.go` generation — removing them here is the correct place; do not hand-edit `platform.go`.
- After all model edits: run `python3 -m tools.codegen.common_bootstrap --project all --apply`.
- Review the diff: confirm round5 files are gone, ratchet xxdh header now has `use_kem`/`take_kem`, ML-KEM/ML-DSA files are untouched.

**Patterns to follow:**
- `codegen/models/external/library_falcon.xml` — surviving library XML to use as reference for what stays.
- `codegen/models/project_ratchet/class_ratchet_xxdh.xml` — current property format to understand the change.

**Test scenarios:**
- Test expectation: none — this unit changes IR models and runs codegen. Verification is by inspecting generated file diff.

**Verification:**
- `vscf_alg_id_ROUND5_ND_1CCA_5D` no longer appears in `library/foundation/include/`.
- `vscr_ratchet_xxdh_use_kem` appears in the generated `vscr_ratchet_xxdh.h`.
- `vscr_ratchet_xxdh_use_round5` does not appear in any generated file.
- `wrappers/go/foundation/round5.go` is deleted.

---

- [x] **Unit 3: Delete hand-written round5 source and update integration points**

**Goal:** The hand-written `vscf_round5.c` implementation is deleted; any hand-written integration files that directly reference round5 are updated.

**Requirements:** R2

**Dependencies:** Unit 2 (codegen must have run; generated stubs for round5 are gone)

**Files:**
- Delete: `library/foundation/src/vscf_round5.c`
- Modify: `library/foundation/sources.cmake` (remove round5 source entries if present)
- Modify: `library/foundation/src/vscf_key_alg_factory.c` (remove round5 factory case — if hand-written; verify after codegen run)
- Modify: `library/foundation/src/vscf_key_provider.c` (remove round5 case — if hand-written)
- Modify: `library/foundation/src/vscf_oid.c` (remove round5 OID entries — hand-written)

**Approach:**
- `git rm library/foundation/src/vscf_round5.c`.
- In `vscf_oid.c`: find and remove the round5 OID bytes array and its mapping case in the switch or lookup table.
- For `vscf_key_alg_factory.c` and `vscf_key_provider.c`: first check if they are generated files (compare against codegen output). If hand-written, remove the `case vscf_alg_id_ROUND5_ND_1CCA_5D:` branch and associated `vscf_round5_*` calls.
- Confirm no remaining `#include "vscf_round5.h"` or `vscf_round5_` symbol references in the library source tree.

**Patterns to follow:** `library/foundation/src/vscf_falcon.c` — the surviving PQ key signer implementation, as a reference for what a correct PQ implementation looks like post-cleanup.

**Test scenarios:**
- Test expectation: none — no new tests; the build-and-link verification in Unit 2 and the ctest run in Unit 6 validate this.

**Verification:**
- `grep -r "round5\|ROUND5" library/foundation/src/ library/foundation/include/` returns no matches.
- `cmake --build build -j8` succeeds with no linker errors.

---

- [x] **Unit 4: Update ratchet hand-written sources for kem interface and ML-KEM constants**

**Goal:** All ratchet hand-written C files that used round5 types or constants are updated to use the kem interface and ML-KEM-768 constant values.

**Requirements:** R3, R4

**Dependencies:** Unit 2 (generated `vscr_ratchet_xxdh.h` now declares `use_kem`), Unit 3 (no more round5 symbols in foundation)

**Files:**
- Note: `library/ratchet/include/virgil/crypto/ratchet/private/vscr_ratchet_common_hidden.h` is codegen-generated from `class_ratchet_common_hidden.xml` — do NOT edit it directly; the Unit 2 model change regenerates it with the correct KEM constant names and values.
- Modify: `library/ratchet/src/vscr_ratchet_xxdh.c`
- Modify: `library/ratchet/src/vscr_ratchet_keys.c`
- Modify: `library/ratchet/src/vscr_ratchet_session.c`
- Modify: `library/ratchet/src/vscr_ratchet_sender_chain.c`
- Modify: `library/ratchet/src/vscr_ratchet_key_utils.c` (replace `vscf_alg_id_ROUND5_ND_1CCA_5D` validation → `vscf_alg_id_ML_KEM_768`)
- Modify: `library/ratchet/src/vscr_ratchet.c` (replace `vscf_round5_generate_key(self->round5, ...)` for ephemeral PQ key generation → use kem interface)
- Modify: `library/ratchet/src/vscr_ratchet_pb_utils.c` (replace `vscf_round5_import_public/private_key_data` → `vscf_key_alg_factory_create_alg` pattern)
- Modify: `library/ratchet/protobuf/vscr_RatchetMessage.options` (update `max_size` values for PQ fields)
- Modify: `library/ratchet/protobuf/vscr_RatchetSession.options` (update `max_size` values for all three `encapsulated_key1/2/3` fields)
- Modify: `tests/ratchet/test_ratchet_xxdh.c`
- Modify: `tests/ratchet/test_utils_ratchet.h` (if it creates round5 instances)

**Approach:**

*`vscr_ratchet_common_hidden.h`:*
- Rename `ROUND5_ENCAPSULATED_KEY_LEN` → `KEM_ENCAPSULATED_KEY_LEN`, value `620 → 1088`.
- Rename `ROUND5_SHARED_KEY_LEN` → `KEM_SHARED_KEY_LEN`, value `16 → 32`.
- Keep `FALCON_SIGNATURE_LEN = 809` unchanged.
- Add a comment noting this is a wire-format breaking change from round5 to ML-KEM-768.

*`vscr_ratchet_xxdh.c`:*
- The codegen-generated internal file now has a `kem` field of `vscf_impl_t*` type. The hand-written init must:
  - Remove `self->round5 = vscf_round5_new()`.
  - The kem instance is no longer self-created — it must be injected by the caller via `vscr_ratchet_xxdh_use_kem`. 
  - In `vscr_ratchet_xxdh_setup_defaults` (or wherever rng is injected): create `vscf_ml_kem_t`, call `vscf_ml_kem_use_random`, inject via `vscr_ratchet_xxdh_use_kem`. Look for the analogous pattern for how `self->falcon` is set up and follow the same pattern.
- Replace `vscf_round5_kem_encapsulate(self->round5, ...)` → `vscf_kem_encapsulate(self->kem, ...)`.
- Replace `vscf_round5_kem_decapsulate(self->round5, ...)` → `vscf_kem_decapsulate(self->kem, ...)`.
- Replace all `ROUND5_ENCAPSULATED_KEY_LEN` → `KEM_ENCAPSULATED_KEY_LEN` (same for SHARED).

*`vscr_ratchet_keys.c`, `vscr_ratchet_session.c`, `vscr_ratchet_sender_chain.c`:*
- Replace all occurrences of `ROUND5_ENCAPSULATED_KEY_LEN` → `KEM_ENCAPSULATED_KEY_LEN` (now 1088 from generated header).
- Replace all occurrences of `ROUND5_SHARED_KEY_LEN` → `KEM_SHARED_KEY_LEN` (now 32).
- `ROUND5_PUBLIC_KEY_LEN` → `KEM_PUBLIC_KEY_LEN` (now 1184) where it appears.

*`vscr_ratchet_key_utils.c`:*
- Replace four `vscf_alg_id_ROUND5_ND_1CCA_5D` comparisons with `vscf_alg_id_ML_KEM_768`. These guard the second-key validation in hybrid key pair construction.

*`vscr_ratchet.c`:*
- Find the ephemeral PQ key generation call: `vscf_round5_generate_key(self->round5, vscf_alg_id_ROUND5_ND_1CCA_5D, &error_ctx)`. Replace with the equivalent kem interface call — obtain the key-alg handle from the injected kem object (`vscf_key_alg_api_t` is implemented by `vscf_ml_kem_t`) and call `vscf_key_alg_generate_key(self->kem, vscf_alg_id_ML_KEM_768, &error_ctx)`.

*`vscr_ratchet_pb_utils.c`:*
- Remove the `round5` parameter from both affected methods (codegen already removes it from the signature in Unit 2).
- Replace `vscf_round5_import_public_key_data(self->round5, ...)` with: read the alg_id from the `simple_alg_info` field already present in the protobuf message → call `vscf_key_alg_factory_create_alg(alg_id)` to get a key-alg impl → call `vscf_key_alg_import_public_key_data(key_alg, ...)` → release the factory product.
- Same pattern for `vscf_round5_import_private_key_data`.
- This keeps pb_utils algorithm-agnostic: any KEM alg_id encoded in the session bytes is handled without a hardcoded concrete type.

*Protobuf `.options` files:*
- Key insight: PQ key fields already carry `type:FT_POINTER` — they are **heap-allocated**. The `max_size` is a decode-time length guard, not a static buffer allocation. Removing it makes nanopb accept any wire length; application-layer validation handles algorithm-specific enforcement.
- `vscr_RatchetMessage.options`: for `vscr_RegularMessageHeaderPqcInfo` and `vscr_PrekeyMessagePqcInfo` — remove `max_size:620` from `encapsulated_key*` fields; remove `max_size:461` from `public_key` field. Keep `type:FT_POINTER`. Keep `decapsulated_keys_signature max_size:809 type:FT_POINTER` unchanged (Falcon signature size is fixed at 809 bytes for CT format).
- `vscr_RatchetSession.options`: for `vscr_SenderChain` and `vscr_ReceiverChain` — remove `max_size` from `private_key_second`, `public_key_second`, and `encapsulated_key` fields. Remove `max_size` from `vscr_SessionPqcInfo.encapsulated_key1/2/3`. Keep `max_size:32 fixed_length:true` on all classical (X25519) key fields — those are truly fixed size.
- Fields NOT to touch: any field with `fixed_length:true` — these are cryptographically fixed-size (DH keys, chain keys, root key).

*`tests/ratchet/test_ratchet_xxdh.c`:*
- Replace round5 instance creation and injection: `vscf_round5_t *round5 = vscf_round5_new(); ... vscr_ratchet_xxdh_use_round5(xxdh, round5);` → `vscf_ml_kem_t *ml_kem = vscf_ml_kem_new(); vscf_ml_kem_use_random(ml_kem, rng); vscr_ratchet_xxdh_use_kem(xxdh, vscf_ml_kem_impl(ml_kem));`.
- Update any test data vectors that embed the encapsulated key (620-byte → 1088-byte, 16-byte → 32-byte shared secret).

**Patterns to follow:**
- How `self->falcon` is created and set up in `vscr_ratchet_xxdh.c` — apply the same pattern for `self->kem` with `vscf_ml_kem_t`.
- `library/foundation/src/vscf_round5.c` → `library/foundation/src/vscf_ml_kem.c` — understand the kem interface call signatures (`kem_encapsulate`, `kem_decapsulate`).

**Test scenarios:**
- Happy path: `test_ratchet_xxdh__encrypt_decrypt__success` — full XXDH key exchange with ML-KEM-768 injected as KEM; shared secret matches on both sides.
- Happy path: `test_ratchet_xxdh__pqc_encapsulate__produces_ml_kem_sized_ciphertext` — encapsulated key is 1088 bytes (not 620).
- Happy path: `test_ratchet_xxdh__pqc_shared_secret__is_32_bytes` — shared secret is 32 bytes (not 16).
- Error path: `test_ratchet_xxdh__without_kem_injected__returns_error` — calling encapsulate without a KEM instance set returns a precondition error.
- Integration: `test_ratchet_xxdh__full_pqc_xxdh_with_ml_kem__both_parties_compute_same_root_key` — end-to-end ratchet session with new key sizes.
- Integration: `test_ratchet__prekey_message_encode_decode__with_ml_kem_keys__three_encapsulated_keys_correct_size` — encode a prekey message with three ML-KEM-768 encapsulated keys (1088 bytes each); decode on the receiver; verify all three shared secrets match. This exercises the triple-encapsulation path in `vscr_PrekeyMessagePqcInfo` and validates the updated `.options` max_size.
- Integration: `test_ratchet__session_serialization_roundtrip__with_ml_kem__succeeds` — serialize a ratchet session containing ML-KEM PQ data, deserialize, verify state is identical. Confirms protobuf `.options` buffer sizes are sufficient.

**Verification:**
- `ctest -R ratchet --output-on-failure` passes.
- No `ROUND5` or `round5` symbols remain in `library/ratchet/`.
- All existing ratchet binary test fixture files (serialized sessions) are regenerated — any fixture embedding `encapsulated_key` at 620 bytes will fail to decode with the new constant; delete old fixtures and generate fresh ones.

---

- [x] **Unit 5: Remove round5 tests and expand ML-KEM / ML-DSA integration test coverage**

**Goal:** All round5-specific tests are deleted; all integration tests that tested round5 hybrid key scenarios are updated to use ML-KEM-768 equivalents; a multi-threading test for ML-KEM is added.

**Requirements:** R5, R6, R7, R8

**Dependencies:** Units 1–4 (foundation and ratchet must build clean with ML-KEM before tests can run)

**Files:**
- Delete: `tests/foundation/test_round5.c`
- Delete: `tests/foundation/test_mt_round5.c`
- Delete: `tests/foundation/test_post_quantum_library_round5_kem.c`
- Delete: `tests/foundation/data/src/test_data_round5.c`
- Delete: `tests/foundation/data/include/test_data_round5.h`
- Modify: `tests/foundation/CMakeLists.txt` (remove round5 test targets, register `test_mt_ml_kem` and `test_post_quantum_library_ml_kem` if not already registered)
- Modify: `tests/foundation/data/CMakeLists.txt` (remove round5 data sources)
- Create: `tests/foundation/test_mt_ml_kem.c`
- Modify: `tests/foundation/test_key_provider.c` (replace round5 test cases with ML-KEM equivalents)
- Modify: `tests/foundation/test_hybrid_key_alg.c` (replace curve25519_round5 tests with curve25519_ml_kem_768 tests)
- Modify: `tests/foundation/test_recipient_cipher.c` (replace pqc_curve25519_round5_falcon tests with pqc_curve25519_ml_kem_768_falcon)
- Modify: `tests/foundation/test_key_info.c` (add ML-KEM-768 key info assertions)
- Modify: `tests/foundation/test_key_asn1_deserializer.c` (replace round5 DER vectors with ML-KEM equivalents)
- Modify: `tests/foundation/test_pkcs8_serializer.c` (same)
- Create or Modify: `tests/foundation/data/src/test_data_ml_kem_hybrid.c` (ML-KEM hybrid key DER vectors)
- Create or Modify: `tests/foundation/data/include/test_data_ml_kem_hybrid.h`

**Approach:**

*`test_mt_ml_kem.c`:*
- Mirror `test_mt_round5.c` in structure: multiple threads each perform keygen + encapsulate + decapsulate using the same `vscf_ml_kem_t` instance (or separate instances). Verify no data races.

*Integration test updates (test_key_provider, test_hybrid_key_alg, test_recipient_cipher):*
- For each `curve25519_round5_*` test, create a `curve25519_ml_kem_768_*` counterpart (or rename in-place). Use fresh ML-KEM-768 test vectors for import/export tests.
- Generate new hybrid key DER vectors: follow the existing test data generation pattern for hybrid keys (a keygen with fixed RNG seed, then serialize to PKCS#8 DER, capture the bytes as test_data array). Use `test_data_ml_kem` as the inner PQ key source.
- Keep `curve25519_..._falcon` tests that do NOT involve round5 — only remove the round5 half.

*`test_post_quantum_library_ml_kem.c` and `test_post_quantum_library_ml_dsa.c`:*
- Audit against the scenario lists from the previous plan (Unit 4 and Unit 6 of `2026-04-26-003`). Verify all 8 scenarios per algorithm are present. Add any missing scenarios.

**Execution note:** Audit `test_ml_kem.c` and `test_ml_dsa.c` before writing new test data — some vectors may already be generated; do not duplicate them.

**Patterns to follow:**
- `tests/foundation/test_mt_round5.c` — multi-threading test structure to mirror for `test_mt_ml_kem.c`.
- `tests/foundation/test_hybrid_key_alg.c` existing non-round5 tests — pattern for writing ML-KEM hybrid tests.
- `tests/foundation/data/src/test_data_falcon.c` — byte array format for test vector data files.

**Test scenarios for `test_mt_ml_kem.c`:**
- Happy path: `test__concurrent_keygen__multiple_threads__no_race` — N threads each call `vscf_ml_kem_generate_key`; assert all complete without crash.
- Happy path: `test__concurrent_encapsulate_decapsulate__multiple_threads__shared_secrets_match` — N threads each encapsulate with shared pk, decapsulate with own sk; assert all ss match.

**Test scenarios for integration test updates (representative):**
- Happy path: `test__generate_private_key__ml_kem_768__success` — in test_key_provider, replaces `test__generate_private_key__round5__success`.
- Happy path: `test__import_public_key__ml_kem_768_and_then_export__are_equals` — DER round-trip for standalone ML-KEM-768 public key.
- Happy path: `test__import_public_key__curve25519_ml_kem_768_falcon_and_then_export__are_equals` — hybrid key round-trip.
- Happy path: `test__import_public_key__curve25519_ml_kem_768_ed25519_falcon_and_then_export__are_equals` — compound hybrid key round-trip.
- Happy path: `test__make_key__curve25519_ml_kem_768__is_valid_alg` — in test_hybrid_key_alg.
- Happy path: `test__encrypt_decrypt__with_curve25519_and_ml_kem_768_keys__plain_text_match` — in test_hybrid_key_alg.
- Happy path: `test__encrypt_decrypt__with_pqc_curve25519_ml_kem_768_falcon_key_recipient__success` — in test_recipient_cipher.
- Happy path: `test__sign_then_encrypt_and_decrypt_then_verify__with_pqc_curve25519_ml_kem_768_ed25519_falcon__success`.
- Integration: `test__import_private_key__curve25519_ml_kem_768_ed25519_falcon_and_then_export_public_key__are_equals` — verifies public key extraction from hybrid compound key.

**Verification:**
- `ctest -R foundation --output-on-failure` passes with no round5 tests present and all ML-KEM/ML-DSA tests passing.
- `grep -r "round5\|ROUND5" tests/` returns no matches.
- `ctest -R test_mt_ml_kem --output-on-failure` passes (thread-safety verified with TSAN if available).

---

- [x] **Unit 6: Remove round5 from non-generated Go wrapper code**

**Goal:** The hand-written Go wrapper layer (`platform.go`, `keytype.go`, associated tests) no longer references round5 or `AlgIdRound5Nd1cca5d`. The WASM `exported_functions.json` files are now codegen-generated (Unit 7) and are not hand-edited here.

**Requirements:** R2

**Dependencies:** Unit 2 (codegen must have removed `round5.go` and updated `AlgId` enum in Go generated code), Unit 7 (WASM exported_functions.json is now generated — do not hand-edit those files)

**Files:**
- Modify: `wrappers/go/crypto/keytype.go` (rename `Curve25519Round5` → `Curve25519MlKem768`, `Curve25519Round5Ed25519Falcon` → `Curve25519MlKem768Ed25519Falcon`; update `AlgIdRound5Nd1cca5d` → `AlgIdMlKem768`)
- Modify: `wrappers/go/crypto/crypto_test.go` (update key type references)
- Modify: `wrappers/go/crypto/keytype_test.go` (update key type references)
- Modify: `wrappers/go/crypto/crypto_bench_test.go` (remove round5 benchmark if present, add ML-KEM benchmark)

**Approach:**
- `platform.go` (foundation and ratchet): `-lround5` was removed via `project_foundation.xml` and `project_ratchet.xml` cgo_link edits in Unit 2 — codegen regenerated these files. Do not hand-edit.
- `wrappers/wasm/*/exported_functions.json`: now generated by codegen (Unit 7). Do not hand-edit.
- In `keytype.go`: rename the two key type constants and update the `AlgId` references once the codegen-generated `AlgIdMlKem768` constant name is confirmed from `wrappers/go/foundation/` generated code after the Unit 2 codegen run.
- `Curve25519MlKem768Ed25519Falcon` retains `Falcon` (not ML-DSA) — the Go hybrid key type pairs ML-KEM-768 with the existing Falcon signer. The falcon half is unchanged.
- Update all tests that create `Curve25519Round5` or `Curve25519Round5Ed25519Falcon` key pairs.

**Patterns to follow:** Model the new `Curve25519MlKem768` entry after the `Curve25519Round5` block structure in `keytype.go`.

**Test scenarios:**
- Happy path: `TestCurve25519MlKem768KeyGeneration` — generate and use a `Curve25519MlKem768` key pair.
- Happy path: `TestCurve25519MlKem768Ed25519FalconKeyGeneration` — compound hybrid key with new type.
- Error path: code referencing the old `Curve25519Round5` constant does not compile (build verification).

**Verification:**
- `go build ./...` in `wrappers/go/` succeeds with no round5 symbol references.
- `go test ./crypto/...` passes (note: requires pre-built static libs in `wrappers/go/pkg/`; skip or tag until libs are rebuilt — see Deferred tasks).

---

- [x] **Unit 7: Extend WASM codegen backend to generate exported_functions.json**

**Goal:** `wrappers/wasm/{project}/exported_functions.json` is generated by `project_wasm_backend.py` alongside the existing `.js` files. The three hand-maintained JSON files are replaced by codegen output. After this unit, running `--project all` also writes the correct exported symbols for every WASM project, including ML-KEM-768 and ML-DSA-65 automatically.

**Requirements:** R2 (eliminates the WASM link-failure risk from stale hand-maintained JSON)

**Dependencies:** None (pure Python codegen change — can be implemented first, before any model edits)

**Sequencing note:** Implement this unit before the codegen run in Unit 2. When Unit 2 runs `--project all`, the backend will also emit the updated JSON files, including removal of all round5 symbols and addition of ML-KEM-768 and ML-DSA-65 symbols.

**Files:**
- Modify: `tools/codegen/project_wasm_backend.py` (add `generate_exported_functions_json()` function, call from `generate_wasm_files()`)
- Generated (replaces hand-maintained): `wrappers/wasm/foundation/exported_functions.json`
- Generated (replaces hand-maintained): `wrappers/wasm/ratchet/exported_functions.json`
- Generated (replaces hand-maintained): `wrappers/wasm/phe/exported_functions.json`

**Approach:**

The existing `generate_wasm_files()` function (line 1258) already has the full `IRProject` and builds `all_entities`. Extend it to call a new `_generate_exported_functions_json(project_ir)` before returning, appending the result to `files`.

*Symbol categories to emit (in order):*

1. **Memory** (always): `_malloc`, `_free`

2. **Dependency project symbols** — for each project in `project_ir.fallback_projects` (i.e., `common` for all projects, `foundation` for `ratchet` and `phe`): emit the public class/impl lifecycle and method symbols from those projects using the same rules below. This is how ratchet's JSON includes `_vscf_*` symbols.

3. **Error infrastructure**: `_{prefix}_error_ctx_size`, `_{prefix}_error_status`, `_{prefix}_error_reset`.

4. **Impl-tag / interface infrastructure** (if project has implementations):
   - `_{prefix}_impl_tag`, `_{prefix}_impl_shallow_copy`, `_{prefix}_impl_delete`, `_{prefix}_impl_api`

5. **Per-implementation symbols** (for each `impl` in `project_ir.implementations`):
   - Lifecycle: `_{prefix}_{snake(impl.name)}_new`, `_shallow_copy`, `_delete`
   - Per dependency `dep`: `_use_{snake(dep.name)}`, `_take_{snake(dep.name)}`, `_release_{snake(dep.name)}`
   - Per method (own + inherited interface methods, filtered by `_method_should_wrap`): `_{prefix}_{snake(impl.name)}_{snake(m.name)}`

6. **Per-class symbols** (for each public `cls` in `project_ir.classes`, excluding `error`):
   - Lifecycle: `_{prefix}_{snake(cls.name)}_ctx_size` (for value/context classes), `_new`, `_delete`
   - Per method (filtered by `_method_should_wrap`): `_{prefix}_{snake(cls.name)}_{snake(m.name)}`

*Output format:* Valid JSON array (no JS-style `//` comments). Add a `@generated` marker comment only if the file format permits — or leave it as clean JSON since the file is now auto-managed. Emit with `json.dumps(symbols, indent=4)`.

*Validation:* After generating, compare symbol count against the existing hand-maintained file. The count should be close (within a few percent); large discrepancies indicate a missed symbol category. The round5 symbols (`_vscf_round5_*`) must be absent from the generated output; ML-KEM and ML-DSA symbols must be present.

**Patterns to follow:**
- `generate_wasm_files()` return structure: `files.append((path, content))` — same pattern.
- `_method_should_wrap(method)` — existing filter for public methods (line 162).
- `_resolve_project_prefix(project_ir, project_name)` — existing prefix lookup for dependency projects (line 149).
- The `_snake()` helper — existing name-to-snake-case converter used throughout the backend.
- The existing file `wrappers/wasm/foundation/exported_functions.json` — use as a ground-truth reference during implementation to verify output completeness. It has 1086 symbols; the generated output should be in the same ballpark.

**Test scenarios:**
- Happy path: `python3 -m tools.codegen.common_bootstrap --project foundation --apply` writes `wrappers/wasm/foundation/exported_functions.json`; the file contains `_vscf_ml_kem_new` and `_vscf_ml_dsa_new` (confirming new PQ algorithms are captured).
- Happy path: generated file does NOT contain `_vscf_round5_new` (round5 removed from IR models).
- Happy path: `python3 -m tools.codegen.common_bootstrap --project ratchet --apply` generates `wrappers/wasm/ratchet/exported_functions.json` containing both `_vscf_*` (foundation deps) and `_vscr_*` (ratchet) symbols.
- Happy path: WASM build with `emcmake cmake` + `cmake --build` links successfully using the generated `exported_functions.json` — no undefined symbol errors.
- Edge case: running codegen twice produces the same file content (idempotent output).
- Edge case: adding a new implementation to the IR model and re-running codegen adds the new implementation's symbols to the JSON automatically.

**Verification:**
- `grep "_vscf_round5_new" wrappers/wasm/foundation/exported_functions.json` → no match.
- `grep "_vscf_ml_kem_new\|_vscf_ml_dsa_new" wrappers/wasm/foundation/exported_functions.json` → matches present.
- WASM build of `libfoundation.js` succeeds: `source ~/Library/emsdk/emsdk_env.sh && cmake --build build-wasm --target libfoundation -j8`.

---

## System-Wide Impact

- **Wire format break:** Ratchet sessions serialized with round5 encapsulated keys (620 bytes) are incompatible with post-change code. Any stored session state must be discarded. This affects any consumer of the ratchet library that persists session state.
- **Apple framework build mechanics:** Currently `vscf_round5_new()` is compiled unconditionally in `vscf_round5.c` (lifecycle functions are not behind `#if ROUND5_LIBRARY`), so `libvscf_foundation` always exports this symbol even when `ROUND5_LIBRARY=0`. Ratchet links fine against this stub; `enable_post_quantum=false` gates all actual KEM calls at runtime. After Unit 3 deletes `vscf_round5.c`, `vscf_ml_kem_new()` fills the same role (`vscf_ml_kem.c` has the same pattern). Unit 4's migration to the kem interface removes the unconditional object creation from `vscr_ratchet_xxdh_init_ctx`, so the Apple framework build (`VIRGIL_POST_QUANTUM=OFF`) remains clean.
- **Swift higher-level SDKs (`virgil-ratchet-x`):** `SecureChat.swift` and `KeysRotator.swift` reference `.curve25519Round5` when PQC is enabled. Removing round5 from the C library breaks these files at compile time. `virgil-e3kit-x` ships with `enableRatchetPqc = false` so no runtime regression for default deployments. Updating these files to `.curve25519MlKem768` is a deferred follow-up (separate repo, separate PR).
- **Interaction graph:** `vscr_ratchet_t` likely calls `vscr_ratchet_xxdh_use_round5` or creates round5 in its own init. After this change it must call `vscr_ratchet_xxdh_use_kem`. Search all callers of `vscr_ratchet_xxdh_use_round5` before Unit 4.
- **API surface parity:** The Go crypto layer exposes `Curve25519Round5` as a public key type. Renaming it is a breaking Go API change. Consumers of the Go wrapper must update their key type references.
- **Error propagation:** `vscr_status_ERROR_ROUND5` is removed from the ratchet status enum. Any caller catching that error code will see a compile error, which is the desired outcome.
- **Unchanged invariants:** Falcon (algorithm, wire format, tests, key size constants) is not touched. ML-KEM and ML-DSA algorithm implementations are not touched. `vscf_alg_id_FALCON` and `vscf_alg_id_ML_KEM_768` / `vscf_alg_id_ML_DSA_65` enum values are unchanged.
- **Integration coverage:** Ratchet end-to-end session tests must verify a full XXDH exchange with ML-KEM-injected xxdh to prove the kem interface injection is wired correctly through the entire ratchet session lifecycle, not just the xxdh unit.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Codegen aborts if any ratchet model still references `class="round5"` when `library_round5.xml` is deleted | All six ratchet class models referencing round5 must be updated in a single commit before running codegen (Unit 2) |
| Protobuf `.options` `max_size` on `FT_POINTER` fields was a decode-length guard, not a buffer size — was previously set to round5 values | Unit 4 removes `max_size` from all PQ `FT_POINTER` fields entirely; nanopb heap-allocates whatever the wire provides; application layer validates sizes |
| `vscr_ratchet_common_hidden.h` is codegen-generated — hand-editing it is overwritten on next codegen run | Update `class_ratchet_common_hidden.xml` in Unit 2; never edit the generated header directly |
| `vscr_ratchet_pb_utils.c` imports keys via concrete `vscf_round5_t*` — kem interface does not expose key import | Use `vscf_key_alg_factory_create_alg` pattern as designed; verify factory is available in the ratchet build |
| `vscr_ratchet.c` ephemeral key generation uses `round5_generate_key` — not in xxdh, easy to miss | Explicitly added to Unit 4 file list; verify with `grep -r "round5\|ROUND5" library/ratchet/src/` before declaring done |
| WASM `exported_functions.json` was hand-maintained and stale (already missing `_vscf_ml_kem_*`) | Unit 7 extends codegen to generate these files; once generated, round5 symbols are absent and ML-KEM/ML-DSA symbols are present automatically |
| `vscf_key_alg_factory.c` and `vscf_key_provider.c` contain hand-written round5 cases not driven by codegen | Inspect files after codegen run; if round5 cases remain, remove manually |
| Ratchet binary test fixtures embed 620-byte encapsulated keys | Delete and regenerate all binary fixture files encoding ratchet session state |
| Go pre-built static libs in `wrappers/go/pkg/*/` still contain `libround5.a` | Deferred to separate CI rebuild; Go tests that link against pre-built libs should be skipped or tagged until libs are rebuilt |
| `AlgIdMlKem768` exact constant name in generated Go may differ | Verify from generated `wrappers/go/foundation/` after Unit 2 before editing `keytype.go` |

## Sources & References

- Related plan: `docs/plans/2026-04-26-003-feat-pqc-upgrade-falcon-mlkem-mldsa-plan.md` — ML-KEM-768 and ML-DSA-65 implementation plan (completed); provides ML-KEM key size constants and test vector strategy.
- Related code: `library/foundation/src/vscf_round5.c` (pattern to delete), `library/foundation/src/vscf_ml_kem.c` (surviving KEM implementation)
- Related code: `library/ratchet/src/vscr_ratchet_xxdh.c`, `library/ratchet/include/virgil/crypto/ratchet/private/vscr_ratchet_common_hidden.h`
- Related codegen: `codegen/models/project_ratchet/class_ratchet_xxdh.xml`, `codegen/models/project_foundation/implementor_post_quantum.xml`
- WASM codegen backend: `tools/codegen/project_wasm_backend.py` — `generate_wasm_files()` (line 1258), `_method_should_wrap()` (line 162), `_resolve_project_prefix()` (line 149)
- Ground-truth reference for generated JSON: `wrappers/wasm/foundation/exported_functions.json` (1086 symbols in current hand-maintained version)
