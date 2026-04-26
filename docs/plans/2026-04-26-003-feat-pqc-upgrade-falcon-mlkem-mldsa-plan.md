---
title: "feat: Upgrade Falcon to 2021 and add ML-KEM-768 and ML-DSA-65 as standalone thirdparty libraries"
type: feat
status: active
date: 2026-04-26
---

# feat: Upgrade Falcon to 2021 and add ML-KEM-768 / ML-DSA-65

## Overview

Three coordinated upgrades to the post-quantum cryptography layer:

1. **Falcon 2019 → 2021** — upgrade `thirdparty/falcon` to `Falcon-impl-20211101.zip`, fix the breaking API change (`int ct` → `int sig_type`), regenerate test vectors.
2. **ML-KEM-768** — add `mlkem-native v1.0.0` (pq-code-package) as a new standalone thirdparty library, wire it into codegen and foundation, implement the KEM wrapper `vscf_ml_kem.c`.
3. **ML-DSA-65** — same pattern with `mldsa-native v1.0.0-beta`, implement the key-signer wrapper `vscf_ml_dsa.c`.

ML-KEM and ML-DSA are brought in as standalone thirdparty libraries (not through liboqs) for formal verification guarantees, cleaner cross-compilation, and no dependency on PQClean (which archives July 2026).

## Problem Frame

The current `thirdparty/falcon` uses a 2019 reference implementation predating the Round 3 submission. The 2021 release fixes the signing API (named `sig_type` constants instead of a raw boolean) and is the authoritative Round 3 source. Staying on 2019 means running old, renamed-internally code and using `ct=1` which in the new API silently means COMPRESSED (variable-length) instead of the CT (constant-time, fixed-length) format we intend.

ML-KEM (FIPS 203) and ML-DSA (FIPS 204) are now final NIST standards. liboqs 0.15.0 already vendors mlkem-native and mldsa-native internally, but our cross-compilation fixes (per-arch ExternalProject build) are specific to liboqs's CMake structure. Bringing mlkem-native and mldsa-native in as standalone libraries avoids that complexity: both use C90 with preprocessor-selected native backends and no hardcoded `-march` flags.

## Requirements Trace

- R1. `thirdparty/falcon` uses `Falcon-impl-20211101.zip` with correct SHA256.
- R2. `vscf_falcon_sign_hash` produces constant-time fixed-size signatures using the new `FALCON_SIG_CT` constant; all existing tests pass with regenerated vectors.
- R3. `mlkem-native v1.0.0` builds as a static library via `ExternalProject_Add` on all CI platforms (Linux x86_64, Linux aarch64, macOS arm64, macOS x86_64, Windows x64).
- R4. `vscf_ml_kem` implements `vscf_kem_api`: generate key, encapsulate (shared-key + ciphertext), decapsulate.
- R5. `mldsa-native v1.0.0-beta` builds as a static library on all CI platforms.
- R6. `vscf_ml_dsa` implements `vscf_key_signer_api`: generate key, sign hash, verify hash.
- R7. All new implementations use deterministic (`*_derand` / `*_internal`) API variants with seeds from `vscf_ctr_drbg`; no thirdparty OS-RNG dependency.
- R8. `ctest` passes for foundation on all CI platforms.

## Scope Boundaries

- Only ML-KEM-768 and ML-DSA-65 parameter sets. Other parameter sets (512, 1024, 44, 87) are deferred.
- No native assembly backends (AVX2, NEON) for mlkem-native or mldsa-native in this plan — pure C only. Assembly optimization is a separate follow-up.
- No changes to the key serialization format (PKCS#8 DER, `vscf_key_provider`); keys are stored as raw bytes inside existing containers.
- No changes to language wrappers (Python, Go, Java, Swift). They will pick up new algorithms through the existing codegen-generated C interfaces.
- No changes to `thirdparty/liboqs` or its algorithm selection flags.

### Deferred to Separate Tasks

- Additional ML-KEM parameter sets (512, 1024): separate plan.
- Additional ML-DSA parameter sets (44, 87): separate plan.
- Native assembly backends for mlkem-native / mldsa-native: performance optimization pass.
- Hybrid KEM (X25519 + ML-KEM-768): future plan.
- Go wrapper pre-built static lib updates for mlkem-native and mldsa-native: separate task after C implementation lands.

## Context & Research

### Relevant Code and Patterns

**Thirdparty ExternalProject pattern:**
- `thirdparty/falcon/CMakeLists.txt` — canonical pattern: `URL`+`URL_HASH`, `PATCH_COMMAND` to inject custom CMakeLists.txt, `CMAKE_INSTALL_LIBDIR=lib` override, `BUILD_BYPRODUCTS`, `add_library(STATIC IMPORTED GLOBAL)`.
- `thirdparty/liboqs/CMakeLists.txt` — more complex (per-arch + lipo for Apple universal), shows how `-DCMAKE_INSTALL_LIBDIR=lib` prevents transitive `_libs` override.
- `thirdparty/falcon/config.h` — disables all OS entropy (`FALCON_RAND_GETENTROPY=0` etc.) to make falcon's internal RNG inert; the wrapper injects entropy via `falcon_shake256_inject()`.

**KEM wrapper pattern:**
- `library/foundation/src/vscf_round5.c` — the existing PQC KEM wrapper. Uses `crypto_kem_keypair` (round5 API), `randombytes_init(seed)` for deterministic keygen, implements `vscf_kem_api`: `kem_shared_key_len`, `kem_encapsulate`, `kem_decapsulate`.
- `library/foundation/src/vscf_falcon.c` — key-signer pattern: seed drawn from `vscf_random` (48 bytes), injected into `falcon_shake256_context`, passed as RNG to `falcon_keygen_make` / `falcon_sign_dyn`.

**Codegen IR pattern:**
- `codegen/models/external/library_falcon.xml` — library declaration: `<feature name="library" default="${VIRGIL_POST_QUANTUM}"/>`, feature sub-options.
- `codegen/models/project_foundation/implementor_post_quantum.xml` — all PQC implementation blocks live here.
- `codegen/models/project_foundation/enum_alg_id.xml` — one `<constant name="..."/>` per algorithm.
- `codegen/models/project_foundation/project_foundation.xml` — `<require library="..." feature="library"/>` registration.

**Compile-definition propagation** (`library/foundation/CMakeLists.txt`): `FALCON_LIBRARY` and `ROUND5_LIBRARY` are propagated as `target_compile_definitions` to the foundation target. Same pattern needed for `MLKEM_LIBRARY` and `MLDSA_LIBRARY`.

### External References

- [mlkem-native v1.0.0](https://github.com/pq-code-package/mlkem-native) — tarball SHA256: `2a219b460f6e85353b26355f7cf2a0d54d8131798825869e9d822b04d9fa8418`
- [mldsa-native v1.0.0-beta](https://github.com/pq-code-package/mldsa-native) — tarball SHA256: `85bebfbb38dd7abb104bfd1a9b070754f515495f60dff6407b0f327c1b291831`
- [Falcon-impl-20211101.zip](https://falcon-sign.info/Falcon-impl-20211101.zip) — SHA256: `d9f982bd825b9903b57b686d6d26018dac173a1dff09f224cc39302f9d85a595`
- `docs/pqc-libraries-survey-2026-04.md` — cross-compilation portability assessment

## Key Technical Decisions

- **Standalone thirdparty libs (not through liboqs):** mlkem-native and mldsa-native are formally verified (CBMC + HOL-Light), have no hardcoded `-march` flags in pure-C mode, and require no CMake arch-detection workarounds. Going through liboqs would add the same per-arch ExternalProject complexity we already wrestle with.

- **Pure C, no native assembly backends (initial):** Both SCU `.S` files (assembly) in mlkem-native and mldsa-native include platform-specific code gated by `MLK_CONFIG_USE_NATIVE_BACKEND_ARITH`. Not defining this flag produces correct pure-C code with no `-march` flags, making the build trivially portable to all CI platforms and watchOS. Assembly optimization can be added later following the liboqs per-arch pattern.

- **Injected CMakeLists.txt (same as falcon):** Neither mlkem-native nor mldsa-native ships a CMakeLists.txt. The project provides one via `PATCH_COMMAND` in `ExternalProject_Add`, following the exact falcon pattern.

- **Config header approach for parameter set and RNG:** Both libraries read their parameter set and RNG hook from a compile-time config header (`-DMLK_CONFIG_FILE="..."`, `-DMLD_CONFIG_FILE="..."`). The project injects a custom config header file alongside the custom CMakeLists.txt. For mlkem-native: `MLK_CONFIG_PARAMETER_SET=768` + `MLK_CONFIG_CUSTOM_RANDOMBYTES` with a no-op `mlk_randombytes` (only derand API used). For mldsa-native: `MLD_CONFIG_PARAMETER_SET=65` + `MLD_CONFIG_NO_RANDOMIZED_API` (removes all randomized functions entirely).

- **Short namespace prefixes:** Set `MLK_CONFIG_NAMESPACE_PREFIX=mlkem768` so functions become `mlkem768_keypair_derand`, `mlkem768_enc_derand`, `mlkem768_dec`. Set `MLD_CONFIG_NAMESPACE_PREFIX=mldsa65` so functions become `mldsa65_keypair_internal`, `mldsa65_signature_internal`, `mldsa65_verify`. This avoids the verbose default `PQCP_MLKEM_NATIVE_MLKEM768_*` prefix throughout wrapper code.

- **ML-KEM: use derand API exclusively:** `mlkem768_keypair_derand(pk, sk, 64_byte_seed)` and `mlkem768_enc_derand(ct, ss, pk, 32_byte_seed)` with seeds from `vscf_ctr_drbg`. Never call the randomized `keypair` / `enc` variants. This matches the falcon pattern of injecting RNG from `vscf_random`.

- **ML-DSA: deterministic signing via zero `rnd`:** `mldsa65_signature_internal(sig, &siglen, digest, len, NULL, 0, zero32, sk, 0)` where `zero32` is 32 zero bytes. FIPS 204 §5.4.1 permits deterministic ML-DSA when `rnd = 0^32`. This gives test-vector stability and avoids an RNG call in the signing path.

- **ML-DSA signing input: treat digest as message:** The wrapper's `sign_hash` receives a 64-byte SHA-512 digest. This digest is passed as `m` to `mldsa65_signature_internal` with `externalmu=0`. ML-DSA then hashes it again internally as part of the signing protocol — this is correct and matches how falcon treats the digest input.

- **Falcon sig_type upgrade: keep CT, not PADDED:** The new `FALCON_SIG_PADDED` format (666 bytes) is smaller but would be a wire-format breaking change for any existing stored signatures. Keep `FALCON_SIG_CT` (809 bytes). All existing test vectors are regenerated because the 2021 keygen may produce different key bytes from the same seed (implementation details changed between 2019 and 2021). Wire format compatibility with external parties using 2021+ Falcon is preserved.

- **falcon_verify sig_type=0 for auto-detection:** On the verify side, pass `sig_type=0` to `falcon_verify`. FIPS 203 §A.2: when `sig_type=0`, the library reads the header byte of the signature to determine format. This future-proofs the verifier against signatures produced by other format choices.

- **patch_shake256.cmake still applies:** The 2021 falcon source still uses `shake256_*` function names (same as 2019). The round5 library still provides its own SHAKE256. The patch (regex rename to `falcon_shake256_*`) is still required.

## Open Questions

### Resolved During Planning

- **Does mlkem-native need the `.S` assembly file for correct behavior?** Yes, but only for "value barriers" (prevent compiler optimizing away constant-time code). Without `MLK_CONFIG_USE_NATIVE_BACKEND_ARITH`, the `.S` SCU contains only minimal barrier stubs. Compile both `mlkem_native.c` and `mlkem_native.S`; the `.S` carries `-x assembler-with-cpp` flags in the injected CMakeLists.
- **Can the ML-KEM public key be extracted from the secret key on import?** Yes. The FIPS 203 decapsulation key layout is `dk = (dk_PKE || ek || H(ek) || z)` where `ek` is the 1184-byte public key starting at offset `MLKEM768_INDCPA_SECRETKEYBYTES` (1152 bytes). Verify this offset from the mlkem-native source during implementation.
- **Does mldsa-native need `randombytes` at all with `MLD_CONFIG_NO_RANDOMIZED_API`?** No. That flag removes all randomized API functions and their RNG calls. Only `keypair_internal` and `signature_internal` remain, which take explicit seed/rnd parameters.

### Deferred to Implementation

- Exact offset for extracting public key from ML-KEM secret key (verify `MLKEM768_INDCPA_SECRETKEYBYTES` constant in mlkem-native v1.0.0 source).
- Whether the 2021 falcon keygen produces different keys from the same RNG seed as 2019 (requires building and running; if same, old test vectors stay valid; if different, regenerate).
- Whether `falcon_verify(..., sig_type=0, ...)` in the 2021 API correctly auto-detects CT-format signatures produced by the old 2019 code (wire format unchanged, so should work, but verify in tests).
- Exact function name generated by `MLK_API_NAMESPACE(keypair_derand)` when `MLK_CONFIG_NAMESPACE_PREFIX=mlkem768` — check header after first build.

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

```
Root CMakeLists.txt
  if(VIRGIL_POST_QUANTUM)
    thirdparty/falcon       → libfalcon.a      ← Unit 1
    thirdparty/mlkem-native → libmlkem768.a    ← Unit 3
    thirdparty/mldsa-native → libmldsa65.a     ← Unit 5
    thirdparty/round5       → libround5.a
    thirdparty/liboqs       → liboqs.a
  endif()

library/foundation (target: foundation)
  links: falcon, mlkem768, mldsa65, round5, oqs
  compile defs: FALCON_LIBRARY, MLKEM_LIBRARY, MLDSA_LIBRARY, ROUND5_LIBRARY, OQS_LIBRARY

  vscf_falcon.c      → sign/verify (FALCON_SIG_CT)   ← Unit 2
  vscf_ml_kem.c      → KEM (mlkem768 derand API)      ← Unit 4
  vscf_ml_dsa.c      → sign/verify (mldsa65 _internal) ← Unit 6

codegen/models/external/
  library_falcon.xml    (exists)
  library_mlkem.xml     ← Unit 3
  library_mldsa.xml     ← Unit 5

codegen/models/project_foundation/
  implementor_post_quantum.xml  (+ ml_kem, + ml_dsa blocks)  ← Units 3, 5
  enum_alg_id.xml               (+ ML_KEM_768, + ML_DSA_65)  ← Units 3, 5

Seed/RNG flow (all three algorithms):
  vscf_ctr_drbg
    → vscf_random(N bytes)
    → falcon: inject into shake256_context, pass to _keygen_make / _sign_dyn
    → mlkem768: pass directly to keypair_derand(seed[64]) / enc_derand(seed[32])
    → mldsa65: pass directly to keypair_internal(seed[32]); sign: zero rnd[32]
```

## Implementation Units

---

- [ ] **Unit 1: Upgrade thirdparty/falcon to Falcon-impl-20211101**

**Goal:** Replace the 2019 falcon source tarball with the 2021 Round 3 final release in the ExternalProject definition.

**Requirements:** R1

**Dependencies:** None

**Files:**
- Modify: `thirdparty/falcon/CMakeLists.txt`
- Modify: `thirdparty/falcon/falcon.CMakeLists.txt`

**Approach:**
- In `CMakeLists.txt`: change `URL` to `https://falcon-sign.info/Falcon-impl-20211101.zip`, update `URL_HASH SHA256` to `d9f982bd825b9903b57b686d6d26018dac173a1dff09f224cc39302f9d85a595`.
- In `falcon.CMakeLists.txt`: update `project(falcon VERSION 2021.11.01 LANGUAGES C)` version string.
- Verify the 2021 source file list matches what `falcon.CMakeLists.txt` compiles: `codec.c common.c falcon.c fft.c fpr.c keygen.c shake.c sign.c vrfy.c rng.c` — same set.
- The `PATCH_COMMAND` (patch_shake256.cmake + config.h + CMakeLists.txt replacement) remains unchanged: 2021 still uses `shake256_*` names and has no CMakeLists.txt.
- The `BUILD_BYPRODUCTS` path is unchanged (`lib/libfalcon.a`).
- Delete the cached ExternalProject stamp (`thirdparty/falcon/falcon-ext-prefix/src/falcon-ext-stamp/`) before or during the build step to force re-download.

**Patterns to follow:** `thirdparty/liboqs/CMakeLists.txt` for how to use `URL`+`URL_HASH`+`SHA256=`.

**Test scenarios:**
- Happy path: clean CMake configure + build; `libfalcon.a` present at expected path.
- Test expectation: the existing `test_post_quantum_library_falcon.c` tests still compile (they include `<falcon/falcon.h>` directly; the 2021 header has the same layout).

**Verification:**
- `cmake -B build -S . && cmake --build build --target falcon-ext` succeeds.
- SHA256 of downloaded zip matches the declared hash (CMake prints an error if not).

---

- [ ] **Unit 2: Fix falcon API call site and regenerate test vectors**

**Goal:** Update `vscf_falcon.c` to use the named `sig_type` constants from the 2021 API, and regenerate all falcon test vectors that depend on signature format.

**Requirements:** R2

**Dependencies:** Unit 1 (2021 falcon headers must be present)

**Files:**
- Modify: `library/foundation/src/vscf_falcon.c`
- Modify: `tests/foundation/data/src/test_data_falcon.c`
- Modify: `tests/foundation/data/include/test_data_falcon.h` (if sizes change)

**Approach:**
- In `vscf_falcon.c` line ~561: change `falcon_sign_dyn(..., 1, tmp, sizeof(tmp))` to `falcon_sign_dyn(..., FALCON_SIG_CT, tmp, sizeof(tmp))`. `FALCON_SIG_CT = 3` in the 2021 header.
- In `vscf_falcon_verify_hash` line ~611: add `sig_type=0` as the new third parameter: `falcon_verify(sig_bytes, sig_len, 0, pk_bytes, pk_len, digest_bytes, digest_len, tmp, sizeof(tmp))`. Using `0` enables auto-detection from the signature header byte, which correctly handles CT-format signatures.
- Run the test suite with a local build to determine whether the 2021 keygen produces identical keys from the same seed as 2019. If keys differ, regenerate `test_data_falcon_PUBLIC_KEY_512`, `test_data_falcon_PRIVATE_KEY_512`, and all derived vectors.
- Regenerate `test_data_falcon_CONST_SIGNATURE` unconditionally: the 2021 `falcon_sign_dyn` with `FALCON_SIG_CT` produces a different header byte than 2019's `ct=1` path (the header byte encodes the format). A test run with `test_data_falcon_RNG_SEED` and `test_data_falcon_RNG_SEED2` gives the new reference values.
- Update `test_data_falcon.c` with new byte arrays; update `test_data_falcon.h` size constants if they changed.

**Patterns to follow:** `library/foundation/src/vscf_falcon.c` existing structure; `tests/foundation/data/src/test_data_falcon.c` existing vector format.

**Test scenarios:**
- Happy path: `test__sign_hash__sha512_digest_with_512_degree_key__produce_const_signature` passes with new CONST_SIGNATURE vector.
- Happy path: `test__verify_hash__sha512_digest_and_const_signature_with_512_degree_key__success` passes.
- Happy path: `test__generate_key__512_degree_with_fake_rng__success` passes (or regenerated vectors match if keygen output changed).
- Edge case: `falcon_verify` with `sig_type=0` correctly auto-detects CT format from the 0x59 (logn=9, CT) header byte.
- Error path: `test__sign_hash__with_bad_private_key__returns_error` (existing test should continue to catch `FALCON_ERR_FORMAT` → `vscf_status_ERROR_BAD_FALCON_PRIVATE_KEY`).

**Verification:**
- `cd build && ctest -R falcon --output-on-failure` — all falcon tests pass.

---

- [ ] **Unit 3: Add thirdparty/mlkem-native ExternalProject + codegen IR + foundation wiring**

**Goal:** Integrate mlkem-native v1.0.0 as a static library target and register it in codegen so `vscf_ml_kem` stubs can be generated.

**Requirements:** R3, and enables R4

**Dependencies:** None (parallel to Units 1–2)

**Files:**
- Create: `thirdparty/mlkem-native/features.cmake`
- Create: `thirdparty/mlkem-native/CMakeLists.txt`
- Create: `thirdparty/mlkem-native/mlkem.CMakeLists.txt`
- Create: `thirdparty/mlkem-native/mlkem_config_768.h`
- Create: `codegen/models/external/library_mlkem.xml`
- Modify: `codegen/models/project_foundation/implementor_post_quantum.xml`
- Modify: `codegen/models/project_foundation/enum_alg_id.xml`
- Modify: `codegen/models/project_foundation/project_foundation.xml`
- Modify: `CMakeLists.txt` (add `add_subdirectory("thirdparty/mlkem-native")` in PQ block)
- Modify: `library/foundation/CMakeLists.txt` (link `mlkem768`, propagate `MLKEM_LIBRARY` compile definition)
- Generated (by codegen): `library/foundation/src/vscf_ml_kem_internal.c`, `library/foundation/src/vscf_ml_kem_defs.c`, `library/foundation/include/virgil/crypto/foundation/vscf_ml_kem.h`, `library/foundation/include/virgil/crypto/foundation/vscf_ml_kem_defs.h`, `library/foundation/include/virgil/crypto/foundation/vscf_alg_id.h` (updated), `library/foundation/features.cmake` (updated)

**Approach:**

*`features.cmake`:*
- Declares `MLKEM_LIBRARY` option defaulting to `${VIRGIL_POST_QUANTUM}`.
- Mark as advanced.

*`CMakeLists.txt` (ExternalProject):*
- URL: `https://github.com/pq-code-package/mlkem-native/archive/refs/tags/v1.0.0.tar.gz`, SHA256: `2a219b460f6e85353b26355f7cf2a0d54d8131798825869e9d822b04d9fa8418`.
- `PATCH_COMMAND`: copy `mlkem.CMakeLists.txt` → `<SOURCE_DIR>/CMakeLists.txt`; copy `mlkem_config_768.h` → `<SOURCE_DIR>/mlkem/mlkem_config_768.h`.
- `CMAKE_ARGS`: `${TRANSITIVE_ARGS}`, toolchain, build type, `CMAKE_INSTALL_PREFIX`, `CMAKE_INSTALL_LIBDIR=lib`.
- `BUILD_BYPRODUCTS`: `${MLKEM_INSTALL_LOCATION}/lib/libmlkem768.a` (or platform equivalent using `${CMAKE_STATIC_LIBRARY_PREFIX}mlkem768${CMAKE_STATIC_LIBRARY_SUFFIX}`).
- `add_library(mlkem768 STATIC IMPORTED GLOBAL)`, `IMPORTED_LOCATION`, `INTERFACE_INCLUDE_DIRECTORIES` pointing to `${MLKEM_INSTALL_LOCATION}/include`.

*`mlkem.CMakeLists.txt`* (injected into source tree):
- Sets `cmake_minimum_required`, `project(mlkem768 ...)`, includes GNUInstallDirs.
- `add_library(mlkem768 STATIC mlkem/mlkem_native.c mlkem/mlkem_native.S)` — both SCU files.
- `target_include_directories(mlkem768 PUBLIC mlkem/)` — mlkem/ is the include root for `mlkem_native.h`.
- `target_compile_definitions(mlkem768 PRIVATE MLK_CONFIG_FILE="mlkem_config_768.h")` — selects config header.
- Do NOT define `MLK_CONFIG_USE_NATIVE_BACKEND_ARITH` or `MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202` — pure C mode.
- `set_source_files_properties(mlkem/mlkem_native.S PROPERTIES LANGUAGE C)` — assembler-with-cpp (or `COMPILE_FLAGS "-x assembler-with-cpp"` depending on platform).
- Install target + headers from `mlkem/mlkem_native.h` to `${CMAKE_INSTALL_INCLUDEDIR}/mlkem/`.

*`mlkem_config_768.h`*:
- `#define MLK_CONFIG_PARAMETER_SET 768`
- `#define MLK_CONFIG_NAMESPACE_PREFIX mlkem768`
- `#define MLK_CONFIG_CUSTOM_RANDOMBYTES` + `static inline void mlk_randombytes(uint8_t *p, size_t n) { (void)p; (void)n; }` — stub, never called because wrapper uses only derand API.

*Codegen IR:*
- `library_mlkem.xml`: `<library name="mlkem" path="../thirdparty/mlkem-native">` with `<feature name="library" default="${VIRGIL_POST_QUANTUM}"/>`.
- In `implementor_post_quantum.xml`: add `<implementation name="ml kem">` with `<interface name="kem"/>`, `<interface name="alg"/>`, `<interface name="key alg"/>`, constants `PUBLIC_KEY_LEN=1184`, `SECRET_KEY_LEN=2400`, `CIPHERTEXT_LEN=1088`, `SHARED_KEY_LEN=32`, `SEED_LEN=64`, `ENC_SEED_LEN=32`, dependency on `<random interface="random"/>`. Pattern: mirror `<implementation name="round5">` for KEM shape, mirror `<implementation name="falcon">` for random-dependency injection.
- In `enum_alg_id.xml`: add `<constant name="ml kem 768"/>` → generates `vscf_alg_id_ML_KEM_768`.
- In `project_foundation.xml`: add `<require library="mlkem" feature="library"/>`.
- Run codegen: `python3 -m tools.codegen.common_bootstrap --project foundation --apply`.

*Foundation CMakeLists.txt:*
- Add `mlkem768` to `target_link_libraries(foundation PUBLIC ...)` (guarded by `if(MLKEM_LIBRARY)`).
- Add `MLKEM_LIBRARY=$<BOOL:${MLKEM_LIBRARY}>` to `target_compile_definitions`.

**Patterns to follow:**
- `thirdparty/falcon/CMakeLists.txt` — ExternalProject pattern.
- `codegen/models/external/library_liboqs.xml` — library XML with sub-features.
- `codegen/models/project_foundation/implementor_post_quantum.xml` — implementation XML with interfaces and constants.

**Test scenarios:**
- Happy path: `cmake -B build -S . -DMLKEM_LIBRARY=ON` configures without errors; `cmake --build build --target mlkem768-ext` succeeds; `libmlkem768.a` present at install prefix.
- Happy path: codegen run produces `vscf_ml_kem.h`, `vscf_ml_kem_internal.c`, `vscf_ml_kem_defs.h`; `vscf_alg_id.h` contains `vscf_alg_id_ML_KEM_768`.
- Edge case: build with `VIRGIL_POST_QUANTUM=OFF` skips mlkem-native entirely; foundation compiles without `MLKEM_LIBRARY` defined.
- Error path: wrong SHA256 causes CMake to fail with a descriptive hash mismatch error (CMake built-in behavior).

**Verification:**
- `cmake -B build -S . && cmake --build build` — no linker errors for the foundation target.
- `vscf_alg_id_ML_KEM_768` visible in `library/foundation/include/virgil/crypto/foundation/vscf_alg_id.h`.

---

- [ ] **Unit 4: Implement vscf_ml_kem.c + tests**

**Goal:** Implement the ML-KEM-768 KEM wrapper: key generation, encapsulation, decapsulation; with deterministic tests using test vectors.

**Requirements:** R4, R7, R8

**Dependencies:** Unit 3 (mlkem768 library target and generated header stubs must exist)

**Files:**
- Create: `library/foundation/src/vscf_ml_kem.c`
- Create: `tests/foundation/test_ml_kem.c`
- Create: `tests/foundation/data/src/test_data_ml_kem.c`
- Create: `tests/foundation/data/include/test_data_ml_kem.h`
- Modify: `tests/foundation/CMakeLists.txt` (register new test executable)

**Approach:**

*Key generation:*
- Draw 64 bytes from `vscf_random` (2 × `MLKEM_SYMBYTES` = 2 × 32).
- Call `mlkem768_keypair_derand(pk_buf, sk_buf, seed_64)`.
- Wrap in `vscf_raw_public_key` / `vscf_raw_private_key` with alg_id `vscf_alg_id_ML_KEM_768`, set `impl_tag`, attach public key to private key via `vscf_raw_private_key_set_public_key`.

*Import private key — extracting embedded public key:*
- The FIPS 203 ML-KEM-768 secret key layout: `dk = dk_PKE (1152 bytes) || ek (1184 bytes) || H(ek) (32 bytes) || z (32 bytes)`.
- Extract `pk_bytes = sk_bytes[1152 .. 1152+1184]` — confirm offset via `MLKEM768_INDCPA_SECRETKEYBYTES` constant in `mlkem_native.h`.
- No mlkem-native function call needed; it is a pure byte offset extraction.

*Encapsulation:*
- Draw 32 bytes from `vscf_random` (`MLKEM_SYMBYTES = 32`).
- Call `mlkem768_enc_derand(ct_buf, ss_buf, pk_bytes, seed_32)`.
- Fill `shared_key` and `encapsulated_key` buffers.

*Decapsulation:*
- Call `mlkem768_dec(ss_buf, ct_bytes, sk_bytes)`.
- Fill `shared_key` buffer.
- Return `vscf_status_ERROR_BAD_ENCRYPTED_DATA` on non-zero return (implicit rejection under FIPS 203 decapsulation failure does not return non-zero; the library always "succeeds" and returns a random key on failure — so this is always 0; document this in code comment).

*Test data:*
- Generate deterministically using a known 64-byte seed: run a small C program (or add a test that prints) to capture fixed pk, sk, encapsulated_key, and shared_secret for a known enc_seed.
- Store in `test_data_ml_kem.c` as byte arrays.

**Execution note:** Run a quick smoke-test build before writing test vectors to confirm the correct symbol names (`mlkem768_keypair_derand` etc.) actually appear in the installed `mlkem_native.h`.

**Patterns to follow:**
- `library/foundation/src/vscf_round5.c` — KEM interface implementation pattern.
- `library/foundation/src/vscf_falcon.c` — seed injection from `vscf_random`, buffer management.
- `tests/foundation/test_falcon.c` — test structure, `TEST_DEPENDENCIES_AVAILABLE` guard.

**Test scenarios:**
- Happy path: `test__generate_key__ml_kem_768_with_fake_rng__success` — deterministic keygen from known seed produces expected pk/sk byte arrays matching stored test vectors.
- Happy path: `test__encapsulate__ml_kem_768_with_fake_rng__success` — encapsulate with known seed on test pk produces expected ct and ss.
- Happy path: `test__decapsulate__ml_kem_768__success` — decapsulate test ct with test sk produces matching ss.
- Happy path: `test__encapsulate_then_decapsulate__live_rng__shared_secrets_match` — end-to-end with real RNG, verify sender ss == receiver ss.
- Happy path: `test__export_public_key__from_generated_key__valid_alg_and_key_data` — exported pk has alg_id `ML_KEM_768`, correct length 1184.
- Edge case: `test__import_private_key__extract_public_key__matches_original` — import raw sk, extract embedded pk, compare with originally generated pk.
- Error path: `test__decapsulate__wrong_ciphertext__returns_implicit_rejection` — ML-KEM decapsulation always succeeds; caller gets a random-looking ss; assert return is 0 and ss length is correct (FIPS 203 implicit rejection is transparent).
- Error path: `test__encapsulate__with_invalid_public_key_length__returns_error` — pass truncated pk; verify error status returned.

**Verification:**
- `ctest -R ml_kem --output-on-failure` — all ML-KEM tests pass.
- `vscf_ml_kem_encapsulate` and `vscf_ml_kem_decapsulate` run without ASAN / UBSAN errors.

---

- [ ] **Unit 5: Add thirdparty/mldsa-native ExternalProject + codegen IR + foundation wiring**

**Goal:** Integrate mldsa-native v1.0.0-beta as a static library target and register it in codegen.

**Requirements:** R5, and enables R6

**Dependencies:** Unit 3 (parallel; same structural approach — can land independently)

**Files:**
- Create: `thirdparty/mldsa-native/features.cmake`
- Create: `thirdparty/mldsa-native/CMakeLists.txt`
- Create: `thirdparty/mldsa-native/mldsa.CMakeLists.txt`
- Create: `thirdparty/mldsa-native/mldsa_config_65.h`
- Create: `codegen/models/external/library_mldsa.xml`
- Modify: `codegen/models/project_foundation/implementor_post_quantum.xml`
- Modify: `codegen/models/project_foundation/enum_alg_id.xml`
- Modify: `codegen/models/project_foundation/project_foundation.xml`
- Modify: `CMakeLists.txt` (add `add_subdirectory("thirdparty/mldsa-native")`)
- Modify: `library/foundation/CMakeLists.txt` (link `mldsa65`, propagate `MLDSA_LIBRARY`)
- Generated (by codegen): `vscf_ml_dsa_internal.c`, `vscf_ml_dsa_defs.c`, `vscf_ml_dsa.h`, `vscf_ml_dsa_defs.h`, updated `vscf_alg_id.h`

**Approach:**

Mirrors Unit 3 exactly, replacing `mlkem` with `mldsa`:

- `features.cmake`: `MLDSA_LIBRARY` option defaulting to `${VIRGIL_POST_QUANTUM}`.
- `CMakeLists.txt`: URL `https://github.com/pq-code-package/mldsa-native/archive/refs/tags/v1.0.0-beta.tar.gz`, SHA256 `85bebfbb38dd7abb104bfd1a9b070754f515495f60dff6407b0f327c1b291831`, same ExternalProject pattern, `BUILD_BYPRODUCTS` using `libmldsa65.a`.
- `mldsa.CMakeLists.txt`: `add_library(mldsa65 STATIC mldsa/mldsa_native.c mldsa/mldsa_native_asm.S)`, include dir `mldsa/`, config file define `MLD_CONFIG_FILE="mldsa_config_65.h"`.
- `mldsa_config_65.h`: `#define MLD_CONFIG_PARAMETER_SET 65`, `#define MLD_CONFIG_NAMESPACE_PREFIX mldsa65`, `#define MLD_CONFIG_NO_RANDOMIZED_API` — removes all randomized functions and `randombytes` dependency entirely.
- Codegen: `library_mldsa.xml`, add `<implementation name="ml dsa">` with `<interface name="key signer"/>`, constants `PUBLIC_KEY_LEN=1952`, `SECRET_KEY_LEN=4032`, `SIGNATURE_LEN=3309`, `SEED_LEN=32`, random dependency.
- `enum_alg_id.xml`: add `<constant name="ml dsa 65"/>` → `vscf_alg_id_ML_DSA_65`.

**Patterns to follow:** Exactly as Unit 3 (swap mlkem for mldsa throughout).

**Test scenarios:** Mirror Unit 3 test scenarios with mldsa-specific values.

**Verification:**
- `cmake -B build -S . && cmake --build build --target mldsa65-ext` succeeds; `libmldsa65.a` present.
- `vscf_alg_id_ML_DSA_65` visible in `vscf_alg_id.h`.
- Foundation target links without errors.

---

- [ ] **Unit 6: Implement vscf_ml_dsa.c + tests**

**Goal:** Implement the ML-DSA-65 key-signer wrapper: key generation, sign hash, verify hash; with deterministic tests.

**Requirements:** R6, R7, R8

**Dependencies:** Unit 5 (mldsa65 library target and generated header stubs must exist)

**Files:**
- Create: `library/foundation/src/vscf_ml_dsa.c`
- Create: `tests/foundation/test_ml_dsa.c`
- Create: `tests/foundation/data/src/test_data_ml_dsa.c`
- Create: `tests/foundation/data/include/test_data_ml_dsa.h`
- Modify: `tests/foundation/CMakeLists.txt`

**Approach:**

*Key generation:*
- Draw 32 bytes from `vscf_random` (`MLDSA_SEEDBYTES = 32`).
- Call `mldsa65_keypair_internal(pk_buf, sk_buf, seed_32)`.
- Wrap in `vscf_raw_public_key` / `vscf_raw_private_key` with alg_id `vscf_alg_id_ML_DSA_65`.

*Import private key — extracting embedded public key:*
- ML-DSA FIPS 204 secret key layout: `sk = (ρ || K || tr || s₁ || s₂ || t₀)`. The public key `pk = (ρ || t₁)` is NOT embedded in sk (unlike ML-KEM). Therefore `import_private_key` for standalone sk cannot reconstruct pk without a full key expansion.
- Decision (deferred to implementation): either (a) store pk alongside sk as a single blob (safe, no key expansion needed), or (b) call `mldsa65_pk_from_sk(pk, sk)` if such a function exists in the library. Verify during implementation.
- If no `pk_from_sk` function exists: store pk concatenated to sk in the raw key container (`sk_bytes + pk_bytes`), with a well-defined size split.

*sign_hash:*
- The digest (64 bytes for SHA-512) is treated as the message `m`.
- Call `mldsa65_signature_internal(sig_buf, &siglen, digest_bytes, digest_len, NULL, 0, zero32, sk_bytes, 0)` where `zero32` is a 32-byte zero array.
- `zero32` as `rnd` gives deterministic signatures per FIPS 204 §5.4.1.
- Return `vscf_status_ERROR_BAD_ML_DSA_PRIVATE_KEY` on non-zero return.

*verify_hash:*
- Call `mldsa65_verify(sig_bytes, siglen, digest_bytes, digest_len, NULL, 0, pk_bytes)`.
- Return `true` if 0, `false` otherwise.

*Signature length:*
- `signature_len()` returns `MLDSA65_BYTES = 3309` (the maximum; actual signatures may be shorter since ML-DSA-65 produces variable-length signatures). Buffer must be allocated at max size; `siglen` is updated after signing.
- `vsc_buffer_inc_used(signature, siglen)` (not the max).

*Test data:*
- Known seed (32 bytes), resulting pk (1952 bytes) and sk (4032 bytes), known digest (SHA-512 of known data, 64 bytes), resulting deterministic signature (with zero rnd).

**Patterns to follow:**
- `library/foundation/src/vscf_falcon.c` — key signer interface: `sign_hash`, `verify_hash`, buffer management, seed injection.
- `tests/foundation/test_falcon.c` — test structure.

**Test scenarios:**
- Happy path: `test__generate_key__ml_dsa_65_with_fake_rng__success` — deterministic keygen from known 32-byte seed matches stored pk/sk vectors.
- Happy path: `test__sign_hash__sha512_digest_with_ml_dsa_65_key__produce_const_signature` — sign a known digest with zero-rnd; compare against stored reference signature.
- Happy path: `test__verify_hash__sha512_digest_and_const_signature_with_ml_dsa_65_key__success` — verify stored signature passes.
- Happy path: `test__generate_and_sign_then_verify__live_rng__success` — end-to-end live test.
- Edge case: `test__sign_hash__minimum_signature_fits_in_buffer` — allocate exactly `MLDSA65_BYTES` bytes; verify signing succeeds and actual `siglen ≤ MLDSA65_BYTES`.
- Error path: `test__verify_hash__modified_signature_byte__returns_false`.
- Error path: `test__verify_hash__wrong_public_key__returns_false`.
- Integration: `test__export_import_private_key__then_sign_verify__success` — verify that pk recovered from imported sk matches original; sign with imported sk and verify with extracted pk.

**Verification:**
- `ctest -R ml_dsa --output-on-failure` — all ML-DSA tests pass.
- Deterministic signature test is byte-exact against stored vector (confirms zero-rnd mode is active).
- ASAN / UBSAN clean.

---

## System-Wide Impact

- **Interaction graph:** `vscf_key_provider` aggregates all `vscf_key_alg` implementations; new ML-KEM and ML-DSA entries will be auto-registered in the impl-tag dispatch table after codegen. No manual changes to `vscf_key_provider.c` expected. Verify `vscf_post_quantum_key_provider` (if it exists) picks up new algorithms.
- **Error propagation:** New error codes `vscf_status_ERROR_BAD_ML_KEM_PUBLIC_KEY` and `vscf_status_ERROR_BAD_ML_DSA_PRIVATE_KEY` must be added to `vscf_status.h` and `vscf_status.xml` (codegen). They follow the existing `vscf_status_ERROR_BAD_FALCON_PRIVATE_KEY` pattern.
- **State lifecycle risks:** mlkem-native and mldsa-native are both stateless (no global state, no init/cleanup). No thread-safety issues from the library side. `vscf_ml_kem_t` and `vscf_ml_dsa_t` structs hold only a `random` dependency pointer, same as `vscf_falcon_t`.
- **API surface parity:** The ratchet library (`library/ratchet/src/vscf_ratchet_xxdh.c`) currently uses `vscf_falcon_sign_hash` / `vscf_falcon_verify_hash` directly. It will not automatically use ML-DSA without separate ratchet changes — this is intentional and out of scope.
- **Integration coverage:** Python and Go wrappers regenerate from codegen; they will expose the new `vscf_ml_kem` and `vscf_ml_dsa` types once the codegen is applied to wrapper projects. This is a follow-up task per Scope Boundaries above.
- **Unchanged invariants:** Existing falcon, round5, and liboqs algorithm behavior and wire formats are not changed. ML-KEM and ML-DSA are additive. The `vscf_alg_id_FALCON` enum value and associated serialization format are unchanged.

## Phased Delivery

### Phase 1 — Falcon upgrade (Units 1–2)
Self-contained. Delivers the 2021 Round 3 Falcon with clean `sig_type` API. Can be landed as a standalone PR with no ML-KEM/ML-DSA changes.

### Phase 2 — ML-KEM-768 (Units 3–4)
New KEM algorithm. Depends only on Phase 1 being landed (or can land in parallel if falcon upgrade is on a separate branch). Requires a new thirdparty library and codegen IR.

### Phase 3 — ML-DSA-65 (Units 5–6)
New digital signature algorithm. Structurally parallel to Phase 2; can be developed in parallel and landed in sequence or as a combined PR with Phase 2.

## Risks & Dependencies

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| 2021 falcon keygen produces different key bytes from same seed as 2019 | Medium | Low — test vectors need regeneration; no wire format change | Detect in Unit 2 first build; regenerate vectors if needed |
| mlkem_native.S assembly compilation fails on Windows MSVC | Medium | Medium — MSVC does not support GNU inline asm | Use `-DMLK_CONFIG_NO_ASM` on MSVC (add MSVC-specific guard in `mlkem.CMakeLists.txt`); pure C fallback is available |
| mldsa_native_asm.S fails similarly on Windows | Medium | Medium | Same mitigation as above |
| `MLK_CONFIG_NAMESPACE_PREFIX=mlkem768` does not produce expected symbol names | Low | Medium — wrapper code uses wrong function names | Verify by inspecting `mlkem_native.h` after first build; adjust prefix or call via `MLK_API_NAMESPACE` macro directly |
| ML-DSA sk does not embed pk (no `pk_from_sk` in mldsa-native) | Medium | Medium — import_private_key must store pk alongside sk, changing key size | Verify from source in Unit 5 first; if confirmed, use concatenated sk+pk blob with documented split |
| mldsa-native v1.0.0-beta API changes before v1.0.0 stable | Low | Medium — function signatures may shift | Pin to exact tag; if stable v1.0.0 releases before implementation, prefer it |
| Cross-compilation (Apple universal macOS): `.S` SCU compiles for wrong arch | Low | Medium | Without native backends, `.S` only contains minimal barriers; pure-C mode avoids arch-specific code entirely. If issues arise, guard `.S` compilation like liboqs (per-arch ExternalProject) |

## Sources & References

- [mlkem-native v1.0.0](https://github.com/pq-code-package/mlkem-native)
- [mldsa-native v1.0.0-beta](https://github.com/pq-code-package/mldsa-native)
- [falcon-sign.info Falcon-impl-20211101](https://falcon-sign.info/)
- `docs/pqc-libraries-survey-2026-04.md` — cross-compilation portability analysis
- `docs/plans/2026-04-26-002-refactor-falcon-migrate-to-liboqs-plan.md` — prior Falcon/liboqs migration plan (superseded for Falcon; still relevant if liboqs ML-KEM/ML-DSA paths are needed later)
- Related code: `thirdparty/falcon/`, `thirdparty/liboqs/`, `library/foundation/src/vscf_falcon.c`, `library/foundation/src/vscf_round5.c`
- `codegen/models/external/library_falcon.xml`, `codegen/models/project_foundation/implementor_post_quantum.xml`
