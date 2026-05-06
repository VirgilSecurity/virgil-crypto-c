# Post-Quantum Cryptography Libraries Survey

**Date:** April 2026  
**Scope:** Standalone C/C++ implementations of NIST FIPS 203/204/205/206 (ML-KEM, ML-DSA, SLH-DSA, FN-DSA) with emphasis on cross-compilation portability (macOS universal, iOS, watchOS, Linux aarch64, Windows x64).

---

## Standards Status

| Standard | Algorithm | Basis | Status | Published |
|---|---|---|---|---|
| FIPS 203 | ML-KEM (Kyber) | Final | Published | Aug 13, 2024 |
| FIPS 204 | ML-DSA (Dilithium) | Final | Published | Aug 13, 2024 |
| FIPS 205 | SLH-DSA (SPHINCS+) | Final | Published | Aug 13, 2024 |
| FIPS 206 | FN-DSA (Falcon) | **Draft** | Submitted Aug 2025; final expected late 2026/early 2027 | — |

FIPS 206 is **not yet finalized**. All FN-DSA implementations currently track the Round 3 Falcon spec.

---

## Libraries

### 1. mlkem-native

| Field | Value |
|---|---|
| **GitHub** | https://github.com/pq-code-package/mlkem-native |
| **License** | Apache-2.0 OR MIT OR ISC |
| **Language** | C90 |
| **Latest release** | v1.0.0 (June 2025, production-stable) |
| **Algorithms** | ML-KEM-512, ML-KEM-768, ML-KEM-1024 (all FIPS 203 parameter sets) |
| **Build system** | Makefile (dev/CI only); embed `mlkem/` directory into your own build |
| **Formal verification** | **Strongest available:** CBMC for all C (memory-safety, type-safety), HOL-Light for all AArch64 assembly + all x86-64 AVX2 assembly (functional correctness, constant-time at object-code level) |
| **Maintained by** | Post-Quantum Cryptography Alliance (PQCA); core contributors from AWS and Arm |

**Cross-compilation:**
- Backends: C90 generic fallback, AArch64 + Neon, x86-64 + AVX2, Armv8.1-M MVE (experimental).
- No `-march=native` hardcoding. Backends are selected at compile time via preprocessor symbols, not CMake arch detection.
- No issues reported on iOS, watchOS, Windows. QEMU cross-compile testing in CI.
- Embedded-capable: no dynamic allocation required in the core; external RNG hook supported.

**Notes:** Already integrated into liboqs 0.15.0 and AWS-LC. The single best standalone ML-KEM source.

---

### 2. mldsa-native

| Field | Value |
|---|---|
| **GitHub** | https://github.com/pq-code-package/mldsa-native |
| **License** | Apache-2.0 OR MIT OR ISC |
| **Language** | C90 |
| **Latest release** | v1.0.0-beta (March 2026) — not yet stable API |
| **Algorithms** | ML-DSA-44, ML-DSA-65, ML-DSA-87 (all FIPS 204 parameter sets) |
| **Build system** | Makefile (dev/CI only); embed `mldsa/` directory |
| **Formal verification** | CBMC (all C), HOL-Light (select AArch64 functions), Isabelle/HOL (scalar decomposition routines) |
| **Maintained by** | PQCA; same team as mlkem-native |

**Cross-compilation:** Same architecture as mlkem-native — C90 baseline, no hardcoded `-march` flags, no known iOS/watchOS issues. AArch64 Neon and x86-64 AVX2 backends activate via preprocessor.

**Notes:** AWS is actively integrating it into AWS-LC. The beta designation refers to API stability, not security quality. Expect v1.0.0 stable within a few months.

---

### 3. slhdsa-c

| Field | Value |
|---|---|
| **GitHub** | https://github.com/pq-code-package/slhdsa-c |
| **License** | MIT OR Apache-2.0 |
| **Language** | C90, pure C, no assembly |
| **Latest release** | No versioned releases yet |
| **Algorithms** | All 12 FIPS 205 parameter sets (SHA2 and SHAKE variants, both `s` and `f` speed/size modes), including prehash modes |
| **Build system** | Makefile, no external dependencies (SHA-2 and SHAKE included) |
| **Formal verification** | CBMC for memory-safety; no assembly to verify |
| **Maintained by** | PQCA (donated by Markku-Juhani Saarinen from the SLotH project) |

**Cross-compilation:** Pure C90, no detected `-march`/`-mcpu` flags. Passes all 1,248 NIST ACVP test vectors. Works on any platform that can compile C90.

**Notes:** Not yet production-recommended by its maintainers. This is the same source integrated into liboqs 0.15.0. For production SLH-DSA today, consuming through wolfSSL 5.9 or OpenSSL 3.5 is more validated.

---

### 4. pornin/c-fn-dsa (FN-DSA / Falcon)

| Field | Value |
|---|---|
| **GitHub** | https://github.com/pornin/c-fn-dsa |
| **License** | Unlicense (public domain) |
| **Language** | C |
| **Latest release** | No versioned releases. Pre-v1.0 — API may change. |
| **Algorithms** | FN-DSA-512 (Falcon-512), FN-DSA-1024 (Falcon-1024) — both FIPS 206 draft parameter sets |
| **Build system** | Makefile; separate `Makefile.cm4` for ARM Cortex-M4F, `Makefile.win32` |
| **Formal verification** | None |
| **Maintained by** | Thomas Pornin (Falcon co-author) |

**Cross-compilation:** Supports Unix-like, Windows, ARM Cortex-M4F. Portable C, no detected hardcoded `-march`/`-mcpu`. "Bare metal" builds require an external seed source.

**Notes:** Most authoritative portable C for FN-DSA — from the algorithm's co-author. Do not depend on it in production until FIPS 206 is finalized (expected late 2026/early 2027). The formally verified path is `pq-code-package/rust-libcrux` (Rust, F* proofs via hax), but there is no equivalently verified C FN-DSA implementation yet.

---

### 5. liboqs 0.15.0

| Field | Value |
|---|---|
| **GitHub** | https://github.com/open-quantum-safe/liboqs |
| **License** | MIT |
| **Language** | C (with algorithm-specific assembly) |
| **Latest release** | 0.15.0 (November 14, 2025) |
| **Algorithms** | ML-KEM-512/768/1024, ML-DSA-44/65/87, SLH-DSA (all 12 variants), Falcon-512/1024/padded, plus 35 KEMs and 77 sig variants total |
| **Build system** | CMake (required) + Ninja |
| **Formal verification** | ML-KEM inherits mlkem-native proofs; ML-DSA and SLH-DSA — test vectors only; Falcon — test vectors only |
| **Maintained by** | PQCA / Open Quantum Safe project |

**Key algorithm changes in 0.15.0:**
- ML-KEM backend migrated to **mlkem-native v1.0.0**
- SLH-DSA integrated from **slhdsa-c** (replaces SPHINCS+; SPHINCS+ will be removed in 0.16.0)
- **Dilithium removed**
- **armel (ARM 32-bit LE) platform removed**
- NTRU variants restored

**Cross-compilation issues:**
- CMake reads `CMAKE_SYSTEM_PROCESSOR` (always the host CPU on macOS cross-compile) to set `ARCH_ARM64v8` etc., then hardcodes `-march=armv8-a+crypto` based on that. Building a universal binary (`arm64;x86_64`) requires building each arch separately and merging with `lipo` — it cannot be done in a single CMake invocation.
- iOS, watchOS: not documented as supported platforms. `armel` was actively removed.
- Known issue: [#2029](https://github.com/open-quantum-safe/liboqs/issues/2029) — CMake settings not suitable for cross-compilation.
- "Argument list too long" linker error on macOS when all algorithms enabled (workaround: disable unused algorithms).
- Requires OpenSSL 3.x as a build dependency for some algorithms.

**Disclaimer from the project itself:** "WE DO NOT CURRENTLY RECOMMEND RELYING ON THIS LIBRARY IN A PRODUCTION ENVIRONMENT."

**Notes:** The bundled mlkem-native and slhdsa-c are the same sources as the standalone repos. liboqs adds build complexity, cross-compile friction, and OpenSSL dependency. For a focused integration, the individual PQ Code Package libraries are cleaner.

---

### 6. OpenSSL 3.5

| Field | Value |
|---|---|
| **GitHub** | https://github.com/openssl/openssl |
| **License** | Apache 2.0 |
| **Language** | C |
| **Latest release** | 3.5.0 (April 8, 2025) — LTS until 2030 |
| **Algorithms** | ML-KEM-512/768/1024, ML-DSA-44/65/87, SLH-DSA (all 12 variants, FIPS 205). **No FN-DSA.** |
| **Build system** | Custom `Configure` + Makefile (Perl); no native CMake |
| **Formal verification** | None for PQC implementations |
| **Maintained by** | OpenSSL Foundation |

**Cross-compilation:** Mature cross-compile support via `Configure` targets. For Apple platforms, third-party projects (e.g., `apotocki/openssl-iosx`) build XCFrameworks covering iOS, watchOS, tvOS, visionOS, macOS. The PQC code is portable C within the EVP framework.

**Notes:** Best choice if you already link OpenSSL. Overkill as a standalone PQC dependency. PQC available natively in the default and FIPS providers — no oqs-provider plugin required.

---

### 7. wolfSSL 5.9

| Field | Value |
|---|---|
| **GitHub** | https://github.com/wolfSSL/wolfssl |
| **License** | GPLv2 (commercial license available) |
| **Language** | C |
| **Latest release** | 5.9.0 (March 23, 2026); 5.9.1 followed with security/bug fixes |
| **Algorithms** | ML-KEM-512/768/1024 (enabled by default), ML-DSA-44/65/87, SLH-DSA (FIPS 205), Falcon (pre-standard) |
| **Build system** | Autotools + CMake |
| **Formal verification** | None |
| **Maintained by** | wolfSSL Inc. |

**Cross-compilation:** Designed for embedded portability from inception. Explicit support: iOS, watchOS (watchOS target tested — a watchOS-specific security bug was fixed in 5.8.2, demonstrating active watchOS CI), ARM Cortex-M (fault injection hardening for ML-KEM/ML-DSA in 5.9.0), Zephyr RTOS 4.1+, Renesas, STM32. `WOLFSSL_NO_MALLOC` build works with ML-KEM and ML-DSA (improved 5.9.0).

**Notes:** Best choice for embedded targets (Cortex-M, RTOS, watchOS) and for applications needing FIPS 140-3 with PQC (certification in progress for ML-DSA and SLH-DSA). The GPLv2 license requires a commercial license for closed-source use.

---

### 8. AWS-LC

| Field | Value |
|---|---|
| **GitHub** | https://github.com/aws/aws-lc |
| **License** | Apache 2.0 + ISC + OpenSSL (mixed) |
| **Language** | C/C++ (BoringSSL fork) |
| **Latest release** | Continuous; FIPS 140-3 validated (#4631, #4759, #4816) — first open-source module with ML-KEM in FIPS 140-3 |
| **Algorithms** | ML-KEM-512/768/1024, ML-DSA-44/65/87. SLH-DSA and FN-DSA not confirmed. |
| **Build system** | CMake 3.0+ (also requires Go 1.20+, Perl, NASM on Windows) |
| **Formal verification** | ML-KEM inherits mlkem-native proofs; rest — none |
| **Maintained by** | AWS Cryptography team |

**Cross-compilation:** iOS via `-DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_OSX_ARCHITECTURES=<arch>`. Android via NDK toolchain. ARM CPU capabilities use compile-time ACLE symbols (not `-march=native`). Windows ARM64 assembly requires ClangCL. `-DOPENSSL_SMALL=1` for size-constrained builds.

**Notes:** Production-quality, FIPS 140-3 validated. Heavier than standalone PQ Code Package libs (full TLS/crypto stack).

---

### 9. Apple CryptoKit

| Field | Value |
|---|---|
| **Documentation** | https://developer.apple.com/documentation/cryptokit |
| **License** | Proprietary (Apple OS; Swift Crypto is open-source) |
| **Language** | Swift / closed-source C |
| **PQC availability** | iOS 26 / macOS 26 / watchOS 26 (WWDC 2025) |
| **Algorithms** | ML-KEM-768, ML-KEM-1024, ML-DSA-65, ML-DSA-87, X-Wing hybrid KEM, PQ HPKE |

**Notes:** ML-KEM and ML-DSA were available internally in iMessage since iOS 17.4 (PQ3 protocol), but the public CryptoKit API was only announced at WWDC 2025 for the iOS 26 / macOS 26 / watchOS 26 releases. Swift-only — not directly callable from C. Server-side via Swift Crypto (open-source). Not useful for `virgil-crypto-c` (C library), but relevant for upper-layer Swift wrappers.

---

### 10. mbedTLS (current status)

No PQC in any released version as of April 2026.

**Roadmap (official):**
- ML-DSA: investigation Q4 2025 → prototype Q1 2026 → initial support Q2 2026
- ML-KEM: "Future" — no timeline
- SLH-DSA, FN-DSA: not on roadmap

mbedTLS 3.6.x LTS (used in this project) has no PQC. Not viable as a PQC source until at least Q3 2026, and even then only ML-DSA.

---

### 11. PQClean

**Status: BEING ARCHIVED. Will become read-only July 2026.**

Covers ML-KEM, ML-DSA, SLH-DSA, FN-DSA (Falcon-512, Falcon-1024), HQC, Classic McEliece, and more. Extremely portable portable C, no hardcoded `-march` flags, no external dependencies. No formal verification.

The retirement was announced on the NIST PQC Forum in January 2026. Libraries depending on PQClean (including liboqs's Falcon source and the Rust `pqcrypto` crate) must migrate. The PQ Code Package is the recommended successor.

**Do not take new dependencies on PQClean.**

---

## Cross-Compilation Portability Summary

| Library | macOS universal (arm64+x86_64) | iOS | watchOS (armv7k, arm64_32) | Linux aarch64 | Windows x64 | `-march`/`-mcpu` hazards |
|---|---|---|---|---|---|---|
| **mlkem-native** | Yes (C90 backend) | Yes | Likely yes (C90 fallback) | Yes (Neon backend) | Yes | None — preprocessor-selected backends, no `-march=native` |
| **mldsa-native** | Yes | Yes | Likely yes | Yes | Yes | Same as mlkem-native |
| **slhdsa-c** | Yes | Yes | Yes | Yes | Yes | None — pure C, no assembly |
| **pornin/c-fn-dsa** | Likely | Likely | Likely (C baseline) | Yes | Yes | None documented |
| **liboqs 0.15.0** | Partial (per-arch + lipo required) | Not documented | Not documented; armel removed | Extended testing only | Yes | Yes — CMake reads host processor, not target ([#2029](https://github.com/open-quantum-safe/liboqs/issues/2029)) |
| **OpenSSL 3.5** | Yes (via third-party XCFramework builder) | Yes | Yes | Yes | Yes | None in PQC code |
| **wolfSSL 5.9** | Yes | Yes | **Yes (actively tested)** | Yes | Yes | None for PQC |
| **AWS-LC** | Yes | Yes | Not explicitly documented | Yes | Yes (ClangCL for ARM64 asm) | ACLE macros, not `-march=native` |
| **Apple CryptoKit** | macOS only | iOS 26+ | watchOS 26+ | — | — | N/A (closed-source) |
| **mbedTLS** | Yes (no PQC yet) | Yes (no PQC yet) | Yes (no PQC yet) | Yes | Yes | N/A |
| **PQClean** | Yes | Yes | Yes | Yes | Yes | None in reference impls (**archiving July 2026**) |

---

## Formal Verification Summary

| Library | Method | Coverage |
|---|---|---|
| **mlkem-native v1.0.0** | CBMC + HOL-Light | Memory-safety + type-safety (all C); functional correctness + constant-time at object level (all AArch64 asm + all AVX2 asm) — **strongest available** |
| **mldsa-native v1.0.0-beta** | CBMC + HOL-Light + Isabelle/HOL | Memory-safety (all C); partial assembly correctness; scalar decomposition |
| **slhdsa-c** | CBMC | Memory-safety only; no assembly |
| **liboqs ML-KEM** | Inherits mlkem-native | Same as mlkem-native for ML-KEM |
| **liboqs ML-DSA / SLH-DSA / Falcon** | None | ACVP test vectors only |
| **OpenSSL 3.5 PQC** | None | Test vectors only |
| **wolfSSL PQC** | None | Test vectors only |
| **AWS-LC ML-KEM** | Inherits mlkem-native | Same as mlkem-native (integration in progress) |
| **Apple CryptoKit** | Undisclosed ("formally verified as equivalent to FIPS 203/204") | No public proof artifacts |
| **pornin/c-fn-dsa** | None | — |
| **rust-libcrux (Rust)** | F* via hax toolchain | Panic-freedom, correctness, secret-independence (ML-KEM + FN-DSA) |

---

## Maintenance Status

| Library | Last Release | Status |
|---|---|---|
| mlkem-native | v1.0.0, June 2025 | Active, production-stable |
| mldsa-native | v1.0.0-beta, March 2026 | Active, API not yet stable |
| slhdsa-c | No versioned releases | Active, not production-recommended |
| pornin/c-fn-dsa | No versioned releases | Active, pre-standard (FIPS 206 not final) |
| liboqs | 0.15.0, Nov 2025 | Active; own "not production" disclaimer |
| PQClean | ~2023 | **Archiving July 2026** |
| OpenSSL 3.5 | 3.5.0, Apr 2025 | Active LTS until 2030 |
| wolfSSL | 5.9.0, Mar 2026 | Very active |
| AWS-LC | Continuous | Very active, FIPS 140-3 validated |
| mbedTLS | 3.6.5 LTS | Active; PQC planned Q2–Q3 2026 at earliest |

---

## Falcon: Current thirdparty vs Available Versions

### What we currently use

`thirdparty/falcon` fetches `falcon-20190918.tar.gz` from `https://falcon-sign.info/` (SHA256: `229fca9b3116ca3ff1f0952227419fc8b2ce11ce0be74a6e92a3837bacda19a2`).

This is the **2019-09-18 reference implementation** — the Round 2 submission era code.

### What's available on falcon-sign.info

| Archive | Date | Notes |
|---|---|---|
| `falcon-20190918.tar.gz` | Sep 18, 2019 | **Currently used.** Round 2 era. |
| `Falcon-impl-20211101.zip` | Nov 1, 2021 | Latest reference implementation. Round 3 final submission era. Same file set (~782 KB), only `falcon.c` has a Nov 2021 timestamp. |
| `falcon-round3.zip` | — | Round 3 submission package (4 MB) — includes test vectors, spec, multiple implementations; not a drop-in source tarball. |

### API changes between 2019 and 2021 (breaking)

The `Falcon-impl-20211101` version introduces a **breaking API change** to all sign and verify functions:

**Old (2019) API:**
```c
int falcon_sign_dyn(shake256_context *rng,
    void *sig, size_t *sig_len,
    const void *sk, size_t sk_len,
    const void *data, size_t data_len,
    int ct,               // 0 = compressed/vartime, 1 = CT fixed-size
    void *tmp, size_t tmp_len);

int falcon_verify(const void *sig, size_t sig_len,
    const void *pk, size_t pk_len,
    const void *data, size_t data_len,
    void *tmp, size_t tmp_len);
```

**New (2021) API:**
```c
int falcon_sign_dyn(shake256_context *rng,
    void *sig, size_t *sig_len, int sig_type,   // explicit type enum
    const void *sk, size_t sk_len,
    const void *data, size_t data_len,
    void *tmp, size_t tmp_len);

int falcon_verify(const void *sig, size_t sig_len, int sig_type,  // new param
    const void *pk, size_t pk_len,
    const void *data, size_t data_len,
    void *tmp, size_t tmp_len);
```

New `sig_type` constants:
```c
#define FALCON_SIG_COMPRESSED  1   // variable-size (was ct=0)
#define FALCON_SIG_PADDED      2   // NEW: fixed-size padded (shorter than CT)
#define FALCON_SIG_CT          3   // constant-time fixed-size (was ct=1)
```

Also new in 2021: `FALCON_SIG_PADDED_SIZE(logn)` macro — smaller than CT (e.g., 666 bytes vs 809 for Falcon-512).

### How vscf_falcon.c calls the API today

`library/foundation/src/vscf_falcon.c` calls:

- `falcon_sign_dyn(..., ct=1, ...)` — uses CT format (809 bytes for Falcon-512)
- Returns `FALCON_SIG_CT_SIZE(logn)` = 809 bytes from `signature_len()`
- `falcon_verify(...)` — no `sig_type` arg (old API infers from signature header byte)

**The `ct=1` value coincides with `FALCON_SIG_COMPRESSED = 1` in the new API** — so upgrading to the 2021 tarball without changing the call site would silently produce compressed (variable-size) signatures instead of CT signatures. This would be a silent behavioral regression, not a compile error.

### Wire format compatibility

- The **2019 → 2021** change does **not** alter the Falcon Round 3 wire format. CT signatures produced by the 2019 code are verifiable by the 2021 code (and vice versa), provided `sig_type` is correctly specified or auto-detected from the header byte.
- The **FIPS 206 draft** (`pornin/c-fn-dsa`) uses a **different wire format** — keys and signatures from the Round 3 reference implementation are not compatible with the FIPS 206 draft. This is the "private key format break" described in the migration plan.

### Comparison: our Falcon vs liboqs Falcon

| Aspect | `thirdparty/falcon` (ours) | liboqs 0.15.0 Falcon |
|---|---|---|
| Source | falcon-sign.info `falcon-20190918.tar.gz` | PQClean `falcon-512` / `falcon-1024` |
| Spec version | Round 3 Falcon (same as NIST submission) | Round 3 Falcon |
| Wire format | Round 3 — same | Round 3 — same |
| FIPS 206 compliant | No (FIPS 206 not final) | No |
| Assembly optimizations | None (pure C) | AVX2 (x86-64), AArch64 — from PQClean |
| Cross-compile issues | None — pure C, no `-march` flags | PQClean AVX2 backend may trip cross-compile guards |
| Custom SHAKE256 patch | Yes (`falcon_shake256_*` prefix to avoid Round5 collision) | No patch needed (separate namespacing) |
| PQClean dependency | No | Yes — archiving July 2026 |
| `FALCON_SIG_PADDED` format | No (2019 API) | Available (PQClean exposes padded format) |
| Age of source | 2019 (Round 2 era) | PQClean snapshot, ~2022 |

### Recommendation

**Keep `thirdparty/falcon` as-is for now.** FIPS 206 is not final (expected late 2026). The Round 3 format produced by our 2019 code is wire-compatible with all other Round 3 implementations.

**Option: upgrade to `Falcon-impl-20211101`** — this is a low-risk, small patch. Benefits: cleaner API (named `sig_type` constants, `FALCON_SIG_PADDED` available), 2 years more maintenance, same wire format. Required change in `vscf_falcon.c`:
- Replace `ct=1` with `FALCON_SIG_CT` (=3) in `falcon_sign_dyn()` call
- Add `sig_type` parameter (`FALCON_SIG_CT`) to `falcon_verify()` call (or pass `0` for auto-detection)
- Update `CMakeLists.txt` URL and SHA256

This is a **6-line code change** with **no wire format or key format change**.

**Do not migrate to liboqs's Falcon** — it pulls in PQClean (archiving July 2026) and adds assembly backends that complicate cross-compilation, with no wire format benefit.

---

## Recommendations for virgil-crypto-c

### Short term (use liboqs as today)

Continue using liboqs 0.15.0. The universal macOS and Python CI cross-compile issues are now fixed in this project by building liboqs per-arch (arm64 + x86_64 separately, then lipo-merged). The `CMAKE_INSTALL_LIBDIR` transitive leak and `BUILD_BYPRODUCTS` naming bugs are fixed. The remaining known gap is watchOS (PQ disabled entirely as a conservative measure).

### Medium term: replace liboqs with direct PQ Code Package deps

For a cleaner build, especially to resolve watchOS PQ support and reduce build complexity:

| Goal | Library | Readiness |
|---|---|---|
| ML-KEM | **mlkem-native v1.0.0** | Production-stable now |
| ML-DSA | **mldsa-native** | Ready on API-stability-is-acceptable terms; v1.0.0 stable likely within months |
| SLH-DSA | **slhdsa-c** or wolfSSL/OpenSSL | Source-level not production-recommended; use through a wrapper lib |
| FN-DSA / Falcon | **pornin/c-fn-dsa** or keep existing `thirdparty/falcon` | Wait for FIPS 206 finalization (late 2026) |

Integration approach: add `mlkem/` and `mldsa/` as ExternalProject (or Git submodule) source directories. No CMake arch-detection problem — they use preprocessor-selected backends. watchOS would get the C90 fallback (no Neon) with no flags that break cross-compilation.

### For watchOS PQ support (future)

wolfSSL 5.9 is the most proven path for watchOS PQC — it actively tests watchOS targets. Alternatively, mlkem-native + mldsa-native with C90 backends should work once integrated directly (no liboqs CMake arch-detection in the path).

### For FN-DSA: wait

FIPS 206 is not final. Keep the existing `thirdparty/falcon` (cleaner than liboqs's PQClean-sourced Falcon) until the standard is published and a production-ready implementation exists. PQClean archiving in July 2026 does not affect the existing `thirdparty/falcon` — it fetches from falcon-sign.info directly.

---

## Sources

- [mlkem-native](https://github.com/pq-code-package/mlkem-native) — PQCA mlkem-native
- [mldsa-native](https://github.com/pq-code-package/mldsa-native) — PQCA mldsa-native
- [PQCA blog: mlkem-native v1.0.0](https://pqca.org/blog/2025/first-stable-release-of-mlkem-native-v1-under-pq-code-package-project/)
- [PQCA blog: mldsa-native alpha](https://pqca.org/blog/2025/pqca-announces-alpha-release-of-mldsa-native/)
- [slhdsa-c](https://github.com/pq-code-package/slhdsa-c)
- [liboqs 0.15.0 release](https://github.com/open-quantum-safe/liboqs/releases/tag/0.15.0)
- [liboqs cross-compile issue #2029](https://github.com/open-quantum-safe/liboqs/issues/2029)
- [OpenSSL 3.5.0 release](https://openssl-library.org/post/2025-04-08-openssl-35-final-release/)
- [wolfSSL 5.9.0 release](https://www.wolfssl.com/wolfssl-5-9-0-released/)
- [wolfCrypt FIPS 140-3 with PQC](https://www.wolfssl.com/wolfcrypt-fips-140-3-with-post-quantum-cryptography-available-now/)
- [AWS-LC FIPS 3.0 ML-KEM validation](https://aws.amazon.com/blogs/security/aws-lc-fips-3-0-first-cryptographic-library-to-include-ml-kem-in-fips-140-3-validation/)
- [Apple WWDC25 Session 314: Quantum-secure cryptography](https://developer.apple.com/videos/play/wwdc2025/314/)
- [mbedTLS roadmap](https://mbed-tls.readthedocs.io/en/latest/project/roadmap/)
- [pornin/c-fn-dsa](https://github.com/pornin/c-fn-dsa)
- [PQClean retirement announcement](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/Z30-l8mTNRU)
- [rust-libcrux (formally verified Rust)](https://github.com/pq-code-package/rust-libcrux)
