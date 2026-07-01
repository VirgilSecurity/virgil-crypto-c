# AES-256-SIV (Deterministic AEAD) — Requirements

**Date:** 2026-06-30
**Status:** Draft — open decisions to resolve before planning (see review findings)
**Scope:** Standard (new foundation algorithm + codegen wiring + wrapper propagation)

## Problem & Goal

Add a **dedicated deterministic-encryption API** to the `foundation` library, with **AES-256-SIV**
(RFC 5297, Synthetic Initialization Vector) as its first algorithm. The driving use case is
**deterministic encryption**: callers need ciphertext that is a deterministic function of
`(key, associated data, plaintext)`, so that equal inputs produce equal ciphertext (e.g. for
indexable/searchable encrypted values or deduplication), while still getting authentication.

AES-SIV is the chosen first primitive because it is nonce-misuse-resistant by design and supports a
vector of associated-data inputs, which lets callers domain-separate the determinism (per field, per
tenant, etc.).

### Why a dedicated API, not the generic CMS/envelope path

The library's crypto agility lives in the **CMS envelope**: `recipient_cipher` / `ecies` / `pbes2`
emit a self-describing message whose `AlgorithmIdentifier`/OID tells the decryptor which algorithm was
used. That path is **probabilistic and enveloped**. Deterministic encryption is the opposite shape —
its output is a **bare ciphertext** (a searchable token, a dedup key) with **no envelope**: the CMS is
empty. Three consequences shape this design:

1. **Out of the envelope path.** A deterministic cipher must **not** be reachable through the generic
   envelope-cipher factory consumed by `recipient_cipher`/`ecies`/`pbes2` — those produce agile,
   probabilistic, self-describing messages, the wrong home for a deterministic primitive. SIV lives
   behind a dedicated API that emits raw `(synthetic-IV, ciphertext)`.
2. **Agility is application-owned, out-of-band.** A bare deterministic ciphertext does **not**
   self-describe (no embedded OID), so the caller must track which algorithm + key + params produced a
   given value in schema/column metadata. The API docs must state this, because a future rotation
   (e.g. AES-SIV → AES-GCM-SIV) has no in-band migration handle.
3. **Agility at the API layer.** Since agility can't live in an empty CMS, the dedicated API is
   **algorithm-agnostic** (selectable), with AES-256-SIV as the first implementation and room to add
   other deterministic AEADs later without a second API.

## Users & Value

- **Downstream SDK / application code** that needs deterministic, authenticated encryption and currently
  has no safe option in `foundation` (AES-256-GCM is non-deterministic and catastrophically fails under
  nonce reuse).
- Value: a misuse-resistant deterministic AEAD reached through a **dedicated, algorithm-agnostic
  deterministic-encryption API** that sits *beside* the CMS/envelope path, not inside it — keeping
  deterministic use explicit at the call site (no silent determinism in enveloped flows) while leaving
  room for future deterministic algorithms.

## Decisions (resolved in brainstorm)

1. **Variant: AES-256-SIV only.** Uses RFC 5297 double-length keying: a 512-bit (64-byte) key split into
   a 256-bit S2V/CMAC key and a 256-bit AES-CTR key. Per RFC 5297 the **leftmost** 256 bits are the
   S2V/CMAC key and the **rightmost** 256 bits are the CTR key — pin this ordering, since reversing the
   halves still round-trips internally but breaks RFC 5297 conformance and all cross-library interop.
   Matches the repo convention of shipping only AES-256 variants (we ship AES-256-GCM / AES-256-CBC, not
   the 128-bit forms).
2. **Interface surface: one-shot AEAD.** The public, intended path is `auth_encrypt` / `auth_decrypt`
   plus `set_auth_data`, mirroring AES-256-GCM. SIV is inherently two-pass (the synthetic IV is computed
   over the entire plaintext before any ciphertext exists), so streaming encryption is not real.
3. **Dedicated deterministic API, excluded from the envelope path.** AES-256-SIV implements the
   `cipher_auth` interface family internally (so the algorithm is reusable and testable through the
   standard `auth_encrypt`/`auth_decrypt` abstractions), but it is reached through a **dedicated
   deterministic-encryption API** and is **excluded** from the generic cipher selection used by
   `recipient_cipher`/`ecies`/`pbes2`:
   - New `vscf_alg_id_AES256_SIV` enum entry (`enum_alg_id.xml` → generated `vscf_alg_id.h`), used by the
     deterministic API for algorithm selection (API-layer agility).
   - **Not** added as a generic case in `vscf_alg_factory_create_cipher_from_alg_id`, or otherwise made
     selectable as a data cipher for the CMS/envelope flows — those assume a probabilistic (IND-CPA)
     cipher and must reject/never receive SIV.
   - The dedicated API is **algorithm-agnostic** (selects by `alg_id`/impl) so future deterministic
     AEADs (e.g. AES-GCM-SIV) can be added without a new API.
   - *(Exact shape of the dedicated API — standalone class vs. a thin deterministic-cipher facade — is a
     planning decision; the constraint is: explicit deterministic entry point, never the envelope path.)*
4. **Skeleton is codegen-generated, not hand-written.** The class is declared in the IR models under
   `codegen/models/project_foundation/` and the entire scaffold — public header, `_defs.h`/`_defs.c`,
   `_internal.{c,h}`, the factory wiring, and the `vscf_aes256_siv.c` stub with empty method bodies — is
   produced by `tools/codegen` (`python3 -m tools.codegen.common_bootstrap --project foundation --apply`).
   The **only** hand-written code is the RFC 5297 algorithm logic (S2V + AES-CTR) filled into the
   generated method bodies. Do not author the class files from scratch.
5. **Backend.** Built on the vendored mbedTLS 3.6.5 primitives (AES core + CMAC), since mbedTLS has **no
   native AES-SIV**. See Technical Notes.

## Functional Requirements

- **FR1** — A `vscf_aes256_siv` foundation class implementing the `cipher_auth` interface family
  (`alg`, `encrypt`, `decrypt`, `cipher_info`, `cipher`, `cipher_auth_info`, `auth_encrypt`,
  `auth_decrypt`, `cipher_auth`), declared in the codegen IR alongside AES-256-GCM.
- **FR2** — `auth_encrypt(data, auth_data) → (ciphertext, tag)` and the inverse `auth_decrypt`,
  computing/verifying the synthetic IV per RFC 5297. Tag (synthetic IV) length = 16 bytes. The exact
  wire format (how the synthetic IV maps onto the `(ciphertext, tag)` split, including the tag-embedded
  `tag == NULL` path) is an **open layout decision** — see Technical Notes; conformance is verifiable
  only once it is fixed.
- **FR3** — `set_auth_data` supports associated data; the same `(key, auth_data, plaintext)` always
  yields identical ciphertext (the deterministic property), and different `auth_data` yields different
  ciphertext.
- **FR4** — Reached through the dedicated deterministic-encryption API (algorithm-agnostic, selecting
  AES-256-SIV by `alg_id`/impl), and **excluded** from the generic envelope-cipher selection in
  `recipient_cipher`/`ecies`/`pbes2` — those paths must reject or never be offered SIV (FR aligns with
  Decision 3). Output is a bare `(synthetic-IV, ciphertext)`, not a CMS envelope.
- **FR5** — Decryption fails cleanly (authentication error, no plaintext leaked) on a tampered tag,
  tampered ciphertext, or mismatched associated data.
- **FR7** — Nonce-free by construction: `cipher_info` `NONCE_LEN = 0`, and `set_nonce` (inherited from
  the `cipher` interface) must return an error or be a documented no-op. A caller-supplied nonce must
  **never** be incorporated into the SIV construction — this preserves RFC 5297 determinism and prevents
  a developer porting GCM code from silently believing they added randomness.
- **FR6** — Propagated to all language wrappers (Swift, Java/Android, Python, Go, PHP, WASM) via
  `python3 -m tools.codegen.common_bootstrap --project foundation --apply`, with the algorithm reachable
  through each wrapper's existing AEAD surface.

## Non-Goals

- AES-128-SIV (or any 128-bit variant).
- A meaningful streaming-encryption guarantee. The `cipher` interface inherited by `cipher_auth`
  **mandates** `update`/`finish`/`start_encryption`/`start_decryption` (no optional methods), so these
  must be implemented — with internal buffering that accumulates all plaintext before computing the SIV
  (matching the two-pass nature). This is a **required implementation task**, not an optional planning
  detail; `out_len(data_len)` for `update` returns 0 and all output appears at `finish`. The internal
  buffer needs a defined memory bound and failure mode for very large inputs (see judgment findings).
- Exposing a standalone public CMAC / S2V class. CMAC is used internally only (unless planning finds an
  independent need).
- Plugging SIV into the CMS/envelope flows (`recipient_cipher`/`ecies`/`pbes2`) as a selectable data
  cipher. Deterministic output is bare ciphertext; the empty-CMS, out-of-band-agility model is the whole
  point (see Problem & Goal).
- In-band algorithm/version metadata on deterministic ciphertext. Agility for deterministic values is
  the application's responsibility (track alg/key/params in schema). A new OID is **not** required for
  the bare path; add one only if a deterministic value must be embedded in a CMS `AlgorithmIdentifier`
  (open question below).

## Success Criteria

- RFC 5297 Appendix A test vectors pass for encrypt and decrypt.
- **Byte-for-byte interop** validated against at least one independent AES-256-SIV implementation
  (e.g. miscreant, a Go third-party, or BoringSSL) for both encrypt and decrypt, exercising the exact
  chosen wire format and AD encoding. (RFC 5297 vectors alone fix S2V+CTR but not the library's
  framing/AD-encoding choices — two parties can pass the vectors yet be mutually undecryptable.)
- Negative tests: tampered-ciphertext, tampered-tag, and mismatched-`auth_data` cases all return an
  authentication error with **zero plaintext** emitted (FR5).
- Boundary tests: empty-plaintext round-trip; multi-AD test with 3+ distinct `auth_data` values to
  exercise the full S2V loop; wrong-key-length (≠ 64 bytes) rejected.
- Determinism verified: identical inputs → identical ciphertext; differing `auth_data` → differing
  ciphertext.
- The algorithm is creatable by `alg_id` through the factory and exercised through the abstract
  interface in at least the C test suite, and builds/passes in the Go and Swift wrappers per the
  repo's pre-push checks.
- C build + `ctest` green; codegen pytest green.

## Security & Vulnerability Review Requirements

Planning **must** include an explicit security-review pass (e.g. `/security-review` and the `ce-review`
security personas) covering at least:

- **Side-channel / SWE weaknesses.** S2V and CMAC operate on secret key material and must be
  constant-time: no secret-dependent branches or memory-access patterns. The final tag/synthetic-IV
  comparison on decrypt must use an identified **constant-time comparator** (not `memcmp` or any
  branch-on-secret loop). Confirm such a comparator exists in the vendored mbedTLS 3.6.5 tree before
  implementation — `constant_time.h`/`mbedtls_ct_memcmp` was **not** found in a quick scan, so a
  comparator (mbedTLS internal, a `vscf` helper, or equivalent) must be selected up front. Also confirm
  mbedTLS AES is built in its constant-time/hardware mode on targets without AES-NI (incl. WASM), and
  audit the CTR keystream path and key handling for timing leaks.
- **Deterministic-leakage caveat (by design).** AES-SIV intentionally leaks equality of
  `(key, auth_data, plaintext)`: equal inputs → equal ciphertext. This is the chosen behavior for this
  use case but is a confidentiality limitation that **must be documented** on the public API and in any
  downstream guidance, so callers don't assume IND-CPA semantics. The docs must also warn that **a key
  shared across isolation domains (e.g. tenants) leaks plaintext equality across those domains** — the
  key must be unique per domain, and/or a domain-specific value must be included in `auth_data`. (Whether
  to *enforce* this structurally vs document it is a judgment finding below.)
- **Memory safety of new C code.** The RFC 5297 logic hand-written into the generated stub is the new
  attack surface. Review for buffer bounds (S2V doubling/XOR, CTR length math), integer overflow in
  length calculations, and **endianness of the GF(2^128) doubling step** (easy to get wrong across
  little/big-endian targets). All intermediate secret state — CMAC context, derived subkeys K1/K2, the
  S2V doubling accumulator, and the CTR keystream block — must be zeroized on **every** exit path,
  including error paths (use `vscf_zeroize` / secure buffers; the plan must enumerate each value and its
  cleanup path). Run the existing memory/sanitizer checks; consider a fuzz target for `auth_decrypt`.
- **Fail-closed decryption.** Verify no plaintext is emitted before authentication succeeds (FR5).
- **Key-length enforcement.** Reject keys that are not the required 64-byte double-length key.
- **MSVC / cross-platform pitfalls** for the new class (no VLAs; correct `context="public"` and
  const-length helper methods) per `docs/solutions/best-practices/codegen-class-context-and-const-length-methods-2026-06-18.md`.

> **Note on "SWE":** interpreted here as side-channel / software-weakness (CWE-class) review. If you
> meant a specific tool or checklist, flag it during planning.

## Technical Notes (for planning — not final design)

- **mbedTLS has no AES-SIV.** Confirmed against vendored mbedTLS 3.6.5
  (`thirdparty/mbedtls/patched_src/PATCH_INFO.md`). Native AEADs are GCM, CCM, ChaCha20-Poly1305, KW/KWP.
  The S2V (CMAC-based synthetic IV) + AES-CTR construction must be implemented on top of mbedTLS
  primitives.
- **Building blocks present but not enabled — symbols are absent, not just off.** mbedTLS CMAC
  (`mbedtls/cmac.h`) and AES-CTR exist in the tree, but `MBEDTLS_CMAC_C` and `MBEDTLS_CIPHER_MODE_CTR`
  appear **nowhere** in `thirdparty/mbedtls/config.h.in` *or* `thirdparty/mbedtls/features.cmake` —
  enabling them is a two-place add, not a flag flip. Note `features.cmake` is **fully generated** (header:
  "fully generated by script `cmake_files_codegen.gsl`"), so the option declarations + dependency checks
  must be added to the **generator** (`cmake_files_codegen.gsl`), not hand-edited into `features.cmake`
  (which would be reverted on the next codegen run), alongside the `#cmakedefine` lines in `config.h.in`.
  Enabling these activates code in **every** target that links mbed::crypto (foundation/phe/ratchet, all
  wrapper prebuilts, WASM) — plan to scope build/size impact and a WASM/mobile size budget.
- **Reference implementations in-repo:** AES-256-GCM (`library/foundation/src/vscf_aes256_gcm.c`,
  `.../private/vscf_aes256_gcm_defs.h`) for the AEAD/cipher_auth pattern; HMAC (`vscf_hmac.c`) for a
  stateful keyed primitive. Codegen IR lives in `codegen/models/project_foundation/`
  (`implementor_mbedtls.xml`, `enum_alg_id.xml`, `interface_cipher_auth.xml`).
- **Open question — ciphertext layout:** RFC 5297 prepends the 16-byte synthetic IV to the CTR output;
  the library's `auth_encrypt` convention (per GCM) returns ciphertext plus a separate tag. Planning
  should settle how the SIV maps onto `(ciphertext, tag)` so the format is unambiguous and interoperable.
- **Open question — OID/interop:** the bare deterministic path needs no OID (agility is application-owned
  out-of-band). Decide whether to add an `enum_oid_id.xml` entry + `vscf_oid.c` mapping *only* for the
  case where a deterministic value is embedded in a CMS `AlgorithmIdentifier`.
- **Open question — dedicated-API shape:** standalone deterministic-encryption class vs. a thin facade
  over the `cipher_auth` impl; how the algorithm-agnostic selection (`alg_id`/impl) is exposed; and the
  exclusion mechanism that keeps SIV out of `recipient_cipher`/`ecies`/`pbes2` cipher selection.

## Implementation Touch Points (summary)

| Area | Path |
|------|------|
| Codegen IR (declare class) | `codegen/models/project_foundation/implementor_mbedtls.xml` |
| Algorithm enum | `codegen/models/project_foundation/enum_alg_id.xml` |
| Dedicated deterministic API (shape TBD in planning) | new IR declaration in `codegen/models/project_foundation/` |
| Codegen engine (generates skeleton) | `tools/codegen` (`common_bootstrap --project foundation --apply`) |
| Envelope-cipher exclusion (do **not** add SIV here; ensure rejection) | `library/foundation/src/vscf_alg_factory.c`, `vscf_recipient_cipher.c`, `vscf_ecies.c`, `vscf_pkcs5_pbes2.c` |
| Generated skeleton (fill SIV logic into stub) | `library/foundation/src/vscf_aes256_siv.c` + generated `_defs.{c,h}` / `_internal.{c,h}` / public header |
| mbedTLS config — add `#cmakedefine` | `thirdparty/mbedtls/config.h.in` (vendored template, hand-edited) |
| mbedTLS feature options — add to **IR model** | `codegen/models/external/library_mbedtls.xml` (regen produces `thirdparty/mbedtls/features.cmake` via `codegen/cmake_files_codegen.gsl`; never hand-edit the generated file) |
| Tests | foundation C test suite (RFC 5297 vectors + interop + negative/multi-AD + determinism) |
| Wrapper regen | `python3 -m tools.codegen.common_bootstrap --project foundation --apply` |
