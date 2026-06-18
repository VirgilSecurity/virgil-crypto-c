# Shamir Secret Sharing (k-of-n) — Requirements

**Date:** 2026-06-18
**Status:** Requirements captured — ready for `/ce:plan`
**Type:** New `foundation` algorithm class; vendors only the GF(256) share math from `dsprenkels/sss`, builds the authenticated envelope on the in-tree mbedTLS.

## Problem & Value

`virgil-crypto-c` has no threshold secret-sharing primitive. Consumers who want to split a
symmetric (data-encryption) key so it can only be reconstructed when a quorum of holders cooperate
have nothing to call. The motivating case is **2-of-3**: a key split among three custodians where
any two reconstruct it (one can be lost without losing the key; no single holder can recover it).

This is built **proactively** — there is no specific blocked downstream consumer today. The
opportunity cost is acknowledged: see *Strategic Notes*. We add a Shamir Secret Sharing class to
the `foundation` library and surface it through the normal codegen pipeline so it lands in all six
language wrappers (Python, Java/Android, Go, PHP, WASM, Swift).

## Architecture (decided)

Use the **split-key-encrypt-data** construction, built on primitives already in the tree:

1. Generate a random **32-byte data key (DK)** from virgil's `random` interface.
2. Encrypt the (arbitrary-length) secret with DK using an **mbedTLS AEAD** (encrypt-then-MAC;
   ChaCha20-Poly1305 or AES-256-GCM — chosen in planning) → nonce + ciphertext + auth tag.
3. **Shamir-split only the 32-byte DK** into `n` key-shares with threshold `k`, using the
   vendored constant-time GF(256) routines from `dsprenkels/sss`'s `hazmat.c`.
4. Reconstruct: combine `k` key-shares → DK → AEAD-decrypt the ciphertext. A wrong/insufficient
   set yields a wrong DK → **AEAD tag verification fails → clean error** (this is the integrity
   mechanism; `hazmat` itself provides no integrity).

This means: **no TweetNaCl** (mbedTLS already ships the AEAD), **no patched fork** of upstream
(we call `vscf_random` directly in our own C — the bundled `randombytes` seam never enters the
build), and **no fixed-size limit** on the secret (the AEAD handles any length; only the 32-byte
DK goes through Shamir).

## Goals

- Split an **arbitrary-length** symmetric secret into `n` shares, reconstructable from any `k`
  (general k-of-n, runtime params, `1 ≤ k ≤ n ≤ 255`). 2-of-3 is the primary case, not special-cased.
- Reconstruct the secret from any `k` valid shares.
- **Authenticated**: wrong, tampered, or insufficient shares fail cleanly (AEAD tag), never return
  garbage.
- Expose the primitive idiomatically: a `foundation` class with a `random` dependency, available in
  every generated wrapper, with **byte-for-byte interoperable** shares across wrappers.
- Match existing foundation conventions for memory management, error handling, codegen, and RNG.

## Non-Goals

- **No** key-management, escrow protocol, or share-distribution transport.
- **No** public exposure of the unauthenticated raw `hazmat` key-share API.
- **No** wrapper-specific share encoding/framing — shares are raw bytes; cross-wrapper interop is a
  hard requirement (a share produced by one wrapper must combine in another).

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Scheme | General **k-of-n** (1–255), runtime `n`/`k` | Native to the share math; 2-of-3 is one call. |
| Construction | **Split-key-encrypt-data** on mbedTLS AEAD | Integrity + arbitrary length for free; reuses maintained, LTS-tracked crypto. |
| Vendoring | **`hazmat.c` + `hazmat.h` only** (constant-time GF(256) split of a 32-byte key) | Smallest trusted surface (~150 lines); avoids a second crypto core and CVE-ownership of a pre-1.0 lib. |
| Secret size | **Variable length**, handled internally | The secret is AEAD-encrypted; only the random 32-byte DK is Shamir-split. No caller padding, no interop hazard. |
| Integrity | **AEAD tag** over the ciphertext | Wrong reconstructed DK ⇒ tag fails ⇒ clean error. |
| RNG | `random` dependency + `setup_defaults` provisioning a `ctr_drbg` | Matches `vscf_signer`/`vscf_ed25519` convention; real-RNG testable; called directly (no source fork). |

## Behavioral Requirements

Working class name **`shamir`** → `vscf_shamir` (final name decided in planning; candidates:
`shamir`, `secret_sharing`).

1. **Split** — given an arbitrary-length secret, total shares `n`, threshold `k`, produce `n`
   shares. Requires a configured `random` (injected via `use_random`/`take_random`, or provisioned
   by `setup_defaults`).
2. **Combine** — given `k` shares, reconstruct the secret, returning a status distinguishing
   success from failure.

**Validation / edge cases (all must have a regression test — fails before fix, passes after, per
`CLAUDE.md`):**
- `1 ≤ k ≤ n ≤ 255`; reject out-of-range or `k > n`.
- Combine with **fewer than k** shares → error (no partial/garbage output).
- Combine with **wrong or tampered** shares → error (AEAD tag), never silent garbage.
- Combine with duplicate / colliding share indices → error.
- Combine with any valid k-subset of the n shares, in any order → original secret.
- Round-trip across wrappers: a share from one language combines in another (byte interop).

**Security requirements:**
- DK and all intermediate key material zeroized with `vscf_erase` (the optimization-resistant
  variant), not plain `memset` — including on every error path.
- Combine **zeroizes the output buffer** before returning a failure status, so callers that ignore
  the return code receive zeroed bytes, not partial key material.
- Preserve upstream's **constant-time GF(256)** arithmetic in `hazmat.c` — do not "optimize" it; if
  any byte comparison on share data is needed, use the foundation constant-time comparator
  (`vscf_memory_secure_equal` / equivalent), never `memcmp`.
- AEAD nonce handling must be safe given DK is fresh-random per split (document the nonce policy:
  random nonce, or fixed nonce justified by single-use DK).
- `n`/`k` are public (not constant-time); document this. DK and the secret are not.

## Implementation Surface (for planning)

- **Vendoring:** `thirdparty/sss/` containing only `hazmat.c`, `hazmat.h`, the MIT `LICENSE`, and a
  short `VERSION`/provenance note pinning the **exact upstream commit**. Preserve the MIT notice in
  the repo's third-party license records.
- **Build wiring:** prefer **compiling the two `hazmat` sources directly into the `foundation`
  target** (only two files) so no new static-lib link entry is needed — this avoids touching the Go
  `cgo_link` lib list and shipping a new prebuilt `.a`. If a standalone target is chosen instead,
  follow the established `codegen/models/external/library_*.xml` pattern (which generates
  `thirdparty/<lib>/features.cmake` + `CMakeLists.txt`) rather than hand-rolling CMake, and add the
  `-l<lib>` entry to all four `cgo_link` directives. Rename/scope any exported `hazmat` symbols
  (e.g. prefix) to avoid collisions.
- **Codegen model:** author `codegen/models/project_foundation/class_shamir.xml`, register it in
  `project_foundation.xml`, run `python3 -m tools.codegen.common_bootstrap --project foundation
  --apply`, then hand-write the C method bodies in `library/foundation/src/vscf_shamir.c` (inside
  `@generated … @end` markers). Use `vscf_signer` (a `<class>` carrying a `random` dependency) as
  the structural precedent — not `vscf_ed25519`, which is modeled as an `<implementor>`.
- **CMake:** `option(VSCF_SHAMIR …)` in `library/foundation/features.cmake`, regenerated
  `sources.cmake`, link mbedTLS (already linked) and the `hazmat` sources in
  `library/foundation/CMakeLists.txt`.
- **Share representation (resolved):** the codegen IR has **no variable-count-of-buffers** type, so
  split writes the `n` equal-length shares into a **single concatenated `n × share_size` buffer**
  (with a `split_share_count` / size helper), and combine takes a single concatenated `k × share_size`
  buffer plus an explicit `k` count. This is the only shape the existing single-buffer convention
  can express across all six wrappers. Each share = key-share ‖ AEAD nonce ‖ tag ‖ ciphertext
  (self-contained), unless planning chooses the leaner "key-shares + one shared ciphertext blob"
  layout (see Open Questions). Use a named `share_size` constant, never a literal.

## Open Questions / Risks (resolve in planning)

1. **Share layout — self-contained vs. shared ciphertext.** Self-contained shares (each embeds the
   full ciphertext) are simplest to store/transport but duplicate the ciphertext `n` times — costly
   for large secrets. The alternative returns `n` fixed-size 33-byte key-shares plus one ciphertext
   blob; combine takes `k` key-shares + the blob. Decide based on expected secret sizes and the
   wrapper API ergonomics of returning two outputs.
2. **AEAD choice** (ChaCha20-Poly1305 vs. AES-256-GCM) and nonce policy.
3. **Final class name** (`shamir` vs. `secret_sharing`).
4. **Spike the share representation** in the two hardest wrappers (WASM and PHP) before committing
   the full six-wrapper scope — the concatenated-buffer shape is believed expressible but unproven
   end-to-end.

## Strategic Notes

- Built proactively with no cited consumer. If the real need turns out to be splitting **arbitrary
  payloads at rest** (not just keys), this construction already supports it — but confirm demand
  before broadening the public surface.
- Once shares are published through six wrappers and stored/transported by consumers, the share
  **byte layout is effectively frozen**. Version the layout (a leading format/version byte) so a
  future change is detectable rather than silently mis-parsed.

## Success Criteria

- 2-of-3 round-trip works end-to-end in the C tests **and all six generated wrapper builds pass**;
  round-trip verified in **≥2 wrapper languages** (one statically typed — Go or Java — and one
  dynamically typed — Python).
- General k-of-n verified across representative `(n, k)` combinations.
- Tamper / insufficient-share / duplicate-index failures are detected and surfaced as errors,
  with the output buffer zeroized on failure.
- Cross-wrapper byte interop verified (share from one wrapper combines in another).
- A regression test for each edge case above is committed with the implementation.
- C build + `ctest` pass; codegen pytest passes; affected wrapper builds/tests pass before any push.
- MIT license + pinned upstream commit of the vendored `hazmat` recorded in third-party notices.
