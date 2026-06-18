---
title: "feat: Add Shamir k-of-n secret sharing to foundation"
type: feat
status: active
date: 2026-06-18
deepened: 2026-06-18
origin: docs/brainstorms/shamir-secret-sharing-requirements.md
---

# feat: Add Shamir k-of-n secret sharing to foundation

## Overview

Add a `vscf_shamir` class to the `foundation` library that splits an arbitrary-length symmetric
secret into `n` shares, reconstructable from any `k` of them (general k-of-n; 2-of-3 is the primary
case). The construction is **split-key-encrypt-data**: generate a random 32-byte data key (DK),
AEAD-encrypt the secret with DK using the existing `vscf_aes256_gcm`, and Shamir-split only the
32-byte DK using the vendored constant-time GF(256) routines from `dsprenkels/sss` (`hazmat.c`).
Integrity comes from the AEAD tag plus a DK commitment. The class is surfaced through the codegen
pipeline so it lands in all six language wrappers with byte-interoperable shares.

## Problem Frame

`virgil-crypto-c` has no threshold secret-sharing primitive (see origin:
`docs/brainstorms/shamir-secret-sharing-requirements.md`). The motivating case is a 2-of-3 custodian
split of a symmetric key. Built proactively — no specific blocked consumer today; opportunity cost
acknowledged in the origin doc.

## Requirements Trace

- R1. Split an arbitrary-length secret into `n` shares; reconstruct from any `k` (`1 ≤ k ≤ n ≤ 255`).
- R2. Authenticated: wrong, tampered, insufficient, or cross-split shares fail cleanly — never garbage.
- R3. Idiomatic `foundation` class with a `random` dependency; available in all six wrappers.
- R4. Shares are raw bytes, byte-for-byte interoperable across wrappers.
- R5. Vendor only the constant-time GF(256) share math (`hazmat.c`); reuse in-tree mbedTLS for the
  AEAD and `vscf_ctr_drbg` for RNG. No TweetNaCl, no patched upstream fork.
- R6. Secret/key material zeroized on all paths; constant-time share math preserved.
- R7. Every behavioral edge case has a regression test (per `CLAUDE.md`).

## Scope Boundaries

- No key-management, escrow protocol, or share-distribution transport.
- No public exposure of the raw unauthenticated `hazmat` key-share API.
- No per-wrapper share encoding/framing — one raw byte layout for all wrappers.
- No caller-supplied DK or nonce (prevents the key/nonce-reuse footgun).
- No `alg_id` / `alg` interface / factory integration — `vscf_shamir` is a standalone class
  constructed via `vscf_shamir_new()`, not by algorithm-id lookup.

### Deferred to Separate Tasks

- **Container-split share layout** (ciphertext stored once instead of duplicated per share): future
  optimization for large payloads — see Key Technical Decisions and Open Questions.
- **ChaCha20-Poly1305 AEAD option**: foundation has no ChaCha20-Poly1305 today; adding it is its own
  effort. AES-256-GCM is used now (see decision below). Future iteration if a constant-time AEAD on
  non-AES-NI targets becomes a requirement.
- **`/ce:compound`** a solution doc once shipped (the crypto domain is undocumented in
  `docs/solutions/`).

## Context & Research

### Relevant Code and Patterns

- **Class with `random` dependency + `setup_defaults`**: use **`class_key_provider.xml`** — a *public*
  standalone class that declares `<dependency name="random" interface="random"/>` **plus**
  `<require impl="ctr drbg"/>` and a `setup defaults` method that provisions a `vscf_ctr_drbg`. Prefer
  this over `class_group_session.xml`, which is `context="internal"` (`scope="private"`) and would lead
  an implementer to copy the wrong context attributes. `vscf_signer` (`class_signer.xml`) is the model
  for the `*_len` + buffer-output method pairing but has no `setup_defaults`.
- **Buffer-output convention**: `class_signer.xml` `signature len` + `sign` (`<argument class="buffer">`
  with `<length method="signature len"><proxy .../></length>`) → generated
  `vscf_signer_signature_len(...)` / `vscf_signer_sign(..., vsc_buffer_t *signature)`. Mirror this for
  `shares len`/`split` and `recovered secret len`/`combine`.
- **AEAD**: `library/foundation/src/vscf_aes256_gcm.c` — `vscf_aes256_gcm_new/set_key/set_nonce`,
  `vscf_aes256_gcm_auth_encrypt(self, data, auth_data, out, tag)`,
  `vscf_aes256_gcm_auth_decrypt(self, data, auth_data, tag, out)` (returns
  `vscf_status_ERROR_AUTH_FAILED` on tag mismatch). Constants `vscf_aes256_gcm_KEY_LEN` (32),
  `NONCE_LEN` (12), `AUTH_TAG_LEN` (16). Model: `implementor_mbedtls.xml`.
- **RNG**: `vscf_ctr_drbg` (`vscf_ctr_drbg_setup_defaults`), drawn via `vscf_random(self->random, len, buf)`.
- **Hash for DK commitment**: `vscf_sha256` (already in foundation).
- **Zeroize / constant-time compare**: `vscf_erase(mem, size)` and `vscf_memory_secure_equal(a, b, len)`
  (`library/foundation/include/virgil/crypto/foundation/vscf_memory.h`).
- **Thirdparty vendoring**: `codegen/models/external/library_ed25519.xml` →
  generated `thirdparty/ed25519/features.cmake`/`sources.cmake`, built as a STATIC lib, linked in
  `library/foundation/CMakeLists.txt` `target_link_libraries(...)`.
- **Tests**: `tests/foundation/test_signer.c`, `test_aes256_gcm.c`, `test_group_session.c` as
  structure templates; new test at `tests/foundation/test_shamir.c`.

### Institutional Learnings

- `docs/solutions/logic-errors/oid-enum-missing-from-codegen-model-2026-04-26.md` — **never** edit
  `@generated` blocks; author in `codegen/models/` and regenerate, or codegen silently erases edits.
- `docs/solutions/best-practices/external-library-cmake-codegen-2026-04-26.md` — vendor thirdparty
  via `codegen/models/external/library_*.xml`; do **not** hand-write `thirdparty/<lib>/features.cmake`.
- `docs/solutions/build-errors/vscf-post-quantum-stale-cache-on-reconfigure-2026-04-27.md` — feature
  cache flags must use `FORCE` in **both** `if()`/`else()` branches and link via
  `$<$<BOOL:${FLAG}>:target>` so include dirs propagate; test OFF→ON reconfigure without cache delete.
- `docs/solutions/best-practices/codegen-test-stale-assertions-2026-05-12.md` — adding a class shifts
  count/parity assertions across `tools/codegen/test_*.py`; expect to update those numbers; run
  `python3 -m pytest tools/codegen/ -q` and treat anything above the established baseline as a real
  regression.
- `docs/solutions/build-errors/go-wrapper-linux-arm64-wrong-arch-prebuilt-2026-05-15.md` — the Go
  wrapper links **pre-built** static libs in `wrappers/go/pkg/<os>_<arch>/`; new C symbols are not
  linkable from Go until those prebuilts are rebuilt (a CI/release step), so full Go round-trip
  testing of the new class is gated on prebuilt regeneration.
- `docs/solutions/logic-errors/key-alg-factory-missing-pq-cases-2026-04-27.md` — the key-alg factory
  is hand-written; **not relevant here** because `vscf_shamir` is not a key algorithm (confirms the
  no-factory scope boundary).

### External References

- `dsprenkels/sss` `hazmat.h`/`hazmat.c`: `sss_create_keyshares(out, key[32], n, k)` and
  `sss_combine_keyshares(key[32], shares, k)` — both `void`, **no integrity**, x-coordinates 1..n in
  byte 0, `n ≤ 255`, **no duplicate-x check** (colliding indices → GF(256) divide-by-zero → garbage),
  constant-time GF(256). Caller must supply a uniformly random 32-byte key.
- AEAD nonce policy: a fresh-random single-use DK makes a fixed nonce safe, but a **random nonce
  stored in the envelope** removes the single-use invariant as a load-bearing assumption (libsodium
  secretbox guidance). AES-GCM nonce reuse is catastrophic (GHASH subkey recovery → universal
  forgery), so the random-nonce belt-and-suspenders is worth the 12 bytes.
- AES-GCM and ChaCha20-Poly1305 are **not key-committing** (Partitioning Oracle Attacks, IACR
  2020/1491; Len–Chase–Ristenpart, USENIX '21). "Tag passes" ≠ "correct DK". Mitigation: store a DK
  commitment (`SHA-256(DK)`) in the authenticated header and verify it; keep recovery failure
  responses generic/constant so combine can't be used as a fine-grained oracle.

## Key Technical Decisions

- **Construction = split-key-encrypt-data.** Only the 32-byte DK is Shamir-split; the secret is
  AEAD-encrypted. Gives arbitrary length + integrity for free and keeps the GF(256) input uniformly
  random (the security precondition for Shamir). (origin decision)
- **AEAD = AES-256-GCM (reuse `vscf_aes256_gcm`).** Foundation already ships it and uses it
  pervasively; avoids vendoring a second AEAD. Tradeoff: AES-GCM is constant-time only with hardware
  AES; documented as accepted, with ChaCha20-Poly1305 deferred. Nonce = **random 12 bytes** stored
  (and authenticated) in the envelope.
- **DK commitment in the envelope.** Store `SHA-256(DK)` in the authenticated header; combine
  recomputes and constant-time-compares it **strictly before** any AEAD call (hard early-exit on
  mismatch — the AEAD primitive must never run on a wrong DK). Security argument (make it auditable):
  to make a wrong `DK'` pass, an adversary needs a second-preimage on SHA-256 (`~2^256`) *and* a key
  whose AES-256-GCM tag verifies (`~2^128`) — infeasible; this is why commitment + tag closes the
  non-committing-AEAD / partitioning-oracle gap and lets us return one generic recovery error. If the
  commitment is ever truncated, this argument must be re-evaluated.
- **Self-contained shares (single output buffer).** Each of the `n` equal-length shares embeds the
  full envelope (header + nonce + commitment + ciphertext+tag) plus its own 33-byte keyshare. This
  fits the codegen single-buffer convention (split → one concatenated `n × share_size` buffer +
  count; combine → one concatenated `k × share_size` buffer + count) and matches upstream `sss`
  behavior. Cost: ciphertext is duplicated `n×` — negligible for key-sized secrets, the primary use
  case. Container-split layout (ciphertext once) is deferred for large payloads.
- **`k` carried in every share; header fields must agree across shares.** `sss_combine_keyshares`
  needs `k` at recovery time. Carry a random 16-byte `split_id` in every share to detect cross-split
  mixing before interpolation. The cross-share consistency check compares **only the authenticated
  header fields** (`version`, `aead_id`, `k`, `n`, `split_id`, nonce, commitment) — **not** the
  duplicated ciphertext: the ciphertext is authenticated by the AEAD tag, so comparing copies would
  let one tampered ciphertext byte in one presented share deny recovery even when `k` valid shares are
  present (a threshold-availability footgun). Use any one share's ciphertext copy; the tag catches
  tampering. `n` carried for validation/UX. `k`/`n`/`split_id`/nonce/commitment are public.
- **Untrusted-input safety + max secret size.** `ciphertext_len` is a 4-byte field (caps the secret
  at ~4 GiB — documented limit). It is parsed from untrusted bytes, so combine must validate
  `envelope_fixed + ciphertext_len + tag + keyshare == share_buffer_len` before any field access, and
  the output-sizing helper must never trust the embedded length for allocation (see sizing decision).
- **Output sizing = over-estimate, not byte-parse.** Foundation length-methods only receive a
  buffer's *length* (scalar), never its bytes — there is no precedent for a length-method that reads an
  embedded field. So `recovered_secret_len` returns an **upper bound** derived from `shares.len` and
  the fixed overhead (mirroring how `decrypt_len` overestimates); `combine` writes the true plaintext
  length via `vsc_buffer` and re-validates it against the caller buffer. This keeps the single-buffer
  codegen convention without needing the unsupported parse-bytes-in-length-method capability.
- **Unconditional symbol prefix.** Rename all vendored `hazmat` externally-visible symbols to
  `vscf_sss_*` (e.g. `vscf_sss_create_keyshares`/`vscf_sss_combine_keyshares`) at vendor time — not
  conditional. Across six wrappers sharing a flat symbol table, an unprefixed `sss_*` could be silently
  shadowed by a future consumer that vendors the same lib, substituting different GF(256) math.
- **Versioned, self-describing layout.** Leading `format_version` + `aead_id` bytes so AEAD, nonce
  policy, or layout can change later without ambiguity; authenticate the header as AEAD associated
  data so tampering with declared `k`/`n`/commitment is caught.
- **Standalone `<class>`, no `alg_id`/factory.** Constructed via `vscf_shamir_new()`; `split`/`combine`
  are the only public crypto methods. (confirmed by repo research)
- **Error strategy.** Structural/caller-misuse failures (`k>n`, `n>255`, duplicate index, bad length,
  cross-split mismatch) → `vscf_status_ERROR_BAD_ARGUMENTS`. All cryptographic recovery failures
  (commitment mismatch, AEAD tag fail) → a single generic code, identical response regardless of
  cause, to avoid a fine-grained oracle. Add a dedicated `error shamir recovery failed` constant to
  `enum_status.xml` for that generic case rather than overloading `ERROR_AUTH_FAILED` (whose AEAD
  semantics could confuse downstream handlers). Accepted residual: the structural-vs-crypto split lets
  an attacker confirm a share is well-formed before the crypto check — no secret-material advantage,
  since anyone with shares already knows the format; `ERROR_BAD_ARGUMENTS` must be returned before any
  computation on secret-bearing fields.

## Open Questions

### Resolved During Planning

- AEAD algorithm → AES-256-GCM (reuse existing); ChaCha20-Poly1305 deferred.
- Nonce policy → random 12-byte nonce in the (authenticated) envelope.
- Share layout → self-contained shares, single concatenated output buffer; container-split deferred.
- "Tag passes = right key?" → no (non-committing AEAD); add `SHA-256(DK)` commitment.
- Duplicate share index → must dedupe/reject before `sss_combine_keyshares` (divide-by-zero pitfall).
- Class shape → standalone class, no `alg_id`/factory; `setup_defaults` provisions `ctr_drbg` (model on
  `class_key_provider.xml`, with `<require impl="ctr drbg"/>`).
- RNG "required" contradiction (origin) → resolved: `setup_defaults` provisions a default; or inject
  via `use_random`/`take_random`. Not an error to call without injecting if defaults were set up.
- Output sizing → `recovered_secret_len(shares_len, count)` returns an upper bound from the buffer
  length (no byte-parsing); `combine` sets the true length via `vsc_buffer`. **Confirmed by precedent**
  (base64 `decode`/`decoded_len`, spiked 2026-06-18 across C/Go/Python) — not a risk.
- Build registration → root `CMakeLists.txt` `option`+`add_subdirectory`; `-lsss` in all four Go
  `<cgo_link>` directives.
- Symbol safety → unconditional `vscf_sss_*` prefix on vendored symbols.
- Cross-share consistency → compare authenticated header fields only (ciphertext authenticated by tag),
  avoiding the threshold-availability footgun.
- Combine ordering → commitment compare is a hard early-exit strictly before any AEAD call.
- Error code → add dedicated `error shamir recovery failed`; generic for all crypto recovery failures.
- Max secret size → ~4 GiB (4-byte `ciphertext_len`); documented, boundary tested.
- Local static-typed wrapper → Java (Go gated to CI by prebuilt linking).

### Deferred to Implementation

- Exact codegen `<argument>` types for `n`/`k` (`size` vs. a smaller int) — confirm when authoring
  `class_shamir.xml`.
- Whether the test registration in `tests/foundation/` is generated or hand-added — confirm when
  adding `test_shamir.c` (mirror the nearest sibling test's registration).
- Whether PHP / Java / WASM link configs also need an explicit `sss` entry (Go's `cgo_link` does);
  verify each wrapper's link path when building in Unit 6.
- `format_version` migration policy — detection-and-reject only, or decode prior versions later. For
  now: version byte present, combine rejects unknown versions; full back-compat decoding deferred.
- Behavior when OS entropy is unavailable at `setup_defaults` time (embedded/early-boot) — surface the
  `ctr_drbg` setup failure as an error from `setup_defaults`; confirm the path during implementation.
- Final snapshot-test count deltas in `tools/codegen/test_*.py` (known mechanical churn).

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation
> specification. The implementing agent should treat it as context, not code to reproduce.*

Per-share byte layout (all `n` shares equal length; only `share_index` + `keyshare_y` differ):

    ┌─ envelope (identical in every share) ─────────────────────────────┐
    │ format_version  1                                                  │
    │ aead_id         1   (1 = AES-256-GCM)                              │
    │ k               1                                                  │
    │ n               1                                                  │
    │ split_id        16  (random per split, binds shares together)     │
    │ nonce_len       1                                                  │
    │ nonce           12                                                 │
    │ commitment      32  (SHA-256(DK))                                  │
    │ ciphertext_len  4                                                  │
    │ ciphertext||tag (ciphertext_len + 16)                             │
    └───────────────────────────────────────────────────────────────────┘
    ┌─ per-share keyshare ──────────────────────────────────────────────┐
    │ keyshare        33  (sss_Keyshare: 1 index byte + 32 y bytes)      │
    └───────────────────────────────────────────────────────────────────┘
    share_size = envelope_len + 33   (constant across the n shares)

Split / combine flow:

    split(secret, n, k):
      validate 1 ≤ k ≤ n ≤ 255
      DK            = random(32)                       # vscf_random
      nonce         = random(12)
      split_id      = random(16)
      commitment    = SHA-256(DK)
      header        = version‖aead_id‖k‖n‖split_id‖nonce_len‖nonce‖commitment‖ciphertext_len
      ct‖tag        = AES256-GCM(key=DK, nonce, aad=header, plaintext=secret)
      keyshares[n]  = vscf_sss_create_keyshares(DK, n, k)
      for i in 0..n-1: out_share[i] = header‖ct‖tag‖keyshares[i]
      erase(DK); erase(keyshares)                      # vscf_erase, all paths (keyshares carry DK-derived y)
      on any error after partial write: zero(out)      # don't leave partial shares for code that ignores status

    combine(shares[k]):
      for each share: bounds-check                                                   → else BAD_ARGUMENTS
        envelope_fixed + ciphertext_len + tag(16) + keyshare(33) == share_len
        version/aead_id recognized
      require all share HEADER fields equal across k (version,aead_id,k,n,split_id,   → else BAD_ARGUMENTS
        nonce,commitment) via constant-time compare; ciphertext NOT compared (tag authenticates it)
      indices = keyshare[*][0]; reject duplicates (constant-time-safe)               → else BAD_ARGUMENTS
      DK'          = vscf_sss_combine_keyshares(keyshares, k)
      if not secure_equal(SHA-256(DK'), commitment):                                 # HARD early-exit
          erase(DK'); zero(out); return RECOVERY_FAILED                              # AEAD never runs
      secret       = AES256-GCM-decrypt(key=DK', nonce, aad=header, ct, tag)
      if tag invalid: erase(DK'); zero(out); return RECOVERY_FAILED                  # same generic code
      out_len      = set via vsc_buffer                                              # true plaintext len
      erase(DK')
      return secret

    Note: recovered_secret_len(shares) returns an UPPER BOUND from shares.len minus fixed overhead
    (does not parse the embedded ciphertext_len for allocation); it is bounds-safe on truncated input
    (returns 0 if shares.len < minimum envelope). combine writes the true length above.

## Implementation Units

- [ ] **Unit 1: Vendor `hazmat` and wire the build**

**Goal:** Bring the constant-time GF(256) share math into the tree behind a feature flag.

**Requirements:** R5, R6

**Dependencies:** None

**Files:**
- Create: `thirdparty/sss/hazmat.c`, `thirdparty/sss/hazmat.h` (from `dsprenkels/sss`, pinned commit)
- Create: `thirdparty/sss/LICENSE` (upstream MIT) and a `thirdparty/sss/VERSION` / provenance note
  (pinned commit hash + the `vscf_sss_*` rename note)
- Create: `codegen/models/external/library_sss.xml` (mirror `library_ed25519.xml`)
- Modify: **root** `CMakeLists.txt` — add `option(VIRGIL_LIB_SSS "Build 'sss' library" ON)` and a
  guarded `add_subdirectory("thirdparty/sss")` (mirror the ed25519 registration). **Without this the
  generated `thirdparty/sss/CMakeLists.txt` is never included and the `sss` link target is undefined.**
- Modify: `library/foundation/CMakeLists.txt` (add the `sss` static-lib link target, guarded via
  `$<$<BOOL:${VSCF_SHAMIR}>:sss>`)
- Generated (via codegen, do not hand-write): `thirdparty/sss/features.cmake`,
  `thirdparty/sss/sources.cmake`, `thirdparty/sss/CMakeLists.txt`

**Approach:**
- Vendor **only** `hazmat.c`/`hazmat.h` — not `sss.c`, `tweetnacl.c`, or `randombytes.*`.
- **Unconditionally** rename externally-visible `hazmat` symbols to `vscf_sss_*` (sed/awk pass at
  vendor time, or `static` where possible) — collision risk is always present across the flat
  multi-wrapper symbol table.
- Feature flag `VSCF_SHAMIR` in the generated `features.cmake`; mirror `FORCE` in both cache branches
  (see institutional learning on stale cache).

**Patterns to follow:** `codegen/models/external/library_ed25519.xml`, `thirdparty/ed25519/CMakeLists.txt`,
the `target_link_libraries` site in `library/foundation/CMakeLists.txt`.

**Test scenarios:**
- Integration: clean configure+build with `VSCF_SHAMIR=ON` links `hazmat` into `foundation`.
- Edge case: OFF→ON reconfigure **without** deleting the build dir picks up the include path
  (regression guard from the stale-cache learning).
- Integration: a throwaway C call to `sss_create_keyshares`/`sss_combine_keyshares` round-trips a
  32-byte key (sanity that the vendored math links and runs).

**Verification:** `foundation` builds with the flag on and off; the vendored sources are reachable.

- [ ] **Unit 2: Author the codegen model and regenerate scaffolding**

**Goal:** Define `vscf_shamir`'s public surface in the IR model and generate C headers + all six wrappers.

**Requirements:** R1, R3, R4

**Dependencies:** Unit 1

**Files:**
- Create: `codegen/models/project_foundation/class_shamir.xml`
- Modify: `codegen/models/project_foundation/project_foundation.xml` (register `<class name="shamir"/>`;
  append `-lsss` to **all four** `<cgo_link ... libraries="...">` directives so the Go wrapper links
  the new static lib)
- Modify: `codegen/models/project_foundation/enum_status.xml` (add `error shamir recovery failed`)
- Generated (commit as produced): `library/foundation/include/.../vscf_shamir.h`,
  `library/foundation/src/vscf_shamir.c` (+ `_defs`/`_internal`), and the Python/Java/Go/PHP/WASM/Swift
  wrapper files (incl. regenerated `wrappers/go/foundation/platform.go` LDFLAGS).

**Approach:**
- Declare `<dependency name="random" interface="random"/>` **and** `<require impl="ctr drbg"/>` (the
  latter is required for the generated `setup_defaults` body to reference `vscf_ctr_drbg`) and a
  `setup defaults` method — model on **`class_key_provider.xml`** (public class), not the internal
  `group_session`.
- Methods: `setup defaults` → status; `share len`(secret_len → size) returning one share's size;
  `shares len`(secret_len, count → size) = count × share_len; `split`(secret data, n, k, out buffer
  via `<length method="shares len">`) → status; `recovered secret len`(shares data → size) returning an
  **upper bound** from the buffer length (NOT parsing the embedded `ciphertext_len`); `combine`(shares
  data, count, out buffer via `<length method="recovered secret len">`) → status. Use `<proxy>` to
  forward scalar args (`count`, secret length, and the shares-buffer *length* via `cast="data_length"`)
  into the length methods (mirror `class_signer.xml`).
- **Sizing — confirmed by precedent (spiked 2026-06-18).** `recovered_secret_len(shares_len, count)`
  uses the **exact `vscf_base64` `decode`/`decoded_len` pattern**: the length method takes scalar
  `size` args; `combine`'s out-buffer proxies the shares-buffer *length* via `cast="data_length"` (and
  `count`). Verified end-to-end: C `vscf_base64_decode(vsc_data_t, vsc_buffer_t*)` + `decoded_len(size_t)`,
  Go `Base64Decode` calling `Base64DecodedLen(len(str))` to size the buffer, Python
  `Buffer(self.decoded_len(str_len=len(str)))`. The over-estimate is how `decoded_len` already behaves;
  the true length is set via `vsc_buffer`. No byte-parsing in a length method and no new codegen
  capability are required. Upper bound: `(shares_len / count) − per_share_fixed_overhead`.
- Author method/parameter docs in the model (they become wrapper docs).

**Execution note:** Model-first. Never edit `@generated` blocks of output files — regenerate with
`python3 -m tools.codegen.common_bootstrap --project foundation --apply` and confirm a clean `git diff`.

**Patterns to follow:** `class_key_provider.xml` (random dep + `require ctr drbg` + setup_defaults),
`class_signer.xml` (len + buffer-output pairing), the `<cgo_link>` block in `project_foundation.xml`.

**Test scenarios:**
- Integration: the generated `recovered_secret_len(shares_len, count)` compiles and is invoked by each
  wrapper's `combine` to size the output (mirrors `base64` decode; confirmed by precedent, re-verify in
  the actual generated output).
- Integration: `common_bootstrap --project foundation --apply` regenerates without error; generated
  `vscf_shamir.h` exposes the six methods with expected signatures; `platform.go` LDFLAGS include `-lsss`.
- Integration: all six wrappers emit a Shamir binding file (presence check across
  `wrappers/python|java|go|php|wasm|swift`).
- Test expectation: behavioral tests deferred to Units 3–5 (this unit is scaffolding).

**Verification:** Clean regeneration; generated surface matches the model in every wrapper.

- [ ] **Unit 3: Implement the envelope + `split` (write path)**

**Goal:** Hand-write the C bodies for DK/nonce/split_id generation, AEAD encrypt, keyshare creation,
envelope assembly, and the length helpers.

**Requirements:** R1, R2, R5, R6

**Dependencies:** Unit 2

**Files:**
- Modify: `library/foundation/src/vscf_shamir.c` (inside `@generated`/`@end` body markers)
- Test: `tests/foundation/test_shamir.c` (write-path assertions; shared with Unit 4)

**Approach:**
- `setup_defaults`: provision a `vscf_ctr_drbg` (mirror `vscf_group_session.c`).
- `share_len`/`shares_len`: compute from envelope constants + `vscf_aes256_gcm_auth_encrypted_len` +
  33; `shares_len = count × share_len`.
- `split`: validate `1 ≤ k ≤ n ≤ 255`; draw DK(32)/nonce(12)/split_id(16) via `vscf_random`; compute
  `SHA-256(DK)`; build the authenticated header; `vscf_aes256_gcm` set_key/set_nonce/auth_encrypt with
  header as `auth_data`; `vscf_sss_create_keyshares(DK, n, k)`; write `n` self-contained shares.
- **Zeroization (all paths, success and error):** `vscf_erase` the DK, the `keyshares[]` buffer
  (n×33, each carries a DK-derived y), and any plaintext scratch. On **any** error after partial
  output is written, `vscf_erase` the full output buffer so callers that ignore the status can't
  recover a usable partial share set.

**Patterns to follow:** `vscf_group_session.c` (setup_defaults), `vscf_aes256_gcm.c` (AEAD calls),
`vscf_signer.c` (len/buffer assert pattern).

**Test scenarios:**
- Happy path: `split` of a 32-byte secret with n=3,k=2 produces 3 shares of equal `share_len`; output
  buffer length equals `shares_len(32, 3)`.
- Happy path: arbitrary-length secret (e.g. 0, 1, 100, 1000 bytes) splits; per-share `ciphertext_len`
  field matches the AEAD output length.
- Edge case: `k=1`, `k=n`, `n=255` accepted; the three shares carry distinct indices 1..n.
- Error path: `k=0`, `n=0`, `k>n`, `n>255` → `ERROR_BAD_ARGUMENTS`, no partial output.
- Error path: `split` with no RNG configured and `setup_defaults` not called → `ERROR_UNINITIALIZED`
  (or the convention's equivalent), not a crash.
- Edge case (memory): with a failing RNG mid-loop, split returns an error and the output buffer is
  fully zeroed; no DK or keyshare-y material survives (assert via instrumented build if feasible;
  otherwise document as inspected).

**Verification:** Split produces well-formed, equal-length shares; all range validation holds; DK,
keyshares scratch, and output-on-failure are erased on success and error paths.

- [ ] **Unit 4: Implement `combine` (read/validate path)**

**Goal:** Parse and validate shares, reconstruct DK, verify the commitment, AEAD-decrypt, and recover
the secret — with the security guards.

**Requirements:** R2, R4, R6

**Dependencies:** Unit 3

**Files:**
- Modify: `library/foundation/src/vscf_shamir.c`
- Test: `tests/foundation/test_shamir.c`

**Approach:**
- `recovered_secret_len`: return an **upper bound** computed from `shares.len` minus the fixed
  overhead (envelope header + tag + keyshare); return `0` if `shares.len` is below the minimum envelope
  size. It must NOT trust the embedded `ciphertext_len` to size an allocation, and must be safe on
  truncated/garbage input (no over-read, no huge allocation).
- `combine`: **bounds-check** each share first —
  `envelope_fixed + ciphertext_len + tag(16) + keyshare(33) == share_len` and recognized
  version/aead_id → else `ERROR_BAD_ARGUMENTS` (no field access before this passes); compare **only the
  authenticated header fields** across the `k` shares (version, aead_id, k, n, split_id, nonce,
  commitment) using `vscf_memory_secure_equal` — **not** the ciphertext (authenticated by the tag) →
  else `ERROR_BAD_ARGUMENTS`; collect the `k` keyshare indices and **reject duplicates** → else
  `ERROR_BAD_ARGUMENTS`; `vscf_sss_combine_keyshares` → DK′; `vscf_memory_secure_equal(SHA-256(DK′),
  commitment)` → on mismatch erase DK′, zero output, return the generic `ERROR_SHAMIR_RECOVERY_FAILED`
  **without ever calling the AEAD**; only on commitment match, `vscf_aes256_gcm` auth_decrypt (header
  as auth_data) → on tag fail same generic error; set the true plaintext length via `vsc_buffer`;
  `vscf_erase` DK′ always; zero the output buffer before returning any failure.

**Execution note:** Implement the bounds-check, duplicate-index, cross-split-mismatch, and
commitment-before-AEAD ordering guards test-first — they are the silent-failure and oracle traps from
the research.

**Patterns to follow:** `vscf_aes256_gcm.c` auth_decrypt; `vscf_memory.h` secure-equal/erase.

**Test scenarios:**
- Happy path: round-trip — `combine` of any 2-of-3 subset returns the original secret; all 3 of the
  C(3,2) subsets work, in any share order.
- Happy path: general k-of-n across representative `(n,k)` — e.g. (5,3), (10,7), (255,2).
- Error path: fewer than `k` shares → error, output buffer zeroed.
- Error path: a tampered share (flip a ciphertext byte / a keyshare byte) → `ERROR_AUTH_FAILED`,
  output zeroed.
- Error path: **duplicate share index** (same x twice) → `ERROR_BAD_ARGUMENTS` (no divide-by-zero,
  no garbage).
- Error path: shares from **two different splits** mixed → `ERROR_BAD_ARGUMENTS` (split_id mismatch).
- Error path: wrong-`k` shares (e.g. shares made with k=2 but combine told k=3) → generic recovery
  error, never a wrong secret returned.
- Error path: **malformed share** with `ciphertext_len` exceeding the buffer (e.g. `0xFFFFFFFF`) or a
  truncated buffer → `ERROR_BAD_ARGUMENTS`, no over-read, no over-allocation; `recovered_secret_len` on
  the same input returns `0` (or a safe bound) without crashing.
- Error path: among `k` otherwise-valid shares, one has a flipped **ciphertext** byte → still recovers
  (ciphertext authenticated by tag; header-only consistency check does not reject), OR if the flipped
  copy is the one used, AEAD tag fails → generic recovery error. (Asserts the availability-footgun fix.)
- Edge case: empty (0-byte) secret round-trips.
- Edge case: `k=1` round-trip recovers the secret from a single share (documents the no-threshold
  property of k=1).
- Edge case: `combine` into an **over-allocated** output buffer returns the correct recovered length
  and exposes no stale bytes past it.
- Edge case: a secret near the 4-byte `ciphertext_len` cap is either supported or cleanly rejected with
  `ERROR_BAD_ARGUMENTS` (document the ~4 GiB max).
- Integration: commitment mismatch returns the generic error and the AEAD decrypt is **never invoked**
  on the wrong DK (assert ordering, e.g. via an instrumented/mock AEAD if feasible).

**Verification:** All recovery failures return generic errors with zeroed output; only valid k-subsets
of one split recover the secret; no path returns unauthenticated plaintext.

- [ ] **Unit 5: C test suite registration and full coverage**

**Goal:** Register `test_shamir.c` in the C test build and ensure the full edge-case matrix runs under
`ctest`.

**Requirements:** R7

**Dependencies:** Units 3–4

**Files:**
- Modify: the foundation test registration (`tests/foundation/CMakeLists.txt` or the codegen-driven
  test list — confirm which; mirror `test_signer`/`test_group_session` registration)
- Test: `tests/foundation/test_shamir.c` (finalized)

**Approach:** Consolidate the scenarios from Units 3–4 into one test file using the repo's test
framework (mirror `test_aes256_gcm.c`). Use **real RNG** (per `CLAUDE.md`, no fake random post-mbedTLS
3.6.5) except where a deliberately failing RNG is needed to test the error path.

**Test scenarios:** (the union of Unit 3 and Unit 4 scenarios, plus) cross-check that
`shares_len`/`recovered_secret_len` exactly size the buffers the round-trip needs.

**Verification:** `cd build && ctest --output-on-failure` passes including the new `test_shamir` target.

- [ ] **Unit 6: Wrapper validation and codegen test updates**

**Goal:** Confirm the generated bindings build and round-trip, and fix mechanical codegen snapshot
assertions.

**Requirements:** R3, R4

**Dependencies:** Units 2–5

**Files:**
- Modify: `tools/codegen/test_*.py` (count/parity assertions that shift when a class is added)
- Add (round-trip wrapper tests, minimal): one statically-typed wrapper (Go under `wrappers/go/` or
  Java) and one dynamically-typed (`wrappers/python/`)
- Modify (if Swift touched): follow the `useLocalBinaries` verification dance from `CLAUDE.md`

**Approach:**
- Run `python3 -m pytest tools/codegen/ -q`; update count/parity numbers to the new baseline (treat
  anything beyond the mechanical delta as a real regression).
- Build each of the six wrappers; round-trip a 2-of-3 split/combine in ≥2 languages. **For the local
  gate, use Java as the static-typed language and Python as the dynamic** — Go cannot serve locally
  (see gate below). Verify **cross-wrapper byte interop**: a share produced in language A combines in
  language B.
- **Go-prebuilt gate:** Go links the *pre-built* static libs in `wrappers/go/pkg/<os>_<arch>/`; the new
  `vscf_shamir_*` symbols (and `-lsss`) are not linkable from Go until those prebuilts are rebuilt (a
  CI/release step). So Go round-trip and any Go-involving cross-wrapper interop are verified **only in
  CI post-prebuilt-rebuild**, not locally — state this explicitly; do not silently skip. The
  `CLAUDE.md` Go pre-push `go build/test` will not exercise the new symbols until prebuilts exist.

**Test scenarios:**
- Integration: `pytest tools/codegen/` green after assertion updates.
- Integration: Python round-trip (2-of-3) returns the original secret.
- Integration: Java round-trip (the local static-typed language).
- Integration: cross-wrapper interop — share bytes from Python combine in Java (and vice versa).
- Integration (CI only): Go round-trip after prebuilt regeneration.

**Verification:** All six wrapper builds pass; round-trip verified locally in Java + Python;
cross-wrapper interop confirmed; Go validated in CI; codegen pytest green.

- [ ] **Unit 7: Licensing and documentation**

**Goal:** Record the vendored dependency and document the feature.

**Requirements:** R5

**Dependencies:** Unit 1

**Files:**
- Modify: repo third-party license notices (record `dsprenkels/sss` MIT + pinned commit)
- Modify: `README.md` / `ChangeLog.md` as appropriate (append `[skip ci]` for docs-only commits per
  `CLAUDE.md`)

**Approach:** Add the MIT notice + provenance; brief usage note for the new class. Defer a
`docs/solutions/` write-up to a post-merge `/ce:compound`.

**Test scenarios:** Test expectation: none — documentation/licensing only.

**Verification:** License notice present with pinned commit; changelog/readme updated.

## System-Wide Impact

- **Interaction graph:** Self-contained class; depends only on `vscf_ctr_drbg`/`random`,
  `vscf_aes256_gcm`, `vscf_sha256`, and vendored `hazmat`. No factory, no `alg_id`, no `alg_info`
  serialization path — minimal blast radius.
- **Error propagation:** `vscf_status_t` throughout; structural errors → `ERROR_BAD_ARGUMENTS`, all
  crypto recovery failures → a single generic `ERROR_AUTH_FAILED` with zeroed output (no oracle).
- **State lifecycle risks:** DK and intermediate key material must be `vscf_erase`d on every path
  including early-return errors; output buffer zeroed on failure.
- **API surface parity:** New surface replicated across six wrappers by codegen; the risk is the
  variable-count share representation — mitigated by the self-contained-share single-buffer design.
- **Integration coverage:** Cross-wrapper byte interop is the cross-layer property unit tests can't
  prove; covered in Unit 6.
- **Unchanged invariants:** No existing class, interface, `alg_id`, or wire format changes; the
  feature is purely additive behind `VSCF_SHAMIR`.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Variable-count shares don't express cleanly in all six wrappers | Self-contained shares → single concatenated buffer + count (the proven single-buffer convention); validate in Unit 6 across a static + dynamic wrapper before declaring done |
| Length-method can't read embedded `ciphertext_len` (no codegen precedent) | RESOLVED (spiked): use the `base64` `decode`/`decoded_len` pattern — over-estimate from buffer length + count, no byte-parsing; proven in C/Go/Python |
| Untrusted `ciphertext_len` → OOB read / huge allocation / DoS from any wrapper | Bounds-check `envelope+ct_len+tag+keyshare == share_len` before any field access; sizing helper never trusts the embedded length; malformed-input tests |
| One tampered ciphertext copy denies recovery despite k valid shares | Cross-share consistency compares authenticated header fields only; ciphertext authenticated by tag |
| Commitment check bypassed / AEAD run on wrong DK (oracle surface) | Hard early-exit: commitment compare strictly before any AEAD call; ordering test |
| Duplicate share index → GF(256) divide-by-zero → silent garbage | Explicit dedupe/reject in `combine` (Unit 4), tested directly |
| Non-committing AEAD: "tag passes" ≠ correct DK (partitioning oracle) | `SHA-256(DK)` commitment in authenticated header + generic constant recovery error |
| AES-GCM not constant-time without HW AES | Accepted and documented; ChaCha20-Poly1305 deferred; DK is single-use + random-nonce reduces exposure |
| Codegen overwrites hand edits / generated CMake | Model-first authoring; vendored lib via `library_sss.xml`; only `foundation/CMakeLists.txt` hand-edited |
| Go wrapper can't link new symbols until prebuilts rebuilt | Documented gate; validate Go via CI-produced prebuilts; don't silently skip |
| Codegen snapshot-test count drift | Expected mechanical churn; update to new baseline and re-run `pytest tools/codegen/` |
| Stale CMake cache hides the feature include path | `FORCE` both branches + `$<BOOL>` link expr; test OFF→ON reconfigure |

## Documentation / Operational Notes

- Pre-push gate (`CLAUDE.md`): C build + `ctest`, `pytest tools/codegen/`, and — since wrappers
  change — Go `go build/test` and the Swift `useLocalBinaries` verification if Swift sources changed.
- Docs-only commits get `[skip ci]`.
- Releases are CI/tag-driven; no local binary build needed for the feature itself.

## Alternative Approaches Considered

- **Full vendor of `sss` + `tweetnacl`** (origin's first option): rejected — second crypto core,
  pre-1.0 CVE ownership, patched-fork RNG, fixed-64-byte limit. (see origin)
- **Fully native Shamir on mbedTLS** (no vendoring): more constant-time GF(256) code to write and own;
  the vendored `hazmat.c` is small, well-reviewed, and constant-time — better trust/effort tradeoff.
- **ChaCha20-Poly1305 envelope**: better uniform constant-time, but not in foundation today; deferred.
- **Container-split layout** (ciphertext once + n keyshares): avoids `n×` blowup but adds a second
  output to split / second input to combine, complicating the wrapper API; deferred until large-payload
  demand is real.

## Sources & References

- **Origin document:** [docs/brainstorms/shamir-secret-sharing-requirements.md](docs/brainstorms/shamir-secret-sharing-requirements.md)
- Patterns: `codegen/models/project_foundation/class_group_session.xml`, `class_signer.xml`,
  `library/foundation/src/vscf_aes256_gcm.c`, `codegen/models/external/library_ed25519.xml`
- Learnings: `docs/solutions/best-practices/external-library-cmake-codegen-2026-04-26.md`,
  `docs/solutions/logic-errors/oid-enum-missing-from-codegen-model-2026-04-26.md`,
  `docs/solutions/build-errors/vscf-post-quantum-stale-cache-on-reconfigure-2026-04-27.md`,
  `docs/solutions/best-practices/codegen-test-stale-assertions-2026-05-12.md`
- External: `dsprenkels/sss` `hazmat.{c,h}`; Partitioning Oracle Attacks (IACR 2020/1491);
  libsodium secretbox nonce guidance
