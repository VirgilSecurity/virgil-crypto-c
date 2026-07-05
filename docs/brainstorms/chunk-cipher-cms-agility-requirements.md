# Chunk Cipher — Self-Describing CMS Crypto-Agility — Requirements

**Date:** 2026-07-01
**Status:** Draft — ready for planning (reviewed; scope + trust model resolved)
**Scope:** Deep (new algorithm identifier + params-carrying alg_info + DER serialization + factory/envelope routing + authenticated-metadata binding). **Concrete AES-256-GCM only** — no cipher-agnostic generalization in v1.
**Branch:** `feat/chunk-cipher-seek-api` (follow-up to the merged `encrypt_at`/`decrypt_at` seek API)

## Problem & Goal

`vscf_chunk_cipher` (framed, per-chunk AES-256-GCM) is **invisible to CMS crypto-agility**. It has no
`alg_id`, no OID, and is not in `vscf_alg_factory`. The CMS `data_encryption_alg_info` (the
`AlgorithmIdentifier` that *is* the agility channel in `vscf_message_info`) can therefore only say
`AES-256-GCM` — byte-indistinguishable from a single-shot GCM message. A generic agility-driven
decryptor (`recipient_cipher` → `vscf_alg_factory_create_cipher_from_info`) reconstructs a plain
`vscf_aes256_gcm` and fails on the frame stream. Today the only "this is chunked" signal is an
out-of-band convention: the caller stashes `chunkNonce`/`chunkSize` in `message_info` **custom params**
and the application checks for them — not self-describing, and those parameters live outside any
integrity protection.

**Goal:** make a chunked stream **self-identify from CMS metadata alone**, so a generic decryptor can
recognize it, restore its parameters (initial nonce + chunk size), reconstruct the cipher, and decrypt —
as it already does for AES-256-GCM, but framed. Move `chunk_size`/`initial_nonce` out of ad-hoc custom
params into a DER-serialized `AlgorithmIdentifier`, **and make that identifier integrity-protected** so
its parameters and the algorithm choice cannot be tampered undetected.

## Users & Value

- **Generic decryption path (`recipient_cipher`):** decrypts chunked streams transparently, no
  application-level knowledge — the same code path that handles AES-256-GCM.
- **seald-vault (Seald `VLT-D15`, ENG-11):** dispatches from a real `alg_info` with integrity-bound
  parameters instead of custom-param sniffing.
- **Durable format:** a self-describing, versioned identifier under the Virgil OID arc.

## Decisions (resolved in brainstorm + review)

1. **Full generic auto-routing.** chunk_cipher becomes a first-class data cipher that the generic
   decryptor reconstructs from CMS and drives via the `cipher` interface — modeled on the **data-cipher**
   round-trip (`produce_alg_info`/`restore_alg_info` + `vscf_alg_factory_create_cipher_from_info` +
   `cipher` interface). This **reverses** chunk_cipher's "not registered in `alg_factory`" stance —
   the reversal is what enables the generic decryptor. *(Feasibility confirmed recipient_cipher's data
   loop is genuinely streaming — `vscf_cipher_update`/`finish` — so a framed cipher composes with it.)*
2. **Fixed `aes256-gcm-chunked` identifier — NOT composable/agnostic (descoped after review).** A single
   concrete `alg_id` + OID for the current construction. The `chunked_alg_info` carries a **version**,
   `chunk_size`, and `initial_nonce` directly (no nested inner-cipher `alg_info`). chunk_cipher stays
   concrete AES-256-GCM (no `cipher_auth` generalization). Rationale: 3 reviewers (scope/feasibility/
   adversarial) found the composable design speculative — a fixed OID meets every success criterion, the
   frame math hardcodes 12-byte-nonce/16-byte-tag, and the only wired AEAD is AES-256-GCM. Composability
   is deferred to a future version behind a *new* OID if a second AEAD is ever needed.
3. **Greenfield — no backward-compat** (pending owner confirmation). The new `AlgorithmIdentifier` is the
   only format; the `chunkNonce`/`chunkSize` custom-params convention is dropped (no fallback/sniffing).
   **Blocking check for planning:** confirm with the seald-vault owner that **no chunked CMS envelopes
   using the custom-params convention are already persisted** — if any exist they become undecryptable.
4. **Authenticated metadata — bind `message_info` into the data AEAD.** Parameters in the
   `AlgorithmIdentifier` must be integrity-protected even on the **unsigned** envelope path (today the
   unsigned path sets the data AEAD auth-data to empty, leaving `data_encryption_alg_info` tamperable —
   the P0 finding). The serialized `message_info` (or at minimum the `data_encryption_alg_info`) is bound
   as AEAD associated data so an OID swap (chunked↔plain GCM) or a `chunk_size`/`initial_nonce` change
   fails closed. Additionally, frame-0 AAD binds **both** `chunk_size` and `initial_nonce` (today only
   `chunk_size`) as defense-in-depth.
5. **OID = `1.3.6.1.4.1.54811.1.4`** (next free value in the Virgil constructions sub-arc `.1`, after
   `.1.1` compound-key, `.1.2` hybrid-key, `.1.3` random-padding). DER bytes
   `{0x2B,0x06,0x01,0x04,0x01,0x83,0xAC,0x1B,0x01,0x04}`. A `version` INTEGER inside `chunked_alg_info`
   lets a future framing change avoid a new OID.

## Functional Requirements

- **R1** — New `enum_alg_id` constant (e.g. `aes256 gcm chunked`) + `enum_oid_id` entry + `vscf_oid.c`
  mapping for OID `1.3.6.1.4.1.54811.1.4`.
- **R2** — New **`chunked_alg_info`** (implementor_alg_info) carrying `alg_id`, a `version` INTEGER,
  `chunk_size`, and `initial_nonce`, with DER serialize/deserialize in `alg_info_der`. DER
  deserialization **validates**: `chunk_size` within `[min, max]` bounds (return error, not assert),
  `initial_nonce` length == 12, `version` recognized — malformed/oversized inputs rejected cleanly.
- **R3** — chunk_cipher implements the `alg` interface: `produce_alg_info()` emits `chunked_alg_info`;
  `restore_alg_info()` restores `version` + `chunk_size` + `initial_nonce` (setting them directly, not
  via the `state==INITIAL`-guarded `set_chunk_size`).
- **R4** — chunk_cipher implements the `cipher` + `cipher_info` interfaces so the generic decryptor can
  drive it. **This is net-new interface work, not exposure of existing methods:** map the existing
  `process_encryption`/`finish_encryption`/`process_decryption`/`finish_decryption` onto the interface's
  single `update`/`finish` (state-dispatched), reconcile the `start_*` status return vs the interface's
  `void`, and implement `cipher_info` (`key_len`, `nonce_len`, `block_len`) + the `out_len` /
  `encrypted_out_len` / `decrypted_out_len` sizing for the **framed** layout (per-frame `8 + tag`
  overhead — not GCM's near-1:1).
- **R5** — `vscf_alg_factory` reconstructs chunk_cipher from a `chunked_alg_info`
  (`create_cipher_from_info` → build by `alg_id` → `restore_alg_info`), so `recipient_cipher` decrypts a
  chunked stream with no application knowledge.
- **R6** — Encryption side: a caller selects chunked mode by injecting a configured chunk_cipher as the
  data-encryption cipher (`recipient_cipher` `use/take_encryption_cipher`) after `set_chunk_size`; the
  produced CMS carries the `chunked_alg_info`.
- **R7** — **Nonce ownership resolved:** define a single owner for `initial_nonce` generation and a fixed
  call order so `recipient_cipher`'s generic `set_nonce` and chunk_cipher's internal `start_encryption`
  nonce generation do not conflict (today `start_encryption` unconditionally regenerates, overwriting an
  injected nonce). Planning picks one: (a) chunk_cipher honors an injected nonce and only self-generates
  when none is set; or (b) chunk_cipher self-generates and `produce_alg_info` (called after
  `start_encryption`) reports it, with `recipient_cipher` not injecting a data nonce for this cipher.
  Add an integration test round-tripping through the `recipient_cipher` generic path.
- **R8** — Metadata-binding (Decision 4): bind serialized `message_info`/`data_encryption_alg_info` into
  the data-cipher AEAD associated data on both signed and unsigned paths; extend frame-0 AAD to include
  `initial_nonce`. Tampered OID/params → auth failure.
- **R9** — Propagate to all language wrappers via codegen; update the `class_chunk_cipher.xml` class
  docstring (which still mandates the dropped custom-params convention). Refresh committed Go pkg headers
  (per the seek-API learnings); verify Go + Swift builds.

## Non-Goals

- **Composable / algorithm-agnostic chunked-AEAD** (nested inner-cipher `alg_info`, `cipher_auth`
  generalization, inner AEADs other than AES-256-GCM) — descoped to a future version behind a new OID.
- Backward-compatible decryption of custom-params-convention streams (greenfield, pending owner confirm).
- Changing the frame wire format (`counter_le64[8] | ciphertext | tag[16]`) beyond adding `initial_nonce`
  to frame-0 AAD, or changing the seek API (`encrypt_at`/`decrypt_at`/`chunk_count`) — unchanged.

## Success Criteria

- A chunked stream produced through the envelope flow round-trips through `recipient_cipher` decryption
  **with no application-level chunk knowledge**.
- `produce_alg_info` → DER serialize → deserialize → `restore_alg_info` reproduces
  `version`+`chunk_size`+`initial_nonce`; decrypt after restore matches the original plaintext.
- A CMS with the chunked OID is distinguishable from plain AES-256-GCM by `alg_id` alone.
- **Downgrade/tamper fails closed:** swapping the OID (chunked↔GCM) or altering `chunk_size`/
  `initial_nonce` in the `AlgorithmIdentifier` causes an authentication failure (via metadata AEAD
  binding + frame-0 AAD), never a silent mis-decrypt.
- `chunk_size`/`initial_nonce` no longer written to `message_info` custom params by the chunked path.
- DER deserializer rejects malformed/out-of-range `chunked_alg_info` (fuzzed).
- Existing seek-API + sequential chunk_cipher tests remain green; C build + `ctest` + codegen pytest green.

## Security & Agility Review Requirements (for planning)

- **Metadata integrity (P0 — resolved by Decision 4):** implement + test the `message_info`→AEAD
  binding on the unsigned path; verify OID/param tampering fails closed. Confirm the exact bytes bound
  (whole `message_info` vs `data_encryption_alg_info`) and that it doesn't break the existing signed path.
- **Parameter tampering:** `initial_nonce` must be bound (frame-0 AAD + metadata binding), not left to
  implicit nonce-derivation mismatch.
- **DER robustness:** bounds/length/version validation (R2) is a delivery requirement; fuzz the
  deserializer.
- **Nonce reuse / counter cap:** confirm the 2^48 frame cap error surfaces distinguishably through the
  `recipient_cipher` layer (not an opaque failure).
- **DER `restore` vs `set_chunk_size` assert:** `restore_alg_info` must set `chunk_size` without tripping
  `set_chunk_size`'s `state==INITIAL` assert.

## Technical Notes (for planning)

- **OID:** `1.3.6.1.4.1.54811.1.4`, DER `{0x2B,0x06,0x01,0x04,0x01,0x83,0xAC,0x1B,0x01,0x04}` — verified
  next-free in the Virgil `.1` constructions sub-arc (`vscf_oid.c`: compound `.1.1`, hybrid `.1.2`,
  random-padding `.1.3`).
- **Params-carrying alg_info precedent:** `implementor_alg_info.xml` — `salted_kdf_alg_info` (alg_id +
  salt + `iteration_count`, a numeric param like chunk_size) is the closest single-level precedent;
  `pbe_alg_info` shows composites. `chunked_alg_info` is a simple params-carrying variant (version +
  chunk_size + nonce). DER via `implementor_alg_info_der.xml` (dispatch on alg_id; well-precedented).
- **Data-cipher generic round-trip to mirror:** `vscf_aes256_gcm_produce_alg_info`/`restore_alg_info`;
  `vscf_alg_factory_create_cipher_from_info` + `restore_alg_info_and_return`; `recipient_cipher` drives
  the data cipher via `vscf_cipher_update`/`finish` (streaming — composes with framing).
- **Interface adaptation (R4) — the real work:** chunk_cipher currently declares **no** `cipher`/
  `cipher_info` interface; `interface_cipher.xml` wants single `update`/`finish` + `out_len` split +
  `state` + `void` starts. Map chunk_cipher's enc/dec `process`/`finish` pairs onto it; implement framed
  `out_len` math.
- **Nonce-ownership conflict (R7):** `recipient_cipher.configure_encryption_cipher` generates a data
  nonce and calls `vscf_cipher_set_nonce`; chunk_cipher's `start_encryption` regenerates its own via
  `random`. `cipher_info.nonce_len` drives recipient_cipher's generation — decide whether chunk_cipher
  reports `nonce_len=12` (triggering injection) or opts out, and pin the call order.
- **Metadata binding (R8):** today `recipient_cipher` only sets AEAD auth-data on the signed path
  (`serialized_signed_data_info`); unsigned sets empty. Extend so the chunked path binds
  `message_info`/alg_info even unsigned. Assess impact on the existing signed path + on
  `set_cipher_auth_data`.
- **Docstring:** `class_chunk_cipher.xml` lines ~11-12 still mandate the custom-params convention — update
  before codegen (R9).
- **Seek API interaction:** `encrypt_at`/`decrypt_at`/`chunk_count` operate below the CMS layer and are
  unchanged; note that a generically-driven instance gets `chunk_size`/`nonce` via `restore_alg_info`, so
  any caller mixing generic decryption with seek must ensure restore ran first.

## Sources & References

- Prior work: `docs/plans/2026-07-01-002-feat-chunk-cipher-seek-api-plan.md` (seek API; the gap that
  motivated this). Original design: `docs/plans/2026-06-11-001-feat-chunk-cipher-plan.md`.
- Code: `library/foundation/src/vscf_chunk_cipher.c`, `vscf_recipient_cipher.c`, `vscf_alg_factory.c`,
  `vscf_aes256_gcm.c`, `vscf_oid.c`, `implementor_alg_info.xml`, `implementor_alg_info_der.xml`,
  `interface_cipher.xml`.
