---
title: "feat: Self-describing CMS AlgorithmIdentifier for chunk_cipher (aes256-gcm-chunked)"
type: feat
status: complete
date: 2026-07-01
origin: docs/brainstorms/chunk-cipher-cms-agility-requirements.md
---

# feat: Self-describing CMS AlgorithmIdentifier for chunk_cipher (aes256-gcm-chunked)

## Overview

Make `vscf_chunk_cipher` a first-class, self-describing data cipher in CMS crypto-agility. Today a
chunked stream is byte-indistinguishable from single-shot AES-256-GCM in the CMS `data_encryption_alg_info`,
and its parameters (`initial_nonce`, `chunk_size`) live in ad-hoc, unauthenticated `message_info` custom
params. This plan gives the construction its own **`aes256-gcm-chunked`** algorithm identifier
(OID `1.3.6.1.4.1.54811.1.4`) with a params-carrying, DER-serialized `alg_info` (version + chunk_size +
initial_nonce), wires `vscf_alg_factory` + the `cipher` interface so `recipient_cipher` reconstructs and
decrypts it generically, and **binds the CMS metadata into the data AEAD** so the identifier/parameters
cannot be tampered undetected (even on the unsigned envelope path).

Scope is deliberately **concrete AES-256-GCM only** — no composable/algorithm-agnostic generalization
(descoped after review; see origin). Follow-up to the merged `encrypt_at`/`decrypt_at` seek API.

## Problem Frame

`vscf_chunk_cipher` has no `alg_id`/OID and isn't in `vscf_alg_factory`, so the generic decryptor
(`recipient_cipher` → `vscf_alg_factory_create_cipher_from_info`) builds a plain `vscf_aes256_gcm` and
fails on the frame stream. The only "chunked" signal is out-of-band custom-param sniffing, and those
params are unauthenticated. See origin: `docs/brainstorms/chunk-cipher-cms-agility-requirements.md`.

## Requirements Trace

- **R1** — `aes256-gcm-chunked` `alg_id` + OID `1.3.6.1.4.1.54811.1.4` + `vscf_oid.c` mapping.
- **R2** — `chunked_alg_info` (version + chunk_size + initial_nonce) with DER serialize/deserialize + input validation.
- **R3** — chunk_cipher implements `alg` (`produce_alg_info`/`restore_alg_info`).
- **R4** — chunk_cipher implements `cipher` + `cipher_info` (net-new interface + framed `out_len`).
- **R5** — `vscf_alg_factory` reconstructs chunk_cipher from `chunked_alg_info`.
- **R6** — Encryption-side selection via `recipient_cipher` cipher injection; CMS carries `chunked_alg_info`.
- **R7** — Resolve nonce ownership / call-order between `recipient_cipher` and chunk_cipher's `start_encryption`.
- **R8** — Bind `message_info`/`data_encryption_alg_info` into the data AEAD (authenticated metadata); frame-0 AAD binds `initial_nonce`.
- **R9** — Codegen wrapper propagation + docstring fix + Go headers + Swift/Go verify.

## Scope Boundaries

- **Concrete AES-256-GCM only.** No composable inner-cipher `alg_info`, no `cipher_auth` generalization, no inner AEADs beyond AES-256-GCM (origin Decision 2).
- No backward-compat with the custom-params convention (greenfield — origin Decision 3), **pending the prerequisite confirmation below**.
- No change to the frame wire format except a **possible** frame-0 AAD binding of `initial_nonce` (provisional, decided in Unit 5 per R8), and no change to the seek API (`encrypt_at`/`decrypt_at`/`chunk_count`).

### Deferred to Separate Tasks

- Composable / algorithm-agnostic chunked-AEAD (nested inner `alg_info`, `cipher_auth`) — future version behind a **new** OID.

## Prerequisite (blocking, from origin Decision 3)

Confirm with the seald-vault owner (VLT-D15 / ENG-11) that **no chunked CMS envelopes using the
`chunkNonce`/`chunkSize` custom-params convention are already persisted**. If any exist, greenfield is
false and a migration/read-path must be added (re-opens scope). Treated as an assumption until confirmed.

## Context & Research

### Relevant Code and Patterns

- **Params-carrying `alg_info` precedent:** `codegen/models/project_foundation/implementor_alg_info.xml` — `salted_kdf_alg_info` (alg_id + salt + `iteration_count`, a numeric param like chunk_size) is the closest single-level model; `cipher_alg_info` (alg_id + nonce) is the data-cipher analog.
- **DER serialization:** `implementor_alg_info_der.xml` / `vscf_alg_info_der_serializer.c` (dispatch on alg_id; `pbe`/`compound_key`/`hybrid_key` show nested/recursive serialization patterns and where a new case slots in).
- **Data-cipher generic round-trip to mirror:** `vscf_aes256_gcm_produce_alg_info`/`restore_alg_info` (`library/foundation/src/vscf_aes256_gcm.c`); `vscf_alg_factory_create_cipher_from_info` + `restore_alg_info_and_return` (`vscf_alg_factory.c`).
- **`cipher` interface contract:** `codegen/models/project_foundation/interface_cipher.xml` — single `update`/`finish`, `state`, `void` `start_encryption`/`start_decryption`, inherited `cipher_info` (`key_len`/`nonce_len`/`block_len`) + `out_len`/`encrypted_out_len`/`decrypted_out_len`. chunk_cipher currently declares **none** of these and exposes enc/dec `process`/`finish` pairs.
- **Envelope drive:** `vscf_recipient_cipher.c` — single data-cipher slot (default AES-256-GCM at ~line 2124); drives via `vscf_cipher_update`/`finish` (**streaming — composes with framing**); `configure_encryption_cipher` (~2156-2184) generates+injects key & nonce via `cipher_info_nonce_len`/`set_nonce`; `configure_decryption_cipher` (~1416) rebuilds from `data_encryption_alg_info`; AEAD auth-data set only on the signed path (`set_cipher_auth_data`), **empty on unsigned** (the P0).
- **OID arc:** `vscf_oid.c` — Virgil arc `1.3.6.1.4.1.54811`, sub-arc `.1` constructions (`.1.1` compound-key, `.1.2` hybrid-key, `.1.3` random-padding); next free = **`.1.4`**.
- **Existing chunk_cipher:** `library/foundation/src/vscf_chunk_cipher.c` (frame AAD build, per-chunk nonce derivation, the seek `_with` helpers), `codegen/models/project_foundation/class_chunk_cipher.xml`.

### Institutional Learnings

- `docs/solutions/best-practices/codegen-test-stale-assertions-2026-05-12.md` — adding an alg_id/oid/alg_info variant shifts codegen snapshot/parity counts; re-baseline (develop currently 13 failed / 351 passed — 0 new is the bar).
- `docs/solutions/logic-errors/oid-enum-missing-from-codegen-model-2026-04-26.md` — register alg_id/oid/status in the model XML, never hand-edit generated headers.
- `docs/solutions/build-errors/go-cgo-stale-committed-pkg-headers-2026-06-18.md` — refresh committed Go pkg headers (platform-independent; windows target is CRLF — surgical insert, not LF overwrite).
- `docs/solutions/build-errors/msvc-no-c99-vla-vendored-c-2026-06-18.md` — no VLAs in the new DER/AAD C.

### External References

- Virgil OID arc (`1.3.6.1.4.1.54811`); ASN.1 DER `AlgorithmIdentifier`. NIST SP 800-38D (GCM nonce uniqueness).

## Key Technical Decisions

- **Fixed identifier, not composable.** `aes256-gcm-chunked` alg_id + OID `1.3.6.1.4.1.54811.1.4`
  (DER `{0x2B,0x06,0x01,0x04,0x01,0x83,0xAC,0x1B,0x01,0x04}`). `chunked_alg_info` carries a `version`
  INTEGER (=1) + `chunk_size` + `initial_nonce` directly — no nested inner-cipher `alg_info`. The version
  field lets a future framing change avoid a new OID (origin Decision 5).
- **chunk_cipher stays concrete AES-256-GCM.** The seek-path per-call stack GCM and the sequential shared
  GCM are unchanged; only interface/alg_info/factory wiring is added.
- **Interface adaptation is net-new (not "expose existing methods").** Implement `cipher`+`cipher_info`
  by mapping the enc/dec `process`/`finish` pairs onto the interface's state-dispatched single
  `update`/`finish`, reconciling `start_*`'s status return against the interface `void`, and implementing
  framed `out_len`/`encrypted_out_len`/`decrypted_out_len` (per-frame `8 + AUTH_TAG_LEN` overhead — not
  GCM's near-1:1). `cipher_info` reports `key_len=32`, `block_len=16`, and `nonce_len` per the R7 decision.
- **Nonce ownership (R7) — `nonce_len=12`, honor the injected nonce.** `cipher_info.nonce_len` returns
  **12**. `recipient_cipher.configure_encryption_cipher` generates a random 12-byte nonce and calls
  `set_nonce` **unconditionally** (verified: no `nonce_len>0` guard, and chunk_cipher's `set_nonce`
  asserts `len==12` — so a `nonce_len=0` cipher would abort). chunk_cipher's `start_encryption` therefore
  changes to **generate `initial_nonce` only if unset**, so the recipient-injected nonce is honored;
  `produce_alg_info` (called after `start_encryption`, at `update_message_info_for_encryption`) reports
  that nonce into the CMS. On decrypt, `restore_alg_info` sets it directly (bypassing `set_chunk_size`'s
  `state==INITIAL` assert). Confirm the encrypt call order (`set_nonce` → `start_encryption` →
  `produce_alg_info`) end-to-end in Unit 6.
- **Authenticated metadata (R8):** bind serialized CMS metadata as the data-cipher AEAD associated data on
  **both** signed and unsigned paths, extending the mechanism today used only for `signed_data_info`, so
  OID-swap and param-tamper fail closed. **Ordering constraint (verified):** the data AEAD's auth-data
  must be set *before* `start_encryption` (mbedtls `update_ad` runs at start), but
  `data_encryption_alg_info` is only produced/stored into `message_info` *after* `start_encryption` today
  (`update_message_info_for_encryption`). Unit 5 must reorder the encrypt path so the alg_info is produced
  and bound as auth-data **before** the cipher starts. *(Exact bytes bound — `data_encryption_alg_info`
  alone vs full `message_info` — deferred to Unit 5; see Deferred Questions.)*
- **Frame-0 AAD `initial_nonce` binding — provisional, decided in Unit 5.** R8's metadata binding already
  authenticates `initial_nonce` for the CMS path; adding it to frame-0 AAD is *optional* defense-in-depth
  for the raw (non-CMS) stream and re-touches the just-shipped frame format. Leaning include (low cost,
  verified not to break the seek tests — no KAT), but the call is made in Unit 5.
- **DER validation (R2):** deserializer rejects (returns error, not assert) `chunk_size` out of
  `[MIN, MAX]` bounds, `initial_nonce` length != 12, and unknown `version`.

## Open Questions

### Resolved During Planning

- Descope to fixed OID (not composable) — origin Decision 2.
- Trust model = bind metadata into the AEAD — origin Decision 4.
- OID value = `1.3.6.1.4.1.54811.1.4` (verified next-free).
- recipient_cipher's data loop is streaming → framed cipher composes (feasibility-confirmed).
- Nonce ownership = `nonce_len=12` + honor injected nonce (self-generate-if-unset). `nonce_len=0` was rejected — recipient_cipher calls `set_nonce` unconditionally and a 0-byte nonce aborts the assert (feasibility-verified).

### Deferred to Implementation

- Exact DER shape/tag choices for `chunked_alg_info` (version/chunk_size/nonce ordering) — settle for a minimal, unambiguous encoding.
- Exactly which bytes R8 binds (`data_encryption_alg_info` alone vs full `message_info`) — decide against the CMS serialization + the existing signed-path binding; must not break the signed path.
- `chunk_size` `[MIN, MAX]` bound values.
- Whether frame-0-AAD `initial_nonce` binding is kept given R8 already authenticates it (defense-in-depth vs re-touching the just-shipped frame format) — decide in Unit 5.
- Final `out_len` formulas once the `cipher_info` interface shape is generated.

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

```
ENCRYPT (envelope)                                    DECRYPT (generic, envelope)
──────────────────                                    ───────────────────────────
recipient_cipher.use_encryption_cipher(chunk_cipher)  recipient_cipher reads message_info
chunk_cipher.set_key / set_chunk_size                   .data_encryption_alg_info  (chunked OID)
recipient_cipher.start_encryption                     alg_factory.create_cipher_from_info
  → chunk_cipher.start_encryption                       → build chunk_cipher by alg_id
      (generate initial_nonce IF unset)                 → chunk_cipher.restore_alg_info
  → produce_alg_info → chunked_alg_info{v,cs,nonce}         (set version, chunk_size, initial_nonce)
  → message_info.data_encryption_alg_info (DER)        recipient_cipher drives cipher.update/finish
  → BIND serialized alg_info as data-AEAD auth-data      (framed decrypt; AEAD auth-data = bound
process/finish → framed ciphertext                        message_info → tamper fails closed)

chunked_alg_info (DER):  AlgorithmIdentifier {
    algorithm  = 1.3.6.1.4.1.54811.1.4 (aes256-gcm-chunked)
    parameters = SEQUENCE { version INTEGER, chunkSize INTEGER, initialNonce OCTET STRING(12) }
}
```

## Implementation Units

- [x] **Unit 1: alg_id + OID registration**

**Goal:** Register the `aes256-gcm-chunked` algorithm identifier.

**Requirements:** R1

**Dependencies:** None

**Files:**
- Modify: `codegen/models/project_foundation/enum_alg_id.xml`, `enum_oid_id.xml`
- Modify: `library/foundation/src/vscf_oid.c` (OID bytes + alg_id↔oid maps)
- Test: `tests/foundation/test_oid.c` (if present) or a focused assertion in the chunk-cipher tests

**Approach:**
- Append `<constant name="aes256 gcm chunked"/>` to `enum_alg_id.xml` (end — serialized values must not shift) and the parallel `enum_oid_id.xml`.
- Add `oid_aes256_gcm_chunked_bytes[] = {0x2B,0x06,0x01,0x04,0x01,0x83,0xAC,0x1B,0x01,0x04}` with the `1.3.6.1.4.1.54811.1.4` comment (mirror `random_padding`), and wire the alg_id↔oid / oid_id↔oid maps.

**Patterns to follow:** `random_padding` OID entry in `vscf_oid.c`; `oid-enum-missing-from-codegen-model` learning.

**Test scenarios:**
- Happy path: `alg_id ↔ OID` round-trips both directions for the new constant.
- Edge case: OID bytes match `1.3.6.1.4.1.54811.1.4` exactly.

**Verification:** codegen regenerates the enums; OID maps resolve; build green.

---

- [x] **Unit 2: `chunked_alg_info` + DER serialize/deserialize + validation**

**Goal:** A params-carrying alg_info (version + chunk_size + initial_nonce) that round-trips through DER with input validation.

**Requirements:** R2

**Dependencies:** Unit 1

**Files:**
- Modify: `codegen/models/project_foundation/implementor_alg_info.xml` (new `chunked alg info`)
- Modify: `codegen/models/project_foundation/implementor_alg_info_der.xml` + generated `vscf_alg_info_der_serializer.c`/`_deserializer.c` (fill the new serialize/deserialize case)
- Generated: `vscf_chunked_alg_info.{c,h}` + defs
- Test: `tests/foundation/test_alg_info_der.c` (or a new `test_chunked_alg_info.c`)

**Approach:**
- Model `chunked alg info` on `salted_kdf_alg_info` (alg_id + numeric params) — properties: `version` (int), `chunk_size` (size/int), `initial_nonce` (buffer).
- Serialize as `AlgorithmIdentifier{ OID, SEQUENCE{ version, chunkSize, initialNonce } }`; dispatch on the new alg_id in the serializer; add the matching deserialize case.
- **Validation in deserialize:** reject `chunk_size` outside `[MIN,MAX]`, `initial_nonce.len != 12`, unknown `version` — return `vscf_status_ERROR_BAD_ENCRYPTED_DATA`/`ERROR_BAD_ARGUMENTS`, never assert.

**Execution note:** Test-first on the DER round-trip + the rejection cases before wiring the cipher.

**Patterns to follow:** `salted_kdf_alg_info` (model), `pbe`/`compound_key` serialize/deserialize cases in `vscf_alg_info_der_serializer.c`/`_deserializer.c`.

**Test scenarios:**
- Happy path: build `chunked_alg_info` → serialize → deserialize → fields equal (version=1, chunk_size, 12-byte nonce).
- Error path: DER with `chunk_size=0`, `chunk_size=SIZE_MAX`/over-max, `initial_nonce` length 8/16, unknown version → clean error, no crash/UB.
- Edge case: malformed/truncated DER → error (fuzz-style inputs).

**Verification:** `ctest -R alg_info` (or the new test) green incl. rejection cases.

---

- [x] **Unit 3: chunk_cipher implements `alg` + `cipher` + `cipher_info` (interface adaptation + nonce ownership)**

**Goal:** Make chunk_cipher drivable by the generic path and able to produce/restore its alg_info.

**Requirements:** R3, R4, R7

**Dependencies:** Unit 2

**Files:**
- Modify: `codegen/models/project_foundation/class_chunk_cipher.xml` (add `alg`, `cipher`, `cipher_info` interfaces + `produce/restore_alg_info`; nonce_len constant per R7)
- Modify: `library/foundation/src/vscf_chunk_cipher.c` (fill produce/restore_alg_info; map process/finish → update/finish; framed out_len; nonce-if-unset)
- Test: `tests/foundation/test_chunk_cipher.c`

**Approach:**
- `produce_alg_info` → `chunked_alg_info{version=1, chunk_size, initial_nonce}`; `restore_alg_info` sets them directly (bypass the `state==INITIAL` assert in `set_chunk_size`).
- Implement the `cipher` interface: state-dispatched `update`/`finish` delegating to the existing enc/dec frame logic (mirrors `aes256_gcm`'s state-dispatch — feasibility-confirmed the state model supports it); `start_encryption`/`start_decryption` adapted to the `void` interface signature. **Status reconciliation:** with the injected-nonce decision (below) the envelope path no longer self-generates in `start_encryption`, so the RNG-failure path is avoided there; for the raw/seek path where `start_encryption` still self-generates, carry any RNG failure to the first `update`/`finish` (stored error) rather than asserting.
- `cipher_info`: `key_len=32`, `block_len=16`, **`nonce_len=12`** (R7 — `nonce_len=0` aborts because `recipient_cipher` injects unconditionally and `set_nonce` asserts `len==12`); framed `encrypted_out_len`/`decrypted_out_len` reusing the existing `encryption_out_len`/`decryption_out_len` math.
- **Nonce ownership:** `start_encryption` generates `initial_nonce` **only if unset**, so the recipient-injected 12-byte nonce is honored; `produce_alg_info` reports the final nonce.

**Execution note:** Characterization-first — existing seek + sequential chunk_cipher tests must stay green through the interface refactor.

**Patterns to follow:** `vscf_aes256_gcm` (`cipher`/`cipher_info`/`alg` implementation + produce/restore_alg_info); `interface_cipher.xml`.

**Test scenarios:**
- Happy path: `produce_alg_info` → `restore_alg_info` on a fresh instance reproduces chunk_size + initial_nonce; decrypt after restore matches plaintext.
- Happy path: drive encrypt then decrypt purely via the `cipher` interface (`update`/`finish`) → round-trips.
- Edge case: `restore_alg_info` works while `state != INITIAL`-guarded setter would reject.
- Edge case: `start_encryption` with a pre-set nonce does NOT regenerate (nonce honored).
- Error path: framed `decrypted_out_len` sizing sufficient for arbitrary `update` split sizes.
- Regression: all existing chunk_cipher (seek + sequential) tests green.

**Verification:** `ctest -R chunk_cipher` green; interface round-trip works.

---

- [x] **Unit 4: `vscf_alg_factory` routing**

**Goal:** Reconstruct chunk_cipher from a `chunked_alg_info` so the generic decryptor auto-routes.

**Requirements:** R5

**Dependencies:** Unit 3

**Files:**
- Modify: `codegen/models/project_foundation/class_alg_factory.xml` (`<require impl="chunk cipher"/>`), generated `library/foundation/src/vscf_alg_factory.c`
- Test: `tests/foundation/test_chunk_cipher.c` (factory reconstruction)

**Approach:**
- Add a `create_cipher_from_alg_id` case for the chunked alg_id → `vscf_chunk_cipher_impl(vscf_chunk_cipher_new())`; ensure `restore_alg_info_and_return` calls chunk_cipher's `restore_alg_info`.

**Patterns to follow:** the AES256_GCM case in `vscf_alg_factory_create_cipher_from_alg_id`.

**Test scenarios:**
- Happy path: `create_cipher_from_info(chunked_alg_info)` returns a chunk_cipher with chunk_size + nonce restored; decrypt works.
- Error path: unknown/invalid alg_info → NULL (no crash).

**Verification:** factory reconstruction test green.

---

- [x] **Unit 5: Authenticated metadata binding (R8)**

**Goal:** Bind CMS metadata into the data AEAD so OID/param tampering fails closed, incl. the unsigned path.

**Requirements:** R8

**Dependencies:** Unit 4

**Files:**
- Modify: `library/foundation/src/vscf_recipient_cipher.c` (extend `set_cipher_auth_data` / the auth-data path to bind `data_encryption_alg_info`/`message_info` on the unsigned path)
- Modify: `library/foundation/src/vscf_chunk_cipher.c` (frame-0 AAD += `initial_nonce`, if kept — see deferred question)
- Test: `tests/foundation/test_recipient_cipher.c` (or the chunk-cipher integration test)

**Approach:**
- **Reorder the encrypt path (verified sequencing gap):** today `data_encryption_alg_info` is produced/stored at `update_message_info_for_encryption` **after** `start_encryption`, but the AEAD auth-data must be set **before** `start_encryption` (mbedtls `update_ad` runs at start). So on encrypt: produce the alg_info → compute + `cipher_auth_set_auth_data` the serialized metadata → **then** `start_encryption`. On decrypt, recompute the auth-data from the received `message_info` before driving `update`. Preserve the existing signed-path binding (don't double-bind or break it).
- Decide the frame-0 AAD `initial_nonce` binding here (provisional lean: include, for raw-stream defense-in-depth; R8 metadata binding already covers the CMS path). If included, update the shared `encrypt_chunk_with`/`decrypt_chunk_with` frame-0 AAD build consistently (both paths share it, so seek round-trip tests stay consistent).

**Execution note:** Test-first on the tamper cases — they define the security contract.

**Patterns to follow:** existing signed-path `serialized_signed_data_info` → `set_cipher_auth_data` in `vscf_recipient_cipher.c`.

**Test scenarios:**
- Happy path: envelope encrypt → decrypt round-trips with metadata binding on both signed and unsigned paths.
- Error path (downgrade): flip the OID in `data_encryption_alg_info` (chunked→GCM) → decrypt fails closed.
- Error path (param tamper): alter `chunk_size` / `initial_nonce` in the alg_info → auth failure, no plaintext.
- Regression: plain AES-256-GCM envelopes (signed + unsigned) still round-trip (binding didn't break them).

**Verification:** tamper tests fail closed; existing recipient_cipher tests green.

---

- [x] **Unit 6: Encryption-side selection + end-to-end generic round-trip**

**Goal:** A caller selects chunked mode via the envelope API and the whole path round-trips generically.

**Requirements:** R6

**Dependencies:** Units 3-5 (transitively Units 1-6 — the full chain must complete first)

**Files:**
- Modify: `library/foundation/src/vscf_recipient_cipher.c` (only if selection needs a seam beyond `use/take_encryption_cipher`)
- Test: `tests/foundation/test_recipient_cipher.c` / `test_chunk_cipher.c` (end-to-end)

**Approach:**
- Confirm `use_encryption_cipher(chunk_cipher)` + `set_chunk_size` reaches `configure_encryption_cipher` and that `produce_alg_info` emits the chunked identifier; add a seam only if the nonce_len=0 path needs it.

**Test scenarios:**
- Integration: encrypt a multi-chunk payload through `recipient_cipher` with an injected chunk_cipher → decrypt through a fresh `recipient_cipher` with **no chunk knowledge** → plaintext matches.
- Edge case: single-chunk and exact-multiple payloads round-trip.
- Error path: counter-cap (2^48) surfaces a distinguishable error through the recipient_cipher layer.

**Verification:** end-to-end generic round-trip green.

---

- [x] **Unit 7: Wrapper propagation + docstring + Go/Swift verification**

**Goal:** Propagate to all wrappers consistently and update the stale docstring.

**Requirements:** R9

**Dependencies:** Units 1-6

**Files:**
- Modify: `codegen/models/project_foundation/class_chunk_cipher.xml` docstring (drop the custom-params mandate; describe the self-describing alg_info)
- Generated: `wrappers/{go,java,swift,python,php,wasm}/…`; committed Go pkg headers (5 targets; windows CRLF)
- Modify: `tools/codegen` snapshot/parity assertions if they shift

**Approach:**
- Run `common_bootstrap --project foundation --apply`; revert spurious `*_platform.h` drift; refresh committed Go pkg headers (LF for darwin/linux, CRLF surgical for windows); re-baseline codegen pytest; verify Go (`go build/test`) and Swift (`useLocalBinaries` dance).

**Execution note:** Watch the `Build JVM (Windows x86_64)` CI job (MSVC/VLA gate) after push.

**Test scenarios:**
- Integration: Go + Swift wrapper builds/tests pass with the new class API.
- Regression: codegen pytest at develop baseline (no new failures).
- Doc: the custom-params mandate is gone from generated wrapper docs.

**Verification:** all wrappers build; Go+Swift green; codegen pytest baseline.

## System-Wide Impact

- **Interaction graph:** new coupling chunk_cipher ↔ `alg_factory` ↔ `recipient_cipher` (previously none). `recipient_cipher`'s AEAD auth-data path changes for all data ciphers (R8) — blast radius includes plain AES-256-GCM envelopes.
- **Error propagation:** downgrade/param-tamper → `ERROR_AUTH_FAILED`; malformed DER → `ERROR_BAD_ENCRYPTED_DATA`/`BAD_ARGUMENTS`; counter cap → `ERROR_CHUNK_COUNTER_LIMIT_REACHED` surfaced distinguishably.
- **State lifecycle:** `restore_alg_info` must set params without tripping `set_chunk_size`'s state assert; `start_encryption` nonce-if-unset must not break the sequential/seek paths.
- **API surface parity:** the new alg_id/oid/alg_info + chunk_cipher interface additions propagate to all 6 wrappers.
- **Unchanged invariants:** the frame wire format (except frame-0 AAD `initial_nonce`, if kept), the seek API, and plain AES-256-GCM envelope behavior must be preserved.

## Risk Analysis & Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| R8 metadata-binding breaks existing (esp. signed) envelopes | Med | High | Preserve the signed-path binding; regression-test plain GCM signed+unsigned round-trips before/after |
| Nonce ownership (nonce_len=0 vs injection) chosen wrong → nonce mismatch or reuse | Med | High | Decision pinned (self-generate-if-unset + nonce_len=0); integration test through configure_encryption_cipher; confirm against real flow in Unit 3/6 |
| `cipher` interface adaptation changes sequential/seek behavior | Med | High | Characterization-first; full existing chunk_cipher suite green before/after |
| Greenfield assumption false (persisted custom-params streams) | Low | High | Blocking prerequisite confirmation with seald-vault owner before implementation |
| DER deserializer accepts malformed params → UB | Low | High | Explicit bounds/length/version validation (Unit 2) + fuzz-style tests |
| Unsigned-path metadata still tamperable if binding incomplete | Low | High | Tamper tests (OID swap, param change) must fail closed; the security contract is defined by these tests |
| Codegen snapshot/parity churn | High | Low | Expected; re-baseline (develop = 13 failed) |
| Go/Swift/MSVC wrapper breakage | Med | Med | Committed Go header refresh (CRLF-aware), Swift dance, watch Windows JVM CI |

## Documentation / Operational Notes

- Document the `aes256-gcm-chunked` OID (`1.3.6.1.4.1.54811.1.4`) and the `chunked_alg_info` DER shape.
- Note the security property: chunked metadata is integrity-protected via the data-AEAD binding (R8) on both signed and unsigned paths.
- PR references seald-vault (VLT-D15 / ENG-11).

## Sources & References

- **Origin document:** [docs/brainstorms/chunk-cipher-cms-agility-requirements.md](../brainstorms/chunk-cipher-cms-agility-requirements.md)
- Prior: `docs/plans/2026-07-01-002-feat-chunk-cipher-seek-api-plan.md`, `docs/plans/2026-06-11-001-feat-chunk-cipher-plan.md`
- Code: `vscf_oid.c`, `implementor_alg_info.xml`, `implementor_alg_info_der.xml`, `vscf_alg_info_der_serializer.c`, `vscf_aes256_gcm.c`, `vscf_alg_factory.c`, `vscf_recipient_cipher.c`, `vscf_chunk_cipher.c`, `interface_cipher.xml`
