---
title: "refactor: Make ratchet session API algorithm-agnostic"
type: refactor
status: active
date: 2026-04-28
---

# refactor: Make ratchet session API algorithm-agnostic

## Overview

The ratchet session API currently hard-codes two specific post-quantum algorithms — Falcon-1024
for signing and ML-KEM-768 for key encapsulation — across its XXDH key agreement, double ratchet
step, key utilities, serialization, and all language wrapper APIs. The goal of this refactor is to
remove every concrete algorithm reference from the ratchet library so it operates purely on the
`vscf_impl_t *` key interfaces already provided by the foundation library. Callers choose the
algorithm combination by passing the appropriate key type (classical, compound, or hybrid); the
ratchet library introspects the key to determine what operations to perform.

## Problem Frame

The ratchet library was initially built for a specific PQC algorithm pair (Round5 + Falcon, later
ML-KEM-768 + Falcon). Each algorithm change required deep surgery across XXDH, chain key
derivation, key utilities, serialization, and all language wrappers — as evidenced by the Round5 →
ML-KEM-768 migration in this PR. Making the ratchet algorithm-agnostic eliminates this category of
work permanently and allows callers to use:

- **Classical-only**: Curve25519 + Ed25519 (no PQC, no `enable_post_quantum` flag required)
- **Current PQC**: compound(Curve25519, Ed25519) + hybrid(Curve25519, ML-KEM-768) identity/long-term keys
- **Future PQC**: Any algorithm that implements the `vscf_kem` and `vscf_key_signer` interfaces

## Requirements Trace

- R1. `vscr_ratchet_session_initiate/respond` accept any key type implementing the foundation key interfaces — no algorithm check beyond capability detection.
- R2. PQC path activates automatically when the provided keys contain a KEM/signer component (compound/hybrid); no `enable_post_quantum` bool parameter.
- R3. `vscr_ratchet_xxdh_t` and `vscr_ratchet_keys_t` contain no concrete PQC type references (`vscf_falcon_t *` removed; no `vscf_ml_kem_new()` in init).
- R4. Buffer sizes for encapsulated keys and signatures are derived at runtime from the key via `vscf_kem_kem_encapsulated_key_len()` and `vscf_key_signer_signature_len()`; compile-time constants `KEM_ENCAPSULATED_KEY_LEN` and `FALCON_SIGNATURE_LEN` are removed.
- R5. `vscr_ratchet_key_utils` validates KEM/signer capability via `vscf_kem_is_implemented()` and `vscf_key_signer_is_implemented()` rather than checking specific algorithm IDs.
- R6. Serialization stores algorithm IDs alongside key bytes so sessions can be deserialized without baking in `vscf_alg_id_ML_KEM_768`.
- R7. All language wrappers (Java, Swift, WASM) drop the `enablePostQuantum` parameter.
- R8. All existing ratchet tests pass; new tests cover compound-key and classical-only session paths.

## Scope Boundaries

- The "first" classical DH layer (Curve25519 raw 32-byte keys) is **not** generalized in this plan — the double ratchet KDF chain is still Curve25519-based. Generalizing the DH ratchet step itself is deferred.
- Group session (`vscr_group_session`) is not in scope — it uses a different key agreement model.
- No changes to the `vscf_compound_key` or `vscf_hybrid_key` foundation implementations.
- No new algorithm implementations — this refactor enables any existing or future algorithm that implements `vscf_kem` / `vscf_key_signer`.

### Deferred to Separate Tasks

- Generalize the "first" (Curve25519) DH layer to accept any DH key interface: separate plan/PR.
- Migrate pre-existing serialized sessions across the wire format break: migration tooling if needed by downstream consumers.

## Context & Research

### Relevant Code and Patterns

- `library/ratchet/src/vscr_ratchet_xxdh.c` — hard-coded `vscf_falcon_t *falcon` field; `vscf_ml_kem_new()` in `init_ctx`; `FALCON_SIGNATURE_LEN` buffer allocation at line 557; `KEM_ENCAPSULATED_KEY_LEN` at line 362.
- `library/ratchet/src/vscr_ratchet_keys.c` — `vscf_ml_kem_new()` in `init_ctx`; `KEM_ENCAPSULATED_KEY_LEN` buffer allocation at line 417.
- `library/ratchet/src/vscr_ratchet_key_utils.c` — 14 hard-coded alg ID checks (`vscf_alg_id_ML_KEM_768`, `vscf_alg_id_FALCON`); `enable_post_quantum` parameter gates second-key extraction.
- `library/ratchet/src/vscr_ratchet_pb_utils.c` — 4 hard-coded `vscf_alg_id_ML_KEM_768` references reconstruct second keys during deserialization.
- `library/ratchet/src/vscr_ratchet_session.c` — `enable_post_quantum` used 26 times; `KEM_ENCAPSULATED_KEY_LEN` and `FALCON_SIGNATURE_LEN` used in deserialization size validation.
- `library/ratchet/src/vscr_ratchet_sender_chain.c` — `KEM_ENCAPSULATED_KEY_LEN` size validation during deserialization.
- `library/ratchet/protobuf/vscr_RatchetSession.proto` — `enable_post_quantum` persisted in both `vscr_Session` and `vscr_Ratchet`; `second_key` blobs stored without algorithm info.
- `codegen/models/project_ratchet/class_ratchet_xxdh.xml` — `<property name="falcon" class="falcon"/>` (concrete type); `<require impl="falcon"/>` and `<require impl="ml kem"/>` hard deps.
- `codegen/models/project_ratchet/class_ratchet_common_hidden.xml` — four algorithm-specific constants: `falcon_signature_len=809`, `kem_encapsulated_key_len=1088`, `kem_public_key_len=1184`, `kem_shared_key_len=32`.
- `library/foundation/include/virgil/crypto/foundation/vscf_key_signer.h` — `vscf_key_signer_signature_len(impl, private_key)`, `vscf_key_signer_sign_hash(...)`, `vscf_key_signer_verify_hash(...)`, `vscf_key_signer_is_implemented(impl)`.
- `library/foundation/include/virgil/crypto/foundation/vscf_kem.h` — `vscf_kem_kem_encapsulated_key_len(impl, public_key)`, `vscf_kem_kem_encapsulate(...)`, `vscf_kem_kem_decapsulate(...)`, `vscf_kem_is_implemented(impl)`.
- `library/foundation/src/vscf_key_alg_factory.c` — `vscf_key_alg_factory_create_from_key(key, rng, error)` creates the algorithm implementation from any `vscf_impl_t *` key — this is the on-demand factory pattern to use everywhere.

### Institutional Learnings

- The Round5 → ML-KEM-768 migration required touching 20+ files across XXDH, codegen models, wrappers, tests, and constants. This refactor is the last time that migration class of work should be needed.

### External References

- Signal Protocol double ratchet specification: the KDF chain is Curve25519-based; only the XXDH initial key agreement touches the PQC layer.

## Key Technical Decisions

- **On-demand algorithm factory, not stored instances**: `vscr_ratchet_xxdh_t` and `vscr_ratchet_keys_t` will not store pre-created Falcon/KEM objects. Instead, each operation that needs to sign, verify, encapsulate, or decapsulate calls `vscf_key_alg_factory_create_from_key(key, self->rng, &error)`, uses the result for one operation, and destroys it. This avoids algorithm-typed struct fields and eliminates the `init_ctx`/`did_setup_rng` coupling to specific implementations.

- **`enable_post_quantum` removed, key type determines mode**: `key_utils` detects the presence of a second (PQC) key component by inspecting key structure (compound/hybrid), not by reading the flag. If a compound identity key is provided, the signer component is extracted; if not, the signer reference is NULL and the PQC path is skipped. This is consistent with how `vscf_key_info` is already used in `key_utils`.

- **Capability checks, not algorithm ID checks**: `key_utils` replaces `vscf_alg_id_ML_KEM_768` and `vscf_alg_id_FALCON` guards with `vscf_kem_is_implemented(alg)` and `vscf_key_signer_is_implemented(alg)`. Any future algorithm that implements these interfaces will work automatically.

- **Wire format version bump to store algorithm IDs**: The protobuf schema adds `uint32` alg ID fields alongside second-key bytes in `vscr_SenderChain`, `vscr_ReceiverChain`, and `vscr_SessionPqcInfo`. `vscr_Session.version` is bumped. Old sessions (version 1) cannot be deserialized with the new library — this is a documented breaking change.

- **Classical "first" layer stays fixed**: Curve25519 raw 32-byte keys for DH ratchet steps remain as typed arrays, not `vscf_impl_t *`. This preserves the double ratchet KDF chain without the complexity of generalizing DH key agreement.

## Open Questions

### Resolved During Planning

- **Does a `vscf_key_signer` interface already exist?** Yes — `vscf_key_signer.h` provides `sign_hash`, `verify_hash`, `signature_len`, and `is_implemented`. Falcon, Ed25519, and ML-DSA all implement it.
- **Does `vscf_kem_is_implemented()` exist?** Yes — `vscf_kem.h` exposes it. ML-KEM-768 and Curve25519 implement it.
- **Is `vscf_key_alg_factory_create_from_key` the right factory?** Yes — it takes any `vscf_impl_t *` key and returns the algorithm that operates on it, passing the RNG for randomized operations like encapsulation.
- **Is `kem_public_key_len` (1184) used anywhere in C source?** No — `grep` confirms zero uses in `library/ratchet/src/`. Safe to remove from the codegen model.

### Deferred to Implementation

- Exact error code to return when a compound key's second component implements neither KEM nor key_signer — determine during `key_utils` implementation.
- Whether to keep `enable_post_quantum` as a deprecated, ignored field in the protobuf during load-time backwards compat read path (version 1 sessions).

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

**Session initiation flow (new design):**

```
initiate(sender_identity_priv, receiver_identity_pub, receiver_long_term_pub, [receiver_one_time_pub])
    ↓
key_utils.import_private_key(sender_identity_priv)
    → extracts: curve25519_first_priv, second_signer_priv (if compound → signer component, else NULL)
key_utils.import_public_key(receiver_identity_pub)
    → extracts: curve25519_first_pub, second_signer_pub (if compound → signer component, else NULL)
key_utils.import_public_key(receiver_long_term_pub)
    → extracts: curve25519_first_pub, second_kem_pub (if compound/hybrid → KEM component, else NULL)
    ↓
xxdh.compute_initiator_shared_secret(...)
    classical path (always):
        ed25519 DH with curve25519 keys → shared_secret_first
    pqc path (only when second_kem_pub != NULL):
        kem_alg = key_alg_factory.create_from_key(second_kem_pub, rng)
        encap_len = vscf_kem_kem_encapsulated_key_len(kem_alg, second_kem_pub)
        vscf_kem_kem_encapsulate(kem_alg, second_kem_pub, ...) → encapsulated_key, shared_secret_second
        if second_signer_priv != NULL:
            signer_alg = key_alg_factory.create_from_key(second_signer_priv, rng)
            sig_len = vscf_key_signer_signature_len(signer_alg, second_signer_priv)
            vscf_key_signer_sign_hash(signer_alg, second_signer_priv, ...) → signature
```

**key_utils second-key extraction (new design, no `enable_post_quantum` param):**

```
import_private_key(key, &first_out, &second_kem_out, &second_signer_out):
    if key is compound:
        cipher_key → validate vscf_kem_is_implemented → second_kem_out
        signer_key → validate vscf_key_signer_is_implemented → second_signer_out
    elif key is hybrid:
        first_key → classical first_out
        second_key → if vscf_kem_is_implemented → second_kem_out
    else:
        classical first_out only; second_* = NULL
```

## Implementation Units

- [ ] **Unit 1: Remove algorithm-specific constants from `class_ratchet_common_hidden`**

**Goal:** Delete `falcon_signature_len`, `kem_encapsulated_key_len`, and `kem_public_key_len` constants from the codegen model; regenerate the `vscr_ratchet_common_hidden.h` header.

**Requirements:** R4

**Dependencies:** None

**Files:**
- Modify: `codegen/models/project_ratchet/class_ratchet_common_hidden.xml`
- Modify (regenerated): `library/ratchet/include/virgil/crypto/ratchet/private/vscr_ratchet_common_hidden.h`

**Approach:**
- Remove the three `<constant>` elements for `falcon signature len`, `kem encapsulated key len`, and `kem public key len` from the XML model.
- Keep `kem shared key len` (32), `shared key len`, `key len`, `max skipped dh`, `max session len`.
- Run `python3 -m tools.codegen.common_bootstrap --project ratchet --apply` to regenerate.
- The C source files that reference the removed constants will fail to compile after this unit — that is intentional and expected; they are fixed in subsequent units.

**Test scenarios:**
- Test expectation: none — pure constant removal; behavior verified by later units compiling and passing.

**Verification:**
- Regenerated header no longer contains `FALCON_SIGNATURE_LEN`, `KEM_ENCAPSULATED_KEY_LEN`, or `KEM_PUBLIC_KEY_LEN`.
- Remaining constants still present in the header.

---

- [ ] **Unit 2: Remove concrete algorithm properties from `class_ratchet_xxdh` codegen model**

**Goal:** Remove `<property name="falcon" class="falcon"/>` and the hard deps `<require impl="falcon"/>` / `<require impl="ml kem"/>` from `class_ratchet_xxdh.xml`; regenerate. This collapses the generated struct and init scaffolding to remove the Falcon typed field.

**Requirements:** R3

**Dependencies:** Unit 1

**Files:**
- Modify: `codegen/models/project_ratchet/class_ratchet_xxdh.xml`
- Modify (regenerated): `library/ratchet/src/vscr_ratchet_xxdh.c`, `library/ratchet/features.cmake`

**Approach:**
- Remove `<property name="falcon" class="falcon" project="foundation"/>` — this deletes the `vscf_falcon_t *falcon` struct field and its generated getter/setter.
- Remove `<require impl="falcon" project="foundation"/>` and `<require impl="ml kem" project="foundation"/>` (the hard deps added earlier in this PR to catch invalid configs — they are replaced by the capability-check pattern).
- The `<property name="kem" interface="kem" project="foundation"/>` can also be removed since the KEM is now created on-demand. If it generates only optional accessors that are unused, remove it.
- Regenerate. The hand-written `init_ctx`, `cleanup_ctx`, and `did_setup_rng` sections in `vscr_ratchet_xxdh.c` are updated in Unit 3.

**Patterns to follow:**
- `codegen/models/project_ratchet/class_ratchet_keys.xml` — shows how kem property is declared; remove it there too (see Unit 4).

**Test scenarios:**
- Test expectation: none — model change only; verified by regenerated file compiling in later units.

**Verification:**
- `library/ratchet/features.cmake` no longer contains `VSCR_RATCHET_XXDH AND NOT VSCF_FALCON` or `NOT VSCF_ML_KEM` checks.
- Generated `vscr_ratchet_xxdh_defs.h` no longer contains a `falcon` field.

---

- [ ] **Unit 3: Refactor `vscr_ratchet_xxdh.c` — on-demand algorithm factory pattern**

**Goal:** Replace all concrete Falcon/ML-KEM usage in the hand-written sections of `vscr_ratchet_xxdh.c` with on-demand `vscf_key_alg_factory_create_from_key` calls; replace compile-time buffer sizes with runtime queries.

**Requirements:** R3, R4

**Dependencies:** Units 1, 2

**Files:**
- Modify: `library/ratchet/src/vscr_ratchet_xxdh.c`

**Approach:**
- `init_ctx`: Remove `self->kem = vscf_ml_kem_impl(vscf_ml_kem_new())` and `self->falcon = vscf_falcon_new()`.
- `cleanup_ctx`: Remove `vscf_impl_destroy(&self->kem)` and `vscf_falcon_destroy(&self->falcon)`.
- `did_setup_rng`: Remove `vscf_ml_kem_use_random(...)` and `vscf_falcon_use_random(...)`. RNG is now passed to the factory at operation time.
- `compute_initiator_pqc_shared_secret`:
  - For each `encapsulate_pqc_key` call: before calling, create a local `kem_alg` via `vscf_key_alg_factory_create_from_key(public_key, self->rng, &error)`. Replace `KEM_ENCAPSULATED_KEY_LEN` with `vscf_kem_kem_encapsulated_key_len(kem_alg, public_key)`. Destroy `kem_alg` after use.
  - For signature buffer: create `signer_alg` via `vscf_key_alg_factory_create_from_key(sender_identity_private_key_second_signer, self->rng, &error)`. Replace `FALCON_SIGNATURE_LEN` with `vscf_key_signer_signature_len(signer_alg, sender_identity_private_key_second_signer)`. Call `vscf_key_signer_sign_hash(signer_alg, ...)` instead of `vscf_falcon_sign_hash(self->falcon, ...)`. Destroy after use.
- `compute_responder_pqc_shared_secret`:
  - Decapsulate: same factory pattern for KEM.
  - Verify: create `verifier_alg` from public verifier key, call `vscf_key_signer_verify_hash(verifier_alg, ...)`, destroy.
- `encapsulate_pqc_key` / `decapsulate_pqc_key`: Replace the hard-coded `KEM_ENCAPSULATED_KEY_LEN` capacity with a runtime `vscf_kem_kem_encapsulated_key_len(kem_alg, public_key)` call using a locally created `kem_alg`.

**Patterns to follow:**
- `library/foundation/src/vscf_key_alg_factory.c` — pattern for factory + use + destroy.
- `library/ratchet/src/vscr_ratchet_xxdh.c` lines 508–570 (existing `compute_initiator_pqc_shared_secret`) — structure to follow, replacing the Falcon/ML-KEM specifics.

**Test scenarios:**
- Happy path: XXDH with ML-KEM-768 + Falcon keys produces matching shared secrets (existing `test__pqc_xxdh__fixed_keys__should_match` and `test__xxdh__random_keys_pqc__should_match` must pass).
- Happy path: XXDH with classical-only Curve25519 keys (second params NULL) produces matching shared secrets (`test__curve25519_xxdh__fixed_keys__should_match` must pass).
- Edge case: Second signer key is NULL — PQC signing step is skipped, no signature buffer allocated.
- Error path: `vscf_key_alg_factory_create_from_key` returns error — propagated as `vscr_status_ERROR_KEY_AGREEMENT` (or appropriate ratchet error).

**Verification:**
- All seven existing `test_ratchet_xxdh.c` tests pass.
- No reference to `vscf_falcon_t`, `vscf_falcon_new`, `FALCON_SIGNATURE_LEN`, or `KEM_ENCAPSULATED_KEY_LEN` remains in the file.

---

- [ ] **Unit 4: Refactor `vscr_ratchet_keys.c` — remove hardcoded ML-KEM instance**

**Goal:** Apply the same on-demand factory pattern to `vscr_ratchet_keys_t`, which creates `vscf_ml_kem_new()` in its `init_ctx` and uses a fixed `KEM_ENCAPSULATED_KEY_LEN` buffer capacity for the double-ratchet KEM step.

**Requirements:** R3, R4

**Dependencies:** Units 1, 2

**Files:**
- Modify: `codegen/models/project_ratchet/class_ratchet_keys.xml`
- Modify (regenerated): `library/ratchet/src/vscr_ratchet_keys.c`

**Approach:**
- In `class_ratchet_keys.xml`: remove `<require impl="ml kem" project="foundation"/>` and `<property name="kem" interface="kem" project="foundation"/>`.
- In `vscr_ratchet_keys.c` (hand-written section):
  - `init_ctx`: Remove `self->kem = vscf_ml_kem_impl(vscf_ml_kem_new())`.
  - `cleanup_ctx`: Remove `vscf_impl_destroy(&self->kem)`.
  - `did_setup_rng`: Remove `vscf_ml_kem_use_random(...)`.
  - In the PQC ratchet-step method: create `kem_alg` on demand from the sender/receiver chain's `public_key_second` via `vscf_key_alg_factory_create_from_key`; use `vscf_kem_kem_encapsulated_key_len(kem_alg, key)` instead of `KEM_ENCAPSULATED_KEY_LEN`; destroy `kem_alg` after use.
- Regenerate ratchet project after model change.

**Test scenarios:**
- Happy path: Double-ratchet step with ML-KEM-768 second key produces correct encapsulated key and derived chain key.
- Happy path: Double-ratchet step with no second key (`public_key_second == NULL`) skips KEM step — classical ratchet only.
- Integration: Full session encrypt/decrypt round-trip with PQC keys passes `test_ratchet_session_integration`.

**Verification:**
- `vscr_ratchet_keys.c` contains no reference to `vscf_ml_kem_new`, `vscf_ml_kem_use_random`, or `KEM_ENCAPSULATED_KEY_LEN`.
- `test_ratchet_keys` C test passes.

---

- [ ] **Unit 5: Refactor `vscr_ratchet_key_utils.c` — capability checks, remove `enable_post_quantum`**

**Goal:** Replace all hard-coded algorithm ID checks (`vscf_alg_id_ML_KEM_768`, `vscf_alg_id_FALCON`) with capability interface checks; remove `enable_post_quantum` and `with_signer` parameters from `import_private_key` and `import_public_key` internal functions; second-key extraction becomes unconditional (present when key structure contains it, absent when not).

**Requirements:** R2, R5

**Dependencies:** None (can proceed in parallel with Units 1–4)

**Files:**
- Modify: `library/ratchet/src/vscr_ratchet_key_utils.c`

**Approach:**
- Remove the `bool enable_post_quantum` and `bool with_signer` parameters from `vscr_ratchet_key_utils_import_private_key` and `vscr_ratchet_key_utils_import_public_key` (internal functions; callers in `vscr_ratchet_session.c` updated in Unit 7).
- Replace the 6 `vscf_alg_id_ML_KEM_768` checks: after extracting the candidate second KEM key, call `vscf_key_alg_factory_create_from_key(key, NULL, &error)` and assert `vscf_kem_is_implemented(alg)`. If not implemented, return an appropriate error. Destroy the factory object.
- Replace the 6 `vscf_alg_id_FALCON` checks: after extracting the candidate signer key, assert `vscf_key_signer_is_implemented(alg)`.
- Remove the `if (enable_post_quantum) { ... set second_key_ref ... } else { *second_key_ref = NULL; }` branches — always attempt extraction; if no second component found in key structure, set to NULL.
- Keep the `vscf_alg_id_CURVE25519` and `vscf_alg_id_ED25519` checks for the "first" classical layer — these remain in scope.

**Patterns to follow:**
- `library/ratchet/src/vscr_ratchet_key_utils.c` lines 268–400 — existing compound/hybrid unwrapping logic; the structure is preserved, only the alg-ID guards are replaced.

**Test scenarios:**
- Happy path: compound(Ed25519, Falcon) identity key → signer component extracted; second_kem_ref = NULL.
- Happy path: compound(Curve25519, ML-KEM-768) long-term key → KEM component extracted; second_signer_ref = NULL.
- Happy path: bare Curve25519 key → first = raw key, second_kem = NULL, second_signer = NULL.
- Happy path: hybrid(Curve25519, ML-DSA-65) identity key → ML-DSA-65 component extracted as signer (validates `vscf_key_signer_is_implemented`).
- Error path: second component found but implements neither KEM nor key_signer → error returned.
- Edge case: compound key where cipher_key is Ed25519 (signer) and signer_key is ML-KEM-768 (KEM) — unusual but the code should assign based on capability, not position.

**Verification:**
- `vscr_ratchet_key_utils.c` contains no reference to `vscf_alg_id_ML_KEM_768` or `vscf_alg_id_FALCON`.
- `test_ratchet_keys` and `test_ratchet_xxdh` pass.

---

- [ ] **Unit 6: Update protobuf schema and `vscr_ratchet_pb_utils.c` — algorithm-agnostic serialization**

**Goal:** Store algorithm IDs alongside second-key bytes in the protobuf schema; update `vscr_ratchet_pb_utils.c` to use stored alg IDs during deserialization instead of hard-coding `vscf_alg_id_ML_KEM_768`; bump session wire format version.

**Requirements:** R6

**Dependencies:** None (can proceed in parallel)

**Files:**
- Modify: `library/ratchet/protobuf/vscr_RatchetSession.proto`
- Modify: `library/ratchet/src/vscr_ratchet_pb_utils.c`
- Modify (regenerated nanopb): `library/ratchet/src/vscr_RatchetSession.pb.h`, `library/ratchet/src/vscr_RatchetSession.pb.c`

**Approach:**
- Add `optional uint32 second_key_alg_id = 10;` to `vscr_SenderChain`.
- Add `optional uint32 second_key_alg_id = 10;` to `vscr_ReceiverChain`.
- Add `optional uint32 kem_alg_id = 10;` and `optional uint32 signer_alg_id = 11;` to `vscr_SessionPqcInfo`.
- Remove `required bool enable_post_quantum` from both `vscr_Session` (field 4) and `vscr_Ratchet` (field 6). Replace with `optional bool enable_post_quantum = 4/6` for load-time backwards compatibility (field 4/6 reads as false when absent in new sessions).
- Bump `vscr_Session.version`: the serializer writes `version = 2`; the deserializer accepts both 1 (legacy, reconstruct as ML-KEM-768 for second keys) and 2 (new format, use stored alg IDs).
- In `vscr_ratchet_pb_utils_deserialize_public_key` / `deserialize_private_key`: use `stored_alg_id` from the proto field; for version-1 sessions, default to `vscf_alg_id_ML_KEM_768`.
- In serialize direction: write the key's actual `vscf_alg_id` via `vscf_key_info_alg_id(vscf_key_info_new_with_alg_info(vscf_key_alg_info(key)))`.

**Patterns to follow:**
- `library/ratchet/src/vscr_ratchet_pb_utils.c` lines 300–360 — existing serialize/deserialize pattern.

**Test scenarios:**
- Happy path: Serialize a PQC session and deserialize it — all keys round-trip correctly with the new format.
- Happy path: Serialize a classical-only session (no second keys) and deserialize it — `second_key_alg_id` absent; no KEM/signer keys reconstructed.
- Backwards compat: A version-1 session blob (ML-KEM-768 hardcoded) deserializes correctly using the legacy path.
- Error path: Version-1 session blob with unknown alg in a version-2 context → `vscr_status_ERROR_SESSION_IS_NOT_INITIALIZED` or equivalent.
- Integration: Serialize then deserialize a full session; re-encrypt/decrypt a message with the restored session.

**Verification:**
- `vscr_ratchet_pb_utils.c` contains no hard-coded `vscf_alg_id_ML_KEM_768`.
- `test_ratchet_session_serialization` C test passes.

---

- [ ] **Unit 7: Update `vscr_ratchet_session.c` and codegen model — remove `enable_post_quantum` from public API**

**Goal:** Remove `bool enable_post_quantum` from all four public session methods (`initiate`, `initiate_no_one_time_key`, `respond`, `respond_no_one_time_key`); update the codegen model and regenerate; update callers of internal `key_utils` functions.

**Requirements:** R1, R2

**Dependencies:** Units 5, 6

**Files:**
- Modify: `codegen/models/project_ratchet/class_ratchet_session.xml`
- Modify (regenerated): `library/ratchet/include/virgil/crypto/ratchet/vscr_ratchet_session.h`, `library/ratchet/src/vscr_ratchet_session.c`
- Modify: `library/ratchet/src/vscr_ratchet_session.c` (hand-written sections)

**Approach:**
- Remove `<argument name="enable post quantum" type="bool"/>` from all four method declarations in `class_ratchet_session.xml`.
- Regenerate ratchet project — this updates the public header and generated method stubs.
- In `vscr_ratchet_session.c` hand-written sections: update the 26 `enable_post_quantum` references.
  - Calls to `vscr_ratchet_key_utils_import_private/public_key` lose the `enable_post_quantum` param (Unit 5 removed it).
  - The `self->enable_post_quantum` session field is replaced with runtime detection: session is considered PQC-enabled when `second_kem_key` or `second_signer_key` is non-NULL after key import.
  - The serialized `enable_post_quantum` bool in the proto is written as `(second_keys_present)` for new sessions; for deserialized sessions, it is inferred from whether any second keys were reconstructed.
- Update `vscr_ratchet_session_is_pqc_enabled()` to return whether the session has any PQC key material, not a stored bool.

**Patterns to follow:**
- Existing `initiate`/`respond` logic in `vscr_ratchet_session.c` — keep the same flow, just drop the flag propagation.

**Test scenarios:**
- Happy path: `initiate` with compound keys → session is PQC-enabled, `is_pqc_enabled()` returns true.
- Happy path: `initiate` with bare Curve25519/Ed25519 keys → session is classical-only, `is_pqc_enabled()` returns false.
- Happy path: `respond` without one-time key matches initiator session — both PQC and classical variants.
- Integration: Full initiate + respond + encrypt + decrypt round-trip, PQC keys.
- Integration: Full initiate + respond + encrypt + decrypt round-trip, classical keys only.

**Verification:**
- Public header `vscr_ratchet_session.h` no longer contains `bool enable_post_quantum` in any method signature.
- `vscr_ratchet_session_is_pqc_enabled()` returns correct value for both key configurations.
- `test_ratchet_session_integration` all four cases (pqc/no-pqc × one-time/no-one-time) pass.

---

- [ ] **Unit 8: Regenerate all language wrappers and update wrapper-level APIs**

**Goal:** Run codegen for all projects; update Java, Swift, and WASM wrapper methods to remove the `enablePostQuantum` parameter; verify wrapper tests compile.

**Requirements:** R7

**Dependencies:** Unit 7

**Files:**
- Modify (regenerated): `wrappers/java/ratchet/src/main/java/com/virgilsecurity/crypto/ratchet/RatchetSession.java`
- Modify (regenerated): `wrappers/java/android/ratchet/` (mirrors desktop)
- Modify (regenerated): `wrappers/swift/VirgilCrypto/VirgilCryptoRatchet/RatchetSession.swift`
- Modify (regenerated): `wrappers/wasm/ratchet/src/RatchetSession.js`
- Modify (regenerated): relevant generated C JNI / Swift bridge files

**Approach:**
- Run `python3 -m tools.codegen.common_bootstrap --project all --apply` after Unit 7 completes.
- Verify that `enablePostQuantum` (and equivalents) no longer appear in any of the four wrapper initiation/response methods.
- If any wrapper has hand-written glue code that passes `enable_post_quantum` to the C layer, update it.

**Test scenarios:**
- Test expectation: none for generated wrapper code itself — wrapper API shape is verified by compilation; behavioral correctness is covered by the C-level tests in Unit 9.

**Verification:**
- `grep -r "enablePostQuantum\|enable_post_quantum" wrappers/` returns no results in the ratchet session API files.
- WASM, Java, Swift wrapper projects build without errors.

---

- [ ] **Unit 9: Update C tests — compound-key and classical-only scenarios**

**Goal:** Update all existing ratchet tests that pass `enable_post_quantum` or reference specific PQC algorithms; add tests for compound-key sessions and classical-only sessions using the new API.

**Requirements:** R8

**Dependencies:** Units 3–7

**Files:**
- Modify: `tests/ratchet/test_ratchet_xxdh.c`
- Modify: `tests/ratchet/test_ratchet_session_integration.c`
- Modify: `tests/ratchet/test_ratchet_session_serialization.c`
- Modify: `tests/ratchet/src/test_utils_ratchet.c` (helper that calls `initiate`/`respond`)
- Modify: `tests/ratchet/data/src/` (update KAT vectors if needed after protocol change)

**Approach:**
- Remove all `enable_pqc` boolean parameters from test helper calls.
- In `test_utils_ratchet.c`: `generate_identity_private_key(key_provider, enable_pqc)` and `generate_ephemeral_private_key(...)` should now generate compound keys (or not) purely based on the key type — the test helper decides what key type to generate, not a flag.
- XXDH tests: Replace `vscf_alg_id_FALCON` / `vscf_alg_id_ML_KEM_768` key generation with compound key generation using `vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_COMPOUND_KEY, ...)` (if compound key generation is supported) or the equivalent two-key compound construction.
- Add test: session with bare Ed25519/Curve25519 keys (no PQC component) — full initiate/respond/encrypt/decrypt.
- Add test: session with compound keys using ML-DSA-65 as signer instead of Falcon — validates algorithm agnosticism.
- Update `test_ratchet_session_serialization` to generate a new KAT vector for the new wire format.

**Patterns to follow:**
- `tests/ratchet/src/test_utils_ratchet.c` — key generation helpers; mirror the compound-key construction pattern used for existing PQC tests.
- `tests/foundation/test_compound_key_alg.c` — compound key generation pattern in foundation tests.

**Test scenarios:**
- Happy path: Full session (initiate + respond + 10 messages) with compound(Curve25519/Ed25519 first, ML-KEM-768/Falcon second) keys — matches current behavior.
- Happy path: Full session with bare Curve25519/Ed25519 keys — no PQC material, `is_pqc_enabled()` = false.
- Happy path: Full session with ML-DSA-65 as signer (compound identity key) + ML-KEM-768 as KEM (hybrid long-term key).
- Integration: Serialize PQC session, deserialize, continue messaging — messages decrypt correctly.
- Integration: Serialize classical session, deserialize, continue messaging — messages decrypt correctly.
- Edge case: Initiator uses compound keys, responder code reconstructs session from the wire message — verifies KEM/signer alg IDs round-trip through the protobuf.

**Verification:**
- `ctest -R ratchet` — all ratchet tests pass.
- No test source file references `vscf_alg_id_ML_KEM_768` or `vscf_alg_id_FALCON` for key generation (only for KAT vector comparison if fixed-vector tests remain).

## System-Wide Impact

- **Interaction graph:** `vscr_ratchet_session_t` → `vscr_ratchet_key_utils` → `vscr_ratchet_xxdh` → `vscf_key_alg_factory` + `vscf_kem` + `vscf_key_signer`. The factory call chain adds two levels of indirection vs the direct `vscf_falcon_*` calls today — negligible performance impact for session initiation (not on the hot message path).
- **Error propagation:** `vscf_key_alg_factory_create_from_key` returns NULL + error on failure; the ratchet must propagate this as a new or existing error status code (likely `vscr_status_ERROR_KEY_AGREEMENT`). Define clearly in Unit 5.
- **State lifecycle risks:** Sessions serialized before this change cannot be deserialized with the new library (version 1 → version 2 format break). Document this prominently in the commit and any release notes. Provide a compatibility path for version-1 sessions if downstream consumers exist.
- **API surface parity:** All four language wrappers (Java, Swift, WASM) must be updated in sync. Group session API is unaffected.
- **Integration coverage:** The existing `test_ratchet_session_integration.c` exercises the full initiate/respond/message chain — it must be updated and extended to cover the classical-only path.
- **Unchanged invariants:** The double ratchet KDF chain (Curve25519 DH, HKDF root key derivation) is not changed. The XXDH message format (encapsulated key blobs in the prekey message) is unchanged in structure; only algorithm IDs are added to the serialized session state.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Wire format break breaks existing in-flight sessions | Version-1 backwards compat path in `pb_utils` (Unit 6); document as a breaking change at the library version level |
| `vscf_key_alg_factory_create_from_key` performance cost per ratchet step | Factory is only called during XXDH initiation (rare) and double-ratchet KEM step (per key rotation, not per message); acceptable |
| Compound key generation API may not expose a clean single-call path | Fall back to constructing compound key from two generated sub-keys using `vscf_compound_key_alg_make_key` — check in Unit 9 |
| ML-DSA-65 signature size differs from Falcon (different `signature_len`) — existing `MAX_SESSION_LEN` (55000) may need adjustment | Verify `vscf_key_signer_signature_len` values for all planned signers during Unit 3; update `max_session_len` if needed |
| `enable_post_quantum` removal is a breaking API change for all callers | Callers migrate by removing the flag; the key type carries the algorithm choice |

## Documentation / Operational Notes

- This change is a **wire format break**: sessions serialized with the current library cannot be loaded by the refactored library unless the version-1 compatibility path is included. Announce in the PR and changelog.
- All callers of `vscr_ratchet_session_initiate`/`respond` must remove the final `bool` argument. The key type passed determines whether PQC is active.

## Sources & References

- Related code: `library/ratchet/src/vscr_ratchet_xxdh.c`, `vscr_ratchet_key_utils.c`, `vscr_ratchet_pb_utils.c`
- Related code: `library/foundation/include/virgil/crypto/foundation/vscf_key_signer.h`, `vscf_kem.h`, `vscf_key_alg_factory.h`
- Related PR: #180 (current branch — this plan extends that work)
