---
title: "Ratchet algorithm-agnostic API: infer PQC capability from key structure, not a boolean flag"
date: 2026-04-28
category: docs/solutions/best-practices
module: ratchet
problem_type: best_practice
component: service_object
severity: medium
applies_when:
  - Adding or changing the set of algorithms used in a ratchet session
  - Designing or refactoring public APIs where a boolean flag mirrors an optional key argument
  - Serializing keys in protobuf fields where the algorithm type may vary
  - Changing a proto field from required to optional for backward compatibility
tags:
  - ratchet
  - post-quantum
  - ml-kem
  - algorithm-agnostic
  - api-design
  - boolean-flag
  - key-structure
  - protobuf
  - backward-compat
  - nanopb
  - der
  - asn1
---

# Ratchet algorithm-agnostic API: infer PQC capability from key structure, not a boolean flag

## Context

The ratchet session API originally exposed a boolean `enable_post_quantum` parameter on all four session methods (`initiate`, `initiate_no_one_time_key`, `respond`, `respond_no_one_time_key`). Callers had to explicitly pass `true` to activate hybrid PQC mode and supply two key pairs; passing `false` activated classical mode with one key pair. This created two sources of truth that could diverge: the boolean and the keys themselves. It also meant adding a new algorithm variant would require yet another boolean parameter.

## Guidance

**Remove the algorithm-mode boolean from the public API. Let the key structure communicate algorithm capability.**

**Initiator side** — derive from the second receiver key argument:
```c
bool enable_post_quantum = (receiver_long_term_public_key_second != NULL);
self->enable_post_quantum = enable_post_quantum;
```

**Responder side** — derive from the incoming message header:
```c
bool enable_post_quantum = message->header_pb.has_pqc_info;
self->enable_post_quantum = enable_post_quantum;
```

**Protobuf serialization** — when storing the derived value, use DER/ASN.1 for key fields and nanopb `has_*` flags for optional booleans:

```c
// Keys: use vscf_key_asn1_serializer — embeds the OID so the format is self-describing
vscr_ratchet_pb_utils_serialize_public_key(key, &pb_buffer);

// Boolean fields: if changing required → optional in .proto for backward compat,
// always set has_* so old decoders still find the value
session_pb.has_enable_post_quantum = true;
session_pb.enable_post_quantum = self->enable_post_quantum;
```

**Deserialization** — after ASN.1 deserialization, complete the import pipeline to resolve `impl_tag`:
```c
// vscf_raw_public_key_new_with_data leaves impl_tag = BEGIN; fix it:
vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_raw_public_key(raw_key, NULL, &err);
*key_ref = vscf_key_alg_import_public_key(key_alg, raw_key, &err);
```
See [`docs/solutions/logic-errors/ratchet-der-deserialized-key-impl-tag-begin-2026-04-28.md`](../logic-errors/ratchet-der-deserialized-key-impl-tag-begin-2026-04-28.md) for the full explanation.

## Why This Matters

A boolean flag that mirrors a nullable key parameter is redundant and failure-prone. If both exist, they can be passed inconsistently (flag says PQC, key is NULL; or vice versa). Removing the boolean collapses the two sources of truth to one: the keys.

DER/ASN.1 key serialization embeds the algorithm OID in the wire format. The protobuf schema does not need algorithm-specific fields for each key type; any key type supported by the foundation library round-trips through `serialize_public_key` / `deserialize_public_key` without modification. Adding a new algorithm requires no proto schema changes.

The `required → optional` proto change with always-set `has_*` gives backward wire compatibility: decoders compiled against the old schema still find the field; decoders compiled against the new schema gracefully handle its absence in old messages.

## When to Apply

- A ratchet or similar session protocol adds a new algorithm variant that changes which keys are passed — infer the variant from the key set rather than adding a new boolean.
- Serializing/deserializing keys of varying algorithm type in protobuf — use DER/ASN.1 via `vscf_key_asn1_serializer` rather than raw bytes with a companion alg-id field.
- Changing a proto field from `required` to `optional` for backward compat — always write the nanopb `has_*=true` companion on every encode path.

## Examples

**Before — explicit boolean flag:**
```c
// XML model (class_ratchet_session.xml):
// <argument name="enable post quantum" type="boolean">…</argument>

// Caller (test_utils_ratchet.c):
vscr_ratchet_session_initiate(session,
    sender_id_priv, sender_id,
    recv_id_pub,    recv_id,
    recv_lt_pub,    recv_lt_id,
    recv_ot_pub,    recv_ot_id,
    enable_pqc          // ← explicit boolean
);
```

**After — inferred from key structure:**
```c
// Caller — no boolean; two LT keys → PQC, one LT key → classical:
vscr_ratchet_session_initiate(session,
    sender_id_priv,        sender_id,
    recv_id_pub,           recv_id,
    recv_lt_pub_classical, recv_lt_id,
    recv_lt_pub_pqc,       recv_lt_id,  // second LT key = ML-KEM; NULL = classical
    recv_ot_pub,           recv_ot_id
);

// Inside vscr_ratchet_session_initiate():
bool enable_post_quantum = (receiver_long_term_public_key_second != NULL);
self->enable_post_quantum = enable_post_quantum;
```

**Proto change: required → optional with has_* guard:**
```protobuf
// Before:
required bool enable_post_quantum = 6;

// After:
optional bool enable_post_quantum = 6;
```
```c
// Encode — nanopb requires has_* = true to write optional fields:
ratchet_pb.has_enable_post_quantum = true;
ratchet_pb.enable_post_quantum = self->enable_post_quantum;
```

## Related

- [`docs/solutions/logic-errors/ratchet-der-deserialized-key-impl-tag-begin-2026-04-28.md`](../logic-errors/ratchet-der-deserialized-key-impl-tag-begin-2026-04-28.md) — the `impl_tag_BEGIN` bug encountered when implementing DER key serialization in `vscr_ratchet_pb_utils.c`
- [`docs/solutions/logic-errors/key-alg-factory-missing-pq-cases-2026-04-27.md`](../logic-errors/key-alg-factory-missing-pq-cases-2026-04-27.md) — prerequisite fix: factory must have cases for ML-KEM/ML-DSA before DER deserialization can succeed
