# Ratchet Protocol — Key Roles, PQC Matrix, and Wire Compatibility

## Key roles

| Role | Classic type | PQC type | Per session? |
|---|---|---|---|
| Sender identity key (`IK_s`) | ED25519 / CURVE25519 | compound(ED25519 + ML-DSA/Falcon) + hybrid(CURVE25519 + ML-KEM-768) | No — long-lived |
| Receiver identity key (`IK_r`) | ED25519 / CURVE25519 | compound + hybrid | No — long-lived |
| Receiver long-term / SPK (`SPK_r`) | CURVE25519 | hybrid(CURVE25519 + ML-KEM-768) | No — rotated occasionally |
| Receiver one-time prekey / OPK (`OPK_r`) | CURVE25519 | hybrid(CURVE25519 + ML-KEM-768) | Yes — consumed per session |
| Sender ephemeral key (`EK_s`) | CURVE25519 | CURVE25519 (never hybrid) | Yes — generated per session |
| Ratchet keys | CURVE25519 (per message) | CURVE25519 + ML-KEM-768 | Yes — advanced per ratchet step |

## XXDH handshake (session initiation)

### Classic DH inputs (always present)

```
DH1 = DH(IK_s, SPK_r)      -- sender identity × receiver long-term
DH2 = DH(EK_s, IK_r)       -- sender ephemeral × receiver identity
DH3 = DH(EK_s, SPK_r)      -- sender ephemeral × receiver long-term
DH4 = DH(EK_s, OPK_r)      -- sender ephemeral × receiver OTK  (only if OPK present)
```

### PQC KEM inputs (present only when enabled)

`enable_post_quantum` is set iff `SPK_r` has an ML-KEM component (`receiver_long_term_public_key_second != NULL`). It is determined entirely by the receiver's long-term key at the moment the sender calls `initiate`.

| Field in `PrekeyMessagePqcInfo` | Proto | Present when |
|---|---|---|
| `encapsulated_key1` | optional | `IK_r` has ML-KEM component |
| `encapsulated_key2` | **required** | `enable_post_quantum = true` (always) |
| `encapsulated_key3` | optional | `OPK_r` has ML-KEM component AND receiver has OTK |
| `decapsulated_keys_signature` | optional | `IK_s` has ML-DSA/Falcon signer AND ≥1 KEM was done |

The signature covers SHA-512 of the concatenated KEM shared secrets. It is verified by the receiver only when the sender's identity key exposes a verifier (`sender_identity_public_key_second_verifier != NULL`). If absent (sender has plain identity), it is silently skipped.

### Shared key derivation

```
shared_secret = DH1 ‖ DH2 ‖ DH3 [‖ DH4] [‖ KEM1] [‖ KEM2] [‖ KEM3]
shared_key    = HKDF-SHA-512(shared_secret, info="VIRGIL_RATCHET_KDF_ROOT_INFO")
```

## Sender × receiver PQC matrix

"Sender PQC" = `IK_s` has compound key with ML-DSA/Falcon signer.  
"Receiver PQC" = `SPK_r` has ML-KEM component (controls `enable_post_quantum`).

| Sender | Receiver | `enable_pqc` | `key1` | `key2` | `key3` | `sig` | Ratchet PQC | 0.17 wire compat |
|---|---|---|---|---|---|---|---|---|
| plain | plain | false | — | — | — | — | No | ✓ |
| PQC | plain | false | — | — | — | — | No | ✓ |
| plain | PQC | true | iff `IK_r` hybrid | ✓ | iff `OPK_r` hybrid | — | Yes | ✗ |
| PQC | PQC | true | iff `IK_r` hybrid | ✓ | iff `OPK_r` hybrid | ✓ | Yes | ✗ |

**Case: sender=plain, receiver SPK=hybrid but identity=plain** (the rc.14 bug scenario):
- `key1` is absent (sender has no ML-KEM public key for `IK_r`)
- `key2` present, `key3` present if OPK is hybrid
- No signature (sender has no Falcon/ML-DSA key)
- This is valid. The serialized session and prekey message have no `encapsulated_key1` field on the wire.

**Sub-cases of receiver PQC** (each key type is independently hybrid or plain):

| `IK_r` | `SPK_r` | `OPK_r` | `enable_pqc` | `key1` | `key2` | `key3` |
|---|---|---|---|---|---|---|
| plain | hybrid | hybrid | true | absent | present | present |
| hybrid | hybrid | hybrid | true | present | present | present |
| plain | hybrid | plain/absent | true | absent | present | absent |
| plain | plain | any | false | — | — | — |

## Double Ratchet (post-handshake)

When `enable_post_quantum = true`, each ratchet step combines classic DH with a KEM step:

```
sender_chain.private_key_second   -- fresh ML-KEM private key, generated each ratchet step
sender_chain.public_key_second    -- corresponding ML-KEM public key (sent in RegularMessageHeader)
sender_chain.encapsulated_key     -- KEM(sender_chain.public_key_second, receiver_chain.public_key_second)
```

`RegularMessageHeader.pqc_info` carries `public_key` (sender's new ML-KEM pub) and `encapsulated_key` (KEM output). Both are **required** fields in the header proto — unlike the XXDH prekey fields, they are never optional: when `enable_post_quantum = true`, every regular message header must carry them. If either is missing on decrypt, the session returns an error.

## 0.17 wire compatibility

A session is wire-compatible with 0.17 when `enable_post_quantum = false`:
- Prekey message: `has_pqc_info = false` → no PQC bytes on wire
- Regular message header: `has_pqc_info = false` → no PQC bytes on wire
- Wire bytes are identical to a 0.17 session

This covers two cases from the matrix above: (plain sender + plain receiver) and (PQC sender + plain receiver). In both, the receiver's `SPK_r` has no ML-KEM component, so no KEM is attempted.

A 0.17 client can safely initiate and receive sessions from a 0.19 client **as long as that 0.17 client's prekey bundle does not include hybrid keys**. The moment a client publishes an `SPK_r` with ML-KEM, inbound sessions from any sender (0.17 or 0.19) will use `enable_post_quantum = true` and the resulting messages will not be decodable by 0.17.

## Known limitation: mixed OTK pool

If a receiver has upgraded their `SPK_r` to hybrid but still has plain CURVE25519 OTKs in the pool (a migration window scenario), `enable_post_quantum = true` but `key3` is absent. Session initiation and the prekey message work correctly. However, the session serializer enforces:

```c
has_receiver_one_time_key_id != (pqc_info.encapsulated_key3 != NULL)  → error
```

This means a serialized session with (hybrid SPK, plain OTK) will fail to round-trip through `serialize`/`deserialize`. Avoid this configuration: upgrade all OTKs to hybrid at the same time as `SPK_r`.
