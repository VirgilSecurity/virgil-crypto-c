# Threat model

## What this project does and where untrusted input enters

virgil-crypto-c is a C cryptographic library (with generated wrappers for Go, Java/Android, Swift, Python, PHP,
WASM and C++). It is embedded in end-to-end-encryption SDKs and backend services, so every byte that arrives from
another party — a peer, a server, a stored blob — must be treated as attacker-controlled. The main untrusted-input
surfaces are:

- **Key import / parsing** (`library/foundation`): `vscf_key_provider_import_{public,private}_key`,
  `vscf_key_asn1_deserializer`, `vscf_pem`, `vscf_base64`, `vscf_asn1rd`, SEC1/PKCS#8, raw/compound/hybrid keys
  (RSA, ECC, Curve25519, Ed25519, Falcon, ML-KEM, ML-DSA).
- **Encrypted / signed message parsing**: `vscf_recipient_cipher` (decryption of messages from unknown senders),
  `vscf_message_info_der_serializer`, `vscf_message_info_footer`, `vscf_alg_info_der_deserializer`,
  `vscf_signed_data_info`, padding (`vscf_random_padding`, `vscf_padding_cipher`).
- **Group sessions** (`vscf_group_session*`): tickets and group messages received from other members.
- **Double Ratchet** (`library/ratchet`): `vscr_ratchet_message` deserialization (nanopb protobufs), session
  restore from serialized state, X3DH-style key agreement (`vscr_ratchet_xxdh`), skipped-message handling.
- **PHE / UOKMS** (`library/phe`): client and server process records, enrollment responses and zero-knowledge
  proofs coming from the other side (`vsce_phe_client`, `vsce_phe_server`, `vsce_uokms_*`).
- **Brainkey, Shamir secret sharing, PBES2/PBKDF2** inputs.

Callers are expected to pass correct buffer lengths; misuse of the C API by the caller (NULL pointers, lying about
sizes) is guarded by assertions and is lower priority than bugs reachable through well-formed API calls with
malicious data.

## Components that matter most / least

- **Most important**: everything under `library/foundation`, `library/ratchet` and `library/phe` that parses or
  decrypts external data; constant-time behaviour of secret-dependent comparisons; correctness of signature and
  proof verification (accepting a forged signature/proof is critical); key/nonce reuse and RNG misuse.
- **In scope but lower priority**: key generation and serialization paths that only handle local data.
- **Out of scope**: `thirdparty/` (mbedTLS, ed25519, falcon, mlkem-native, mldsa-native, nanopb, sss) unless the bug
  is in how this library calls them; generated language wrappers under `wrappers/` (they are thin bindings over the
  C API); `benchmarks/`, `tutorials/`, `tools/codegen`, CI scripts.

## How to exercise it

- `/src/build` — RelWithDebInfo build with all libraries (common, foundation, ed25519, ratchet, phe, post-quantum);
  unit tests via `ctest` (test binaries under `build/tests/`), the `generate_keypair` program under `build/programs/`.
- `/src/build-asan` — the same libraries instrumented with ASan + UBSan, plus libFuzzer harnesses in
  `tests/fuzzy/foundation/src/` (binaries in `build-asan/tests/fuzzy/foundation/fuzzy_test__*/`). New harnesses can
  follow the same pattern for ratchet message deserialization, PEM/base64 and PHE inputs.
- Test vectors live in `tests/foundation/data/`, `tests/ratchet/data/` and `tests/phe/data/`.

## How you rate severity

- **Critical**: remote code execution or memory corruption reachable from parsing/decrypting attacker data;
  signature, proof or authentication-tag forgery/bypass; plaintext or private-key disclosure.
- **High**: out-of-bounds read of secret data, use-after-free/double free, timing side channels leaking key
  material, nonce/key reuse or weak randomness in normal use, ratchet state corruption allowing message replay or
  decryption by a third party.
- **Medium**: denial of service (crash, unbounded allocation, CPU exhaustion) from untrusted input; memory leaks
  on error paths reachable from untrusted input.
- **Low**: issues only reachable through API misuse by the caller, hardening suggestions.

## Anything to leave alone

- Assertion failures (`VSCF_ASSERT*`, `VSCR_ASSERT*`, `VSCE_ASSERT*`) triggered by passing invalid arguments
  (NULL, wrong sizes) directly to the C API — these are intentional caller-contract checks.
- `vscf_fake_random` — a deterministic RNG that exists only for tests.
- Legacy algorithms kept for backward compatibility (e.g. KDF1) unless the bug is exploitable in the default
  configuration.
