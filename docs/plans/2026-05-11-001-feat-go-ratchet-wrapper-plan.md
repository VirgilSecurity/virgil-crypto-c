---
title: "Add Ratchet Wrapper for Go"
status: active
created: 2026-05-11
---

# Add Ratchet Wrapper for Go

## Problem Frame

The Go wrapper currently exposes only `foundation` and `phe` packages. The `ratchet` library (double-ratchet E2E encryption sessions) is already wrapped for Java, Swift, and WASM but missing from Go. Go consumers need ratchet to build end-to-end encrypted messaging.

## Scope

Add `wrappers/go/ratchet/` package by:
1. Enabling ratchet in codegen config and CMake
2. Running codegen to generate the Go files
3. Writing handwritten tests

**Out of scope**: group session Go wrapper, adding ratchet to the CMakeLists install (Go wrapper uses pre-built static libs from `pkg/`, not CMake install).

## Requirements

- `wrappers/go/ratchet/` package builds cleanly with CGo
- `RatchetSession` and `RatchetMessage` types are exposed
- `RatchetSession` supports initiate, initiate_no_one_time_key, respond, respond_no_one_time_key, encrypt, decrypt, serialize, deserialize
- `RatchetMessage` supports get_type, get_counter, key-ID accessors, serialize, deserialize
- Tests exercise the full initiator↔responder round-trip using real keys from `foundation`
- Go tests pass in CI (`go test ./...` from `wrappers/go/`)
- Feature branch cut from `develop`

## Implementation Units

### Unit 1: Enable ratchet in codegen and CMake config

**Goal**: Make codegen generate Go files for the ratchet project, and ensure CI builds include `libvsc_ratchet.a`.

**Files to modify**:
- `codegen/models/project_ratchet/project_ratchet.xml` — add `go` to `wrappers` attribute
- `configs/go-config.cmake` — flip `VIRGIL_LIB_RATCHET` from `OFF` to `ON`

**Approach**:
- In `project_ratchet.xml`: change `wrappers="java,swift,wasm"` → `wrappers="java,swift,wasm,go"`
- In `configs/go-config.cmake`: change `set(VIRGIL_LIB_RATCHET OFF ...)` → `set(VIRGIL_LIB_RATCHET ON ...)`
- No CMakeLists.txt changes needed — CI uses `VIRGIL_INSTALL_WRAP_LIBS=ON` which picks up the ratchet lib automatically once enabled

**Verification**: `grep -r 'go' codegen/models/project_ratchet/project_ratchet.xml` shows `go` in wrappers; `grep RATCHET configs/go-config.cmake` shows `ON`

---

### Unit 2: Run codegen to generate `wrappers/go/ratchet/` package

**Goal**: Produce the generated Go wrapper files for the ratchet library.

**Patterns to follow**: `wrappers/go/phe/` — all generated files follow the same structure as phe.

**Command**:
```
python3 -m tools.codegen.common_bootstrap --project ratchet --apply
```

**Expected generated files** in `wrappers/go/ratchet/` (names may vary slightly per codegen template):
- `platform.go` — CGo flags (CFLAGS/LDFLAGS per platform)
- `context.go` — `context` interface with `Ctx() uintptr`
- `helper.go` — `helperWrapData`, `newBuffer`, `buffer` type
- `ratchet_error.go` — `RatchetError` struct, `RatchetErrorHandleStatus`
- `ratchet_common.go` — constants (MAX_PLAIN_TEXT_LEN, KEY_ID_LEN, etc.)
- `ratchet_message.go` — `RatchetMessage` struct, all methods
- `ratchet_session.go` — `RatchetSession` struct, all methods
- `ratchet_msg_type.go` — `MsgType` enum (REGULAR=1, PREKEY=2)

**CGo linker chain for `platform.go`** (patterned after `phe/platform.go`):
```
-lvsc_ratchet -lvsc_ratchet_pb -lvsc_foundation -lvsc_foundation_pb -led25519 -lprotobuf-nanopb -lvsc_common -lmbedcrypto -lfalcon -lmlkem768 -lmldsa65
```
Windows adds `-lbcrypt`. The PQC libs (falcon, mlkem768, mldsa65) are needed because ratchet depends on `foundation` which links them.

**Important**: The codegen may not produce `platform.go` automatically (phe has one but foundation doesn't). If codegen doesn't produce it, write it by hand mirroring `phe/platform.go` with the ratchet linker chain.

**Verification**: `ls wrappers/go/ratchet/*.go` shows multiple files; `cd wrappers/go && go build ./ratchet/` succeeds locally once static libs are present.

---

### Unit 3: Write handwritten tests

**Goal**: Verify the Go ratchet wrapper end-to-end using real keys, covering the full session lifecycle.

**Patterns to follow**: `wrappers/go/phe/phe_client_test.go` — use `require` from testify, initialize dependencies via `SetupDefaults()`, helper functions for shared setup.

**Files to create**:
- `wrappers/go/ratchet/ratchet_session_test.go`
- `wrappers/go/ratchet/ratchet_message_test.go`

#### Test scenarios for `ratchet_session_test.go`

| Scenario | Coverage |
|----------|----------|
| `TestNewRatchetSession` | Construct, `SetupDefaults`, `Delete` without panic |
| `TestInitiateAndRespond_FullRoundTrip` | Initiator calls `Initiate`, responder calls `Respond`, both exchange messages successfully via `Encrypt`/`Decrypt` |
| `TestInitiateNoOneTimeKey_FullRoundTrip` | Same as above but using `InitiateNoOneTimeKey`/`RespondNoOneTimeKey` — verifies the optional one-time key path is not required |
| `TestIsInitiator` | After `Initiate`, `IsInitiator()` returns true; after `Respond`, returns false |
| `TestMultipleMessageExchange` | Both sides exchange multiple messages in alternating order after initial handshake |
| `TestSerializeDeserializeSession` | Serialize session to bytes, deserialize, continue sending/receiving messages |
| `TestEncryptPlaintextTooLong` | Encrypting >30000 bytes returns an error |

**Key setup for tests** — ratchet keys are raw Curve25519 key pairs, not `vscf_impl_t` instances loaded through `KeyProvider`. The `Initiate`/`Respond` functions accept `foundation.PrivateKey`/`foundation.PublicKey` interfaces (via `Ctx()` uintptr → `*C.vscf_impl_t`). Use `foundation.Ed25519` or `foundation.Curve25519` key generation:
```go
keyProvider := foundation.NewKeyProvider()
keyProvider.SetupDefaults()
senderIdentityPriv, _ := keyProvider.GeneratePrivateKey(foundation.AlgIdCurve25519)
senderIdentityPub := senderIdentityPriv.ExtractPublicKey()
```
Key IDs are 8-byte slices (`vscr_ratchet_common_KEY_ID_LEN = 8`) — use any distinct byte arrays in tests.

#### Test scenarios for `ratchet_message_test.go`

| Scenario | Coverage |
|----------|----------|
| `TestRatchetMessage_GetType_Prekey` | After `Initiate` + `Encrypt`, first message has type `MsgTypePrekey` |
| `TestRatchetMessage_GetType_Regular` | After first response received, subsequent messages have type `MsgTypeRegular` |
| `TestRatchetMessage_GetCounter` | Counter increments for each message sent in the same ratchet step |
| `TestRatchetMessage_Serialize_Deserialize` | Serialize a message to bytes, deserialize, type/counter/key IDs match |
| `TestRatchetMessage_KeyIds_Prekey` | On a prekey message: sender/receiver identity key IDs, long-term key ID are non-empty; one-time key ID non-empty when one-time key was used |
| `TestRatchetMessage_KeyIds_NoOneTimeKey` | On a no-one-time-key prekey message: one-time key ID is empty |

**Verification**: `cd wrappers/go && go test ./ratchet/ -v` passes all tests (requires locally built ratchet static libs in `pkg/`).

---

## Dependencies and Sequencing

Unit 1 (config changes) → Unit 2 (codegen) → Unit 3 (tests)

Units 1 and 2 must be sequential: codegen reads `project_ratchet.xml` to decide whether to emit Go output.

## Key Decisions

**Codegen vs. hand-write**: Use codegen for all type wrappers — it handles memory lifecycle, error translation, and CGo bridging correctly. Only `platform.go` (CGo flags) and tests are hand-written, as codegen doesn't generate those.

**Test key types**: Use `Curve25519` keys for all ratchet key material — that is what the C ratchet library expects internally. The `vscf_impl_t*` parameter in `Initiate`/`Respond` is the foundation interface pointer obtained from Go `foundation.PrivateKey.Ctx()`.

**No local build requirement for the PR**: The Go test CI matrix (`build-go.yml`) builds the static libs and then runs `go test ./...`, so tests are validated in CI. Local `go test` for ratchet requires a local build of `libvsc_ratchet.a` — document this in a comment in the test file if needed.

## Test Infrastructure Note

`go test ./...` in `wrappers/go/` will pick up `./ratchet/` automatically once the package exists. No changes to test runner config are needed. The CI workflow already runs `go test ./...` on platforms with `run_tests: true`.

## Files Summary

| File | Action |
|------|--------|
| `codegen/models/project_ratchet/project_ratchet.xml` | Modify — add `go` to wrappers |
| `configs/go-config.cmake` | Modify — `VIRGIL_LIB_RATCHET OFF` → `ON` |
| `wrappers/go/ratchet/platform.go` | Generated or hand-written |
| `wrappers/go/ratchet/context.go` | Generated |
| `wrappers/go/ratchet/helper.go` | Generated |
| `wrappers/go/ratchet/ratchet_error.go` | Generated |
| `wrappers/go/ratchet/ratchet_common.go` | Generated |
| `wrappers/go/ratchet/ratchet_msg_type.go` | Generated |
| `wrappers/go/ratchet/ratchet_message.go` | Generated |
| `wrappers/go/ratchet/ratchet_session.go` | Generated |
| `wrappers/go/ratchet/ratchet_session_test.go` | Hand-written (new) |
| `wrappers/go/ratchet/ratchet_message_test.go` | Hand-written (new) |

## Risks

- **Codegen doesn't emit `platform.go`**: Verified that `phe/platform.go` exists but no equivalent in `foundation/`. If codegen omits it, write it by hand mirroring `phe/platform.go` with the ratchet linker chain.
- **PQC libs in linker chain**: `foundation` now links falcon/mlkem768/mldsa65. `ratchet` depends on foundation, so the ratchet `platform.go` linker flags must include those PQC libs or the build will fail with undefined symbols at link time.
- **Key type mismatch in test setup**: The ratchet C API expects Curve25519 impl pointers. Passing an Ed25519 key where Curve25519 is expected will return `ERROR_INVALID_KEY_TYPE`. Use `AlgIdCurve25519` consistently in tests.
