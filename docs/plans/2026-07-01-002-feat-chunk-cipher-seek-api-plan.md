---
title: "feat: Add vscf_chunk_cipher seek API (encrypt_at / decrypt_at) for random-access + parallel"
type: feat
status: active
date: 2026-07-01
---

# feat: Add vscf_chunk_cipher seek API (encrypt_at / decrypt_at) for random-access + parallel

## Overview

Add two public methods to `vscf_chunk_cipher` (`library/foundation`) that expose the class's existing
per-index chunk machinery for **random-access** and **parallel** use, without touching the sequential
streaming API:

- `encrypt_at(chunk_index, is_last, plaintext, out)` — encrypt a single chunk at an explicit index.
- `decrypt_at(chunk_index, is_last, frame, out)` — decrypt a single frame *as* an explicit index.

The frame format (`counter_le64[8] | ciphertext | tag[16]`) and per-chunk nonce
(`initial_nonce XOR uint64_be(index)`, XORed into nonce bytes 4–11) are a pure function of the chunk
index, so both random-access reads and out-of-order/parallel encryption are already
format-compatible — only the *API* is currently sequential-only. This change surfaces that capability.

Driven by the Seald `seald-vault` component (Seald `VLT-D15`, ENG-11), which needs partial reads of large
files (decrypt chunk N without decrypting 0..N-1) and parallel whole-file re-encrypt across cores.

## Problem Frame

`vscf_chunk_cipher`'s public API is `start/process/finish`-only. The internal static helpers already take
an explicit `chunk_index` + `is_last` (`vscf_chunk_cipher_encrypt_chunk`, `..._decrypt_chunk`), but:

- Encryption is only reachable through the sequential `process_encryption`/`finish_encryption` loop that
  drives `self->chunk_index++`.
- `decrypt_chunk` hard-rejects any frame whose embedded counter ≠ `self->chunk_index`
  (`vscf_chunk_cipher.c:635-637`), which blocks decrypting an arbitrary chunk.

seald-vault (a virtual filesystem over encrypted files) needs random-access reads and parallel encrypt.
The format supports it; the API must be extended additively.

## Requirements Trace

- **R1** — `encrypt_at(chunk_index, is_last, plaintext, out)`: encrypts one chunk at the given index; a thin wrapper over the existing `encrypt_chunk` helper; requires `key` + `initial_nonce` + `chunk_size (>0)` set (uniformly — the seek path does **not** apply the sequential path's default-chunk_size fallback); **must not** generate a nonce; runs only in `state==INITIAL`; validates `chunk_index < MAX_CHUNK_INDEX`; does not touch `self->chunk_index`.
- **R2** — `decrypt_at(chunk_index, is_last, frame, out)`: decrypts one frame validated against the *passed-in* `chunk_index` (not `self->chunk_index`); derives the nonce from `chunk_index`; rebuilds the AAD (counter + chunk_size@index0 + FIN@is_last); auth-decrypts; requires `key` + `initial_nonce` + `chunk_size (>0)` set (uniformly, no auto-default); runs only in `state==INITIAL`.
- **R3** — Refactor `decrypt_chunk` to take an `expected_index` parameter; sequential `process_decryption`/`finish_decryption` pass `self->chunk_index` (behavior byte-for-byte unchanged); `decrypt_at` passes its `chunk_index`.
- **R4** — The existing streaming API is untouched and byte-identical. `encrypt_at` output is bit-identical to the sequential path **only when the caller reproduces the sequential framing contract**: for a plaintext of N bytes at chunk_size C, the sequential path emits `floor(N/C)+1` frames — the trailing `is_last=true` frame is **empty when N is an exact multiple of C**. Parallel callers must replicate this (exactly one `is_last=true` frame at index `floor(N/C)`, which is empty on exact multiples; index 0 carries the chunk_size AAD).
- **R5** — Nonce-safety and thread-safety are authored in the **IR model doc-comments** (`class_chunk_cipher.xml`, Unit 1) so they propagate to all wrappers: per-call index uniqueness is the caller's responsibility (no enforcement — see Risks); the seek methods are **thread-safe** — each call uses a per-call local AES-GCM context and only reads the instance's key/nonce/chunk_size, so a single configured instance may be used concurrently from multiple threads with no lock.
- **R6** — Methods declared in `class_chunk_cipher.xml`, regenerated via codegen; the generated wrapper stubs (Go/Java/Swift/Python/PHP/WASM) are regenerated and committed; committed Go pkg headers refreshed.
- **R7** — Test suite covers parallel-equivalence (incl. exact-multiple), random-access, wrong-index / wrong-`is_last`, tamper (ciphertext/tag/counter), truncation (missing FIN), preconditions, and the nonce cap; all existing sequential tests remain green.
- **R8** — Public `is_const` helper `chunk_count(data_len) -> size` returning the exact number of frames the sequential path emits for `data_len` bytes (`floor(data_len/chunk_size)+1`), so parallel callers compute the index range and place the single `is_last` (empty on exact multiples) without re-deriving the off-by-one. Requires `chunk_size>0` set.

## Scope Boundaries

- No change to the sequential `start/process/finish` API behavior or wire format.
- No locking / internal concurrency primitives — thread-safety comes from the seek methods using a per-call local AES-GCM context (no shared mutable cipher state), not from a lock.
- No open-ended (unknown-length) parallel/seek encryption — `is_last` and the frame-0 `chunk_size` AAD require the total chunk count to be known upfront (whole-file only). Open-ended streams keep the sequential path.
- No new algorithm / `alg_id` / OID — `chunk_cipher` remains a composition class.

### Deferred to Separate Tasks

- **Deeper language-wrapper binding work** (idiomatic per-language helpers, wrapper-level tests, examples): follow-up. This change regenerates and commits the *generated* wrapper stubs so the tree stays consistent, and verifies Go + Swift build, but does not add hand-written binding ergonomics.
- **Stateless free-function variant** (a `chunk_cipher`-free API that takes key+nonce+index directly, avoiding the shared-instance mutation): noted as a possible future ergonomic improvement; not built here.
- **Pre-built Go static lib rebuild**: handled by `release.yml` at release time.

## Context & Research

### Relevant Code and Patterns

- `library/foundation/src/vscf_chunk_cipher.c`:
  - `vscf_chunk_cipher_encrypt_chunk(self, plaintext, chunk_index, is_last, out)` (lines 556–609) — already does per-index nonce (bytes 4–11, `uint64_be(index)`), AAD (counter LE; chunk_size@0 LE; FIN `0xFF×8`@is_last), frame assembly, and the `MAX_CHUNK_INDEX` cap (567–570 → `ERROR_CHUNK_COUNTER_LIMIT_REACHED`).
  - `vscf_chunk_cipher_decrypt_chunk(self, frame, is_last, out)` (lines 611–677) — min-length guard (622–624), LE counter read (626–633), **out-of-order guard** `frame_index64 != self->chunk_index` (635–637), **MAX-index cap** (640–642), AAD rebuild (644–658), nonce derive (660–669), `auth_decrypt` (676 → `ERROR_AUTH_FAILED` on tag mismatch).
  - Sequential callers: `process_encryption` (417–452, `chunk_index++` at 446), `finish_encryption` (454–470, FIN frame, terminal), `process_decryption` (493–531, `chunk_index++` at 525), `finish_decryption` (533–554).
  - `set_chunk_size` (333–341, guards `state==INITIAL`); `encryption_out_len` (360–372, `is_const`); `decryption_out_len` (374–386, `is_const`).
  - Constants: `VSCF_CHUNK_CIPHER_DEFAULT_CHUNK_SIZE` 65536 (280); `VSCF_CHUNK_CIPHER_MAX_CHUNK_INDEX = UINT64_C(1) << 48` (287).
- `library/foundation/include/virgil/crypto/foundation/private/vscf_chunk_cipher_defs.h` (100–120) — struct fields: `key`, `nonce_buffer`, `chunk_size`, `chunk_index`, `pending`, `state`.
- `codegen/models/project_foundation/class_chunk_cipher.xml` — the method-declaration patterns (see Key Technical Decisions for the exact shapes to add).
- `tests/foundation/test_chunk_cipher.c` (716 lines) — Unity harness gated by `TEST_DEPENDENCIES_AVAILABLE = VSCF_CHUNK_CIPHER && VSCF_AES256_GCM && VSCF_FAKE_RANDOM`; round-trip pattern, frame-tamper via `vsc_buffer_begin(ciphertext)[n]`, direct struct access (`enc->chunk_index`) via included `..._defs.h`; existing `test__decrypt__wrong_frame_counter__fails` (360–412) and counter-limit tests (620–682) are direct models. Registered via `_add_test (test_chunk_cipher)` (`tests/foundation/CMakeLists.txt:93`); tests added with `RUN_TEST(...)` in `main()`.
- Original design plan: `docs/plans/2026-06-11-001-feat-chunk-cipher-plan.md` (conventions, nonce/AAD rationale, `is_nonce_used` note).

### Institutional Learnings

- `docs/solutions/best-practices/codegen-test-stale-assertions-2026-05-12.md` — codegen count/parity assertions can shift on IR changes. **Verified for this change:** no `tools/codegen/` test references `chunk_cipher`; the codegen tests are machinery unit tests (membership, not totals). Adding two methods is expected to leave codegen pytest green. Still: regenerate + commit the Swift wrapper so any generated-vs-committed parity check matches.
- `docs/solutions/build-errors/go-cgo-stale-committed-pkg-headers-2026-06-18.md` — new method decls land in the *existing* `vscf_chunk_cipher.h`; `cmake install` skips "up-to-date" committed headers, so cgo won't see them. Refresh the platform-independent committed headers across all 5 Go targets in the same PR; verify `go build/test`.
- `docs/solutions/build-errors/msvc-no-c99-vla-vendored-c-2026-06-18.md` — no C99 VLAs in the hand-written wrapper bodies; the AAD/nonce buffers are already fixed-size (`byte aad[24]`, `byte nonce_i[12]`) — keep them so. The `Build JVM (Windows x86_64)` job is the late gate.
- `docs/solutions/best-practices/vsc-buffer-ownership-and-secure-erasure-2026-06-18.md` — reuse the existing helpers' buffer idioms; the seek wrappers should not introduce new secret scratch.

### External References

- RFC 8446 §5.3 (TLS 1.3 per-record nonce) — the construction `vscf_chunk_cipher` already uses.
- NIST SP 800-38D — AES-GCM nonce-reuse is catastrophic; the whole nonce-safety caveat rests on this.

## Key Technical Decisions

- **`decrypt_chunk` gains an `expected_index` parameter (refactor, behavior-preserving).** The current guard compares the frame's embedded counter to `self->chunk_index`. Refactor to compare against a passed-in `expected_index`; sequential callers pass `self->chunk_index` (unchanged behavior), `decrypt_at` passes its argument. The MAX-index cap guard (640–642) stays. This is the single load-bearing refactor; everything else is additive.
- **`encrypt_at` is a thin public wrapper over `encrypt_chunk`.** It runs the precondition checks below, then delegates. It must **not** call the `random` dependency or generate a nonce, and must not touch `self->chunk_index` or `self->state`. The `MAX_CHUNK_INDEX` cap is already enforced inside `encrypt_chunk`. **Framing contract (R4):** to match the sequential wire output, callers encrypt indices `0..floor(N/C)`, with exactly the last (index `floor(N/C)`) as `is_last=true` — which is an **empty** chunk when `N` is an exact multiple of `C` (because `finish_encryption` always emits a trailing FIN frame). Index 0 carries the chunk_size AAD.
- **`decrypt_at` delegates to the refactored `decrypt_chunk(expected_index=chunk_index, ...)`.** Runs the same precondition checks. The counter-vs-`expected_index` guard makes frame-substitution detectable: a frame carrying counter M presented at `expected_index != M` returns `ERROR_BAD_ENCRYPTED_DATA`, so the caller must pass the true positional index and never trust the frame's own counter field.
- **Precondition validation is net-new soft-fail (no existing precedent to mirror).** `start_encryption`/`start_decryption` and the `encrypt_chunk`/`decrypt_chunk` helpers guard missing key/nonce with `VSCF_ASSERT_PTR`, which **aborts the process** (the default assert handler is `VSCF_NORETURN`) — there is no status-returning precondition path to reuse. So `encrypt_at`/`decrypt_at` must add **new, exhaustive** soft-fail checks *before* delegating, covering **every** field the helper asserts on, or a gap becomes a `SIGABRT` (a DoS via API misuse, not a clean error). Required checks (return `vscf_status_ERROR_UNINITIALIZED` / `ERROR_BAD_ARGUMENTS`):
  - `self->key != NULL`; `self->nonce_buffer != NULL` and its length `== NONCE_LEN`.
  - `self->chunk_size > 0` (uniformly, for all indices — see below).
  - `self->state == vscf_cipher_state_INITIAL` — reject if a sequential session is active (`ERROR_BAD_STATE`/equivalent), since delegating would silently reconfigure the shared inner GCM and corrupt the in-progress stream. "Independent of streaming state" means *does not consult `chunk_index`/`pending`*, **not** "callable in any state."
  - These run in `INITIAL` state without `start_*`, so none of `start_*`'s side effects (chunk_size default, pending alloc) apply.
- **`chunk_size` is always valid (`> 0`); the real caller responsibility is *matching* the encryptor's value.** Verified during implementation: `init_ctx` defaults `chunk_size` to `VSCF_CHUNK_CIPHER_DEFAULT_CHUNK_SIZE` (65536) for **every** instance, and `set_chunk_size` guards `> 0`, so `chunk_size` is never 0 on any path (the seek path inherits the default too — no `start_*` needed). The `encrypt_at`/`decrypt_at` precondition check keeps a defensive `chunk_size > 0` guard, but it is effectively always satisfied. The genuine hazard is a **value mismatch**: `encrypt_chunk` bakes `chunk_size` into the index-0 AAD, so a decryptor that uses a different `chunk_size` than the encryptor (including relying on the 65536 default when the file used another size) gets `ERROR_AUTH_FAILED` at index 0 — indistinguishable from tampering. This is a documented caller responsibility (set `chunk_size` to the value used at encryption), same as the sequential path.
- **Out-buffer capacity.** Unlike `process_encryption` (which asserts `vsc_buffer_unused_len(out) >= encryption_out_len(...)`), the `encrypt_chunk`/`decrypt_chunk` helpers perform no capacity check. `encrypt_at`/`decrypt_at` must assert/validate `out` capacity against `encryption_out_len`/`decryption_out_len` before delegating, so an undersized caller buffer fails cleanly rather than overflowing.
- **`chunk_count` helper (R8) owns the frame-count contract.** Add a public `is_const` `chunk_count(data_len)` returning `floor(data_len/chunk_size)+1` — the same `num_frames` math already inside `encryption_out_len` (lines 360–372). Parallel callers use it to derive the index range `0..chunk_count-1` and place the single `is_last` at the top index (empty when `data_len % chunk_size == 0`), so the off-by-one / empty-trailing-FIN rule lives in the library, not in every caller. `start_encryption` intentionally does not return a count (it is streaming and does not know the total length upfront).
- **Nonce handling is inherited, not re-implemented.** `encrypt_chunk`/`decrypt_chunk` already re-issue `set_key`+`set_nonce` on the inner `aes256_gcm` per call (clearing GCM's internal `is_nonce_used`); the seek wrappers add nothing here. (There is no `is_nonce_used` field in `chunk_cipher` itself.)
- **Output sizing reuses existing `is_const` length methods.** The new `out` buffers are sized via `<length method="encryption out len">` / `<length method="decryption out len">` with a `<proxy>` mapping the `plaintext`/`frame` arg to `data len` (over-allocates by ≤ one frame's overhead — safe). No new length method, and (per the learning) these must be `is_const="1"` — the existing ones already are.
- **XML shapes.** New public methods (no `declaration="private"`, so they appear in the public header and wrappers): args `chunk index` (`type="unsigned" size="8"` → `uint64_t`), `is last` (`type="boolean"` → `bool`), `plaintext`/`frame` (`class="data"`), `out` (`class="buffer"` with the `<length>`/`<proxy>` child), `<return enum="status"/>`.
- **Thread-safety by construction (no lock).** `encrypt_at`/`decrypt_at` use a **per-call local `vscf_aes256_gcm` context** (created + destroyed within the call) instead of the shared `self->aes256_gcm`; they only *read* `self->key`/`nonce_buffer`/`chunk_size` and never touch `self->chunk_index`/`state`/`pending`. So a single configured instance may be used concurrently from multiple threads with no lock and no atomics — full parallelism. (The sequential `process_*`/`finish_*` path keeps reusing the shared `self->aes256_gcm`, which is fine since it is single-threaded per instance.) The per-chunk crypto is factored into a GCM-parameterized helper shared by both paths. *(Chosen over a vscf_atomic per-instance lock, which would only serialize a shared instance rather than enable true parallel sharing.)*

## Open Questions

### Resolved During Planning

- Reuse `decrypt_chunk` for random access? → No, not as-is (its guard rejects out-of-order). Refactor it to take `expected_index` (cleaner than transiently mutating `self->chunk_index`), keeping the sequential API untouched.
- New length methods for the seek `out` buffers? → No; reuse `encryption_out_len`/`decryption_out_len` via `<proxy>`.
- Codegen snapshot-count updates? → Not needed for `chunk_cipher` (verified: no chunk_cipher-specific codegen assertions); just keep pytest green and commit regenerated wrappers.
- Does `encrypt_at`/`decrypt_at` need `start_*` to have run? → No; they run in `INITIAL` state and validate preconditions directly (see below). They reject non-`INITIAL` state so they can't corrupt an active sequential session.
- Precondition validation approach? → **New soft-fail checks**, not "mirror `start_*`": `start_*` and the helpers `VSCF_ASSERT_PTR` (abort) on missing key/nonce, so there is no status-returning precedent. The wrappers must check `key`/`nonce`/`chunk_size>0`/`state==INITIAL` and return status *before* delegating (see Key Technical Decisions).
- Is `chunk_size` required uniformly? → **Yes** (`>0` for all indices). The index-0 AAD needs it and the seek path does not inherit `start_decryption`'s default-65536 fallback; uniform requirement avoids a silent AAD-mismatch trap. (Resolves the prior deferral.)
- Parallel-equivalence frame count? → `floor(N/C)+1` frames; the trailing `is_last=true` frame is empty on exact multiples (sequential `finish_encryption` always emits a FIN frame). Callers must replicate this.

### Deferred to Implementation

- Exact generated method/proxy names after codegen emits the stub.
- Where seald-vault obtains and authenticates the **total chunk count** (needed to set `is_last`/index-0 correctly): prefer deriving it from ciphertext length (tamper-evident) over mutable metadata — confirm against the seald-vault consumer. See Risks (truncation).

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

```
Sequential API (unchanged)                     New seek API (additive)
──────────────────────────                     ───────────────────────
process_encryption(data,out)                   encrypt_at(index, is_last, plaintext, out)
  loop: encrypt_chunk(pending,                    ├─ validate key + nonce + chunk_size>0 + state==INITIAL
        self->chunk_index, false, out)            │   + out capacity   (soft-fail; helpers ABORT otherwise)
        self->chunk_index++                       └─ encrypt_chunk(plaintext, index, is_last, out)  ← existing helper
finish_encryption(out)                                 (MAX_CHUNK_INDEX cap already inside)
  encrypt_chunk(rest, self->chunk_index,       decrypt_at(index, is_last, frame, out)
        true, out)   ← ALWAYS emits a FIN         ├─ validate key + nonce + chunk_size>0 + state==INITIAL
        frame; EMPTY when N % C == 0              └─ decrypt_chunk(frame, expected_index=index, is_last, out)
process_decryption(data,out)
  loop: decrypt_chunk(frame,                   REFACTOR (behavior-preserving):
        expected_index=self->chunk_index,        decrypt_chunk(self, frame, is_last, out)
        false, out); self->chunk_index++          →  decrypt_chunk(self, frame, expected_index, is_last, out)
finish_decryption(out)                            guard: frame_index64 != expected_index  → ERROR_BAD_ENCRYPTED_DATA
  decrypt_chunk(frame,                            (+ existing MAX_CHUNK_INDEX cap guard retained)
        expected_index=self->chunk_index, true, out)

Invariant: encrypt_at(i, is_last, P) frame  ==  the frame the sequential path emits for chunk i
           (same key+nonce+chunk_size). Frame count = chunk_count(N) = floor(N/C)+1; exactly one index
           (= chunk_count(N)-1) has is_last=true and is EMPTY when N is an exact multiple of C; index 0
           carries chunk_size AAD; a single-chunk whole file is index 0 AND is_last.

Parallel caller (per-thread instance, same key+nonce+chunk_size):
  n = cipher.chunk_count(N)                         // library owns the floor+1 / empty-FIN rule
  parallel for i in 0..n-1:
     slice = P[i*C : min((i+1)*C, N)]               // slice n-1 is empty when N % C == 0
     thread_cipher[t].encrypt_at(i, i == n-1, slice, out[i])
```

## Implementation Units

- [ ] **Unit 1: Declare `encrypt_at` / `decrypt_at` in the codegen model + regenerate skeleton**

**Goal:** Add the two public methods to the IR and generate the stubs + wrapper scaffolding.

**Requirements:** R1, R2, R5, R6, R8

**Dependencies:** None

**Files:**
- Modify: `codegen/models/project_foundation/class_chunk_cipher.xml`
- Generated: `library/foundation/include/virgil/crypto/foundation/vscf_chunk_cipher.h`, `library/foundation/src/vscf_chunk_cipher.c` (new `@end` stub blocks), `_internal.c`/`_defs.c`, and wrapper files under `wrappers/`

**Approach:**
- Add two public `<method>` entries (no `declaration="private"`): `encrypt at` and `decrypt at`, each with `chunk index` (`type="unsigned" size="8"`), `is last` (`type="boolean"`), a `class="data"` input (`plaintext` / `frame`), and an `out` `class="buffer"` sized via `<length method="encryption out len">` / `<length method="decryption out len">` with a `<proxy argument="plaintext|frame" to="data len" cast="data_length"/>`. `<return enum="status"/>`.
- Add a third public method `chunk count` (R8), `is_const="1"`, arg `data len` (`type="size"`), `<return type="size"/>` — mirroring the existing `encryption out len` declaration (lines 58–64).
- **Author the R5 doc-comments here** (the `<method>` description text in the XML is what propagates to all wrappers): nonce-safety (each index encrypted at most once per `(key, initial_nonce)` — no enforcement), thread-safety (per-call local GCM → a single configured instance is safe for concurrent use, no lock), whole-file-only framing (caller must know total chunk count; exactly one `is_last`; empty trailing FIN on exact multiples), and preconditions (key + nonce + chunk_size, `INITIAL` state).
- Run `python3 -m tools.codegen.common_bootstrap --project foundation --apply`.

**Patterns to follow:** the existing `process encryption` method (data-in + buffer-out + `<length>`/`<proxy>`) and `encryption out len` (`is_const`) declarations in `class_chunk_cipher.xml`.

**Test scenarios:**
- Test expectation: none (codegen/scaffolding). Behavioral coverage in Unit 4.

**Verification:**
- Codegen runs clean; `vscf_chunk_cipher.h` gains `encrypt_at`/`decrypt_at` decls; stub `@end` blocks appear in the `.c`; `python3 -m pytest tools/codegen/ -q` stays at/below the 25-failed baseline (no new failures).

---

- [ ] **Unit 2: Refactor `decrypt_chunk` to take `expected_index` (behavior-preserving)**

**Goal:** Parameterize the out-of-order guard so the helper can validate against a caller-supplied index.

**Requirements:** R3, R4

**Dependencies:** None (independent of Unit 1; both precede Unit 3)

**Files:**
- Modify: `library/foundation/src/vscf_chunk_cipher.c` (the static `decrypt_chunk` + its forward decl + the two sequential callers)

**Approach:**
- Change `decrypt_chunk(self, frame, is_last, out)` → `decrypt_chunk(self, frame, expected_index, is_last, out)`; the guard becomes `if (frame_index64 != expected_index) return ERROR_BAD_ENCRYPTED_DATA;`. Keep the MAX-index cap guard.
- Update `process_decryption` and `finish_decryption` to pass `self->chunk_index`. No behavior change.

**Execution note:** Characterization-first — run the existing `test_chunk_cipher` suite before and after to prove the sequential path is byte-for-byte unchanged.

**Patterns to follow:** existing `decrypt_chunk` and its callers in the same file.

**Test scenarios:**
- Regression: the entire existing `test_chunk_cipher` suite passes unchanged (this is the correctness signal for a behavior-preserving refactor).

**Verification:**
- `cd build && ctest -R chunk_cipher --output-on-failure` green with no test changes.

---

- [ ] **Unit 3: Implement `encrypt_at` / `decrypt_at` bodies**

**Goal:** Fill the generated stubs with the thin wrappers + precondition validation.

**Requirements:** R1, R2, R4, R8

**Dependencies:** Unit 1 (stubs), Unit 2 (refactored `decrypt_chunk`)

**Files:**
- Modify: `library/foundation/src/vscf_chunk_cipher.c` (fill the `encrypt_at` / `decrypt_at` `@end` blocks)

**Approach:**
- **Exhaustive soft-fail preconditions BEFORE delegating** (the helpers `VSCF_ASSERT_PTR` → abort; a gap = `SIGABRT`, not a clean error). Both methods check, returning status: `self->key != NULL`; `self->nonce_buffer != NULL` && length `== NONCE_LEN`; `self->chunk_size > 0`; `self->state == vscf_cipher_state_INITIAL` (reject if a sequential session is active); and `out` capacity `>= encryption_out_len/decryption_out_len` (the helpers do no capacity check).
- `encrypt_at`: after checks, call `encrypt_chunk(self, plaintext, chunk_index, is_last, out)`. Do not touch `self->chunk_index`/`self->state`; do not invoke `random`.
- `decrypt_at`: after checks, call the refactored `decrypt_chunk(self, frame, chunk_index, is_last, out)`.
- `chunk_count(data_len)` (R8): return `data_len / self->chunk_size + 1` (integer division) — the exact frame count the sequential path emits; requires `chunk_size>0`. Reuse the arithmetic already in `encryption_out_len`.
- No new VLAs; no new secret scratch (delegates to existing helpers). (R5 doc-comments live in the XML — Unit 1.)

**Patterns to follow:** the `start_encryption`/`start_decryption` precondition intent (but note: they `VSCF_ASSERT`, not soft-fail — these wrappers must return status instead); the `process_encryption` out-capacity assert (`vsc_buffer_unused_len(out) >= ...`); the existing helper call sites.

**Test scenarios:**
- (Behavioral coverage lands in Unit 4; this unit's signal is a clean build + Unit 4 green.)

**Verification:**
- `cmake --build build -j$(nproc)` clean; Unit 4 tests pass.

---

- [ ] **Unit 4: Test suite for seek + parallel semantics**

**Goal:** Prove parallel-equivalence, random-access, and fail-closed behavior; keep sequential tests green.

**Requirements:** R4, R7

**Dependencies:** Unit 3

**Files:**
- Modify: `tests/foundation/test_chunk_cipher.c` (new `RUN_TEST` cases)
- Modify (if new vectors needed): `tests/foundation/data/include/test_data_chunk_cipher.h`, `tests/foundation/data/src/test_data_chunk_cipher.c`

**Approach:**
- Reuse the existing fake-random + fixed-key harness so `encrypt_at` output is deterministic and directly comparable to the sequential path's captured frames.

**Test scenarios:**
- Happy path (parallel-equivalence, non-multiple): plaintext `2*C + 100` bytes → `encrypt_at` indices 0,1 (`is_last=false`) + index 2 (the 100-byte remainder, `is_last=true`), in arbitrary order → byte-identical to sequential `process/finish`.
- Happy path (parallel-equivalence, **exact multiple** — the invariant's break point): plaintext exactly `2*C` bytes → `encrypt_at` indices 0,1 (`is_last=false`) **plus an empty `encrypt_at` at index 2 with `is_last=true`** → byte-identical to sequential `process/finish`. (Asserts the empty-trailing-FIN convention; a naive caller that marks index 1 as last would NOT match.)
- Happy path (random-access): `decrypt_at(N)` for arbitrary N (including index 0 and the last/empty chunk) returns the correct plaintext without decrypting any other chunk.
- Happy path: single-chunk whole file — index 0 AND `is_last=true` — round-trips.
- Edge case: `encrypt_at`/`decrypt_at` succeed in `INITIAL` state without any `start_*` call.
- Error path (frame substitution): encrypt distinct chunks at indices 3 and 5; present frame-of-3 to `decrypt_at(expected_index=5)` → `ERROR_BAD_ENCRYPTED_DATA` (counter ≠ expected index), never silent wrong plaintext.
- Error path: `decrypt_at` with wrong `is_last` for the true final chunk (FIN AAD mismatch) → `ERROR_AUTH_FAILED`.
- Error path (is_last misplacement): `encrypt_at` a multi-chunk file with `is_last` on a middle index (or none) → the resulting stream fails closed under a full sequential `start/process/finish` decrypt (documents that misplacement is only caught at sequential-decrypt time, not at `encrypt_at` time).
- Error path: tamper ciphertext / tag / counter byte, then `decrypt_at` → `ERROR_AUTH_FAILED` (or `ERROR_BAD_ENCRYPTED_DATA` if the counter no longer matches the passed index).
- Error path: truncated frame (missing FIN / too short) via `decrypt_at` → fails closed.
- Error path (preconditions, must return a **specific** status — not `ERROR_AUTH_FAILED`, not a crash): `encrypt_at`/`decrypt_at` with no key; no nonce; `chunk_size==0` (test at index 0, a non-last middle index, and `is_last` — all three return the precondition error, proving the uniform check); and while `state != INITIAL` (start a sequential session, then call `encrypt_at` → clean rejection, sequential session uncorrupted).
- Edge case (nonce cap): `encrypt_at(chunk_index = MAX_CHUNK_INDEX)` → `ERROR_CHUNK_COUNTER_LIMIT_REACHED`.
- Happy path (`chunk_count`, R8): for chunk_size C, assert `chunk_count(0)==1`, `chunk_count(C-1)==1`, `chunk_count(C)==2` (exact multiple → the +1 empty-FIN frame), `chunk_count(2C+1)==3`; and that driving `encrypt_at` over `0..chunk_count(N)-1` (is_last on the top index) reproduces the sequential output for both an exact-multiple and a non-multiple N.
- Regression: all pre-existing sequential tests unchanged and green (also the Unit 2 characterization signal).

**Verification:**
- `cd build && ctest -R chunk_cipher --output-on-failure` green incl. new cases; full `ctest` no regressions.

---

- [ ] **Unit 5: Wrapper propagation + committed Go headers**

**Goal:** Keep the generated wrappers and committed Go headers consistent with the new C API.

**Requirements:** R6

**Dependencies:** Units 1–4

**Files:**
- Generated: `wrappers/{go,java,swift,python,php,wasm}/…` (ChunkCipher gains `encrypt_at`/`decrypt_at`)
- Modify: committed `wrappers/go/pkg/<os>_<arch>/include/.../vscf_chunk_cipher.h` (platform-independent) across all 5 Go targets

**Approach:**
- Commit the regenerated wrapper stubs (mechanical codegen output) so the tree is consistent.
- Build once and force-commit the refreshed platform-independent `vscf_chunk_cipher.h` across the 5 Go targets (`cmake install` skips "up-to-date" committed headers); do not commit per-target `*_platform.h` drift or `.a` files.
- Verify Go: `go build ./...` + `go test ./...` from `wrappers/go/` (ignore the benign duplicate-library linker warning).
- Verify Swift: `useLocalBinaries=true` → `swift build` → `swift test` → restore flag.

**Execution note:** Watch the `Build JVM (Windows x86_64)` CI job after push (MSVC VLA gate).

**Test scenarios:**
- Integration: Go and Swift wrapper builds/test suites pass with the new methods present.
- Regression: `python3 -m pytest tools/codegen/ -q` stays green after committing regenerated wrappers.

**Verification:**
- Wrappers generate + build; Go + Swift suites green; codegen pytest green.

## System-Wide Impact

- **Interaction graph:** `encrypt_at`/`decrypt_at` → existing `encrypt_chunk`/`decrypt_chunk` → inner `aes256_gcm`. No new dependencies; `random` is not used by the seek path.
- **Error propagation:** `ERROR_BAD_ENCRYPTED_DATA` (counter/format), `ERROR_AUTH_FAILED` (tag/AAD), `ERROR_CHUNK_COUNTER_LIMIT_REACHED` (cap), precondition errors — all surface to the caller; no plaintext on failure.
- **State lifecycle risks:** the seek methods do not *advance* `self->chunk_index`, but they **do** guard `state==INITIAL` and reject otherwise — so interleaving with an active sequential session fails fast instead of silently reconfiguring the shared inner GCM (which would desync nonce↔index and produce silently-corrupt ciphertext). Use a dedicated instance for seek/parallel work.
- **API surface parity:** the sequential API is unchanged; the new methods are additive across all wrappers.
- **Integration coverage:** the parallel-equivalence test (encrypt_at frames == sequential frames) is the key cross-path invariant; Go/Swift wrapper builds prove the binding boundary.
- **Unchanged invariants:** wire format, sequential behavior, nonce derivation, and the frame-0/FIN AAD rules are all unchanged.

## Risks & Dependencies

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| **Nonce reuse: same `(key, initial_nonce, index)` encrypted twice → catastrophic GCM failure** | Med | High | **Conscious trade-off:** the per-call, out-of-order API cannot enforce single-use without breaking legitimate parallel/random-order encryption (a high-water-mark would reject valid out-of-order writes), so uniqueness is the caller's contract — documented loudly (R5, in the IR doc-comments). The seald-vault caller owns per-index-once discipline; the deferred stateless free-function variant would make this safe by construction. **This is the notable residual for reviewer/user sign-off.** |
| `encrypt_at` frame NOT bit-identical to sequential on **exact-multiple** lengths (missing empty trailing FIN) | Med | High | The framing contract (frame count `floor(N/C)+1`; empty `is_last` frame on exact multiples) is stated in R4/design/doc-comments; the exact-multiple parallel-equivalence test asserts it |
| decrypt_at yields wrong-position plaintext under a substituted frame | Low | High | Counter-vs-`expected_index` guard rejects (`ERROR_BAD_ENCRYPTED_DATA`); caller must pass the true positional index; frame-substitution test asserts it |
| Missing/incomplete precondition check → helper `VSCF_ASSERT` aborts the process (SIGABRT/DoS) | Med | High | Enumerated exhaustive soft-fail checks before delegating (Unit 3); tests assert a *specific* status per missing precondition, proving the assert path is unreachable via the public API |
| Interleaving seek + sequential on one instance silently corrupts the stream | Med | High | `state==INITIAL` guard rejects seek calls during a sequential session; test asserts clean rejection |
| Truncation: adversary drops trailing frames; caller can't tell without an authoritative chunk count | Low | Med | Derive chunk count from ciphertext length (tamper-evident) or authenticate the metadata that carries it; `is_last`/FIN only binds *which* frame is last, not *how many* exist — see Docs |
| ~~Caller shares one instance across threads → data race~~ (resolved) | — | — | **Fixed:** seek methods use a per-call stack-local AES-GCM context and only read `self` config; a single configured instance is safe for concurrent use, no lock |
| Decryptor uses the wrong `chunk_size` (mislocates frames / bad index-0 AAD) | Low | Med | Fail-closed: a wrong `chunk_size` mislocates the frame offset → counter/tag mismatch; and frame-0's AAD binds `chunk_size` → `ERROR_AUTH_FAILED`. `chunk_size` comes from out-of-band CMS metadata (see Docs), never derivable from the raw stream |
| `decrypt_chunk` refactor subtly changes sequential behavior | Low | High | Behavior-preserving param addition; characterization-first (existing suite green before/after) |
| Committed Go pkg headers go stale (cgo can't see new methods) | Med | Med | Refresh platform-independent headers across 5 targets in the same PR; `go build/test` |
| MSVC VLA in any new hand-written C | Low | Med | Delegates to existing fixed-buffer helpers; no new stack arrays; watch Windows JVM CI |
| Whole-file-only constraint misused for open-ended streams | Low | Med | Documented; `is_last`/frame-0 AAD require known chunk count; open-ended keeps sequential path |

## Documentation / Operational Notes

- Doc-comments on `encrypt_at`/`decrypt_at` (authored in the XML, Unit 1) must state: (1) nonce-safety — each index encrypted at most once per `(key, initial_nonce)`, **not enforced**, caller's contract; (2) thread-safety — per-call stack-local GCM → a single configured instance is safe for concurrent use, no lock; (3) whole-file-only framing — caller must know the total chunk count; exactly one `is_last` at index `floor(N/C)`, empty on exact multiples; index 0 carries chunk_size; (4) preconditions — key + nonce + `chunk_size>0` + `INITIAL` state.
- **How the decryptor obtains `chunk_size`:** it is **not** recoverable from the raw ciphertext (frames store only `counter[8] | ciphertext | tag[16]`; `chunk_size` is an AAD input to frame 0, never written in cleartext, and frame-0's length can't be measured without already knowing `chunk_size`). So — exactly like `initial_nonce` — the caller carries `chunk_size` **out-of-band in the CMS `message_info` custom params** (`"chunkSize"` / `"chunkNonce"`), stored at encryption time and read back to call `set_chunk_size` + `set_nonce` before `decrypt_at`. It is tamper-evident in-band: a wrong `chunk_size` mislocates frame offsets (counter/tag mismatch) and fails frame-0's AAD (`ERROR_AUTH_FAILED`). For seald-vault, the per-file CMS envelope carries it. The caller also uses `chunk_size` to compute each frame's byte offset for random access: full frame = `chunk_size + 8 + 16`; frame `i` starts at `i * (chunk_size + 24)`.
- **Chunk-count / truncation:** `decrypt_at` and the sequential decrypt authenticate *which* frame is last (FIN AAD) and each frame's position (counter), but not the *total number* of frames. A caller that trusts a mutable chunk-count field is exposed to truncation. Recommend deriving the chunk count from the ciphertext byte length (tamper-evident) or authenticating the metadata that carries it (higher-level signature/MAC over the message info). Document for the seald-vault consumer.
- PR description references seald-vault (Seald `VLT-D15`, ENG-11) as the driver.
- Language-binding ergonomics + an optional **stateless free-function variant** (key+nonce+index in, no shared mutable instance — removes the nonce-reuse and thread-safety footguns by construction) are noted follow-ups.

## Sources & References

- Related code: `library/foundation/src/vscf_chunk_cipher.c` (`encrypt_chunk`, `decrypt_chunk`, sequential callers), `codegen/models/project_foundation/class_chunk_cipher.xml`, `tests/foundation/test_chunk_cipher.c`
- Original design plan: `docs/plans/2026-06-11-001-feat-chunk-cipher-plan.md`
- Learnings: `docs/solutions/best-practices/codegen-test-stale-assertions-2026-05-12.md`, `docs/solutions/build-errors/go-cgo-stale-committed-pkg-headers-2026-06-18.md`, `docs/solutions/build-errors/msvc-no-c99-vla-vendored-c-2026-06-18.md`
- RFC 8446 §5.3 (TLS 1.3 nonce); NIST SP 800-38D (GCM nonce uniqueness)
