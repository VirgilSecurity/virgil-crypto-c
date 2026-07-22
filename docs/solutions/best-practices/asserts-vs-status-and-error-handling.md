---
title: "Error handling: VSCF_ASSERT for logic errors, vscf_status_t / vscf_error_t for runtime errors"
date: 2026-07-01
category: docs/solutions/best-practices
module: foundation
problem_type: best_practice
component: error_handling
severity: high
symptoms:
  - "Unsure whether a failure should abort (assert) or return an error status"
  - "A tampered/attacker-controlled input aborts the process instead of failing closed"
  - "Function returns ERROR_BAD_ARGUMENTS / ERROR_UNINITIALIZED even though asserts are enabled"
  - "Confusion between the vscf_status_t return value and the vscf_error_t out-parameter conventions"
  - "A third-party (mbedtls) error is silently ignored or mishandled"
root_cause: wrong_api
resolution_type: documentation
tags:
  - foundation
  - error-handling
  - assert
  - status
  - vscf-error
  - fail-closed
  - runtime-vs-logic-error
  - mbedtls
---

# Error handling: VSCF_ASSERT for logic errors, vscf_status_t / vscf_error_t for runtime errors

The library has one hard rule that governs every function boundary:

> **Assertions guard programmer mistakes (logic errors). Return codes report
> conditions that can legitimately occur at runtime (runtime errors).**

Getting this wrong has two failure modes, both bad: an assert on
attacker-controlled or environmental input turns a recoverable condition into a
process **abort** (DoS / fail-open-by-crash), and a return code for a broken
precondition lets a bug slip past silently. The types involved live in
`library/<module>/include/.../vscf_assert.h`, `.../vscf_status.h`, and
`.../vscf_error.h` (mirrored per module as `vscf_`, `vscr_`, `vsce_`, `vsc_`).

> **These are custom assertions, and they are ALWAYS enabled.** `VSCF_ASSERT`,
> `VSCF_ASSERT_OPT`, `VSCF_ASSERT_SAFE`, `VSCF_ASSERT_PTR`, etc. all expand
> unconditionally to `VSCF_ASSERT_INTERNAL`, which calls `vscf_assert_trigger`
> (abort). There is **no** `NDEBUG`/`DEBUG` gate — unlike C's standard
> `assert()`, they are not compiled out in release/optimized builds. The
> "enabled in debug mode" phrasing in the header comments is misleading
> boilerplate; the macros are identical and fire in every build. Consequence: a
> misplaced assert on untrusted input aborts in production, and the
> logic-error status codes below are effectively never reached because the
> assert always triggers first.

## The boundary — logic error vs runtime error

**Logic error (use `VSCF_ASSERT*`)** — a violated contract that only a *caller
bug* can produce. It is unrecoverable and must never happen in correct code:

- NULL where a pointer is required → `VSCF_ASSERT_PTR(self)`
- an out-param buffer the caller under-sized → `VSCF_ASSERT(data.len <= vsc_buffer_unused_len(out))`
- a state-machine precondition (e.g. "call `set_chunk_size` only in INITIAL state")
- an enum/argument that the caller was contractually required to pre-validate
- a failed `malloc` → `VSCF_ASSERT_ALLOC(ptr)` (the codebase treats OOM as fatal)

**Runtime error (return `vscf_status_t` / set `vscf_error_t`)** — a condition
that arises from *data or the environment*, not from a caller bug. It is
expected and must be handled gracefully:

- corrupt / tampered / attacker-supplied input: `ERROR_BAD_ASN1`,
  `ERROR_BAD_ENCRYPTED_DATA`, `ERROR_AUTH_FAILED`, `ERROR_BAD_PKCS8_*`
- an unsupported-but-well-formed algorithm OID: `ERROR_UNSUPPORTED_ALGORITHM`
- RNG / entropy / key-generation failure: `ERROR_RANDOM_FAILED`,
  `ERROR_ENTROPY_SOURCE_FAILED`, `ERROR_KEY_GENERATION_FAILED`
- an output buffer that is too small at runtime: `ERROR_SMALL_BUFFER`
- a third-party (mbedtls) failure surfaced as a status

**The codebase states this rule itself.** In `vscf_status.h`, the "programmer
mistake" codes carry the note *"this error should not be returned if assertions
is enabled"*:

```c
vscf_status_ERROR_BAD_ARGUMENTS            = -1,   // should not be returned if asserts on
vscf_status_ERROR_UNINITIALIZED            = -2,   // "
vscf_status_ERROR_UNHANDLED_THIRDPARTY_ERROR = -3, // "
```

Because assertions are **always** enabled here (see the note above), the
condition guarded by "if assertions is enabled" is effectively unconditional:
these logic-error codes are dead paths — the matching `VSCF_ASSERT*` aborts
before the code could ever be returned. Do **not** write new code that returns
`ERROR_BAD_ARGUMENTS` / `ERROR_UNINITIALIZED` as a normal control-flow path —
assert on the broken precondition instead.

### Security corollary: fail closed, never fail by abort

Anything derived from untrusted bytes (ciphertext, CMS/ASN.1 metadata, an OID,
a length field) is a **runtime** input. It must return an error, never trip an
assert. A concrete example from this repo: `vscf_recipient_cipher.c`'s
`configure_decryption_cipher` reconstructs the data cipher from the message's
`data_encryption_alg_info`. A tampered/downgraded OID makes
`vscf_alg_factory_create_cipher_from_info` return `NULL`; without a guard the
next `vscf_cipher_set_key(NULL, ...)` **asserts and aborts** (fail-open by
crash). The correct handling is to detect the NULL and return
`vscf_status_ERROR_UNSUPPORTED_ALGORITHM` — fail closed:

```c
self->decryption_cipher = vscf_alg_factory_create_cipher_from_info(cipher_alg_info);
if (NULL == self->decryption_cipher) {
    return vscf_status_ERROR_UNSUPPORTED_ALGORITHM;   // runtime error, not an assert
}
```

Rule: `VSCF_ASSERT_PTR` is correct for *your own* invariants (`self`, an internal
buffer you just allocated); it is **wrong** for a pointer whose NULL-ness is
decided by parsing untrusted data.

## The assert macros (`vscf_assert.h`)

All of these (except the compile-time `VSCF_ASSERT_STATIC`) expand
unconditionally to `VSCF_ASSERT_INTERNAL`, which calls `vscf_assert_trigger(...)`
— that **aborts** (via the active, overridable `vscf_assert_handler_fn`). They
are all the same macro under different names; the "debug/optimized/safe" naming
is intent-signalling only and does **not** change when they fire (always). None
of them return.

| Macro | Use for |
|---|---|
| `VSCF_ASSERT(expr)` | general precondition/invariant |
| `VSCF_ASSERT_OPT(expr)` | same behavior; name signals "must hold in optimized builds too" |
| `VSCF_ASSERT_SAFE(expr)` | same behavior; name signals a heavier "safe-mode" check |
| `VSCF_ASSERT_PTR(ptr)` | pointer that must be non-NULL by contract |
| `VSCF_ASSERT_NULL(ptr)` | pointer that must be NULL (e.g. "buffer not yet allocated") |
| `VSCF_ASSERT_ALLOC(ptr)` | result of an allocation (OOM is fatal here) |
| `VSCF_ASSERT_STATIC(expr)` | compile-time check, zero runtime cost (the only one that never fires at runtime) |
| `VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(rc)` | assert an mbedtls call returned 0 |
| `VSCF_ASSERT_LIBRARY_MBEDTLS_UNHANDLED_ERROR(rc)` | mark an mbedtls error path as unhandled (aborts) |

Notes:
- Prefer the specific macro: `VSCF_ASSERT_PTR(x)` over `VSCF_ASSERT(x != NULL)`
  (clearer trigger message).
- Asserts are conventionally the **first statements** of a function — they
  document the contract. Runtime checks come after, in the body.
- Use the module-matching prefix: `VSCF_*` in foundation, `VSCR_*` in ratchet,
  `VSCE_*` in phe, `VSC_*` in common. Do not cross prefixes.

## vscf_status_t — the return-code convention

`vscf_status_SUCCESS == 0`; every error is a negative constant grouped by area
(generic `-1..-3`, buffer `-101`, crypto/ASN.1 `-200..`). The convention:

- Functions whose primary job can fail at runtime **return `vscf_status_t`**.
  Many are marked `VSCF_NODISCARD` — never ignore the return.
- **Propagate, don't swallow.** The standard early-return idiom:

  ```c
  vscf_status_t status = vscf_x_do_step(self);
  if (status != vscf_status_SUCCESS) {
      // clean up anything allocated in this scope
      return status;                       // bubble the original code up
  }
  ```
- Pick the **most specific** existing code (`ERROR_AUTH_FAILED`,
  `ERROR_BAD_ENCRYPTED_DATA`, `ERROR_UNSUPPORTED_ALGORITHM`, ...). Adding a new
  status means editing the codegen enum model
  (`codegen/models/.../enum_status.xml`) and regenerating — do not invent bare
  integers.
- A function that returns a pointer/value (not a status) reports failure through
  a `vscf_error_t` out-parameter instead (next section).

## vscf_error_t — the out-parameter convention

`vscf_error_t` is a one-field carrier (`{ vscf_status_t status; }`) used by
functions that return a *value* and therefore can't return a status directly
(constructors, factories, importers, e.g. `vscf_key_provider_import_public_key(...,
vscf_error_t *error)`). Contract:

- The `error` argument is **optional / nullable**. Callers who don't care may
  pass `NULL`; the function must tolerate it. Internally, always update via
  `VSCF_ERROR_SAFE_UPDATE(error, code)` — it no-ops when `error == NULL`. Never
  dereference `error` directly.
- **Reset before use, check after.** Caller pattern:

  ```c
  vscf_error_t error;
  vscf_error_reset(&error);                          // clear to SUCCESS

  vscf_impl_t *key = vscf_key_provider_import_public_key(kp, data, &error);
  if (vscf_error_has_error(&error)) {
      return vscf_error_status(&error);              // or handle
  }
  ```
- `vscf_error_update` only records the **first** non-success status (success is
  ignored), so an early failure is not overwritten by later benign calls.
- `vscf_error_status()` is `VSCF_NODISCARD`. `vscf_error_has_error()` is the
  boolean test.

## Third-party (mbedtls) errors

mbedtls returns its own `int` codes. Two handling options, both explicit:

- If the failure is a runtime condition you can map, translate it to a
  `vscf_status_t` and return/propagate it.
- If it can only mean a broken invariant, use
  `VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(rc)` (aborts on non-zero) so the failure
  is loud rather than silently coerced. Never leave an mbedtls return unchecked —
  an ignored code becomes `ERROR_UNHANDLED_THIRDPARTY_ERROR` territory.

## Quick decision checklist

1. Can only a **caller bug** cause this? → `VSCF_ASSERT*`.
2. Can **data or the environment** cause this (untrusted input, RNG, OOM-mapped,
   unsupported algorithm)? → return `vscf_status_t` / set `vscf_error_t`, and for
   untrusted input make sure it **fails closed** (no abort).
3. Returning a status? Propagate the original code; pick the most specific enum;
   clean up in the failing scope first.
4. Returning a value? Use the `vscf_error_t *error` out-param with
   `VSCF_ERROR_SAFE_UPDATE` + `reset`/`has_error`/`status`.
5. Tempted to return `ERROR_BAD_ARGUMENTS` / `ERROR_UNINITIALIZED`? That's a
   logic error — assert instead.
