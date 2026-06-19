---
title: "vsc_buffer ownership and secure erasure: new_with_capacity+make_secure vs vsc_buffer_use"
date: 2026-06-18
category: docs/solutions/best-practices
module: common
problem_type: best_practice
component: tooling
severity: medium
applies_when:
  - Allocating a working/scratch buffer inside a foundation C function
  - Handling secret material that must be securely erased
  - Choosing between vsc_buffer_new_with_capacity and vsc_buffer_use
  - Wrapping caller-owned or stack memory as a non-owning buffer view
resolution_type: code_fix
tags:
  - foundation
  - vsc_buffer
  - vsc_data
  - memory-management
  - secure-erase
  - api-idiom
---

# vsc_buffer ownership and secure erasure

## Context
`vsc_buffer_t` has two distinct lifecycles — **owning** (allocates and frees its own storage) and **non-owning** (wraps caller-supplied memory). Mixing them — `vscf_alloc`-ing raw memory, wrapping it with `vsc_buffer_use`, then hand-erasing/freeing — is error-prone, especially for secret material that must be zeroed on every exit path. This came up cleaning up `vscf_shamir.c`.

## Guidance

**Mental model.** A `vsc_buffer` is storage (`capacity`) + a separately tracked *used length* + `is_owner`/`is_secure` flags. A `vsc_data_t` is a read-only view `{ const byte *bytes; size_t len }`. `vsc_buffer_data(buf)` returns a `vsc_data_t` over the buffer's **used** region — the idiomatic way to hand a filled buffer to an API that wants `vsc_data`.

**Anti-pattern** (don't): `vscf_alloc` + `vsc_buffer_use` + manual `vscf_erase`/`vscf_dealloc` — three jobs the buffer already does, with the zeroization burden on every branch.
```c
coeffs = vscf_alloc(len);
vsc_buffer_init(&wrap); vsc_buffer_use(&wrap, coeffs, len);
status = vscf_random(self->random, len, &wrap);
vsc_buffer_cleanup(&wrap);
...
vscf_erase(coeffs, len); vscf_dealloc(coeffs);   // easy to miss on an error path
```

**Owning, sensitive scratch** (do):
```c
vsc_buffer_t *coeffs = vsc_buffer_new_with_capacity(len);  // owns storage
vsc_buffer_make_secure(coeffs);                            // erase on destroy
status = vscf_random(self->random, len, coeffs);
...
vsc_buffer_destroy(&coeffs);   // securely erases the FULL capacity, then frees
```
Fill manually when a foreign C API writes raw bytes, then commit the length:
```c
vscf_sss_create_keyshares((sss_Keyshare *)vsc_buffer_unused_bytes(key_shares), dk, n, k, ...);
vsc_buffer_inc_used(key_shares, (size_t)n * sss_KEYSHARE_LEN);
```
Or append a view:
```c
vsc_buffer_write_data(out, vsc_buffer_data(aead));   // append the AEAD output's used bytes
```

**`vsc_buffer_use` is only for non-owning views** over caller-owned/stack memory (precondition: the buffer is empty; never `make_secure`/`destroy` it). This is the correct way to let `vscf_random`/`vscf_sha256_hash` write into a fixed stack array:
```c
vsc_buffer_t wrap;
vsc_buffer_init(&wrap);
vsc_buffer_use(&wrap, header + POS_COMMITMENT, COMMITMENT_LEN);  // window into a stack array
vscf_sha256_hash(vsc_data(data_key, sizeof(data_key)), &wrap);
vsc_buffer_cleanup(&wrap);
```

## Why This Matters
`make_secure` + `destroy` zeroes the **full capacity** (`vsc_erase(self->bytes, self->capacity)` — verified in `library/common/src/vsc_buffer.c`), not just `len`, on a single RAII-style teardown — so you cannot leak a secret by forgetting to erase one branch. Hand-rolled alloc/erase/dealloc puts that burden on every error path. Conversely, calling an owning constructor when you only want a view (or `destroy`-ing a `use`d buffer) risks a double-free.

## When to Apply
- Heap scratch holding secrets → `vsc_buffer_new_with_capacity` + `vsc_buffer_make_secure` + `vsc_buffer_destroy`.
- Pointing a buffer at memory you do not own (stack array, a slice of the caller's output) → `vsc_buffer_use` on an empty buffer; do not secure/destroy it.
- Never use `vscf_alloc` + `vsc_buffer_use` + manual erase as an ownership scheme.

## Examples
`library/foundation/src/vscf_shamir.c`:
- Owning + secure: `coeffs` and `key_shares` in `split`; `key_shares` in `combine` — all `new_with_capacity` + `make_secure` + `destroy`.
- Non-owning view: the reused `wrap` buffer over the `data_key`/`nonce`/header stack arrays for `vscf_random`/`vscf_sha256_hash`.

## Related
- Surfaced cleaning up `vscf_shamir` (PR #207).
