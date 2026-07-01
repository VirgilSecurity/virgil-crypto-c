---
title: "vsc_data and vsc_buffer: ownership, capacity, and write vs append semantics"
date: 2026-07-01
category: docs/solutions/best-practices
module: common
problem_type: best_practice
component: value_object
severity: medium
symptoms:
  - "Abort in vsc_buffer.c: 'data.len <= vsc_buffer_unused_len(self)' when calling vsc_buffer_write_data into a too-small buffer"
  - "Abort 'self->is_owner' or crash in vsc_buffer_append_data on a buffer created with vsc_buffer_use"
  - "Silent truncation: bytes written to a buffer are fewer than expected"
  - "Confusion about when vsc_data_t owns memory (it never does) vs vsc_buffer_t"
  - "Unsure whether to size an output buffer with *_out_len and whether to add the finalize term"
root_cause: wrong_api
resolution_type: documentation
tags:
  - common
  - vsc-buffer
  - vsc-data
  - memory-ownership
  - aead
  - output-buffer-sizing
  - write-data
  - append-data
---

# vsc_data and vsc_buffer: ownership, capacity, and write vs append semantics

These two types (`library/common/include/virgil/crypto/common/vsc_data.h`,
`.../vsc_buffer.h`; impls in `library/common/src/`) are the input/output currency
of the entire C API. Almost every crypto function takes a `vsc_data_t` in and
writes to a `vsc_buffer_t` out. Getting their semantics wrong causes hard aborts
(the codebase uses `VSC_ASSERT`, which aborts, not returns) or silent data
truncation. This is a reference, not a bug report.

## The one-paragraph mental model

`vsc_data_t` is a **non-owning, read-only `(const byte *bytes, size_t len)`
view** — a fat pointer. It never allocates, never frees, never copies. Whoever
created the underlying bytes owns them; `vsc_data_t` just points at them.
`vsc_buffer_t` is a **growable/owning output sink** with three numbers that
matter: `capacity` (allocated), `len` (used so far), and `unused_len`
(`capacity - len`). You write into the unused region. A buffer may or may not
own its bytes depending on how it was constructed.

## vsc_data_t — the read-only view

```c
struct vsc_data_t { const byte *bytes; size_t len; };
```

- Construct: `vsc_data(ptr, len)`, `vsc_data_from_str(str, len)`,
  `vsc_data_empty()`, or `vsc_buffer_data(buf)` (view over a buffer's used
  region).
- It is a **value type** — pass and return it by value; there is no
  `vsc_data_destroy`. Copying a `vsc_data_t` copies the pointer, not the bytes.
- **Never outlives its backing store.** If you build `vsc_data(vsc_buffer_bytes(b), ...)`
  and then destroy or reallocate `b` (e.g. via `vsc_buffer_append_data`), the
  `vsc_data_t` dangles. Take a fresh `vsc_buffer_data(b)` after any mutation.
- `vsc_data_slice_beg(d, offset, len)` / `vsc_data_slice_end(...)` return
  sub-views (still non-owning) — use these instead of pointer arithmetic.
- `vsc_data_is_valid(d)` is true when `bytes != NULL` **or** `len == 0`.
  `vsc_data_empty()` is valid. Most APIs `VSC_ASSERT(vsc_data_is_valid(data))`.
- Comparison: `vsc_data_equal` (fast) vs `vsc_data_secure_equal`
  (constant-time — use for MACs/tags/secrets).

## vsc_buffer_t — the output sink

Internally (`vsc_buffer_defs.h`): `bytes`, `capacity`, `len`, `is_owner`,
`is_secure`, `is_reverse`, plus a refcount.

### Construction — and who owns the bytes

| Constructor | Allocates? | `is_owner` | Notes |
|---|---|---|---|
| `vsc_buffer_new()` + `vsc_buffer_alloc(b, cap)` | yes | true | `alloc` requires `bytes == NULL` (call once) |
| `vsc_buffer_new_with_capacity(cap)` | yes | true | the common case for outputs |
| `vsc_buffer_new_with_data(data)` | yes | true | **copies** `data`; `len == capacity == data.len` (already "full") |
| `vsc_buffer_use(b, ptr, n)` | no | **false** | wraps caller memory; caller frees it |
| `vsc_buffer_take(b, ptr, n, dealloc)` | no | true | wraps caller memory; buffer frees it via `dealloc` |

Free with `vsc_buffer_destroy(&b)` (nullifies the pointer). `vsc_buffer_destroy`
is refcount-aware; `vsc_buffer_shallow_copy` bumps the refcount rather than
copying bytes.

### The two write functions — THIS is the common crash

```c
// Fixed-capacity write. ASSERTS (aborts) if data does not fit.
vsc_buffer_write_data(buf, data);   // VSC_ASSERT(data.len <= vsc_buffer_unused_len(buf))

// Growable write. Reallocates (capacity doubled) if needed.
vsc_buffer_append_data(buf, data);  // requires is_owner; no-op on empty data
```

- `vsc_buffer_write_data` does **not** grow. If `data.len > unused_len` it
  aborts on `VSC_ASSERT(data.len <= vsc_buffer_unused_len(self))`. These are
  custom assertions that are **always enabled** (no `NDEBUG` gate), so this
  aborts in every build — it never silently truncates in practice. Use it only
  when you have pre-sized the buffer with the correct `*_out_len` (see below).
  This is the single most common source of an abort in `vsc_buffer.c`.
- `vsc_buffer_append_data` grows automatically **but requires `is_owner == true`**.
  It aborts on a buffer created with `vsc_buffer_use` (non-owning). It is a no-op
  for empty `data`. If `bytes == NULL` it allocs to `data.len` first. Use it when
  the final size is not known up front (e.g. concatenating a variable number of
  serialized pieces). Slower (may memcpy on realloc), so prefer `write_data`
  into a correctly pre-sized buffer on hot paths.

Rule of thumb: **crypto out-params → pre-size with `*_out_len` + `write_data`;
ad-hoc concatenation in glue code → `append_data`.**

### Sizing an output buffer for streaming crypto

Streaming ciphers/serializers expose an `*_out_len(self, in_len)` that returns an
**upper bound** for one `update`/`process` call, plus a separate term for the
finalize step obtained by passing length `0`. The idiom throughout the codebase:

```c
size_t cap = vscf_recipient_cipher_decryption_out_len(rc, in.len)   // for process
           + vscf_recipient_cipher_decryption_out_len(rc, 0);       // for finish
vsc_buffer_t *out = vsc_buffer_new_with_capacity(cap);
```

Forgetting the `+ *_out_len(..., 0)` finalize term under-sizes the buffer and
trips the `write_data` assert on `finish`. Sizes are upper bounds, so the final
`vsc_buffer_len(out)` is usually a little smaller than `capacity` — always report
results with `vsc_buffer_data(out)` / `vsc_buffer_len(out)`, never `capacity`.

### Reading back / inspecting

- `vsc_buffer_data(b)` → `vsc_data_t` view over the **used** region (`len`
  bytes). This is what you hand to the next function.
- `vsc_buffer_bytes(b)` → `const byte *` to the start; `vsc_buffer_begin(b)` →
  writable `byte *` to the start (use for in-place tamper/patch in tests).
- `vsc_buffer_len` (used), `vsc_buffer_capacity` (allocated),
  `vsc_buffer_unused_len` (room left), `vsc_buffer_is_full`, `vsc_buffer_is_empty`.
- Manual writes: `vsc_buffer_unused_bytes(b)` gives the write cursor and
  `vsc_buffer_inc_used(b, n)` commits `n` bytes written directly (e.g. by mbedtls
  writing into the raw pointer). Pair them; forgetting `inc_used` leaves `len`
  stale.

### Secure / reset / reverse

- `vsc_buffer_make_secure(b)` marks the buffer so its bytes are zeroized on
  destroy. Use for keys, nonces, plaintext staging. `vsc_chunk_cipher` and
  friends do this for `key`/`nonce` buffers.
- `vsc_buffer_reset(b)` sets `len = 0` (reuse the allocation);
  `vsc_buffer_erase(b)` zeroizes then resets.
- Reverse mode (`vsc_buffer_switch_reverse_mode`) makes writes land at the
  **end** of the allocation — used by ASN.1 DER writers that emit back-to-front.
  You will rarely set this yourself; just know `write_data` honors it.

## Field-tested gotchas (why this doc exists)

1. **`write_data` into an unsized buffer aborts.** Always size with the matching
   `*_out_len(..., n) + *_out_len(..., 0)` idiom. Symptom: abort at
   `data.len <= vsc_buffer_unused_len(self)`.
2. **`append_data` needs ownership.** It aborts on `vsc_buffer_use` buffers.
   `vsc_buffer_new_with_capacity` / `_alloc` / `_take` are owning; `_use` is not.
3. **A fresh `vsc_buffer_new_with_capacity(n)` starts empty (`len==0`), not
   full.** `append_data`/`write_data` both start writing at offset 0. In
   contrast `vsc_buffer_new_with_data(d)` starts **full** (`len==capacity`), so
   appending to it grows it — usually not what you want for an output buffer.
4. **`vsc_data_t` from `vsc_buffer_bytes`/`vsc_buffer_data` dangles after a
   realloc.** If you `append_data` (which may realloc) after taking a view,
   re-take the view.
5. **Empty is not NULL.** `vsc_data_empty()` is valid and length 0;
   `append_data` skips it; `write_data` writes nothing. AEAD `set_auth_data` with
   empty data is a legitimate "no associated data" call, distinct from never
   calling it.
6. **AEAD associated data must be byte-identical on encrypt and decrypt.** When
   composing auth-data from several serialized pieces, build it the same way on
   both sides (same order, same serializer). A convenient pattern is one shared
   helper that appends the pieces into a buffer, called from both paths (see
   `vscf_recipient_cipher_append_signed_data_info` /
   `..._append_data_encryption_alg_info` in
   `library/foundation/src/vscf_recipient_cipher.c`).

## Minimal correct patterns

```c
// Output of a streaming operation (pre-sized + write via the API):
size_t cap = vscf_x_out_len(x, in.len) + vscf_x_out_len(x, 0);
vsc_buffer_t *out = vsc_buffer_new_with_capacity(cap);
vscf_x_update(x, in, out);          // internally write_data — fits by construction
vscf_x_finish(x, out);
vsc_data_t result = vsc_buffer_data(out);   // len bytes, not capacity
// ... use result ...
vsc_buffer_destroy(&out);

// Concatenating an unknown number of serialized blobs (owning buffer + append):
vsc_buffer_t *acc = vsc_buffer_new_with_capacity(64);   // grows as needed
vsc_buffer_append_data(acc, vsc_buffer_data(piece_a));
vsc_buffer_append_data(acc, vsc_buffer_data(piece_b));
vsc_data_t joined = vsc_buffer_data(acc);   // re-taken AFTER the last append
```
