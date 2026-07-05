---
title: "Memory leak: cleanup_ctx must free every owned buffer, not just the happy-path ones"
date: 2026-07-05
category: docs/solutions/logic-errors
module: foundation
problem_type: logic_error
component: library/foundation/src/vscf_recipient_cipher.c
severity: high
symptoms:
  - "build-linux CI job fails only under valgrind (functional ctest is green)"
  - "valgrind: 'N bytes in 1 blocks are definitely lost' with --leak-check=full"
  - "Leak stack points at a vsc_buffer_new_with_capacity inside a *_start/*_init path"
  - "Leak only reproduces on an error/fail-closed code path, not the happy path"
root_cause: cleanup_ctx_did_not_free_a_buffer_only_freed_mid_processing_on_the_happy_path
resolution_type: code_fix
tags:
  - memory-leak
  - valgrind
  - memcheck
  - cleanup-ctx
  - vsc-buffer
  - docker
  - recipient-cipher
  - fail-closed
---

# Memory leak: `cleanup_ctx` must free every owned buffer

## Problem

`build-linux` (the valgrind memcheck job) failed on the chunk-cipher envelope
test `test__chunk_cipher_envelope__oid_downgrade__fails_closed` with a
"definitely lost" leak, even though every functional `ctest` passed. The leak
was ~1.2 KB (56 direct + 1,134 indirect bytes).

## Symptoms

```
==8604== 1,190 (56 direct, 1,134 indirect) bytes in 1 blocks are definitely lost
==8604==    by vsc_buffer_new_with_capacity (vsc_buffer.c:174)
==8604==    by vscf_recipient_cipher_start_decryption_with_key (vscf_recipient_cipher.c:1062)
==8604== ERROR SUMMARY: 1 errors from 1 contexts
```

## Root cause

`vscf_recipient_cipher_cleanup_ctx` destroyed every owned buffer *except*
`self->message_info_buffer`. That buffer is allocated in
`start_decryption_with_key` (grown during embedded-header extraction) and is
normally freed **mid-processing** in `process_decryption` once the message info
is fully consumed. The `oid_downgrade` test takes a **fail-closed early return**
(the tampered data-encryption-alg-info can't reconstruct a cipher, so
`configure_decryption_cipher` returns `ERROR_UNSUPPORTED_ALGORITHM`) *before*
that mid-processing free runs. The buffer was then left dangling and never
freed on teardown, because `cleanup_ctx` didn't cover it.

The general defect: a buffer whose only free is on the happy path leaks on
every error path.

## Solution

One line in `cleanup_ctx` — free the buffer on teardown so every path is
covered:

```c
// vscf_recipient_cipher_cleanup_ctx(...)
    vscf_padding_cipher_destroy(&self->padding_cipher);
    vsc_buffer_destroy(&self->decryption_staging);
+   //  message_info_buffer is normally consumed and freed during
+   //  process_decryption, but an early error return (e.g. a fail-closed
+   //  data-encryption-alg-info) can leave it allocated; free it on teardown.
+   vsc_buffer_destroy(&self->message_info_buffer);
```

`vsc_buffer_destroy` is NULL-safe and idempotent, so freeing on teardown in
addition to the mid-processing free is correct (the mid-processing path sets the
pointer to NULL). Verified with `valgrind --leak-check=full`: 0 errors.

## Diagnosing a Linux-only valgrind leak from macOS (Docker)

valgrind and LeakSanitizer don't run on macOS/arm64, so the CI memcheck can't be
reproduced natively. Reproduce it in Docker with a **Debug** build (`-O0 -g`) so
valgrind prints accurate, un-inlined stacks (a Release build inlines callees into
the caller and mis-attributes the alloc site):

```bash
docker run --rm -v "$PWD":/work -v /path/to/scripts:/scripts ubuntu:24.04 bash -c '
  apt-get update -qq && apt-get install -y -qq cmake build-essential python3 python3-venv valgrind
  cmake -S /work -B /tmp/bl -DCMAKE_BUILD_TYPE=Debug \
    -DENABLE_HEAVY_TESTS=OFF -DVIRGIL_C_MT_TESTING=OFF -DVIRGIL_POST_QUANTUM=OFF -DVIRGIL_WRAP_GO=OFF
  cmake --build /tmp/bl --target <the_failing_test> -j"$(nproc)"
  valgrind --leak-check=full --show-leak-kinds=definite --track-origins=yes --error-exitcode=1 \
    /tmp/bl/tests/foundation/<the_failing_test>'
```

Turning off PQC and building only the single failing test target keeps the loop
fast. The exact CI flags live in `.github/workflows/build-linux.yml`
(`--leak-check=full --show-leak-kinds=definite`, and it fails the job on any
"definitely lost").

## Prevention

- **`*_cleanup_ctx` must free every buffer/impl the object can own.** Treat
  mid-processing frees (freeing a buffer as soon as it's consumed) as an
  optimization, never as the *only* owner-release. Every allocation reachable
  from `self` needs a matching destroy in `cleanup_ctx`.
- When adding a fail-closed early return, ask "what did the object allocate
  before this point, and is each of those freed on teardown?"
- A leak that only shows on an error path won't be caught by happy-path
  functional tests — the negative/fail-closed test plus the valgrind memcheck
  job is what catches it. Keep both.

## Related

- [[asserts-vs-status-and-error-handling]] — error-return conventions in this codebase
- [[vsc-buffer-ownership-and-secure-erasure-2026-06-18]] — vsc_buffer ownership rules
