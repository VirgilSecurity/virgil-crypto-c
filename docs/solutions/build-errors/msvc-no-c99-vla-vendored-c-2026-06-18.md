---
title: "MSVC rejects C99 VLAs in vendored C (Windows JVM build failure)"
date: 2026-06-18
category: docs/solutions/build-errors
module: foundation
problem_type: build_error
component: thirdparty
severity: high
symptoms:
  - "Build JVM (Windows x86_64) CI job fails compiling thirdparty/sss/hazmat.c"
  - "error C2057: expected constant expression"
  - "error C2466: cannot allocate an array of constant size 0"
  - "error C2133: 'poly'/'xs'/'ys': unknown size"
  - "Passes locally on macOS and in the Go (MinGW) build; fails only on MSVC"
root_cause: c99_variable_length_arrays_unsupported_by_msvc
resolution_type: code_fix
tags:
  - msvc
  - windows
  - c99
  - vla
  - thirdparty
  - shamir
  - cross-platform
---

# MSVC rejects C99 VLAs in vendored C (Windows JVM build failure)

## Problem
Vendored `thirdparty/sss/hazmat.c` (Shamir GF(256) share math) sized stack arrays by the runtime threshold `k` using C99 variable-length arrays. GCC and Clang accept VLAs as an extension, so local macOS and the Go/MinGW builds were green — but the Java/Android wrapper builds the C with **MSVC**, which does not implement VLAs at all, and the `Build JVM (Windows x86_64)` CI job failed to compile.

## Symptoms
MSVC errors on the VLA declarations (`poly[k - 1][8]`, `xs[k][8]`, `ys[k][8]`):
- `C2057: expected constant expression`
- `C2466: cannot allocate an array of constant size 0`
- `C2133: ... unknown size`

Every GCC/Clang job (macOS, Linux, Go/MinGW) stays green, so the failure looks platform-specific and is easy to miss without a Windows/MSVC run.

## What Didn't Work
Relying on local macOS + Go/MinGW builds. Those toolchains accept VLAs, so the code compiled everywhere except MSVC; there is no local macOS path that reproduces it. A `k == 1` "floor" tweak (`poly[(k>1)?(k-1):1][8]`) addressed the zero-length-array edge but did **not** help — MSVC rejects *all* VLAs regardless of the expression.

## Solution
Replace the VLAs with fixed-size arrays bounded by the documented maximum (a share's x-coordinate is one byte in 1..255, so `n`,`k` ≤ 255). Only the live rows are touched.

Before:
```c
uint32_t poly0[8], poly[k - 1][8], x[8], y[8], xpow[8], tmp[8];   // VLA
...
uint32_t xs[k][8], ys[k][8];                                      // VLA
```
After (`thirdparty/sss/hazmat.c`):
```c
/* x in 1..255, so n,k <= 255. Fixed-size in place of upstream C99 VLAs (MSVC has none). */
#define VSCF_SSS_MAX_KEYSHARES 255

uint32_t poly0[8], poly[VSCF_SSS_MAX_KEYSHARES][8], x[8], y[8], xpow[8], tmp[8];
memcpy((void *)poly, random_data, (size_t)(k - 1) * sizeof(uint32_t[8])); // only k-1 rows
...
uint32_t xs[VSCF_SSS_MAX_KEYSHARES][8], ys[VSCF_SSS_MAX_KEYSHARES][8];
```

## Why This Works
The array dimension is now a compile-time constant (255), which every C compiler including MSVC accepts. Sizing to the protocol's upper bound is safe because `k`/`n` can never exceed 255. Bonus: it removes the degenerate `k == 1` zero-length-array case. Stack cost is bounded (`255 * 8 * 4 = 8160` bytes per array).

## Prevention
- Do not use C99 VLAs anywhere under `library/` or `thirdparty/` — the Java/Android wrapper compiles the C with MSVC, which has no VLA support.
- When vendoring third-party C, size arrays to a named max-bound `#define` and leave a comment noting the divergence from upstream (see `thirdparty/sss/VERSION`).
- A green local macOS + Go build is **not** sufficient portability signal; the Windows/MSVC (`Build JVM`) job is the gate for VLA / constant-expression issues. Push and watch `gh run list` for the Windows job.

## Related Issues
- `docs/solutions/build-errors/vscf-post-quantum-stale-cache-on-reconfigure-2026-04-27.md` — another cross-platform build trap.
- `docs/solutions/build-errors/go-cgo-stale-committed-pkg-headers-2026-06-18.md` — the other CI failure from the same PR (#207).
- Surfaced shipping `vscf_shamir` (PR #207).
