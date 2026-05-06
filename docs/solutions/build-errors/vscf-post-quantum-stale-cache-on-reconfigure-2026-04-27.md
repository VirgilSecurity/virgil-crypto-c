---
title: "VSCF_POST_QUANTUM stays OFF after re-configuring with VIRGIL_POST_QUANTUM=ON"
date: 2026-04-27
category: docs/solutions/build-errors
module: foundation
problem_type: build_error
component: cmake
severity: high
symptoms:
  - "fatal error: 'falcon/falcon.h' file not found after re-configuring with -DVIRGIL_POST_QUANTUM=ON"
  - "fatal error: 'mlkem/mlkem_native.h' file not found"
  - "CMakeCache.txt shows VSCF_POST_QUANTUM:BOOL=OFF even though VIRGIL_POST_QUANTUM:BOOL=ON"
  - "Compiler flags show -DVSCF_POST_QUANTUM=0 alongside -DFALCON_LIBRARY=1 -DMLKEM_LIBRARY=1 -DMLDSA_LIBRARY=1"
  - "Thirdparty headers exist on disk in build/thirdparty/*/include/ but are absent from the compiler -I path"
root_cause: cmake_cache_not_forced_in_positive_branch
resolution_type: code_fix
tags:
  - cmake
  - post-quantum
  - stale-cache
  - reconfigure
  - falcon
  - ml-kem
  - ml-dsa
  - include-path
  - generator-expression
---

# VSCF_POST_QUANTUM stays OFF after re-configuring with VIRGIL_POST_QUANTUM=ON

## Problem

A one-line asymmetry in `CMakeLists.txt` caused `VSCF_POST_QUANTUM` to remain `OFF` in the CMake cache even when re-configured with `-DVIRGIL_POST_QUANTUM=ON`. The `else()` branch forced the cache value to `OFF`, but the `if()` branch never forced it back to `ON`. Any build directory previously configured with PQ disabled inherited the stale `OFF` value indefinitely, producing "header not found" errors for every PQ thirdparty library even though the headers were physically present in the build tree.

## Symptoms

- Compiler errors: `fatal error: 'falcon/falcon.h' file not found`, `fatal error: 'mlkem/mlkem_native.h' file not found`
- Problem appears only when re-using a build directory that was previously configured with `VIRGIL_POST_QUANTUM=OFF` — fresh build directories are unaffected
- `cmake -L build/ | grep POST_QUANTUM` shows a contradiction:
  ```
  VIRGIL_POST_QUANTUM:BOOL=ON
  VSCF_POST_QUANTUM:BOOL=OFF    ← stale
  ```
- `cmake -L build/ | grep LIBRARY` shows the library flags are correctly set:
  ```
  FALCON_LIBRARY:BOOL=ON
  MLKEM_LIBRARY:BOOL=ON
  MLDSA_LIBRARY:BOOL=ON
  ```
- The thirdparty `add_subdirectory` calls ran (libraries are built, headers exist in `build/thirdparty/*/include/`), but the compiler never gets the `-I` flag pointing to them

## What Didn't Work

- **Verifying headers exist on disk** — they do (`build/thirdparty/falcon/falcon/include/falcon/falcon.h` is present). The issue is not a missing source or a failed `ExternalProject` build; the headers are on disk but not on the compiler's `-I` path.
- **Re-running `cmake --build`** without deleting `CMakeCache.txt` — the cache persists across builds. Re-running configure without deleting the cache does not change a cached `BOOL` unless `FORCE` is used.
- **Checking `VIRGIL_POST_QUANTUM`** — its value is correct at `ON`. `VIRGIL_POST_QUANTUM` and `VSCF_POST_QUANTUM` are separate cache variables; one being correct does not update the other.
- **Parallel vs sequential build** (`-j4` vs `-j1`) — no difference; this is a configure-time problem, not a build parallelism race.
- **First partial fix** (session history): an earlier commit added `set(VSCF_POST_QUANTUM OFF CACHE ... FORCE)` to the `else()` branch to prevent accidental activation when PQ was disabled. This fixed the `OFF→OFF` case but introduced the asymmetry that caused this bug when switching `OFF→ON` in a reused build dir.

## Solution

**File:** `CMakeLists.txt` (root), post-quantum section (~line 218)

Before:
```cmake
if(VIRGIL_POST_QUANTUM)
    add_subdirectory("thirdparty/falcon")
    add_subdirectory("thirdparty/mlkem-native")
    add_subdirectory("thirdparty/mldsa-native")
else()
    set(VSCF_POST_QUANTUM OFF CACHE BOOL "Enable post-quantum cryptography for foundation library [experimental]." FORCE)
endif()
```

After:
```cmake
if(VIRGIL_POST_QUANTUM)
    set(VSCF_POST_QUANTUM ON CACHE BOOL "Enable post-quantum cryptography for foundation library [experimental]." FORCE)
    add_subdirectory("thirdparty/falcon")
    add_subdirectory("thirdparty/mlkem-native")
    add_subdirectory("thirdparty/mldsa-native")
else()
    set(VSCF_POST_QUANTUM OFF CACHE BOOL "Enable post-quantum cryptography for foundation library [experimental]." FORCE)
endif()
```

The single added line mirrors the `FORCE` already present in the `else()` branch, making both cache transitions symmetric.

## Why This Works

CMake `CACHE` variables persist across re-configures: once written to `CMakeCache.txt`, a value survives subsequent `cmake` invocations unless explicitly overridden with `FORCE` or the cache file is deleted. The `else()` branch used `FORCE` to lock `VSCF_POST_QUANTUM=OFF` when PQ was disabled — preventing accidental activation. But the `if()` branch had no corresponding `FORCE`, so a stale `OFF` value in the cache was never corrected when the user switched to `ON`.

The downstream effect: `library/foundation/CMakeLists.txt` uses generator expressions in `target_link_libraries`:

```cmake
$<$<BOOL:${VSCF_POST_QUANTUM}>:falcon>
$<$<BOOL:${VSCF_POST_QUANTUM}>:mlkem768>
$<$<BOOL:${VSCF_POST_QUANTUM}>:mldsa65>
```

When `VSCF_POST_QUANTUM=0`, these expressions evaluate to the empty string — the three PQ link targets are excluded from the link step. CMake's transitive dependency model means their `INTERFACE_INCLUDE_DIRECTORIES` are never added to the `foundation` compile step. The `FALCON_LIBRARY`, `MLKEM_LIBRARY`, `MLDSA_LIBRARY` compile definitions are set independently (via `$<BOOL:${FALCON_LIBRARY}>` etc.) and are always `=1` once `add_subdirectory` runs — making the bug confusing: library flags look correct while include paths are wrong.

## Prevention

- **When writing `if(FLAG) ... set(DERIVED ...) ... else() ... set(DERIVED ...) ... endif()`, always `FORCE` both branches.** The `FORCE` on the `OFF` side exists for a reason (preventing stale `ON` values); the `ON` side needs the same protection against stale `OFF` values.
- **Test the re-configure scenario explicitly** when introducing a new derived cache flag: configure once with the flag `OFF`, then re-configure with `ON` without deleting the cache, and verify the derived variable updates correctly.
- **When headers are confirmed to exist in the build tree but the compiler can't find them**, the first diagnostic step is to check all derived cache variables (`cmake -L build/ | grep <RELEVANT_FLAG>`), not the source files or ExternalProject state.
- **Use the same CACHE description string in both branches** to avoid confusing `cmake-gui` display with duplicated variable entries.

## Related Issues

- `library/foundation/CMakeLists.txt` lines 94–96: the generator expressions `$<$<BOOL:${VSCF_POST_QUANTUM}>:falcon>` that strip include paths when the cache variable is wrong
- Commit `7036c438c`: one-line fix — "force VSCF_POST_QUANTUM=ON when VIRGIL_POST_QUANTUM=ON"
- Background on the `VIRGIL_POST_QUANTUM` → `FALCON_LIBRARY` variable flow: [`docs/solutions/best-practices/external-library-cmake-codegen-2026-04-26.md`](../best-practices/external-library-cmake-codegen-2026-04-26.md) — explains how `${VIRGIL_POST_QUANTUM}` flows into `thirdparty/*/features.cmake` option defaults
