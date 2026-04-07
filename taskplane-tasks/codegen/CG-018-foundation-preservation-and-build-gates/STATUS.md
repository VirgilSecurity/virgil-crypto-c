# CG-018: Foundation Preservation and Build Gates — Status

**Current Step:** Step 4: Delivery
**Status:** ✅ Complete
**Last Updated:** 2026-04-07
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 3
**Size:** S

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Inspect current `foundation` build/test surfaces
- [x] Identify which outputs are preservation-sensitive versus fully generated

---

### Step 1: Define gates
**Status:** ✅ Complete

- [x] Document the recommended verification commands for `foundation`
- [x] Identify any minimal helper script/test work needed to run those checks reliably

---

### Step 2: Implement minimal validation support
**Status:** ✅ Complete

- [x] Add any small helper scripts/tests needed for future `foundation` batches
- [x] Keep the scope limited to validation infrastructure

---

### Step 3: Verification
**Status:** ✅ Complete

- [x] Run the new validation support if added
- [x] Confirm the documented gate is executable or clearly marked if still blocked

---

### Step 4: Delivery
**Status:** ✅ Complete

- [x] Update docs to make the `foundation` validation path explicit

---

## Reviews

| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

---

## Discoveries

| Discovery | Disposition | Location |
|-----------|-------------|----------|
| `foundation` validation already has concrete CMake/CTest surfaces: `library/foundation/CMakeLists.txt`, `tests/foundation/CMakeLists.txt`, `tests/fuzzy/foundation/CMakeLists.txt`, plus the `foundation_pb` protobuf sublibrary. | Use these as the baseline build/test gate instead of inventing a separate ad hoc test harness. | `library/foundation/CMakeLists.txt`; `tests/foundation/CMakeLists.txt`; `fuzzy/foundation/CMakeLists.txt` |
| `library/foundation/include/**` and `library/foundation/src/**` are preservation-sensitive partial-generation surfaces, while `library/foundation/sources.cmake` and `library/foundation/features.cmake` are explicitly fully generated; protobuf assets form a separate dependency boundary owned through `library/foundation/protobuf/**`. | Treat partial C/header files as the core preservation gate, keep fully generated CMake metadata out of first-slice ownership, and include protobuf buildability in the compile gate. | `library/foundation/include/**`; `library/foundation/src/**`; `library/foundation/sources.cmake`; `library/foundation/features.cmake`; `library/foundation/protobuf/**` |
| The first end-to-end helper run (`bash tools/codegen/verify_foundation_validation_gate.sh`) exposed that `ctest -L foundation` needs the `tests/foundation` executables built explicitly; teaching the helper to discover foundation-labeled tests from `ctest -N -L foundation` and build those targets makes the documented gate executable without broadening it to unrelated suites. | Keep the helper's two-phase behavior: build `foundation` first for the library/protobuf dependency path, then build only the labeled foundation test targets before the labeled CTest pass. | `tools/codegen/verify_foundation_validation_gate.sh`; `tests/foundation/CMakeLists.txt` |

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-05 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-07 14:49 | Task started | Runtime V2 lane-runner execution |
| 2026-04-07 14:49 | Step 0 started | Preflight |
| 2026-04-07 14:55 | Inspected `foundation` surfaces | Confirmed dependency-aware library build plus dedicated unit/fuzzy test CMake targets already exist. |
| 2026-04-07 14:57 | Classified output ownership | Marked `include/src` as preservation-sensitive partial outputs and `sources.cmake` / `features.cmake` as fully generated boundaries. |
| 2026-04-07 16:52 | Worker iter 1 | killed (wall-clock timeout) in 7402s, tools: 46 |
| 2026-04-07 18:52 | Worker iter 2 | killed (wall-clock timeout) in 7200s, tools: 50 |
| 2026-04-07 18:52 | Step 3 started | Verification |
| 2026-04-07 19:12 | Ran foundation validation helper | `bash tools/codegen/verify_foundation_validation_gate.sh` configured and built `foundation`, then `ctest -L foundation` failed because the labeled `tests/foundation` executables were not built into the gate tree. |
| 2026-04-07 19:43 | Repaired and re-ran foundation validation helper | Updated the helper to discover/build the `foundation`-labeled test targets before `ctest`; the documented command now passes with 54/54 `foundation` tests green in `build/foundation-gate`. |
| 2026-04-07 19:50 | Updated migration docs | Made the `foundation` validation path explicit in `foundation-next-phase-plan.md`, including the helper's test-target discovery/build step and the passing 54/54 verification result. |

---

## Blockers

*None*
