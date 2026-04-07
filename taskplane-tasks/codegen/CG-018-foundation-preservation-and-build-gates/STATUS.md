# CG-018: Foundation Preservation and Build Gates — Status

**Current Step:** Step 1: Define gates
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-07
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** S

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Inspect current `foundation` build/test surfaces
- [x] Identify which outputs are preservation-sensitive versus fully generated

---

### Step 1: Define gates
**Status:** 🟨 In Progress

- [ ] Document the recommended verification commands for `foundation`
- [ ] Identify any minimal helper script/test work needed to run those checks reliably

---

### Step 2: Implement minimal validation support
**Status:** ⬜ Not Started

- [ ] Add any small helper scripts/tests needed for future `foundation` batches
- [ ] Keep the scope limited to validation infrastructure

---

### Step 3: Verification
**Status:** ⬜ Not Started

- [ ] Run the new validation support if added
- [ ] Confirm the documented gate is executable or clearly marked if still blocked

---

### Step 4: Delivery
**Status:** ⬜ Not Started

- [ ] Update docs to make the `foundation` validation path explicit

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

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-05 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-07 14:49 | Task started | Runtime V2 lane-runner execution |
| 2026-04-07 14:49 | Step 0 started | Preflight |
| 2026-04-07 14:55 | Inspected `foundation` surfaces | Confirmed dependency-aware library build plus dedicated unit/fuzzy test CMake targets already exist. |
| 2026-04-07 14:57 | Classified output ownership | Marked `include/src` as preservation-sensitive partial outputs and `sources.cmake` / `features.cmake` as fully generated boundaries. |

---

## Blockers

*None*
