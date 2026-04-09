# CG-042: Fix Vtable Struct Initializer in Internal Modules — Status

**Current Step:** Step 4: Testing & Verification
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-09
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Done
- [x] Current renderer read
- [x] render_variable() in emitter read
- [x] Bug confirmed

### Step 1: Fix C emitter multi-value struct initializers
**Status:** ✅ Done
- [x] render_variable() collects all c_value children, renders multi-value struct initializer with c_cast wrapping and per-value comments
- [x] Committed

### Step 2: Fix backend API table variable emission
**Status:** ✅ Done
- [x] Multi-value c_values for API tables (verified already correct from CG-040)
- [x] impl_info variable emission (verified already correct from CG-040)
- [x] Committed (no backend changes needed)

### Step 3: Generate find_api method
**Status:** ✅ Done
- [x] find_api with switch/case (verified already generated from CG-040)
- [x] Committed (no changes needed)

### Step 4: Testing & Verification
**Status:** 🟨 In Progress
- [ ] All tests pass
- [ ] Common build gate passes
- [ ] sha256_internal.c correct

### Step 5: Documentation & Delivery
**Status:** ⬜ Not Started
- [ ] Discoveries logged

---

## Reviews
| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

## Discoveries
| Discovery | Disposition | Location |
|-----------|-------------|----------|
| Backend already emits multi-value c_values, find_api, impl_info correctly (from CG-040) | Steps 2-3 may already be done; only render_variable fix needed | project_c_backend.py:4024-4360 |

## Execution Log
| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-09 | Task staged | Restructured PROMPT with inline XML patterns |
| 2026-04-09 22:29 | Task started | Runtime V2 lane-runner execution |
| 2026-04-09 22:29 | Step 0 started | Preflight |

## Blockers
*None*

## Notes
Previous attempt failed after 3 iterations with zero code commits. Root cause: worker spent all context reading GSL files. This version inlines the exact XML structure and C output patterns.
