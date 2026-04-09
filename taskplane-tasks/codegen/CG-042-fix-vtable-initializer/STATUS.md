# CG-042: Fix Vtable Struct Initializer in Internal Modules — Status

**Current Step:** Not Started
**Status:** 🔵 Ready for Execution
**Last Updated:** 2026-04-09
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 0
**Size:** M

---

### Step 0: Preflight
**Status:** ⬜ Not Started
- [ ] Current renderer read
- [ ] render_variable() in emitter read
- [ ] Bug confirmed

### Step 1: Fix C emitter multi-value struct initializers
**Status:** ⬜ Not Started
- [ ] render_variable() handles all c_value children
- [ ] c_cast wrapping works
- [ ] Per-value comments rendered
- [ ] Committed

### Step 2: Fix backend API table variable emission
**Status:** ⬜ Not Started
- [ ] Multi-value c_values for API tables
- [ ] impl_info variable emission
- [ ] Committed

### Step 3: Generate find_api method
**Status:** ⬜ Not Started
- [ ] find_api with switch/case
- [ ] Committed

### Step 4: Testing & Verification
**Status:** ⬜ Not Started
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

## Execution Log
| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-09 | Task staged | Restructured PROMPT with inline XML patterns |

## Blockers
*None*

## Notes
Previous attempt failed after 3 iterations with zero code commits. Root cause: worker spent all context reading GSL files. This version inlines the exact XML structure and C output patterns.
