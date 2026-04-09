# CG-041: Fix Type Resolution for Foundation Entities — Status

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
- [ ] Issues confirmed via diff
- [ ] Renderers read
- [ ] argument/return_from_source understood

### Step 1: Fix defs rendering (C1, C2, C3)
**Status:** ⬜ Not Started
- [ ] Dependency struct fields (C1)
- [ ] Interface properties → impl_t * (C2)
- [ ] Fixed-size arrays (C3)
- [ ] Committed

### Step 2: Fix argument/return type resolution (D2-D6)
**Status:** ⬜ Not Started
- [ ] Interface-typed args → impl_t * (D4)
- [ ] const for readonly (D2)
- [ ] data by value (D3)
- [ ] Enum returns (D5)
- [ ] NODISCARD (D6)
- [ ] Committed

### Step 3: Fix enum constant comments (D7)
**Status:** ⬜ Not Started
- [ ] Per-constant comments added
- [ ] Committed

### Step 4: Testing & Verification
**Status:** ⬜ Not Started
- [ ] All tests pass
- [ ] Common build gate passes
- [ ] sha256.h signatures correct
- [ ] aes256_gcm_defs.h arrays correct
- [ ] key_info.h enum returns correct

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
| 2026-04-09 | Task staged | PROMPT.md and STATUS.md created |

## Blockers
*None*

## Notes
*Reserved for execution notes*
