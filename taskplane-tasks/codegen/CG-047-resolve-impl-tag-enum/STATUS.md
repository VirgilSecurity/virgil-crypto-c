# CG-047: Resolve impl/tag Enum in IR — Status

**Current Step:** Step 0: Preflight
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-10
**Review Level:** 1
**Review Counter:** 0
**Iteration:** 1
**Size:** M

---

### Step 0: Preflight
**Status:** 🟨 In Progress

- [x] 2 module skips confirmed
- [x] impl/tag XML references examined
- [x] Legacy vscf_impl_tag_t generation understood
- [x] Approach decided: Synthetic IREnum in project_to_ir() — add 'impl tag' enum with BEGIN/END + one constant per implementation

### Step 1: Implement impl/tag enum resolution
**Status:** ⬜ Not Started

> ⚠️ Hydrate: Expand based on approach chosen in Step 0

- [ ] impl/tag resolves in IR or type system
- [ ] Both skipped modules generate successfully
- [ ] No new skips introduced

### Step 2: Testing & Verification
**Status:** ⬜ Not Started

- [ ] Python test suite passing (159+ tests)
- [ ] Common build gate passes
- [ ] Foundation codegen: 0 unexpected skips
- [ ] Foundation build checked
- [ ] No regressions
- [ ] KNOWN_SKIPS updated if applicable

### Step 3: Documentation & Delivery
**Status:** ⬜ Not Started

- [ ] CONTEXT.md updated (tech debt removed)
- [ ] Foundation status doc updated if applicable
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
| 2026-04-10 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-10 02:14 | Task started | Runtime V2 lane-runner execution |
| 2026-04-10 02:14 | Step 0 started | Preflight |

## Blockers
*None*

## Notes
*Reserved for execution notes*
