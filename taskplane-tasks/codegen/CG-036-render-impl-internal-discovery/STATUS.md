# CG-036: Render Implementation Internal Module and Extend Auto-Discovery — Status

**Current Step:** Step 0: Preflight
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-08
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 2
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] CG-033 and CG-035 complete
- [x] vscf_sha256_internal resolved XML studied
- [x] API table initialization pattern understood
- [x] impl_info structure understood
- [x] discover_renderers implementation reviewed

---

### Step 1: Implement render_implementation_internal_c_module()
**Status:** ⬜ Not Started

> ⚠️ Hydrate: Expand based on exact variable/init patterns from resolved XML

- [ ] render_implementation_internal_c_module() implemented
- [ ] API table variables with function pointers
- [ ] impl_info variable
- [ ] Constant values from bindings
- [ ] Inherited API table references
- [ ] Correct includes

---

### Step 2: Extend auto-discovery
**Status:** ⬜ Not Started

- [ ] discover_renderers handles entity_kinds={"interface"}
- [ ] discover_renderers handles entity_kinds={"implementation"}
- [ ] Interface → 2 renderers (dispatch + api)
- [ ] Implementation → 3 renderers (main + defs + internal)
- [ ] Default discovery includes all kinds

---

### Step 3: Add parity and discovery tests
**Status:** ⬜ Not Started

- [ ] sha256_internal api table variables
- [ ] sha256_internal impl_info variable
- [ ] sha256_internal includes match
- [ ] sha256_internal init/cleanup present
- [ ] hash api table function pointers correct
- [ ] Foundation interface discovery count
- [ ] Foundation implementation discovery count
- [ ] Full discovery covers all kinds
- [ ] Common discovery unchanged

---

### Step 4: Testing & Verification
**Status:** ⬜ Not Started

- [ ] New tests pass
- [ ] Existing tests pass
- [ ] Build gate passes

---

### Step 5: Documentation & Delivery
**Status:** ⬜ Not Started

- [ ] CONTEXT.md updated
- [ ] Discoveries logged

---

## Reviews

| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

---

## Discoveries

| Discovery | Disposition | Location |
|-----------|-------------|----------|

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-08 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-08 23:45 | Task started | Runtime V2 lane-runner execution |
| 2026-04-08 23:45 | Step 0 started | Preflight |
| 2026-04-08 23:49 | Worker iter 1 | done in 205s, tools: 29 |

---

## Blockers

*None*

---

## Notes

*Reserved for execution notes*
