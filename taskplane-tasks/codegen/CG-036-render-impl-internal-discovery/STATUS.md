# CG-036: Render Implementation Internal Module and Extend Auto-Discovery — Status

**Current Step:** Not Started
**Status:** 🔵 Ready for Execution
**Last Updated:** 2026-04-08
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 0
**Size:** M

---

### Step 0: Preflight
**Status:** ⬜ Not Started

- [ ] CG-034 and CG-035 complete
- [ ] vscf_sha256_internal resolved XML studied
- [ ] API table initialization pattern understood
- [ ] impl_info structure understood
- [ ] discover_renderers implementation reviewed

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

---

## Blockers

*None*

---

## Notes

*Reserved for execution notes*
