# CG-033: Render Interface Modules (Dispatch + API) — Status

**Current Step:** Step 1: Add interface helper utilities
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-08
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] CG-031 complete
- [x] Resolved XML for hash_api and hash studied
- [x] Naming conventions identified

---

### Step 1: Add interface helper utilities
**Status:** ⬜ Not Started

- [ ] interface_ir() lookup
- [ ] entity_output() extended for interface
- [ ] interface_api_output() helper
- [ ] Committed

---

### Step 2: Implement render_interface_api_c_module()
**Status:** ⬜ Not Started

- [ ] render_interface_api_c_module() implemented
- [ ] Callback typedefs
- [ ] API struct with fields
- [ ] Inherited API references
- [ ] Committed

---

### Step 3: Implement render_interface_c_module()
**Status:** ⬜ Not Started

- [ ] Scaffold (root, includes, struct decl)
- [ ] Dispatch method generation with bodies
- [ ] Constant getter generation
- [ ] _api(), _is_implemented(), _api_tag() utilities
- [ ] Inherited method/constant flattening
- [ ] Committed

---

### Step 4: Add parity tests
**Status:** ⬜ Not Started

- [ ] hash_api callbacks correct
- [ ] hash_api struct fields correct
- [ ] hash dispatch method count correct
- [ ] hash dispatch bodies have vtable calls
- [ ] cipher dispatch has inherited methods
- [ ] Includes correct

---

### Step 5: Testing & Verification
**Status:** ⬜ Not Started

- [ ] New tests pass
- [ ] Existing tests pass
- [ ] Build gate passes

---

### Step 6: Documentation & Delivery
**Status:** ⬜ Not Started

- [ ] Discoveries logged
- [ ] CONTEXT.md updated if needed

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
| 2026-04-08 | Task staged | PROMPT.md and STATUS.md created (restructured from failed CG-033/CG-034 split) |
| 2026-04-08 22:40 | Task started | Runtime V2 lane-runner execution |
| 2026-04-08 22:40 | Step 0 started | Preflight |

---

## Blockers

*None*

---

## Notes

Previous CG-033 attempt failed after 5 iterations with zero code commits. Root cause: single monolithic implementation step. This version has explicit commit points at each step boundary.
