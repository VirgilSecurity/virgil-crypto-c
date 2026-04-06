# CG-012: Extract Shared Project Graph Loader — Status

**Current Step:** Step 3: Verification
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-06
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Read the refactor plan and identify the shared loader responsibilities
- [x] Confirm the compatibility boundary for `common_source.py`

---

### Step 1: Extract shared loader code
**Status:** ✅ Complete

- [x] Move generic project-rooted loading logic into shared modules with generic names
- [x] Preserve tolerant parsing behavior
- [x] Keep project metadata model-driven

---

### Step 2: Preserve compatibility and tests
**Status:** ✅ Complete

- [x] Keep or add thin compatibility adapters only where necessary
- [x] Update imports/tests/scripts affected by the extraction
- [x] Add tests proving the shared loader path still works for `common`

---

### Step 3: Verification
**Status:** 🟨 In Progress

- [ ] Run loader tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`

---

### Step 4: Delivery
**Status:** ⬜ Not Started

- [ ] Document what moved into the shared loader layer and what remains adapter-only

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
| 2026-04-05 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-06 13:22 | Task started | Runtime V2 lane-runner execution |
| 2026-04-06 13:22 | Step 0 started | Preflight |

---

## Blockers

*None*
