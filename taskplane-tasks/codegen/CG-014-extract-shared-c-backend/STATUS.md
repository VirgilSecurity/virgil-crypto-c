# CG-014: Extract Shared C Backend — Status

**Current Step:** Not Started
**Status:** 🔵 Ready for Execution
**Last Updated:** 2026-04-05
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 0
**Size:** M

---

### Step 0: Preflight
**Status:** ⬜ Not Started

- [ ] Read the refactor plan and inspect current C backend boundaries
- [ ] Confirm which pieces are shared backend behavior versus temporary compatibility adapters

---

### Step 1: Extract shared C backend code
**Status:** ⬜ Not Started

- [ ] Move generic C lowering/rendering helpers into shared modules with generic names
- [ ] Keep project metadata model-driven rather than backend-literal-driven
- [ ] Avoid module-name-specific functionality branches where IR metadata already expresses the needed distinction

---

### Step 2: Preserve compatibility and tests
**Status:** ⬜ Not Started

- [ ] Keep or add thin compatibility adapters only where necessary
- [ ] Update imports/tests/scripts affected by the extraction
- [ ] Add tests proving the shared C backend path still works for `common`

---

### Step 3: Verification
**Status:** ⬜ Not Started

- [ ] Run backend tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`
- [ ] Run `bash tools/codegen/build_common_with_new_codegen.sh`

---

### Step 4: Delivery
**Status:** ⬜ Not Started

- [ ] Update docs to describe the shared C backend layer and any remaining adapter-only code

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

---

## Blockers

*None*
