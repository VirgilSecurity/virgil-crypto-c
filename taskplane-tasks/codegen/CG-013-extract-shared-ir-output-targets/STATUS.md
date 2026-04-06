# CG-013: Extract Shared IR and Output Targets — Status

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

- [ ] Read the refactor plan and current IR/output-target docs
- [ ] Confirm which IR responsibilities should become shared generic modules

---

### Step 1: Extract shared IR/output-target code
**Status:** ⬜ Not Started

- [ ] Move generic IR/output-target modeling into shared modules with generic names
- [ ] Keep naming/path/prefix/output routing model-driven
- [ ] Avoid turning the shared IR into project-specific branches

---

### Step 2: Preserve compatibility and tests
**Status:** ⬜ Not Started

- [ ] Keep or add thin compatibility adapters only where necessary
- [ ] Update imports/tests/scripts affected by the extraction
- [ ] Add tests proving the shared IR path still works for `common`

---

### Step 3: Verification
**Status:** ⬜ Not Started

- [ ] Run IR tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`

---

### Step 4: Delivery
**Status:** ⬜ Not Started

- [ ] Update docs to describe the shared IR/output-target layer

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
