# CG-013: Shared IR and Output Targets Beyond Common — Status

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

- [ ] Read the ADR and inspect current IR/output-target assumptions
- [ ] Identify what is still implicitly tied to `common`

---

### Step 1: Generalize the IR model
**Status:** ⬜ Not Started

- [ ] Ensure project/entity/output metadata is represented generically enough for `foundation`
- [ ] Keep naming/path/prefix/output routing model-driven
- [ ] Avoid turning universal IR into a bag of ad hoc project exceptions

---

### Step 2: Add shared IR tests
**Status:** ⬜ Not Started

- [ ] Add tests covering both `common` and `foundation` IR/output-target construction
- [ ] Confirm the IR remains suitable for the C backend

---

### Step 3: Verification
**Status:** ⬜ Not Started

- [ ] Run IR tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`

---

### Step 4: Delivery
**Status:** ⬜ Not Started

- [ ] Update docs to describe the shared IR/output-target contract

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
