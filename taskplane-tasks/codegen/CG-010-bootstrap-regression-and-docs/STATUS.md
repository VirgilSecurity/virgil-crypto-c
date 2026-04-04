# CG-010: Bootstrap Regression Validation & Docs — Status

**Current Step:** Not Started
**Status:** 🔵 Ready for Execution
**Last Updated:** 2026-04-04
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 0
**Size:** M

---

### Step 0: Preflight
**Status:** ⬜ Not Started

- [ ] Read the ADR and predecessor task outputs
- [ ] Inspect current bootstrap integration points

---

### Step 1: Integrate and validate
**Status:** ⬜ Not Started

- [ ] Ensure the bootstrap flow uses the project-rooted graph / IR / model-driven C path where appropriate
- [ ] Add or update regression tests around preservation behavior and architecture entrypoints
- [ ] Keep resolved XML limited to approved migration/parity roles only

---

### Step 2: Full verification
**Status:** ⬜ Not Started

- [ ] Run the relevant automated tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`
- [ ] Run `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Confirm no generated `library/common/**` artifacts remain staged for commit

---

### Step 3: Documentation and delivery
**Status:** ⬜ Not Started

- [ ] Refresh migration docs to describe the new project-rooted architecture and current completion state
- [ ] Summarize any remaining follow-up after the C backend regularization work

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
| 2026-04-04 | Task staged | PROMPT.md and STATUS.md created |

---

## Blockers

*None*

---

## Notes

This task closes the loop on the project-rooted `common` C architecture shift.
