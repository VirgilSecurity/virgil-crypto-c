# CG-006: Project-Rooted Common Graph Tests & Fixtures — Status

**Current Step:** Step 1: Define project-rooted expectations
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-04
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** S

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Read the ADR and current parser notes
- [x] Identify the existing testing pattern that best fits lightweight generator tests

---

### Step 1: Define project-rooted expectations
**Status:** 🟨 In Progress

- [ ] Identify the minimum expected graph facts that must be discoverable from `project_common.xml`
- [ ] Cover referenced classes, modules, enums, and project metadata needed by the C backend

---

### Step 2: Implement tests and fixtures
**Status:** ⬜ Not Started

- [ ] Add tests that start from `project_common.xml`
- [ ] Verify that the loader entrypoint is project-rooted rather than ad hoc per-module
- [ ] Keep fixtures or assertions narrow and maintainable

---

### Step 3: Verification
**Status:** ⬜ Not Started

- [ ] Run the new tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`

---

### Step 4: Delivery
**Status:** ⬜ Not Started

- [ ] Document the new test entrypoints and what architecture assumptions they protect

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
| 2026-04-04 22:08 | Task started | Runtime V2 lane-runner execution |
| 2026-04-04 22:08 | Step 0 started | Preflight |

---

## Blockers

*None*

---

## Notes

This task establishes the tests that guard the next architectural refactor.
