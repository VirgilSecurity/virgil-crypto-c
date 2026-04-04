# CG-007: Project-Rooted Common Graph Loader — Status

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

- [ ] Read the ADR and the tests/fixtures from `CG-006`
- [ ] Inspect current loading flow and identify remaining ad hoc entrypoints

---

### Step 1: Implement project-rooted loading
**Status:** ⬜ Not Started

- [ ] Make `project_common.xml` the explicit loader entrypoint for `common`
- [ ] Resolve referenced model files and expose a coherent project graph
- [ ] Preserve tolerant parsing behavior for legacy XML-like code blocks

---

### Step 2: Clean up loader shape
**Status:** ⬜ Not Started

- [ ] Ensure project metadata needed by later backends is available from the graph
- [ ] Reduce reliance on per-module/manual lookup patterns where practical

---

### Step 3: Verification
**Status:** ⬜ Not Started

- [ ] Run tests from `CG-006`
- [ ] Run any updated loader tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`

---

### Step 4: Delivery
**Status:** ⬜ Not Started

- [ ] Update docs if parser or graph-loading realities changed
- [ ] Summarize what graph facts are now available to the IR layer

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

This task makes the `common` loader explicitly start at the project file.
