# CG-007: Project-Rooted Common Graph Loader — Status

**Current Step:** Step 4: Delivery
**Status:** ✅ Complete
**Last Updated:** 2026-04-04
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 2
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Read the ADR and the tests/fixtures from `CG-006`
- [x] Inspect current loading flow and identify remaining ad hoc entrypoints

---

### Step 1: Implement project-rooted loading
**Status:** ✅ Complete

- [x] Make `project_common.xml` the explicit loader entrypoint for `common`
- [x] Resolve referenced model files and expose a coherent project graph
- [x] Preserve tolerant parsing behavior for legacy XML-like code blocks

---

### Step 2: Clean up loader shape
**Status:** ✅ Complete

- [x] Ensure project metadata needed by later backends is available from the graph
- [x] Reduce reliance on per-module/manual lookup patterns where practical

---

### Step 3: Verification
**Status:** ✅ Complete

- [x] Run tests from `CG-006`
- [x] Run any updated loader tests
- [x] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`

---

### Step 4: Delivery
**Status:** ✅ Complete

- [x] Update docs if parser or graph-loading realities changed
- [x] Summarize what graph facts are now available to the IR layer

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
| 2026-04-04 22:16 | Task started | Runtime V2 lane-runner execution |
| 2026-04-04 22:16 | Step 0 started | Preflight |
| 2026-04-04 22:39 | Worker iter 1 | done in 1367s, tools: 71 |

---

## Blockers

*None*

---

## Notes

This task makes the `common` loader explicitly start at the project file.
