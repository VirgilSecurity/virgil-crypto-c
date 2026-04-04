# CG-008: Common Project Graph to IR — Status

**Current Step:** Step 2: Implement graph-to-IR lowering
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-04
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Read the ADR and inspect the current IR shape
- [x] Identify which project-derived metadata is still missing or implicit

---

### Step 1: Define or refine the normalized IR
**Status:** ✅ Complete

- [x] Ensure the IR can represent project, modules, classes, enums, methods, constants, and output metadata needed by the C backend
- [x] Prefer explicit structured fields over module-specific ad hoc conventions

---

### Step 2: Implement graph-to-IR lowering
**Status:** 🟨 In Progress

- [ ] Lower the project-rooted graph into the normalized IR
- [ ] Preserve enough detail to drive naming/file decisions from model metadata
- [ ] Add or update tests for the IR construction path

---

### Step 3: Verification
**Status:** ⬜ Not Started

- [ ] Run IR tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`

---

### Step 4: Delivery
**Status:** ⬜ Not Started

- [ ] Update docs describing the IR and what it now guarantees to backends

---

## Reviews

| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

---

## Discoveries

| Discovery | Disposition | Location |
|-----------|-------------|----------|
| Current `IRProjectCommon` only carries top-level module/class refs plus raw attrs; it omits enums/constants, resolved dependency modules, stable entity/output metadata, and typed project-relative file targeting now hardcoded in `common_direct_c.py`. | Plan to add normalized project/module/class/enum/output records in Step 1-2. | `tools/codegen/common_ir.py`, `tools/codegen/common_direct_c.py` |

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-04 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-04 22:45 | Task started | Runtime V2 lane-runner execution |
| 2026-04-04 22:45 | Step 0 started | Preflight |
| 2026-04-04 22:52 | Preflight inspection | Confirmed current IR is structural only and still leaves project-derived output/naming metadata implicit in `common_direct_c.py` |
| 2026-04-04 23:02 | IR shape refactor | Added normalized project/entity/output dataclasses plus typed refs/constants/dependency-module coverage in `common_ir.py` |

---

## Blockers

*None*

---

## Notes

This task establishes the model-driven IR layer for the next backend step.

Preflight notes:
- `project_common_to_ir()` currently emits only explicit project modules/classes, preserving most source attrs as raw dictionaries.
- Missing or implicit data includes: dependency modules from graph resolution, enum lowering, constant/grouping metadata, entity origins/source paths, and normalized output target fields (`c_include_file`, `header_file`, `source_file`, once-guards, feature/public-private placement) that the C backend currently reconstructs with hardcoded literals.
