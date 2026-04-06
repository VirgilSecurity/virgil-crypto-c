# CG-014: Extract Shared C Backend — Status

**Current Step:** Step 3: Verification
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-06
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 2
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Read the refactor plan and inspect current C backend boundaries
- [x] Confirm which pieces are shared backend behavior versus temporary compatibility adapters

---

### Step 1: Extract shared C backend code
**Status:** ✅ Complete

- [x] Move generic C lowering/rendering helpers into shared modules with generic names
- [x] Keep project metadata model-driven rather than backend-literal-driven
- [x] Avoid module-name-specific functionality branches where IR metadata already expresses the needed distinction

---

### Step 2: Preserve compatibility and tests
**Status:** ✅ Complete

- [x] Keep or add thin compatibility adapters only where necessary
- [x] Update imports/tests/scripts affected by the extraction
- [x] Add tests proving the shared C backend path still works for `common`

---

### Step 3: Verification
**Status:** 🟨 In Progress

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
| `foundation-next-phase-plan.md` defines the shared C backend split: IR navigation, XML helpers, argument/return lowering, and renderer registration should leave `common_direct_c.py`; only handwritten entity builders should remain adapter/project-specific. | Use as the extraction boundary for CG-014 implementation. | `docs/codegen-migration/foundation-next-phase-plan.md`, `tools/codegen/common_direct_c.py` |
| `common_source.py` and `common_ir.py` are already thin compatibility wrappers over `project_source.py` / `project_ir.py`, while `common_bootstrap.py` and inspect scripts still depend on `common_direct_c.py` for project selection. | Keep `common`-named entrypoints thin; extract shared backend internals under generic modules and preserve wrapper behavior. | `tools/codegen/common_source.py`, `tools/codegen/common_ir.py`, `tools/codegen/common_bootstrap.py`, `tools/codegen/inspect_common_direct.py` |

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-05 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-06 14:23 | Task started | Runtime V2 lane-runner execution |
| 2026-04-06 14:23 | Step 0 started | Preflight |
| 2026-04-06 14:25 | Preflight inspection | Read CG-011 plan, migration docs, and current `common_direct_c.py` helper/builder split |
| 2026-04-06 14:27 | Step 0 completed | Shared-backend helpers vs thin compatibility adapters confirmed |
| 2026-04-06 14:27 | Step 1 started | Extract shared C backend code |
| 2026-04-06 14:41 | Worker iter 1 | done in 1085s, tools: 40 |

---

## Blockers

*None*
