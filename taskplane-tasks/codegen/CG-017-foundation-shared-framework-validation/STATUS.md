# CG-017: Foundation Validation on Shared Project-Rooted Framework — Status

**Current Step:** Step 3: Delivery
**Status:** ✅ Complete
**Last Updated:** 2026-04-06
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Review the shared-framework refactor outputs and `foundation` inventory
- [x] Identify the key shared-behavior assertions for `project_foundation.xml`

---

### Step 1: Validate shared behavior on `foundation`
**Status:** ✅ Complete

- [x] Add/update tests proving that the shared loader/IR/output-target path works on `project_foundation.xml`
- [x] Confirm that project metadata remains model-driven rather than hardcoded
- [x] Capture any gaps that block the first emitter slice

---

### Step 2: Verification
**Status:** ✅ Complete

- [x] Run the new shared-framework tests
- [x] Run `python3 -m py_compile` on the relevant codegen modules

---

### Step 3: Delivery
**Status:** ✅ Complete

- [x] Document what is now proven on `foundation` before emitter work begins

---

## Reviews

| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

---

## Discoveries

| Discovery | Disposition | Location |
|-----------|-------------|----------|
| `load_named_project_source("foundation")` currently fails when local `foundation` modules require shared modules (`library` / `assert`) without explicit `from="shared"`; the shared loader resolves those nested dependencies under `project_foundation/` instead of `shared/`. | Fix in Step 1 while adding shared-framework coverage. | `tools/codegen/project_source.py`; `codegen/models/project_foundation/module_mbedtls_bridge_*.xml` |
| The first emitter slice will likely target enums, but the shared C backend helper currently resolves output metadata only for modules/classes, so enum-target routing still needs either explicit support or a slice-specific adapter later. | Captured as the remaining pre-emitter blocker after shared-framework validation; defer the fix to the emitter slice task instead of broadening this validation task. | `tools/codegen/project_c_backend.py` |

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-05 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-06 19:10 | Task started | Runtime V2 lane-runner execution |
| 2026-04-06 19:10 | Step 0 started | Preflight |
| 2026-04-06 19:20 | Shared-framework + foundation inventory reviewed | Confirmed shared loader/IR/backend modules from CG-012..016 and identified current foundation loader gap on nested shared-module requires. |
| 2026-04-06 19:22 | Shared-behavior assertions identified | Foundation validation should prove model-driven project metadata (`vscf`, namespace/framework, roots), shared-module dependency resolution, and foundation-specific output-target routing without `common` literals. |
| 2026-04-06 19:35 | Foundation shared-framework tests added | Added a dedicated `foundation` shared-framework test file and fixed shared loader recursion for nested shared-module references / non-source generated-module requires. |
| 2026-04-06 19:40 | Model-driven metadata confirmed | Added assertions that `foundation` output prefixes/namespaces/paths diverge cleanly from `common`, proving shared routing derives from project XML metadata rather than backend literals. |
| 2026-04-06 19:41 | First-slice blocker captured | Logged enum-output routing support in the shared C backend as the remaining gap to resolve before the likely enum-first emitter slice. |
| 2026-04-06 19:44 | Shared-framework verification tests passed | `python3 -m unittest tests.codegen.test_project_foundation_shared_framework` passed (3 tests). |
| 2026-04-06 19:44 | Python compile verification passed | `python3 -m py_compile` succeeded for the touched shared codegen modules and the new foundation validation test. |
| 2026-04-06 19:46 | Delivery docs updated | Added a CG-017 validation-status section to `foundation-next-phase-plan.md` describing what is proven on `foundation` and the remaining enum-routing gap before emitter work. |
| 2026-04-06 19:20 | Worker iter 1 | done in 559s, tools: 83 |
| 2026-04-06 19:20 | Task complete | .DONE created |

---

## Blockers

*None*
