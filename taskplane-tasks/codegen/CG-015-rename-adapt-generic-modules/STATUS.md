# CG-015: Rename and Adapt Generic Modules, Imports, and Docs — Status

**Current Step:** Step 3: Delivery
**Status:** ✅ Complete
**Last Updated:** 2026-04-06
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 5
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Review extracted shared-module outputs from predecessor tasks
- [x] Confirm which legacy `common_*` names should remain as temporary adapters, if any

---

### Step 1: Update callers and names
**Status:** ✅ Complete

- [x] Update imports/scripts/tests/docs to prefer the new generic module names
- [x] Reduce legacy `common_*` modules to thin compatibility adapters or remove them where safe
- [x] Keep current `common` workflows working

---

### Step 2: Verification
**Status:** ✅ Complete

- [x] Run relevant tests
- [x] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`
- [x] Run `bash tools/codegen/build_common_with_new_codegen.sh`

---

### Step 3: Delivery
**Status:** ✅ Complete

- [x] Update docs to state the new shared module names and compatibility policy

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
| 2026-04-06 14:54 | Task started | Runtime V2 lane-runner execution |
| 2026-04-06 14:54 | Step 0 started | Preflight |
| 2026-04-06 15:10 | Step 0 review | Reviewed CG-012 through CG-014 outputs plus shared/adapter module boundaries; confirmed `project_source.py`, `project_ir.py`, and `project_c_backend.py` now own the shared loader/IR/backend responsibilities |
| 2026-04-06 15:12 | Worker iter 1 | done in 1067s, tools: 24 |
| 2026-04-06 15:24 | Step 0 adapter boundary | Confirmed `common_source.py`, `common_ir.py`, and `common_direct_c.py` should remain temporary thin `common` compatibility adapters, while `common_bootstrap.py` remains the current `common` CLI/workflow entrypoint |
| 2026-04-06 17:15 | Worker iter 2 | killed (wall-clock timeout) in 7344s, tools: 34 |
| 2026-04-06 17:15 | Step 1 started | Update callers and names |
| 2026-04-06 18:28 | Worker iter 3 | done in 4380s, tools: 7 |
| 2026-04-06 18:28 | No progress | Iteration 3: 0 new checkboxes (1/3 stall limit) |
| 2026-04-06 19:01 | Step 1 targeted tests | `python3 -m unittest tests.codegen.test_project_common_source tests.codegen.test_project_common_ir tests.codegen.test_common_direct_c_resolution tests.codegen.test_common_bootstrap tests.codegen.test_project_c_backend` passed (20 tests) |
| 2026-04-06 19:03 | Step 2 verification tests | `python3 -m unittest tests.codegen.test_project_common_source tests.codegen.test_project_common_ir tests.codegen.test_common_direct_c_resolution tests.codegen.test_common_bootstrap tests.codegen.test_project_c_backend` passed (20 tests) |
| 2026-04-06 19:03 | Step 2 verification compile | `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py` passed |
| 2026-04-06 19:04 | Step 2 build gate | `bash tools/codegen/build_common_with_new_codegen.sh` passed; `common` rebuilt successfully from new codegen outputs |
| 2026-04-06 19:01 | Worker iter 4 | done in 2009s, tools: 64 |
| 2026-04-06 19:01 | Step 3 started | Delivery |
| 2026-04-06 19:12 | Step 3 docs | Updated `docs/codegen-migration/README.md` and `docs/codegen-migration/implementation-notes.md` to document the `project_*` shared module names and the temporary `common_*` compatibility-adapter policy |

---

## Blockers

*None*
