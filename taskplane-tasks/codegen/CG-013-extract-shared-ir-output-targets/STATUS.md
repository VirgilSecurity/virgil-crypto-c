# CG-013: Extract Shared IR and Output Targets — Status

**Current Step:** Step 4: Delivery
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-06
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Read the refactor plan and current IR/output-target docs
- [x] Confirm which IR responsibilities should become shared generic modules

---

### Step 1: Extract shared IR/output-target code
**Status:** ✅ Complete

- [x] Move generic IR/output-target modeling into shared modules with generic names
- [x] Keep naming/path/prefix/output routing model-driven
- [x] Avoid turning the shared IR into project-specific branches

---

### Step 2: Preserve compatibility and tests
**Status:** ✅ Complete

- [x] Keep or add thin compatibility adapters only where necessary
- [x] Update imports/tests/scripts affected by the extraction
- [x] Add tests proving the shared IR path still works for `common`

---

### Step 3: Verification
**Status:** ✅ Complete

- [x] Run IR tests
- [x] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`

---

### Step 4: Delivery
**Status:** 🟨 In Progress

- [ ] Update docs to describe the shared IR/output-target layer

---

## Reviews

| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

---

## Discoveries

| Discovery | Disposition | Location |
|-----------|-------------|----------|
| `common_ir.py` already contains mostly project-generic dataclasses plus output-target derivation; shared extraction should move dataclasses, output-target builder, and `module/class/enum/project -> IR` lowering into a generic module while leaving only `common` convenience wrappers as adapters. | Use as extraction boundary for Step 1; keep project naming/path/prefix/output routing derived from `ProjectSource` metadata rather than backend literals. | `tools/codegen/common_ir.py`, `docs/codegen-migration/common-source-to-ir.md`, `docs/codegen-migration/implementation-notes.md` |
| New `project_ir.py` keeps output routing generic by deriving include namespace, generated namespace, stems, checked-in paths, and generated XML names only from `ProjectSource` metadata (`namespace`, `prefix`, `path`, `work_path`, entity attrs). | Preserve as shared contract and prove with IR tests in Step 2/3. | `tools/codegen/project_ir.py` |
| Internal consumers now import the shared IR module directly where appropriate: `common_direct_c.py` uses shared IR types, `inspect_common_ir.py` lowers through `project_to_ir()`, and tests exercise both the wrapper and shared path. | Keep adapter imports only where they provide compatibility value. | `tools/codegen/common_direct_c.py`, `tools/codegen/inspect_common_ir.py`, `tests/codegen/test_project_common_ir.py`, `tests/codegen/test_common_direct_c_resolution.py` |
| Shared IR extraction did not add project-name switches; `project_to_ir()` is fully generic and `project_common_to_ir()` is only a thin compatibility wrapper. | Keep this boundary for later `foundation` reuse. | `tools/codegen/project_ir.py`, `tools/codegen/common_ir.py` |

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-05 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-06 14:10 | Task started | Runtime V2 lane-runner execution |
| 2026-04-06 14:10 | Step 0 started | Preflight |
| 2026-04-06 14:15 | Step 0 research | Read CG-011 plan, IR docs, and inspected `common_ir.py`/`common_source.py` boundaries |
| 2026-04-06 14:20 | Step 1 extraction | Moved shared IR dataclasses and output-target lowering into new generic module `tools/codegen/project_ir.py`; reduced `common_ir.py` to compatibility exports/wrapper |
| 2026-04-06 14:22 | Step 1 metadata preservation | Kept output-target derivation generic and model-driven via `ProjectSource` metadata in `project_ir.py`; `py_compile` passed for IR-related modules |
| 2026-04-06 14:23 | Step 1 branch control | Confirmed the shared IR layer stays branch-free and generic; `common_ir.py` now only adapts the generic API for compatibility |
| 2026-04-06 14:28 | Step 2 compatibility | Kept `common_ir.py` as a thin adapter over `project_ir.py`; targeted compatibility tests remained green |
| 2026-04-06 14:28 | Step 2 import/test updates | Switched affected internal imports and inspection/test code to the shared IR module while preserving `common` compatibility entrypoints |
| 2026-04-06 14:29 | Step 2 targeted tests | `python3 -m unittest tests.codegen.test_project_common_ir tests.codegen.test_common_direct_c_resolution tests.codegen.test_common_bootstrap tests.codegen.test_project_common_source` passed (18 tests), including new shared-IR coverage for `common` |
| 2026-04-06 14:31 | Step 3 verification tests | `python3 -m unittest tests.codegen.test_project_common_source tests.codegen.test_project_common_ir tests.codegen.test_common_bootstrap tests.codegen.test_common_direct_c_resolution` passed (18 tests) |
| 2026-04-06 14:31 | Step 3 verification compile | `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py` passed |

---

## Blockers

*None*
