# Task: CG-024 — Generic Module Renderer in Shared C Backend

**Created:** 2026-04-07
**Size:** L

## Review Level: 2 (Standard)

## Mission

Add generic module C rendering to `project_c_backend.py` that works for any project's modules from their IR representation. Absorb module-specific builders from `common_direct_c.py` (e.g. `library`, `memory`, `atomic`, `assert`) into the generic renderer where the model/IR expresses the needed structure. Reclassify static runtime support code (hardcoded C macro bodies, platform shims, allocator implementations) as checked-in support code.

## Dependencies

- `CG-023`

## Context to Read First

- `docs/adr/0004-universal-model-driven-codegen.md`
- `tools/codegen/project_c_backend.py`
- `tools/codegen/common_direct_c.py` (module builders to absorb/reclassify)

## Steps

### Step 0: Preflight
- [ ] Identify which module builders are model-derivable vs static runtime

### Step 1: Implement generic module renderer
- [ ] Add generic `render_module_c_module(project_ir, module_ir)` to shared backend
- [ ] Derive macros, methods, variables, callbacks, includes from IR
- [ ] Move static runtime code to checked-in C support files

### Step 2: Tests
- [ ] Tests for `common` modules (`library`, `memory`, `assert`, `atomic`) through generic renderer
- [ ] No regressions

### Step 3: Verification
- [ ] `python3 -m py_compile` on all codegen modules
- [ ] `bash tools/codegen/build_common_with_new_codegen.sh`

## Completion Criteria

- [ ] Module rendering is generic and IR-driven
- [ ] Static runtime C code is reclassified
- [ ] Tests pass

## Git Commit Convention
- **Implementation:** `refactor(CG-024): generic module renderer`

## Do NOT
- Keep module-specific rendering in per-project files when IR expresses the structure
- Generate platform/runtime C code from hardcoded Python strings when it can be checked-in C
