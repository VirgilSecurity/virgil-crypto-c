# Task: CG-023 — Generic Class Renderer in Shared C Backend

**Created:** 2026-04-07
**Size:** L

## Review Level: 2 (Standard)

## Mission

Add generic class C rendering to `project_c_backend.py` that works for any project's classes from their IR representation. Absorb class-specific builders from `common_direct_c.py` (e.g. `data`, `buffer`, `buffer_defs`) into the generic renderer where the model/IR expresses the needed structure. Reclassify truly static runtime support code (e.g. hardcoded C method bodies for allocators, platform shims) as checked-in support code rather than generated-by-Python builders.

## Dependencies

- `CG-022`

## Context to Read First

- `docs/adr/0004-universal-model-driven-codegen.md`
- `tools/codegen/project_c_backend.py`
- `tools/codegen/common_direct_c.py` (class builders to absorb/reclassify)

## Steps

### Step 0: Preflight
- [ ] Identify which class builders are model-derivable vs static runtime support

### Step 1: Implement generic class renderer
- [ ] Add generic `render_class_c_module(project_ir, class_ir)` to shared backend
- [ ] Derive struct fields, methods, constants, includes from IR
- [ ] Move static runtime code out of Python builders into checked-in C where appropriate

### Step 2: Tests
- [ ] Tests for `common` classes (`data`, `buffer`) through generic renderer
- [ ] No regressions

### Step 3: Verification
- [ ] `python3 -m py_compile` on all codegen modules
- [ ] `bash tools/codegen/build_common_with_new_codegen.sh`

## Completion Criteria

- [ ] Class rendering is generic and IR-driven
- [ ] Static runtime C code is reclassified, not generated from Python literals
- [ ] Tests pass

## Git Commit Convention
- **Implementation:** `refactor(CG-023): generic class renderer`

## Do NOT
- Keep class-specific rendering in per-project files when IR already expresses the structure
- Generate static runtime C code from hardcoded Python strings
