# Task: CG-022 — Generic Enum Renderer in Shared C Backend

**Created:** 2026-04-07
**Size:** M

## Review Level: 2 (Standard)

## Mission

Move enum C rendering into `project_c_backend.py` as a generic capability that works for any project's enums from their IR representation. Remove the enum-specific code from `foundation_direct_c.py` and `common_direct_c.py` (if any). The renderer must derive names, constants, and types from the IR — no hardcoded entity lists.

## Dependencies

- **None**

## Context to Read First

- `docs/adr/0004-universal-model-driven-codegen.md`
- `tools/codegen/project_c_backend.py`
- `tools/codegen/foundation_direct_c.py` (enum rendering to absorb)
- `tools/codegen/project_ir.py`

## Steps

### Step 0: Preflight
- [ ] Read ADR 0004 and inspect current enum rendering in `foundation_direct_c.py`

### Step 1: Implement generic enum renderer
- [ ] Add a generic `render_enum_c_module(project_ir, enum_ir)` function to `project_c_backend.py`
- [ ] Derive all names, constant names, type names from IR output targets
- [ ] Remove enum rendering from `foundation_direct_c.py`

### Step 2: Tests
- [ ] Add tests proving the generic enum renderer works for both `common` and `foundation` enums
- [ ] Run existing tests to confirm no regressions

### Step 3: Verification
- [ ] `python3 -m py_compile` on all codegen modules
- [ ] `bash tools/codegen/build_common_with_new_codegen.sh`

## Completion Criteria

- [ ] Enum rendering is a generic shared capability, not per-project
- [ ] Works for any project's enums from IR alone
- [ ] Tests pass for both `common` and `foundation`

## Git Commit Convention
- **Implementation:** `refactor(CG-022): generic enum renderer`

## Do NOT
- Keep enum-specific rendering in per-project files
- Hardcode entity lists
