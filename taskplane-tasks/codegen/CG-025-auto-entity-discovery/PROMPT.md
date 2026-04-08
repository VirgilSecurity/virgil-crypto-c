# Task: CG-025 — Auto-Discovery of Renderable Entities from IR

**Created:** 2026-04-07
**Size:** M

## Review Level: 2 (Standard)

## Mission

Replace hardcoded entity lists with automatic discovery. The shared C backend should inspect the project IR and automatically determine which entities (enums, classes, modules) are renderable, then produce the renderer map without any per-project Python code listing entities.

## Dependencies

- `CG-024`

## Context to Read First

- `docs/adr/0004-universal-model-driven-codegen.md`
- `tools/codegen/project_c_backend.py`
- `tools/codegen/project_ir.py`

## Steps

### Step 0: Preflight
- [ ] Inspect how entities are currently listed/registered for rendering

### Step 1: Implement auto-discovery
- [ ] Add a function that walks the project IR and produces a complete renderer map for all supported entity kinds
- [ ] No hardcoded entity name lists — discovery comes from the IR graph
- [ ] Support filtering/scoping if needed (e.g. render only enums, or only a specific entity) via parameters, not hardcoded lists

### Step 2: Tests
- [ ] Tests proving auto-discovery finds the correct entities for both `common` and `foundation`
- [ ] No regressions

### Step 3: Verification
- [ ] `python3 -m py_compile` on all codegen modules
- [ ] `bash tools/codegen/build_common_with_new_codegen.sh`

## Completion Criteria

- [ ] Entity discovery is automatic from IR
- [ ] No hardcoded entity lists remain in the rendering path
- [ ] Works for both `common` and `foundation`

## Git Commit Convention
- **Implementation:** `refactor(CG-025): auto entity discovery from ir`

## Do NOT
- Maintain hardcoded entity lists anywhere in the rendering pipeline
- Add per-project discovery logic
