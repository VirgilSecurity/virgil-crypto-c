# Task: CG-026 — Eliminate Per-Project Builder Files and Registry

**Created:** 2026-04-07
**Size:** M

## Review Level: 2 (Standard)

## Mission

Remove `common_direct_c.py`, `foundation_direct_c.py`, and `project_direct_registry.py`. All rendering should now flow through the generic shared C backend with auto-discovered entities. Update `common_bootstrap.py` to use the shared backend directly. Update all imports, tests, scripts, and docs.

## Dependencies

- `CG-025`

## Context to Read First

- `docs/adr/0004-universal-model-driven-codegen.md`
- outputs of `CG-022` through `CG-025`

## Steps

### Step 0: Preflight
- [ ] Confirm all entity kinds are handled by the generic backend
- [ ] Confirm auto-discovery is working

### Step 1: Remove per-project files
- [ ] Delete `common_direct_c.py` (or reduce to empty compatibility stub if needed temporarily)
- [ ] Delete `foundation_direct_c.py`
- [ ] Delete `project_direct_registry.py`
- [ ] Update `common_bootstrap.py` to use shared backend directly

### Step 2: Update imports and tests
- [ ] Fix all imports referencing removed files
- [ ] Update tests to use shared backend paths
- [ ] Update docs/scripts

### Step 3: Verification
- [ ] `python3 -m py_compile` on all codegen modules
- [ ] `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] `bash tools/codegen/verify_foundation_validation_gate.sh --post-quantum-off`
- [ ] Run all codegen tests

## Completion Criteria

- [ ] No per-project `*_direct_c.py` files remain (or only empty stubs)
- [ ] No `project_direct_registry.py` remains
- [ ] Adding a new project requires zero new Python files
- [ ] Both `common` and `foundation` pass their verification gates

## Git Commit Convention
- **Implementation:** `refactor(CG-026): eliminate per-project builders`

## Do NOT
- Leave functioning rendering logic in per-project files
- Break existing verification gates
