# Task: CG-015 — Rename and Adapt Generic Modules, Imports, and Docs

**Created:** 2026-04-05
**Size:** M

## Review Level: 2 (Standard)

**Assessment:** Integration/refactor task that finishes the move from `common_*`-named shared-core modules to generic naming, while preserving compatibility where needed.
**Score:** 4/8 — Blast radius: 1, Pattern novelty: 1, Security: 0, Reversibility: 2

## Mission

Finish the shared-framework refactor by updating imports, scripts, tests, and docs to use the new generic modules and by leaving only thin compatibility adapters where necessary.

## Dependencies

- `CG-014`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- refactor plan from `CG-011`
- outputs of `CG-012` through `CG-014`

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `tools/codegen/**`
- tests/docs/scripts that reference the extracted modules

## Steps

### Step 0: Preflight

- [ ] Review extracted shared-module outputs from predecessor tasks
- [ ] Confirm which legacy `common_*` names should remain as temporary adapters, if any

### Step 1: Update callers and names

- [ ] Update imports/scripts/tests/docs to prefer the new generic module names
- [ ] Reduce legacy `common_*` modules to thin compatibility adapters or remove them where safe
- [ ] Keep current `common` workflows working

### Step 2: Verification

- [ ] Run relevant tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`
- [ ] Run `bash tools/codegen/build_common_with_new_codegen.sh`

### Step 3: Delivery

- [ ] Update docs to state the new shared module names and compatibility policy

## Documentation Requirements

**Must Update:** `docs/codegen-migration/README.md`
**Check If Affected:** `docs/codegen-migration/implementation-notes.md`

## Completion Criteria

- [ ] The shared framework is now presented through generic module names
- [ ] Any remaining `common_*` modules are thin compatibility adapters only
- [ ] Tests/build verification still pass for `common`

## Git Commit Convention

- **Implementation:** `refactor(CG-015): rename shared codegen modules`
- **Checkpoints:** `checkpoint: CG-015 <description>`

## Do NOT

- Leave deep shared-core functionality hidden behind misleading `common_*` names without documenting it
- Break current `common` validation flow during the rename/adaptation step

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
