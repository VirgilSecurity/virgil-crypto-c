# Task: CG-002 — Direct Lowering for vsc_buffer_defs

**Created:** 2026-04-04
**Size:** M

## Review Level: 2 (Standard)

**Assessment:** Moderate generator change with compile validation and documentation updates.
**Score:** 5/8 — Blast radius: 2, Pattern novelty: 2, Security: 0, Reversibility: 1

## Mission

Replace the legacy resolved-XML fallback for `vsc_buffer_defs` with direct lowering owned by the new generator.

The implementation must continue to preserve handwritten/non-generated regions and must not commit generated outputs under `library/common/**`.

## Dependencies

- `CG-001`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/codegen-migration/common-direct-foundation-status.md`
- planning docs produced by `CG-001`
- `tools/codegen/common_bootstrap.py`
- `tools/codegen/common_direct_c.py`
- relevant source and resolved models for `buffer_defs`

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `tools/codegen/common_bootstrap.py`
- `tools/codegen/common_direct_c.py`
- `docs/codegen-migration/**`
- temporary generated output under `library/common/**` only via verification script, not for commit

## Steps

### Step 0: Preflight

- [ ] Read the task-area context, current direct-coverage status docs, and the `CG-001` plan
- [ ] Inspect the current fallback path for `vsc_buffer_defs`

### Step 1: Implement direct lowering

- [ ] Add direct-lowering support for `vsc_buffer_defs` in `tools/codegen/common_direct_c.py`
- [ ] Keep the implementation aligned with original-model-as-source-of-truth constraints
- [ ] Avoid introducing a dependency on resolved XML as runtime input for this module

### Step 2: Wire into bootstrap generation

- [ ] Update `tools/codegen/common_bootstrap.py` to route `vsc_buffer_defs` through the new direct path
- [ ] Preserve existing mixed-mode behavior for any still-unmigrated `common` outputs

### Step 3: Verify build safety

- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`
- [ ] Run `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Confirm no generated `library/common/**` artifacts remain staged for commit

### Step 4: Documentation and delivery

- [ ] Update migration docs to reflect direct coverage for `vsc_buffer_defs`
- [ ] Summarize any parity gaps, shortcuts, or follow-up risks for `vsc_buffer`

## Documentation Requirements

**Must Update:** `docs/codegen-migration/`
**Check If Affected:** `taskplane-tasks/codegen/CONTEXT.md`

## Completion Criteria

- [ ] `vsc_buffer_defs` is directly lowered by the new generator path
- [ ] The `common` build still succeeds with the new generated outputs applied temporarily
- [ ] No generated `library/common/**` file changes are committed
- [ ] Documentation reflects the new coverage status and remaining work

## Git Commit Convention

- **Implementation:** `feat(CG-002): lower common buffer defs directly`
- **Checkpoints:** `checkpoint: CG-002 <description>`

## Do NOT

- Commit generated files under `library/common/**`
- Expand beyond the `common` module
- Reintroduce resolved XML as a required generator input for `vsc_buffer_defs`

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
