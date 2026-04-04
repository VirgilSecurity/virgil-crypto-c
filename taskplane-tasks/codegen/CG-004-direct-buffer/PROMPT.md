# Task: CG-004 — Direct Lowering for vsc_buffer

**Created:** 2026-04-04
**Size:** L

## Review Level: 2 (Standard)

**Assessment:** Largest remaining `common` migration slice with real compile-risk and likely nuanced preservation constraints.
**Score:** 6/8 — Blast radius: 2, Pattern novelty: 2, Security: 0, Reversibility: 2

## Mission

Replace the legacy resolved-XML fallback for `vsc_buffer` with direct lowering owned by the new generator.

This task should build on the execution plan from `CG-001`, the support-boundary audit from `CG-003`, and the direct `vsc_buffer_defs` work from `CG-002`.

## Dependencies

- `CG-002`
- `CG-003`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- docs produced by `CG-001` and `CG-003`
- status/docs from `CG-002`
- `tools/codegen/common_bootstrap.py`
- `tools/codegen/common_direct_c.py`
- original and resolved model artifacts for `buffer`

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `tools/codegen/common_bootstrap.py`
- `tools/codegen/common_direct_c.py`
- related codegen docs under `docs/codegen-migration/`
- temporary generated output under `library/common/**` only via verification script, not for commit

## Steps

### Step 0: Preflight

- [ ] Read the task-area context and all predecessor-task outputs
- [ ] Inspect current fallback routing and generated-block behavior for `vsc_buffer`

### Step 1: Implement direct lowering

- [ ] Add direct-lowering support for `vsc_buffer` in `tools/codegen/common_direct_c.py`
- [ ] Preserve compatibility with the current generated-block rewriting approach
- [ ] Keep original source models as the source of truth and avoid runtime dependency on resolved XML for this module

### Step 2: Wire into bootstrap generation

- [ ] Update `tools/codegen/common_bootstrap.py` to use the direct path for `vsc_buffer`
- [ ] Keep any still-legitimate fallback behavior explicit and narrow

### Step 3: Verification and iteration

- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`
- [ ] Run `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Fix compile/parity issues until the `common` target succeeds again
- [ ] Confirm no generated `library/common/**` artifacts remain staged for commit

### Step 4: Documentation and delivery

- [ ] Update migration docs and coverage status notes for `vsc_buffer`
- [ ] Record any remaining gaps, especially around support headers or intentionally retained fallback paths

## Documentation Requirements

**Must Update:** `docs/codegen-migration/`
**Check If Affected:** `taskplane-tasks/codegen/CONTEXT.md`

## Completion Criteria

- [ ] `vsc_buffer` is directly lowered by the new generator path
- [ ] The `common` build passes through `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Remaining fallback usage, if any, is explicit and documented
- [ ] No generated `library/common/**` file changes are committed

## Git Commit Convention

- **Implementation:** `feat(CG-004): lower common buffer directly`
- **Checkpoints:** `checkpoint: CG-004 <description>`

## Do NOT

- Commit generated files under `library/common/**`
- Expand scope outside `library/common`
- Quietly leave new fallback behavior undocumented

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
