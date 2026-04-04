# Task: CG-001 — Buffer Family Migration Spec

**Created:** 2026-04-04
**Size:** S

## Review Level: 2 (Standard)

**Assessment:** Planning and analysis task to make the remaining `common` migration tractable and safe.
**Score:** 3/8 — Blast radius: 1, Pattern novelty: 1, Security: 0, Reversibility: 1

## Mission

Prepare the direct-lowering plan for the remaining buffer-family migration in `library/common`.

This task is documentation-first. It should leave a crisp execution map for `vsc_buffer`, `vsc_buffer_defs`, and remaining support headers so later implementation tasks can proceed with lower ambiguity.

## Dependencies

- **None**

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/codegen-migration/README.md`
- `docs/codegen-migration/roadmap.md`
- `docs/codegen-migration/common-direct-foundation-status.md`
- `tools/codegen/common_bootstrap.py`
- `tools/codegen/common_direct_c.py`
- source and resolved models related to buffer / buffer_defs

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `docs/codegen-migration/**`
- optional read-only inspection of `tools/codegen/**`

## Steps

### Step 0: Preflight

- [ ] Read the task-area context and current migration docs
- [ ] Inspect current fallback handling for buffer-related files in `tools/codegen/common_bootstrap.py`

### Step 1: Analyze remaining buffer-family surface

- [ ] Compare original source models and resolved XML inputs for `buffer` and `buffer_defs`
- [ ] Identify which generated pieces are direct-lowering candidates versus thin support/aggregation artifacts
- [ ] Record any special preservation or formatting constraints that are likely to matter

### Step 2: Document the execution plan

- [ ] Add or update docs under `docs/codegen-migration/` describing the remaining migration map
- [ ] Explicitly sequence `buffer_defs`, `buffer`, and any support-header follow-up
- [ ] Call out expected verification commands and no-commit constraints for generated `library/common/**` files

### Step 3: Verification

- [ ] Re-read the updated docs to ensure they are internally consistent with the current codebase

### Step 4: Delivery

- [ ] Summarize recommended next implementation order and notable risks in the task output

## Documentation Requirements

**Must Update:** `docs/codegen-migration/`
**Check If Affected:** `taskplane-tasks/codegen/CONTEXT.md`

## Completion Criteria

- [ ] There is a concrete documented plan for migrating `buffer` and `buffer_defs`
- [ ] The plan reflects the current direct coverage already achieved for foundational `common` modules
- [ ] The docs explicitly preserve the rule that generated `library/common/**` outputs must not be committed

## Git Commit Convention

- **Implementation:** `docs(CG-001): describe remaining common buffer migration`
- **Checkpoints:** `checkpoint: CG-001 <description>`

## Do NOT

- Modify production source or generator code in this task
- Commit generated files under `library/common/**`
- Broaden the project scope beyond C generation for `library/common`

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
