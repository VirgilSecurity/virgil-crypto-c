# Task: CG-011 — Generic Shared-Codegen Refactor Plan

**Created:** 2026-04-05
**Size:** S

## Review Level: 2 (Standard)

**Assessment:** Planning task to split shared framework responsibilities out of the current `common_*` modules before `foundation` migration continues.
**Score:** 3/8 — Blast radius: 1, Pattern novelty: 1, Security: 0, Reversibility: 1

## Mission

Create the concrete refactor plan for turning the current `common_*` core modules into generic shared codegen modules.

This task must identify what should become shared loader/IR/backend code, what may remain as thin compatibility adapters, and what imports/scripts/docs will need to change.

## Dependencies

- **None**

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/adr/0002-project-rooted-codegen-pipeline.md`
- `docs/adr/0003-generalize-project-rooted-codegen-beyond-common.md`
- `docs/codegen-migration/foundation-next-phase-plan.md`
- `tools/codegen/common_source.py`
- `tools/codegen/common_ir.py`
- `tools/codegen/common_direct_c.py`

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `docs/codegen-migration/**`
- read-only inspection of `tools/codegen/**`

## Steps

### Step 0: Preflight

- [ ] Read the ADRs and current next-phase plan
- [ ] Inspect the current `common_*` module boundaries

### Step 1: Identify refactor boundaries

- [ ] Classify what belongs in shared project graph loading, shared IR/output-targets, and shared C backend code
- [ ] Identify what can remain as thin compatibility adapters during migration
- [ ] Identify import/script/doc changes required by the rename/refactor

### Step 2: Document the plan

- [ ] Write a concise refactor plan with a recommended sequence
- [ ] Explicitly preserve the rule that shared functionality should not branch on specific module names where metadata already expresses the distinction

### Step 3: Delivery

- [ ] Recommend the first extraction step after the planning task

## Documentation Requirements

**Must Update:** `docs/codegen-migration/foundation-next-phase-plan.md`
**Check If Affected:** `taskplane-tasks/codegen/CONTEXT.md`

## Completion Criteria

- [ ] There is a documented split between shared framework code and thin project adapters
- [ ] The plan makes the generic refactor a prerequisite for the next `foundation` implementation steps
- [ ] The no-module-name-specific-functionality rule is explicit

## Git Commit Convention

- **Implementation:** `docs(CG-011): plan generic shared codegen refactor`
- **Checkpoints:** `checkpoint: CG-011 <description>`

## Do NOT

- Start broad code refactors in this task
- Assume the existing `common_*` filenames are acceptable long-term shared architecture

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
