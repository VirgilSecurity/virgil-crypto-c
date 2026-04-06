# Task: CG-016 — Foundation Inventory and Verification Plan

**Created:** 2026-04-05
**Size:** S

## Review Level: 2 (Standard)

**Assessment:** Planning task to scope `foundation` as the next target after the shared-framework refactor and define its validation gates.
**Score:** 3/8 — Blast radius: 1, Pattern novelty: 1, Security: 0, Reversibility: 1

## Mission

Create the execution map for moving from the generic shared-codegen framework into `foundation`.

This task must inventory the `project_foundation.xml` surface, identify the first low-risk migration slice, and define the validation gates needed for `foundation` work.

## Dependencies

- `CG-015`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/adr/0003-generalize-project-rooted-codegen-beyond-common.md`
- `docs/codegen-migration/foundation-next-phase-plan.md`
- `codegen/models/project_foundation/project_foundation.xml`

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `docs/codegen-migration/**`
- read-only inspection of `codegen/models/project_foundation/**`, build files, and test layout

## Steps

### Step 0: Preflight

- [ ] Read the ADR and current next-phase plan
- [ ] Inspect `project_foundation.xml` and the immediate project model surface

### Step 1: Inventory `foundation`

- [ ] Identify the main entity categories in `foundation` (classes, interfaces, implementors, enums, modules)
- [ ] Identify likely low-risk first slices versus high-risk areas
- [ ] Record any obvious preservation/build constraints

### Step 2: Define verification gates

- [ ] Document the recommended test/build/verification commands for `foundation`
- [ ] Call out any missing verification infrastructure that must be added before emitter work

### Step 3: Delivery

- [ ] Produce a concise next-phase plan for `foundation`
- [ ] Recommend the first implementation slice after the inventory work

## Documentation Requirements

**Must Update:** `docs/codegen-migration/foundation-next-phase-plan.md`
**Check If Affected:** `taskplane-tasks/codegen/CONTEXT.md`

## Completion Criteria

- [ ] There is a documented inventory and first-slice recommendation for `foundation`
- [ ] The validation gates for `foundation` are explicit
- [ ] The plan reinforces the shared-framework/no-hardcodes rule

## Git Commit Convention

- **Implementation:** `docs(CG-016): plan foundation migration entrypoint`
- **Checkpoints:** `checkpoint: CG-016 <description>`

## Do NOT

- Start broad emitter implementation in this task
- Reintroduce project-specific hardcodes as planning assumptions

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
