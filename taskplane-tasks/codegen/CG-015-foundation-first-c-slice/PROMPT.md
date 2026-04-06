# Task: CG-015 — First Foundation C Slice on Shared Backend

**Created:** 2026-04-05
**Size:** L

## Review Level: 2 (Standard)

**Assessment:** First real `foundation` emitter task on the generalized framework; moderate-to-high risk and should stay tightly scoped.
**Score:** 6/8 — Blast radius: 2, Pattern novelty: 2, Security: 0, Reversibility: 2

## Mission

Implement one low-risk `foundation` C generation slice using the shared project-rooted loader/IR/backend path.

The slice should be chosen from the inventory/planning work and should prove that the framework generalization is real, not another `common`-only special case.

## Dependencies

- `CG-013`
- `CG-014`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/adr/0003-generalize-project-rooted-codegen-beyond-common.md`
- `docs/codegen-migration/foundation-next-phase-plan.md`
- outputs of `CG-011` through `CG-014`

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- shared loader/IR/backend modules
- `foundation`-relevant tests/docs
- temporary generated outputs only through approved validation flow

## Steps

### Step 0: Preflight

- [ ] Read the foundation inventory/gate outputs
- [ ] Confirm the selected low-risk slice and its acceptance criteria

### Step 1: Implement the first slice

- [ ] Route the selected `foundation` slice through the shared project-rooted loader/IR/backend path
- [ ] Keep project-specific naming/output routing model-driven
- [ ] Avoid adding `foundation`-specific hardcoded backend metadata

### Step 2: Add tests and validation

- [ ] Add or update tests covering the selected `foundation` slice
- [ ] Run the documented `foundation` validation gate(s)
- [ ] Keep generated/manual preservation rules intact where applicable

### Step 3: Delivery

- [ ] Update docs to record what slice now works and what remains intentionally out of scope

## Documentation Requirements

**Must Update:** `docs/codegen-migration/foundation-next-phase-plan.md`
**Check If Affected:** `docs/codegen-migration/implementation-notes.md`

## Completion Criteria

- [ ] A real `foundation` C slice works through the shared framework
- [ ] Project metadata is model-driven rather than hardcoded
- [ ] Tests and validation gates pass

## Git Commit Convention

- **Implementation:** `feat(CG-015): add first foundation c slice`
- **Checkpoints:** `checkpoint: CG-015 <description>`

## Do NOT

- Attempt broad `foundation` coverage in one step
- Reintroduce project-specific hardcodes in shared backend code
- Commit generated files if the validation flow is designed to restore them

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
