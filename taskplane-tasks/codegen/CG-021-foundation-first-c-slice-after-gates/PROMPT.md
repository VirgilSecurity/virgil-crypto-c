# Task: CG-021 — Foundation First C Slice After Validation Gates

**Created:** 2026-04-07
**Size:** L

## Review Level: 2 (Standard)

**Assessment:** Follow-up implementation task that resumes the original `CG-019` intent only after the validation gates are finished and trustworthy.
**Score:** 6/8 — Blast radius: 2, Pattern novelty: 2, Security: 0, Reversibility: 2

## Mission

Implement and integrate one low-risk `foundation` C generation slice using the shared project-rooted loader/IR/backend path, now that the validation gates are finished cleanly.

This task supersedes the blocked dependency path from `CG-019` and should start from the current integrated shared-framework state plus the completed gate work from `CG-020`.

## Dependencies

- `CG-020`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/codegen-migration/foundation-next-phase-plan.md`
- `taskplane-tasks/codegen/CG-019-foundation-first-c-slice-and-integration/PROMPT.md`
- `taskplane-tasks/codegen/CG-020-finish-foundation-validation-gates-from-saved-work/PROMPT.md`

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- shared loader/IR/backend modules
- `foundation`-relevant tests/docs
- temporary generated outputs only through approved validation flow

## Steps

### Step 0: Preflight

- [ ] Reconfirm the selected low-risk `foundation` slice and the active validation gate
- [ ] Read the original `CG-019` intent and the finalized gate output from `CG-020`

### Step 1: Implement the first slice

- [ ] Route the selected `foundation` slice through the shared project-rooted loader/IR/backend path
- [ ] Keep project-specific naming/output routing model-driven
- [ ] Avoid adding `foundation`-specific hardcoded backend metadata

### Step 2: Add tests and validation

- [ ] Add or update tests covering the selected `foundation` slice
- [ ] Run the finalized `foundation` validation gate(s)
- [ ] Keep generated/manual preservation rules intact where applicable

### Step 3: Integrate and document

- [ ] Integrate the first slice into the shared workflow cleanly
- [ ] Update docs to record what slice now works and what remains intentionally out of scope

## Documentation Requirements

**Must Update:** `docs/codegen-migration/foundation-next-phase-plan.md`
**Check If Affected:** `docs/codegen-migration/implementation-notes.md`

## Completion Criteria

- [ ] A real `foundation` C slice works through the shared framework
- [ ] Project metadata is model-driven rather than hardcoded
- [ ] Tests and validation gates pass
- [ ] The slice is integrated into the shared workflow cleanly

## Git Commit Convention

- **Implementation:** `feat(CG-021): add first foundation c slice`
- **Checkpoints:** `checkpoint: CG-021 <description>`

## Do NOT

- Attempt broad `foundation` coverage in one step
- Reintroduce project-specific hardcodes in shared backend code
- Commit generated files if the validation flow is designed to restore them

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
