# Task: CG-017 — Foundation Validation on Shared Project-Rooted Framework

**Created:** 2026-04-05
**Size:** M

## Review Level: 2 (Standard)

**Assessment:** Validation task that proves the generalized framework can load and reason about `project_foundation.xml` without reintroducing hardcodes.
**Score:** 4/8 — Blast radius: 1, Pattern novelty: 2, Security: 0, Reversibility: 1

## Mission

Validate the newly generic shared project-rooted framework against `project_foundation.xml`.

This task should prove shared loader/IR/output-target behavior on `foundation` before the first real emitter slice lands.

## Dependencies

- `CG-016`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/adr/0003-generalize-project-rooted-codegen-beyond-common.md`
- `docs/codegen-migration/foundation-next-phase-plan.md`
- outputs of `CG-012` through `CG-016`

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- shared loader/IR tests and fixtures
- docs if behavior notes must be clarified

## Steps

### Step 0: Preflight

- [ ] Review the shared-framework refactor outputs and `foundation` inventory
- [ ] Identify the key shared-behavior assertions for `project_foundation.xml`

### Step 1: Validate shared behavior on `foundation`

- [ ] Add/update tests proving that the shared loader/IR/output-target path works on `project_foundation.xml`
- [ ] Confirm that project metadata remains model-driven rather than hardcoded
- [ ] Capture any gaps that block the first emitter slice

### Step 2: Verification

- [ ] Run the new shared-framework tests
- [ ] Run `python3 -m py_compile` on the relevant codegen modules

### Step 3: Delivery

- [ ] Document what is now proven on `foundation` before emitter work begins

## Documentation Requirements

**Must Update:** `docs/codegen-migration/foundation-next-phase-plan.md` if behavior notes changed
**Check If Affected:** `docs/codegen-migration/implementation-notes.md`

## Completion Criteria

- [ ] Shared project-rooted framework behavior is proven on `project_foundation.xml`
- [ ] No new project/module-name hardcodes were introduced
- [ ] The first emitter slice has a clearer risk boundary

## Git Commit Convention

- **Implementation:** `test(CG-017): validate foundation on shared framework`
- **Checkpoints:** `checkpoint: CG-017 <description>`

## Do NOT

- Jump into broad foundation emitter implementation in this task
- Hide project-specific behavior behind new special-case branches

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
