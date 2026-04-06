# Task: CG-018 — Foundation Preservation and Build Gates

**Created:** 2026-04-05
**Size:** S

## Review Level: 2 (Standard)

**Assessment:** Validation task to define how `foundation` work is proven safe before broader emitter migration.
**Score:** 3/8 — Blast radius: 1, Pattern novelty: 1, Security: 0, Reversibility: 1

## Mission

Define and implement the validation gates for `foundation` migration work.

This includes preservation constraints, recommended test/build commands, and any small helper scripts or test scaffolding needed to make future `foundation` batches safe and repeatable.

## Dependencies

- `CG-016`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/codegen-migration/foundation-next-phase-plan.md`
- relevant build/test files for `library/foundation`
- current `common` verification scripts as reference only

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `tools/codegen/**` helper scripts if needed
- tests/docs for validation gates
- no broad generator implementation in this task

## Steps

### Step 0: Preflight

- [ ] Inspect current `foundation` build/test surfaces
- [ ] Identify which outputs are preservation-sensitive versus fully generated

### Step 1: Define gates

- [ ] Document the recommended verification commands for `foundation`
- [ ] Identify any minimal helper script/test work needed to run those checks reliably

### Step 2: Implement minimal validation support

- [ ] Add any small helper scripts/tests needed for future `foundation` batches
- [ ] Keep the scope limited to validation infrastructure

### Step 3: Verification

- [ ] Run the new validation support if added
- [ ] Confirm the documented gate is executable or clearly marked if still blocked

### Step 4: Delivery

- [ ] Update docs to make the `foundation` validation path explicit

## Documentation Requirements

**Must Update:** `docs/codegen-migration/foundation-next-phase-plan.md`
**Check If Affected:** `docs/codegen-migration/parity-test-plan.md`

## Completion Criteria

- [ ] `foundation` preservation/build gates are explicit
- [ ] Minimal validation support exists if needed
- [ ] Future foundation emitter work has a concrete safety gate

## Git Commit Convention

- **Implementation:** `test(CG-018): define foundation verification gates`
- **Checkpoints:** `checkpoint: CG-018 <description>`

## Do NOT

- Start broad emitter migration in this task
- Hardcode project metadata into shared generator code while adding validation support

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
