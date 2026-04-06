# Task: CG-016 — Foundation Bootstrap Integration, Regression, and Docs

**Created:** 2026-04-05
**Size:** M

## Review Level: 2 (Standard)

**Assessment:** Integration/regression task that closes the first `foundation` shared-framework slice.
**Score:** 4/8 — Blast radius: 1, Pattern novelty: 1, Security: 0, Reversibility: 2

## Mission

Integrate the first `foundation` slice into the shared bootstrap/generator flow, validate regression coverage, and refresh docs so the post-`common` migration direction is explicit.

## Dependencies

- `CG-015`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/adr/0003-generalize-project-rooted-codegen-beyond-common.md`
- outputs of `CG-011` through `CG-015`

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- shared bootstrap/generator integration points
- tests/docs related to `foundation` onboarding into the framework

## Steps

### Step 0: Preflight

- [ ] Review predecessor task outputs
- [ ] Inspect the relevant bootstrap integration points

### Step 1: Integrate and validate

- [ ] Ensure the first `foundation` slice is integrated into the shared workflow cleanly
- [ ] Add/update regression tests around the shared project-rooted path
- [ ] Keep resolved XML limited to approved parity/reference roles

### Step 2: Verification

- [ ] Run the relevant tests
- [ ] Run documented `foundation` validation gates
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`

### Step 3: Documentation and delivery

- [ ] Refresh docs to state what is now shared across `common` and `foundation`
- [ ] Summarize the next likely `foundation` expansion step

## Documentation Requirements

**Must Update:** `docs/codegen-migration/README.md`
**Check If Affected:** `docs/codegen-migration/roadmap.md`

## Completion Criteria

- [ ] The first `foundation` slice is integrated into the shared framework cleanly
- [ ] Regression tests cover the shared path
- [ ] Docs clearly describe the new post-`common` state

## Git Commit Convention

- **Implementation:** `feat(CG-016): integrate first foundation shared slice`
- **Checkpoints:** `checkpoint: CG-016 <description>`

## Do NOT

- Broaden scope into a full `foundation` migration in one task
- Reintroduce project-specific hardcodes as a shortcut during integration

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
