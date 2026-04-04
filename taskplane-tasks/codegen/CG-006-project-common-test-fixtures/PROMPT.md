# Task: CG-006 — Project-Rooted Common Graph Tests & Fixtures

**Created:** 2026-04-04
**Size:** S

## Review Level: 2 (Standard)

**Assessment:** Test-first task that locks in the intended project-rooted architecture before loader refactoring.
**Score:** 3/8 — Blast radius: 1, Pattern novelty: 1, Security: 0, Reversibility: 1

## Mission

Create focused tests and fixtures for project-rooted `common` graph loading, using `project_common.xml` as the top-level entrypoint.

This task should define the expected behavior of the new architecture before larger refactors begin.

## Dependencies

- **None**

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/adr/0002-project-rooted-codegen-pipeline.md`
- `docs/codegen-migration/model-spec-common.md`
- `docs/codegen-migration/model-parser-notes.md`
- `tools/codegen/common_source.py`

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `tools/codegen/**`
- `tests/**` or another existing Python test location if more appropriate
- `docs/codegen-migration/**` only if behavior notes need to be clarified

## Steps

### Step 0: Preflight

- [ ] Read the ADR and current parser notes
- [ ] Identify the existing testing pattern that best fits lightweight generator tests

### Step 1: Define project-rooted expectations

- [ ] Identify the minimum expected graph facts that must be discoverable from `project_common.xml`
- [ ] Cover referenced classes, modules, enums, and project metadata needed by the C backend

### Step 2: Implement tests and fixtures

- [ ] Add tests that start from `project_common.xml`
- [ ] Verify that the loader entrypoint is project-rooted rather than ad hoc per-module
- [ ] Keep fixtures or assertions narrow and maintainable

### Step 3: Verification

- [ ] Run the new tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`

### Step 4: Delivery

- [ ] Document the new test entrypoints and what architecture assumptions they protect

## Documentation Requirements

**Must Update:** If needed, `docs/codegen-migration/model-parser-notes.md`
**Check If Affected:** `taskplane-tasks/codegen/CONTEXT.md`

## Completion Criteria

- [ ] There are automated tests for project-rooted `common` graph loading
- [ ] The tests assert behavior starting from `project_common.xml`
- [ ] The tests are written to support the ADR direction, not the current hardcoded shortcuts

## Git Commit Convention

- **Implementation:** `test(CG-006): add project-rooted common graph tests`
- **Checkpoints:** `checkpoint: CG-006 <description>`

## Do NOT

- Hardcode project-specific naming/path facts inside the tests unless they are asserted as model-derived expectations
- Expand into wrapper backend work

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
