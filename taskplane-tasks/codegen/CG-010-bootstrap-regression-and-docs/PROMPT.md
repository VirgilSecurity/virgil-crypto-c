# Task: CG-010 — Bootstrap Regression Validation & Docs

**Created:** 2026-04-04
**Size:** M

## Review Level: 2 (Standard)

**Assessment:** Integration and regression task that closes the loop on the architecture shift.
**Score:** 4/8 — Blast radius: 1, Pattern novelty: 1, Security: 0, Reversibility: 2

## Mission

Integrate the project-rooted graph + IR + model-driven C resolution path into the bootstrap flow, validate the preservation/build contract, and refresh the migration docs.

This task should leave the `common` generator in a documented, test-backed state after the architectural regularization work.

## Dependencies

- `CG-009`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/adr/0002-project-rooted-codegen-pipeline.md`
- predecessor task outputs from `CG-006` through `CG-009`
- `tools/codegen/common_bootstrap.py`

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `tools/codegen/common_bootstrap.py`
- tests/docs related to bootstrap integration and validation
- migration docs under `docs/codegen-migration/`

## Steps

### Step 0: Preflight

- [ ] Read the ADR and predecessor task outputs
- [ ] Inspect current bootstrap integration points

### Step 1: Integrate and validate

- [ ] Ensure the bootstrap flow uses the project-rooted graph / IR / model-driven C path where appropriate
- [ ] Add or update regression tests around preservation behavior and architecture entrypoints
- [ ] Keep resolved XML limited to approved migration/parity roles only

### Step 2: Full verification

- [ ] Run the relevant automated tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`
- [ ] Run `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Confirm no generated `library/common/**` artifacts remain staged for commit

### Step 3: Documentation and delivery

- [ ] Refresh migration docs to describe the new project-rooted architecture and current completion state
- [ ] Summarize any remaining follow-up after the C backend regularization work

## Documentation Requirements

**Must Update:** `docs/codegen-migration/README.md`
**Check If Affected:** `docs/codegen-migration/roadmap.md`

## Completion Criteria

- [ ] The bootstrap flow reflects the project-rooted architecture direction
- [ ] Regression tests cover the new architecture entrypoints and preservation/build contract
- [ ] Docs clearly explain the current generator architecture and next remaining work

## Git Commit Convention

- **Implementation:** `feat(CG-010): integrate project-rooted common backend`
- **Checkpoints:** `checkpoint: CG-010 <description>`

## Do NOT

- Broaden scope into wrapper backends
- Commit generated files under `library/common/**`

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
