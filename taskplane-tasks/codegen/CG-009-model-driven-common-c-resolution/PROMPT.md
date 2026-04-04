# Task: CG-009 — Model-Driven Common C Resolution

**Created:** 2026-04-04
**Size:** L

## Review Level: 2 (Standard)

**Assessment:** High-value backend refactor that should remove project-specific hardcoded naming/path metadata from the C layer.
**Score:** 6/8 — Blast radius: 2, Pattern novelty: 2, Security: 0, Reversibility: 2

## Mission

Refactor the `common` C lowering path so that names, file targets, prefixes, and other project-specific metadata come from the resolved project graph / IR rather than Python hardcodes.

C is the first backend. Wrapper generation is out of scope for this task.

## Dependencies

- `CG-008`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/adr/0002-project-rooted-codegen-pipeline.md`
- `tools/codegen/common_ir.py`
- `tools/codegen/common_direct_c.py`
- `tools/codegen/common_bootstrap.py`
- tests added in predecessor tasks

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `tools/codegen/common_direct_c.py`
- `tools/codegen/common_bootstrap.py`
- nearby tests/helpers/docs as needed

## Steps

### Step 0: Preflight

- [ ] Read the ADR and predecessor task outputs
- [ ] Identify project-specific metadata that is still hardcoded in the current C lowering layer

### Step 1: Implement model-driven C resolution

- [ ] Derive names, output files, prefixes, and related metadata from the resolved project graph / IR
- [ ] Replace project-specific hardcodes where the model already defines the information
- [ ] Keep only genuinely static backend/runtime support logic as reusable backend code

### Step 2: Preserve current C-generation contract

- [ ] Keep handwritten-code preservation behavior intact
- [ ] Preserve the working `common` build path and generated-block application flow
- [ ] Add or update tests that protect the no-hardcoded-project-metadata rule

### Step 3: Verification

- [ ] Run the new/updated tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`
- [ ] Run `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Confirm no generated `library/common/**` artifacts remain staged for commit

### Step 4: Delivery

- [ ] Update architecture/migration docs to explain what hardcodes were removed and what static backend logic remains acceptable

## Documentation Requirements

**Must Update:** `docs/codegen-migration/implementation-notes.md`
**Check If Affected:** `docs/codegen-migration/common-c-generator-decision.md`

## Completion Criteria

- [ ] The `common` C backend derives project-specific metadata from models / IR instead of Python literals where the model defines it
- [ ] The `common` build still passes
- [ ] Tests cover the intended model-driven resolution behavior
- [ ] No generated `library/common/**` file changes are committed

## Git Commit Convention

- **Implementation:** `feat(CG-009): derive common C metadata from models`
- **Checkpoints:** `checkpoint: CG-009 <description>`

## Do NOT

- Expand into wrapper backends
- Keep project-specific hardcodes merely because they are convenient when the model already defines the fact
- Commit generated files under `library/common/**`

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
