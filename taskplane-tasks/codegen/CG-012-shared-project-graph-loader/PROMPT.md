# Task: CG-012 — Shared Project Graph Loader for Common + Foundation

**Created:** 2026-04-05
**Size:** M

## Review Level: 2 (Standard)

**Assessment:** Framework task that generalizes the project-rooted loader across more than one project root.
**Score:** 5/8 — Blast radius: 2, Pattern novelty: 2, Security: 0, Reversibility: 1

## Mission

Generalize the project-rooted source loading path so the same loader framework supports both `project_common.xml` and `project_foundation.xml` without project-specific hardcodes.

## Dependencies

- `CG-011`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/adr/0003-generalize-project-rooted-codegen-beyond-common.md`
- `docs/codegen-migration/foundation-next-phase-plan.md`
- `tools/codegen/common_source.py`
- any tests covering project-rooted loading

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `tools/codegen/common_source.py` or a renamed/shared loader module if appropriate
- loader tests/fixtures
- parser docs if needed

## Steps

### Step 0: Preflight

- [ ] Read the ADR and `foundation` inventory output
- [ ] Identify remaining `common`-specific assumptions in the current loader path

### Step 1: Generalize project-rooted loading

- [ ] Support both `project_common.xml` and `project_foundation.xml` through the same loader architecture
- [ ] Keep top-level project metadata model-driven
- [ ] Preserve tolerant parsing behavior for legacy XML-like content

### Step 2: Add shared tests

- [ ] Add tests proving the loader works for both project roots
- [ ] Avoid duplicating project-specific logic where shared structure is sufficient

### Step 3: Verification

- [ ] Run loader tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`

### Step 4: Delivery

- [ ] Document what is now universal in the loader and what remains project-specific only at the model-data level

## Documentation Requirements

**Must Update:** `docs/codegen-migration/model-parser-notes.md` if changed
**Check If Affected:** `docs/codegen-migration/implementation-notes.md`

## Completion Criteria

- [ ] One shared project-rooted loader path supports both `common` and `foundation`
- [ ] No new project-specific hardcodes are introduced in the loader
- [ ] Tests cover both project roots

## Git Commit Convention

- **Implementation:** `feat(CG-012): share project graph loader across roots`
- **Checkpoints:** `checkpoint: CG-012 <description>`

## Do NOT

- Split the architecture into separate hardcoded common/foundation loader stacks
- Introduce resolved XML as a required loader dependency

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
