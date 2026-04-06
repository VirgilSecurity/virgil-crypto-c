# Task: CG-012 — Extract Shared Project Graph Loader

**Created:** 2026-04-05
**Size:** M

## Review Level: 2 (Standard)

**Assessment:** First extraction task that moves project-rooted loading out of `common_source.py` into generic shared codegen modules.
**Score:** 5/8 — Blast radius: 2, Pattern novelty: 2, Security: 0, Reversibility: 1

## Mission

Extract the shared project graph loading responsibilities from `common_source.py` into generic shared codegen modules, keeping only thin compatibility adapters where necessary.

## Dependencies

- `CG-011`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/adr/0003-generalize-project-rooted-codegen-beyond-common.md`
- refactor plan from `CG-011`
- `tools/codegen/common_source.py`
- loader tests

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `tools/codegen/**`
- loader tests/docs

## Steps

### Step 0: Preflight

- [ ] Read the refactor plan and identify the shared loader responsibilities
- [ ] Confirm the compatibility boundary for `common_source.py`

### Step 1: Extract shared loader code

- [ ] Move generic project-rooted loading logic into shared modules with generic names
- [ ] Preserve tolerant parsing behavior
- [ ] Keep project metadata model-driven

### Step 2: Preserve compatibility and tests

- [ ] Keep or add thin compatibility adapters only where necessary
- [ ] Update imports/tests/scripts affected by the extraction
- [ ] Add tests proving the shared loader path still works for `common`

### Step 3: Verification

- [ ] Run loader tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`

### Step 4: Delivery

- [ ] Document what moved into the shared loader layer and what remains adapter-only

## Documentation Requirements

**Must Update:** `docs/codegen-migration/model-parser-notes.md` if changed
**Check If Affected:** `docs/codegen-migration/implementation-notes.md`

## Completion Criteria

- [ ] Shared project graph loading no longer lives only under a `common_*` core module name
- [ ] Compatibility for current `common` workflows is preserved
- [ ] Tests cover the extracted shared loader path

## Git Commit Convention

- **Implementation:** `refactor(CG-012): extract shared project graph loader`
- **Checkpoints:** `checkpoint: CG-012 <description>`

## Do NOT

- Split shared loader behavior into project-specific forks
- Introduce new module-name-specific functionality branches

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
