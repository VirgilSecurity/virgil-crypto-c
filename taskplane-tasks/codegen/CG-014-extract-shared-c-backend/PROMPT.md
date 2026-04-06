# Task: CG-014 — Extract Shared C Backend

**Created:** 2026-04-05
**Size:** M

## Review Level: 2 (Standard)

**Assessment:** Backend extraction task that moves shared C lowering/rendering responsibilities out of `common_direct_c.py` into generic modules.
**Score:** 5/8 — Blast radius: 2, Pattern novelty: 2, Security: 0, Reversibility: 1

## Mission

Extract the shared C backend responsibilities from `common_direct_c.py` into generic shared codegen modules, preserving compatibility for current `common` workflows while reducing `common`-named shared-core assumptions.

## Dependencies

- `CG-013`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- refactor plan from `CG-011`
- `tools/codegen/common_direct_c.py`
- direct-C resolution tests/docs

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `tools/codegen/**`
- backend tests/docs

## Steps

### Step 0: Preflight

- [ ] Read the refactor plan and inspect current C backend boundaries
- [ ] Confirm which pieces are shared backend behavior versus temporary compatibility adapters

### Step 1: Extract shared C backend code

- [ ] Move generic C lowering/rendering helpers into shared modules with generic names
- [ ] Keep project metadata model-driven rather than backend-literal-driven
- [ ] Avoid module-name-specific functionality branches where IR metadata already expresses the needed distinction

### Step 2: Preserve compatibility and tests

- [ ] Keep or add thin compatibility adapters only where necessary
- [ ] Update imports/tests/scripts affected by the extraction
- [ ] Add tests proving the shared C backend path still works for `common`

### Step 3: Verification

- [ ] Run backend tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`
- [ ] Run `bash tools/codegen/build_common_with_new_codegen.sh`

### Step 4: Delivery

- [ ] Update docs to describe the shared C backend layer and any remaining adapter-only code

## Documentation Requirements

**Must Update:** `docs/codegen-migration/implementation-notes.md`
**Check If Affected:** `docs/codegen-migration/common-c-generator-decision.md`

## Completion Criteria

- [ ] Shared C backend logic no longer lives only under a `common_*` core module name
- [ ] Compatibility for current `common` workflows is preserved
- [ ] Tests and build verification cover the extracted shared backend path

## Git Commit Convention

- **Implementation:** `refactor(CG-014): extract shared c backend`
- **Checkpoints:** `checkpoint: CG-014 <description>`

## Do NOT

- Reintroduce project-specific path/prefix/module-name hardcodes in the shared backend
- Commit generated `library/common/**` outputs

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
