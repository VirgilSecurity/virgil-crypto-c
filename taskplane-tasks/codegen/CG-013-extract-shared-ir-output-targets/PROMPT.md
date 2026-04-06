# Task: CG-013 — Extract Shared IR and Output Targets

**Created:** 2026-04-05
**Size:** M

## Review Level: 2 (Standard)

**Assessment:** IR extraction task that moves shared output-target logic out of `common_ir.py` into generic modules.
**Score:** 5/8 — Blast radius: 2, Pattern novelty: 2, Security: 0, Reversibility: 1

## Mission

Extract the shared IR/output-target responsibilities from `common_ir.py` into generic shared codegen modules, preserving compatibility for current `common` workflows.

## Dependencies

- `CG-012`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- refactor plan from `CG-011`
- `tools/codegen/common_ir.py`
- current IR/output-target docs/tests

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `tools/codegen/**`
- IR tests/docs

## Steps

### Step 0: Preflight

- [ ] Read the refactor plan and current IR/output-target docs
- [ ] Confirm which IR responsibilities should become shared generic modules

### Step 1: Extract shared IR/output-target code

- [ ] Move generic IR/output-target modeling into shared modules with generic names
- [ ] Keep naming/path/prefix/output routing model-driven
- [ ] Avoid turning the shared IR into project-specific branches

### Step 2: Preserve compatibility and tests

- [ ] Keep or add thin compatibility adapters only where necessary
- [ ] Update imports/tests/scripts affected by the extraction
- [ ] Add tests proving the shared IR path still works for `common`

### Step 3: Verification

- [ ] Run IR tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`

### Step 4: Delivery

- [ ] Update docs to describe the shared IR/output-target layer

## Documentation Requirements

**Must Update:** `docs/codegen-migration/common-source-to-ir.md`
**Check If Affected:** `docs/codegen-migration/implementation-notes.md`

## Completion Criteria

- [ ] Shared IR/output-target logic no longer lives only under a `common_*` core module name
- [ ] Compatibility for current `common` workflows is preserved
- [ ] Tests cover the extracted shared IR path

## Git Commit Convention

- **Implementation:** `refactor(CG-013): extract shared ir output targets`
- **Checkpoints:** `checkpoint: CG-013 <description>`

## Do NOT

- Encode shared semantics as project-specific exception tables
- Reconstruct model-derived output routing from backend literals

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
