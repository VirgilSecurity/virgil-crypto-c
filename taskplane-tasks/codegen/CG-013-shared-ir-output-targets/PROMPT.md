# Task: CG-013 — Shared IR and Output Targets Beyond Common

**Created:** 2026-04-05
**Size:** M

## Review Level: 2 (Standard)

**Assessment:** Architecture task that removes remaining `common`-centric assumptions from IR/output-target modeling.
**Score:** 5/8 — Blast radius: 2, Pattern novelty: 2, Security: 0, Reversibility: 1

## Mission

Generalize the IR/output-target model so it can represent both `common` and `foundation` from project metadata without embedding `common`-specific assumptions.

## Dependencies

- `CG-012`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/adr/0003-generalize-project-rooted-codegen-beyond-common.md`
- `tools/codegen/common_ir.py`
- tests/docs describing the current project-rooted IR

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `tools/codegen/common_ir.py` or a renamed/shared IR module if appropriate
- IR tests/docs

## Steps

### Step 0: Preflight

- [ ] Read the ADR and inspect current IR/output-target assumptions
- [ ] Identify what is still implicitly tied to `common`

### Step 1: Generalize the IR model

- [ ] Ensure project/entity/output metadata is represented generically enough for `foundation`
- [ ] Keep naming/path/prefix/output routing model-driven
- [ ] Avoid turning universal IR into a bag of ad hoc project exceptions

### Step 2: Add shared IR tests

- [ ] Add tests covering both `common` and `foundation` IR/output-target construction
- [ ] Confirm the IR remains suitable for the C backend

### Step 3: Verification

- [ ] Run IR tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`

### Step 4: Delivery

- [ ] Update docs to describe the shared IR/output-target contract

## Documentation Requirements

**Must Update:** `docs/codegen-migration/common-source-to-ir.md`
**Check If Affected:** `docs/codegen-migration/implementation-notes.md`

## Completion Criteria

- [ ] IR/output-target logic is shared across at least `common` and `foundation`
- [ ] Project-specific metadata remains model-derived rather than hardcoded
- [ ] Tests cover the shared IR contract

## Git Commit Convention

- **Implementation:** `feat(CG-013): generalize shared IR output targets`
- **Checkpoints:** `checkpoint: CG-013 <description>`

## Do NOT

- Encode `foundation` support as another special-case hardcoded layer
- Reconstruct project-specific output routing from backend literals when the IR can carry it

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
