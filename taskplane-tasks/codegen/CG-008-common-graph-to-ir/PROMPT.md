# Task: CG-008 — Common Project Graph to IR

**Created:** 2026-04-04
**Size:** M

## Review Level: 2 (Standard)

**Assessment:** Core architecture task that introduces the normalized IR expected by future backends.
**Score:** 5/8 — Blast radius: 2, Pattern novelty: 2, Security: 0, Reversibility: 1

## Mission

Build a normalized language-neutral IR from the resolved `common` project graph.

The IR should carry model-derived metadata required by the C backend and should become the place where project naming, output grouping, and entity relationships are represented structurally instead of being embedded in per-module Python builders.

## Dependencies

- `CG-007`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/adr/0002-project-rooted-codegen-pipeline.md`
- `tools/codegen/common_source.py`
- `tools/codegen/common_ir.py`
- docs related to current IR mapping

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `tools/codegen/common_ir.py`
- supporting inspection helpers/tests
- docs describing IR expectations if needed

## Steps

### Step 0: Preflight

- [ ] Read the ADR and inspect the current IR shape
- [ ] Identify which project-derived metadata is still missing or implicit

### Step 1: Define or refine the normalized IR

- [ ] Ensure the IR can represent project, modules, classes, enums, methods, constants, and output metadata needed by the C backend
- [ ] Prefer explicit structured fields over module-specific ad hoc conventions

### Step 2: Implement graph-to-IR lowering

- [ ] Lower the project-rooted graph into the normalized IR
- [ ] Preserve enough detail to drive naming/file decisions from model metadata
- [ ] Add or update tests for the IR construction path

### Step 3: Verification

- [ ] Run IR tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`

### Step 4: Delivery

- [ ] Update docs describing the IR and what it now guarantees to backends

## Documentation Requirements

**Must Update:** `docs/codegen-migration/common-source-to-ir.md`
**Check If Affected:** `docs/codegen-migration/implementation-notes.md`

## Completion Criteria

- [ ] There is a project-rooted normalized IR for `common`
- [ ] The IR carries model-derived metadata needed to remove project-specific hardcodes from the C backend
- [ ] Tests cover the new graph-to-IR path

## Git Commit Convention

- **Implementation:** `feat(CG-008): build common IR from project graph`
- **Checkpoints:** `checkpoint: CG-008 <description>`

## Do NOT

- Collapse the IR back into per-module hardcoded builders
- Introduce wrapper-specific assumptions into the core IR

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
