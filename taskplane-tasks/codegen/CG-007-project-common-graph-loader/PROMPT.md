# Task: CG-007 — Project-Rooted Common Graph Loader

**Created:** 2026-04-04
**Size:** M

## Review Level: 2 (Standard)

**Assessment:** Foundational parser/refactor task that changes how `common` generation is rooted.
**Score:** 5/8 — Blast radius: 2, Pattern novelty: 2, Security: 0, Reversibility: 1

## Mission

Refactor the `common` model loader so that `project_common.xml` is the explicit top-level entrypoint and the referenced model graph is resolved from there.

The result should expose project, classes, modules, enums, and related metadata in a way that the later IR and C backend can consume without project-specific hardcodes.

## Dependencies

- `CG-006`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/adr/0002-project-rooted-codegen-pipeline.md`
- `docs/codegen-migration/model-spec-common.md`
- `docs/codegen-migration/model-parser-notes.md`
- tests added by `CG-006`
- `tools/codegen/common_source.py`

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `tools/codegen/common_source.py`
- nearby inspection/helpers if needed
- tests for the loader
- docs only if parser realities changed materially

## Steps

### Step 0: Preflight

- [ ] Read the ADR and the tests/fixtures from `CG-006`
- [ ] Inspect current loading flow and identify remaining ad hoc entrypoints

### Step 1: Implement project-rooted loading

- [ ] Make `project_common.xml` the explicit loader entrypoint for `common`
- [ ] Resolve referenced model files and expose a coherent project graph
- [ ] Preserve tolerant parsing behavior for legacy XML-like code blocks

### Step 2: Clean up loader shape

- [ ] Ensure project metadata needed by later backends is available from the graph
- [ ] Reduce reliance on per-module/manual lookup patterns where practical

### Step 3: Verification

- [ ] Run tests from `CG-006`
- [ ] Run any updated loader tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`

### Step 4: Delivery

- [ ] Update docs if parser or graph-loading realities changed
- [ ] Summarize what graph facts are now available to the IR layer

## Documentation Requirements

**Must Update:** `docs/codegen-migration/model-parser-notes.md` if changed
**Check If Affected:** `docs/codegen-migration/model-spec-common.md`

## Completion Criteria

- [ ] The `common` loader is explicitly project-rooted
- [ ] The resolved graph exposes enough structure for the IR layer to stop depending on project-specific hardcodes
- [ ] Existing tolerant parsing behavior is preserved

## Git Commit Convention

- **Implementation:** `feat(CG-007): load common from project root graph`
- **Checkpoints:** `checkpoint: CG-007 <description>`

## Do NOT

- Re-introduce resolved XML as a required loader dependency
- Hardcode project-specific prefixes/paths that belong in models

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
