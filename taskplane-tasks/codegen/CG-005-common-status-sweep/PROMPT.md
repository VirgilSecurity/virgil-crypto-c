# Task: CG-005 — Common Migration Status Sweep

**Created:** 2026-04-04
**Size:** S

## Review Level: 1 (Light)

**Assessment:** Final documentation and audit task to close the loop after buffer migration.
**Score:** 2/8 — Blast radius: 0, Pattern novelty: 1, Security: 0, Reversibility: 1

## Mission

After the buffer-family implementation tasks complete, perform a final status sweep for the `common` migration.

Make the direct-coverage boundary, any intentionally retained fallback behavior, and the next likely work after `common` explicit in the docs.

## Dependencies

- `CG-004`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- all docs updated by `CG-001` through `CG-004`
- current bootstrap routing in `tools/codegen/common_bootstrap.py`

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `docs/codegen-migration/**`
- `taskplane-tasks/codegen/CONTEXT.md`

## Steps

### Step 0: Preflight

- [ ] Review the outputs of `CG-001` through `CG-004`
- [ ] Confirm the current direct/fallback boundary in code and docs

### Step 1: Update status docs

- [ ] Refresh coverage/status docs under `docs/codegen-migration/`
- [ ] Update the task-area context if the task sequence or remaining work changed materially

### Step 2: Verify consistency

- [ ] Ensure docs are consistent with the implemented bootstrap routing and latest successful build verification

### Step 3: Delivery

- [ ] Summarize what remains after `common`, or state that `common` direct-lowering work is effectively complete if that is now true

## Documentation Requirements

**Must Update:** `docs/codegen-migration/`
**Check If Affected:** `taskplane-tasks/codegen/CONTEXT.md`

## Completion Criteria

- [ ] The `common` migration status is easy to understand from the docs alone
- [ ] Any remaining fallback usage is explicitly documented
- [ ] The next engineering move after `common` is stated clearly

## Git Commit Convention

- **Implementation:** `docs(CG-005): refresh common migration status`
- **Checkpoints:** `checkpoint: CG-005 <description>`

## Do NOT

- Re-open completed implementation work without a concrete documented reason
- Commit generated files under `library/common/**`

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
