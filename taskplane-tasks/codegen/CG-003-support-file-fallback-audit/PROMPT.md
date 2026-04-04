# Task: CG-003 — Support-File Fallback Audit

**Created:** 2026-04-04
**Size:** S

## Review Level: 1 (Light)

**Assessment:** Low-risk analysis and documentation task to keep the remaining migration boundary explicit.
**Score:** 2/8 — Blast radius: 0, Pattern novelty: 1, Security: 0, Reversibility: 1

## Mission

Audit the remaining non-buffer foundational fallback artifacts in `common` and document which ones should remain fallback-derived, become direct, or be deferred until after buffer migration.

The goal is to make the post-buffer endgame explicit so implementation tasks stay scoped.

## Dependencies

- `CG-001`

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/codegen-migration/common-direct-foundation-status.md`
- planning docs produced by `CG-001`
- current fallback handling in `tools/codegen/common_bootstrap.py`

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `docs/codegen-migration/**`
- optional small comments in `tools/codegen/common_bootstrap.py` if helpful for clarity

## Steps

### Step 0: Preflight

- [ ] Review current direct coverage and fallback coverage notes
- [ ] Identify the remaining support/aggregation outputs still not directly owned

### Step 1: Audit remaining support files

- [ ] Classify each remaining support header/output as direct candidate, acceptable fallback, or deferred work
- [ ] Capture rationale for each classification

### Step 2: Update docs

- [ ] Write the audit into `docs/codegen-migration/`
- [ ] Ensure the docs are consistent with the actual bootstrap routing in code

### Step 3: Delivery

- [ ] Summarize what should happen immediately after `buffer_defs` and `buffer`

## Documentation Requirements

**Must Update:** `docs/codegen-migration/`
**Check If Affected:** `taskplane-tasks/codegen/CONTEXT.md`

## Completion Criteria

- [ ] There is an explicit documented classification for the remaining support/aggregation files
- [ ] The likely endgame after buffer migration is clear enough to prevent scope drift

## Git Commit Convention

- **Implementation:** `docs(CG-003): audit remaining common support fallbacks`
- **Checkpoints:** `checkpoint: CG-003 <description>`

## Do NOT

- Implement major generator changes in this task unless a tiny clarifying comment is necessary
- Commit generated files under `library/common/**`

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
