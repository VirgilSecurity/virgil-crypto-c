# Task: CG-020 — Finish Foundation Validation Gates from Saved Work

**Created:** 2026-04-07
**Size:** M

## Review Level: 2 (Standard)

**Assessment:** Recovery task to salvage and complete the partial `CG-018` work preserved on the saved branch, with explicit focus on executable validation gates rather than formatting polish.
**Score:** 5/8 — Blast radius: 2, Pattern novelty: 1, Security: 0, Reversibility: 2

## Mission

Recover and finish the `foundation` validation-gate work using the preserved partial progress from:

- `saved/ssiroshtan-CG-018-20260406T092213`

The goal is to land a clean, minimal, testable `foundation` validation path and documentation update without expanding scope.

## Dependencies

- **None**

## Context to Read First

- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/codegen-migration/foundation-next-phase-plan.md`
- `saved/ssiroshtan-CG-018-20260406T092213`
- `taskplane-tasks/codegen/CG-018-foundation-preservation-and-build-gates/PROMPT.md`

## Environment

- **Workspace:** Project root
- **Services required:** None

## File Scope

- `tools/codegen/verify_foundation_validation_gate.sh`
- `tests/foundation/**`
- `docs/codegen-migration/**`
- any small supporting files directly required by the validation path

## Steps

### Step 0: Preflight

- [ ] Inspect the saved branch work and identify the minimum useful subset to salvage
- [ ] Confirm the validation goal is executable build/test confidence, not formatting polish

### Step 1: Finish the validation gate work

- [ ] Recover the useful saved-branch changes into the active task implementation
- [ ] Keep the scope minimal and focused on executable validation infrastructure
- [ ] Remove or avoid speculative changes that are not required for the gate to run reliably

### Step 2: Verify and document

- [ ] Run the `foundation` validation gate(s)
- [ ] Update the task STATUS and docs to reflect the actual supported validation path
- [ ] Ensure the result is understandable without needing the failed batch history

### Step 3: Delivery

- [ ] Summarize what was salvaged from the saved branch and what was intentionally left out

## Documentation Requirements

**Must Update:** `docs/codegen-migration/foundation-next-phase-plan.md`
**Check If Affected:** `taskplane-tasks/codegen/CONTEXT.md`

## Completion Criteria

- [ ] The `foundation` validation gate exists in a clean, executable form
- [ ] The result is based on the preserved useful work from the saved branch, but reduced to minimal necessary scope
- [ ] Docs explain the supported validation path clearly

## Git Commit Convention

- **Implementation:** `test(CG-020): finish foundation validation gate recovery`
- **Checkpoints:** `checkpoint: CG-020 <description>`

## Do NOT

- Chase formatting polish as a goal by itself
- Reconstruct the entire failed task history inside docs or commits
- Expand into first-slice emitter work in this recovery task

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
