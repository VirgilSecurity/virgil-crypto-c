# Task: CG-061 - Foundation Build Full Parity Sweep

**Created:** 2026-04-11
**Size:** L

## Review Level: 1 (Plan Only)

**Assessment:** After CG-059/060 fix the known error patterns, run a comprehensive foundation build with increased error limit to surface ALL remaining compilation errors, categorize them, and fix as many as feasible. This is the "mop-up" task to get the foundation build as close to clean as possible.
**Score:** 3/8 — Blast radius: 2, Pattern novelty: 1, Security: 0, Reversibility: 0

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-061-foundation-build-parity-sweep/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Run a comprehensive foundation build after CG-059/060 and systematically fix or document all remaining compilation errors. The current build hits `-ferror-limit` (20 errors) and stops — there may be more errors hidden behind it.

**Known remaining patterns (from header diff analysis of 164 differing headers):**

1. **Missing methods in generated headers** — some implementation-specific methods present in legacy headers are not emitted by the new codegen (e.g., `setup_defaults`, `generate_key` on some impls). Likely caused by methods not being in the IR or being filtered.
2. **Conflicting type declarations** — `compound_key_alg_info` accessor return types differ between generated and legacy headers (line wrapping differences may be masking real type mismatches).
3. **Additional `void` parameter or type resolution issues** — may surface once the `-ferror-limit` is lifted.
4. **Line-wrapping differences** — some diffs are just line wrapping (not errors), but some may mask real issues.

**Approach:**

1. Modify the CMake build to use `-ferror-limit=0` temporarily to get ALL errors
2. Categorize errors by root cause
3. Fix each category systematically in the codegen
4. Document any remaining unfixable issues

## Dependencies

- **CG-059** — fixes bare `void` and bare `status` errors
- **CG-060** — fixes `vscf_error_t` struct and class inline definitions

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`
- `taskplane-tasks/codegen/CG-059-fix-void-parameter-and-status-type/STATUS.md`
- `taskplane-tasks/codegen/CG-060-fix-error-t-struct-and-class-inline-defs/STATUS.md`

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** cmake build system configured

## File Scope

- `tools/codegen/project_c_backend.py` (primary)
- `tools/codegen/project_ir.py`
- `tools/codegen/project_source.py`
- `tools/codegen/new_codegen.sh` (may need temp flag for error limit)

## Steps

### Step 0: Preflight

- [ ] Run foundation build with `-ferror-limit=0` or equivalent to capture ALL errors
- [ ] Deduplicate and categorize errors by root cause pattern
- [ ] Estimate effort per category (how many files affected, code path to fix)
- [ ] Prioritize: fix categories that affect the most files first

### Step 1: Fix error categories

> ⚠️ Hydrate: Expand with specific categories after Step 0 analysis

- [ ] Fix category A (highest impact — placeholder for actual category)
- [ ] Fix category B
- [ ] Fix category C
- [ ] After each fix, re-run build to verify error count drops and no regressions

### Step 2: Verification

> ZERO test failures allowed.

- [ ] Run FULL Python test suite: `PYTHONPATH=. python3 -m unittest discover -s tools/codegen -p "test_*.py"`
- [ ] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Run foundation build: `bash tools/codegen/new_codegen.sh --verify foundation`
- [ ] Document final error count and remaining categories

### Step 3: Documentation & Delivery

- [ ] Update `taskplane-tasks/codegen/CONTEXT.md` — comprehensive status update
- [ ] Update diff analysis with current pattern status
- [ ] Create a summary of remaining errors for future work
- [ ] Discoveries logged in STATUS.md

## Documentation Requirements

**Must Update:**
- `taskplane-tasks/codegen/CONTEXT.md` — full foundation status update
- `docs/codegen-migration/common-direct-foundation-status.md` — if significant progress

## Completion Criteria

- [ ] All steps complete
- [ ] All Python tests passing
- [ ] Common build gate passes
- [ ] Foundation build error count documented (target: significant reduction from current)
- [ ] All remaining errors categorized with root causes
- [ ] Documentation updated

## Git Commit Convention

- **Step completion:** `feat(CG-061): complete Step N — description`
- **Bug fixes:** `fix(CG-061): description`
- **Hydration:** `hydrate: CG-061 expand Step N checkboxes`

## Do NOT

- Modify handwritten `.c` files in `library/foundation/src/`
- Commit generated `library/common/**` or `library/foundation/**` outputs
- Modify CMake build files permanently (only temp changes for diagnostics)
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
