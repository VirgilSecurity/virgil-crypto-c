# Task: CG-044 - Foundation Codegen Full Verification

**Created:** 2026-04-09
**Size:** M

## Review Level: 2 (Plan and Code)

**Assessment:** Final integration verification for all foundation codegen fixes. Runs the full codegen → clang-format → build → diff → test pipeline and fixes any remaining discrepancies. This is the quality gate before foundation codegen can be considered production-ready.
**Score:** 4/8 — Blast radius: 2, Pattern novelty: 1, Security: 0, Reversibility: 1

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-044-foundation-codegen-verification/
├── PROMPT.md
├── STATUS.md
├── .reviews/
└── .DONE
```

## Mission

Run the full foundation codegen verification pipeline (`bash tools/codegen/new_codegen.sh --verify foundation`) and fix any remaining parity issues. After CG-040 through CG-043 address the known categories, this task catches edge cases and ensures the foundation project compiles cleanly with new codegen output.

The verification flow is:
1. Apply codegen (`--apply foundation`)
2. Run clang-format on foundation target
3. Build foundation (`cmake --build ... --target foundation`)
4. Check diff — flag non-generated changes
5. Run cmake tests for foundation
6. Restore generated files

The goal: **foundation builds and tests pass with zero compilation errors** using the new codegen output. Some diff differences may remain (ordering, whitespace) but there must be zero **functional** differences that affect compilation or behavior.

## Dependencies

- **Task:** CG-040 (interface API/dispatch fixes)
- **Task:** CG-041 (type resolution fixes)
- **Task:** CG-042 (vtable initializer fix)
- **Task:** CG-043 (dependency methods + library macros)

## Context to Read First

**Tier 2:**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3:**
- `tools/codegen/new_codegen.sh` — the verification script

## Environment

- **Workspace:** `tools/codegen/`, `library/foundation/`
- **Services required:** cmake build system configured

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/common_bootstrap.py`
- `tools/codegen/new_codegen.sh`

## Steps

### Step 0: Preflight

- [ ] CG-040 through CG-043 are complete
- [ ] Common codegen still passes: `bash tools/codegen/new_codegen.sh --verify common`
- [ ] Foundation codegen runs without Python errors: `bash tools/codegen/new_codegen.sh --apply foundation`

### Step 1: Attempt foundation build

- [ ] Run `bash tools/codegen/new_codegen.sh --build foundation`
- [ ] Capture all compilation errors
- [ ] Categorize errors (missing includes, type mismatches, undeclared functions, etc.)
- [ ] Commit any fixes needed

### Step 2: Fix compilation errors

> ⚠️ Hydrate: Expand based on specific errors found in Step 1

- [ ] Fix each category of compilation error in the codegen (not in foundation source)
- [ ] Re-run build until compilation succeeds
- [ ] Commit after each fix category

### Step 3: Run diff check

- [ ] Run `bash tools/codegen/new_codegen.sh --verify foundation`
- [ ] Review non-generated changes
- [ ] Determine which diffs are:
  - Acceptable (whitespace, ordering that doesn't affect compilation)
  - Bugs to fix (functional differences)
- [ ] Fix any remaining functional bugs
- [ ] Commit

### Step 4: Run tests

- [ ] Run cmake tests for foundation
- [ ] Fix any test failures caused by codegen differences
- [ ] Commit

### Step 5: Final verification

- [ ] `bash tools/codegen/new_codegen.sh --verify common` — still passes
- [ ] `bash tools/codegen/new_codegen.sh --verify foundation` — passes (build + tests)
- [ ] `python3 -m unittest discover -s tools/codegen -p "test_*.py" -v` — all pass
- [ ] Document remaining known non-functional diff differences in STATUS.md Discoveries

### Step 6: Documentation & Delivery

- [ ] Update CONTEXT.md: note foundation codegen status
- [ ] Log all discoveries

## Documentation Requirements

**Must Update:**
- `taskplane-tasks/codegen/CONTEXT.md` — update foundation codegen status

**Check If Affected:**
- `docs/codegen-migration/README.md`

## Completion Criteria

- [ ] Foundation builds with zero compilation errors using new codegen
- [ ] Foundation tests pass
- [ ] Common codegen unchanged (no regression)
- [ ] All Python tests pass
- [ ] Remaining diff differences documented and justified as non-functional

## Git Commit Convention

- `feat(CG-044): complete Step N — description`
- `fix(CG-044): description`

**CRITICAL: Commit after EACH fix.**

## Do NOT

- Modify foundation source files outside generated blocks
- Accept compilation errors as "known issues"
- Commit without task ID prefix

---

## Amendments (Added During Execution)
