# Task: CG-058 - Fix HKDF Visibility Gap and Remaining Parity Issues

**Created:** 2026-04-11
**Size:** S

## Review Level: 1 (Plan Only)

**Assessment:** Small targeted fix for the 1 known remaining visibility gap (`scope="private"` impl own methods appearing in wrong header for HKDF extract/expand) plus a sweep for any other parity issues surfaced by the preceding tasks. Low risk, narrow scope.
**Score:** 1/8 — Blast radius: 0, Pattern novelty: 1, Security: 0, Reversibility: 0

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-058-fix-hkdf-visibility-and-remaining-parity/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Fix the remaining known parity gap and perform a final parity sweep:

1. **HKDF visibility gap:** `vscf_hkdf_extract` and `vscf_hkdf_expand` have `scope="private"` in the model but appear in the public header instead of the private header. The codegen should route `scope="private"` implementation own-methods to the private header (e.g., `vscf_hkdf_private.h`).

2. **Parity sweep:** After CG-055/056/057 complete, run a full foundation build and diff analysis to identify any remaining parity issues. Fix small issues in-scope; document larger issues as discoveries for future tasks.

## Dependencies

- **CG-055** — missing `_internal.c` (may surface related issues)
- **CG-056** — remaining interface files (may change error surface)
- **CG-057** — umbrella/support headers (may affect include resolution)

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Specific files to examine:**
- `library/foundation/include/virgil/crypto/foundation/vscf_hkdf.h` (public — should NOT have extract/expand)
- `library/foundation/include/virgil/crypto/foundation/private/vscf_hkdf_private.h` (private — should have extract/expand)
- The XML model for HKDF in `codegen/models/`
- `project_c_backend.py` — method routing logic for `scope="private"`

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** cmake build system configured

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/project_ir.py` (if scope metadata not in IR)

## Steps

### Step 0: Preflight

- [ ] Compare legacy vs generated `vscf_hkdf.h` to confirm the visibility gap
- [ ] Check the XML model for HKDF — identify `scope="private"` on extract/expand methods
- [ ] Trace the codegen path for method visibility routing
- [ ] Run full foundation build and capture remaining error count

### Step 1: Fix HKDF visibility routing

- [ ] Fix `project_c_backend.py` to route `scope="private"` impl methods to private header
- [ ] Verify `vscf_hkdf_extract` and `vscf_hkdf_expand` appear in private header, not public
- [ ] Check if any other implementations have the same pattern

### Step 2: Parity sweep

> ⚠️ Hydrate: Expand based on findings from full build

- [ ] Run full foundation build: `bash tools/codegen/new_codegen.sh --verify foundation`
- [ ] Capture and categorize remaining errors (if any)
- [ ] Fix small parity issues (< 5 files affected each)
- [ ] Document larger issues as discoveries for future tasks

### Step 3: Verification

> ZERO test failures allowed.

- [ ] Run FULL Python test suite: `PYTHONPATH=. python3 -m unittest discover -s tools/codegen -p "test_*.py"`
- [ ] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Run foundation build: `bash tools/codegen/new_codegen.sh --verify foundation`
- [ ] Document final error count and remaining gap summary

### Step 4: Documentation & Delivery

- [ ] Update `taskplane-tasks/codegen/CONTEXT.md` — final foundation status update
- [ ] Update diff analysis table with current state
- [ ] Discoveries logged in STATUS.md

## Documentation Requirements

**Must Update:**
- `taskplane-tasks/codegen/CONTEXT.md` — update foundation build status and diff analysis

**Check If Affected:**
- `docs/codegen-migration/common-direct-foundation-status.md`
- `docs/codegen-migration/roadmap.md`

## Completion Criteria

- [ ] All steps complete
- [ ] All Python tests passing
- [ ] Common build gate passes
- [ ] HKDF extract/expand in private header only
- [ ] Foundation build status documented with remaining error count
- [ ] Documentation updated

## Git Commit Convention

- **Step completion:** `feat(CG-058): complete Step N — description`
- **Bug fixes:** `fix(CG-058): description`
- **Hydration:** `hydrate: CG-058 expand Step N checkboxes`

## Do NOT

- Modify handwritten `.c` files in `library/foundation/src/`
- Commit generated `library/common/**` or `library/foundation/**` outputs
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
