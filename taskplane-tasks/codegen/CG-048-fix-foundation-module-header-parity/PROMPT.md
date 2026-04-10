# Task: CG-048 - Fix Foundation Module Header Parity

**Created:** 2026-04-10
**Size:** M

## Review Level: 1 (Plan Only)

**Assessment:** Fixes codegen output to match legacy handwritten C signatures. Multiple error categories but confined to the C backend. Moderate pattern novelty — requires understanding how legacy code uses generated headers.
**Score:** 2/8 — Blast radius: 1, Pattern novelty: 1, Security: 0, Reversibility: 0

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-048-fix-foundation-module-header-parity/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Fix foundation build errors caused by generated module headers not matching the legacy handwritten `.c` file signatures. After CG-046/047 resolved `vscf_self_t` and `impl/tag` issues, a new layer of 24+ compilation errors surfaced in `vscf_alg_info_der_serializer` and `vscf_alg_info_der_deserializer`. These errors fall into three categories that all stem from the codegen producing header declarations that conflict with the checked-in handwritten implementations.

**Current errors (24+ across 2 modules):**

1. **Undeclared `init_ctx`/`cleanup_ctx`** (2 errors in `_deserializer_internal.c`):
   - `vscf_alg_info_der_deserializer_init_ctx` — called but not declared in generated header
   - `vscf_alg_info_der_deserializer_cleanup_ctx` — called but not declared in generated header

2. **Visibility mismatch** (3 errors in `_deserializer.c` and `_serializer.c`):
   - Functions declared `VSCF_PUBLIC` in generated header but `VSCF_PRIVATE` (or vice versa) in handwritten `.c`

3. **Conflicting types / const qualifiers** (19+ errors in `_serializer.c`):
   - Generated header declares functions with different parameter types than handwritten `.c` definitions
   - `const vscf_impl_t *` in generated header vs `vscf_impl_t *` in handwritten code (or vice versa)
   - Multiple `serialized_*_len` and `serialize_*` functions have type mismatches

**Root cause:** The codegen generates module-level method declarations from the XML model, but the model's method signatures (visibility, const qualifiers, parameter types) don't perfectly match the handwritten implementations. The legacy codegen may have had special handling or the handwritten code may have deviated from the model.

**Approach:** Fix the codegen to emit declarations that match what the legacy handwritten code expects. Compare the generated headers against the legacy (checked-in) headers for these modules to identify the differences, then fix the backend to produce matching output. Do NOT modify the handwritten `.c` files.

## Dependencies

- **Task:** CG-046 (vscf_self_t resolution)
- **Task:** CG-047 (impl/tag enum resolution)

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** cmake build system configured

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/project_ir.py`
- `tools/codegen/common_source.py`

## Steps

### Step 0: Preflight

- [ ] Run `bash tools/codegen/new_codegen.sh --verify foundation` and capture all errors
- [ ] Diff the generated headers against legacy headers for the 2 affected modules:
  - `diff library/foundation/include/virgil/crypto/foundation/vscf_alg_info_der_serializer.h build/new-codegen/library/foundation/include/virgil/crypto/foundation/vscf_alg_info_der_serializer.h`
  - Same for `vscf_alg_info_der_deserializer.h`
- [ ] Categorize each error and trace back to the codegen code that produces the wrong declaration
- [ ] Check if these modules are "class" type or "implementation" type in the XML models

### Step 1: Fix declaration parity

> ⚠️ Hydrate: Expand based on root causes identified in Step 0

- [ ] Fix undeclared `init_ctx`/`cleanup_ctx` functions (ensure lifecycle context functions are declared)
- [ ] Fix visibility mismatches (ensure VSCF_PUBLIC/VSCF_PRIVATE matches legacy)
- [ ] Fix conflicting types and const qualifiers (ensure parameter types match legacy signatures)
- [ ] Run targeted verification after each fix category

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)
- Possibly `tools/codegen/project_ir.py` (modified)
- Possibly `tools/codegen/common_source.py` (modified)

### Step 2: Testing & Verification

> ZERO test failures allowed.

- [ ] Run FULL Python test suite: `PYTHONPATH=. python3 -m unittest discover -s tools/codegen -p "test_*.py"`
- [ ] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Run foundation build: `bash tools/codegen/new_codegen.sh --verify foundation`
- [ ] Confirm `alg_info_der_serializer` and `alg_info_der_deserializer` errors are resolved
- [ ] Document any remaining errors (different modules) as discoveries — do NOT expand scope
- [ ] Fix any regressions

### Step 3: Documentation & Delivery

- [ ] Update `taskplane-tasks/codegen/CONTEXT.md` — update foundation build status
- [ ] Discoveries logged in STATUS.md (especially any remaining errors in other modules)

## Documentation Requirements

**Must Update:**
- `taskplane-tasks/codegen/CONTEXT.md` — update foundation build error status

**Check If Affected:**
- `docs/codegen-migration/common-direct-foundation-status.md` — update if build status changes

## Completion Criteria

- [ ] All steps complete
- [ ] All Python tests passing (159+)
- [ ] Common build gate passes
- [ ] Foundation build: 0 errors in `vscf_alg_info_der_serializer` and `vscf_alg_info_der_deserializer`
- [ ] Any remaining errors in OTHER modules documented as discoveries (not in scope)
- [ ] Documentation updated

## Git Commit Convention

- **Step completion:** `feat(CG-048): complete Step N — description`
- **Bug fixes:** `fix(CG-048): description`
- **Hydration:** `hydrate: CG-048 expand Step N checkboxes`

## Do NOT

- Modify handwritten `.c` files in `library/foundation/src/`
- Commit generated `library/common/**` or `library/foundation/**` outputs
- Fix errors in modules beyond `alg_info_der_serializer` and `alg_info_der_deserializer` — log as discoveries
- Change IR dataclass structure unless necessary for the fix
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
