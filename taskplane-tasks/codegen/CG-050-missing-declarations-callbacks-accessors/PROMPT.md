# Task: CG-050 - Missing Declarations: Callbacks, Lifecycle, Accessors

**Created:** 2026-04-10
**Size:** M

## Review Level: 1 (Plan Only)

**Assessment:** Adds missing function declarations to generated code. Moderate pattern novelty — requires understanding legacy internal wiring patterns. Multiple declaration categories but all follow established codegen patterns.
**Score:** 2/8 — Blast radius: 1, Pattern novelty: 1, Security: 0, Reversibility: 0

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-050-missing-declarations-callbacks-accessors/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Add missing function declarations that cause compilation and link errors when generated headers are used with legacy handwritten `.c` files. These are documented as patterns B, D, and H in CONTEXT.md's Foundation Diff Analysis.

**Pattern B — Missing `_api(void)` accessor functions (16 occurrences):**
Legacy headers declare functions like `vscf_aes256_gcm_cipher_info_api(void)` that return a pointer to the interface API struct. These accessors allow callers to check which interfaces an implementation supports. The new codegen omits these declarations.
Fix: for each implementation that implements interfaces, emit accessor function declarations that return `const vscf_{interface}_api_t *`.

**Pattern D — Missing `did_setup`/`did_release` dependency callbacks (55 occurrences):**
When an implementation has dependency properties (e.g., `vscf_ecc` depends on `random`, `ecies`), the legacy internal headers declare callback functions like `vscf_ecc_did_setup_random(vscf_ecc_t *self)` and `vscf_ecc_did_release_random(vscf_ecc_t *self)`. These are called from the dependency injection wiring in `_internal.c`. The new codegen doesn't emit these declarations.
Fix: for each dependency property on a class/implementation, emit `did_setup_{dep}` and `did_release_{dep}` forward declarations in the appropriate internal header output.

**Pattern H — Missing `init_ctx`/`cleanup_ctx` declarations (8 occurrences):**
Legacy internal code calls `vscf_{name}_init_ctx(self)` and `vscf_{name}_cleanup_ctx(self)` — implementation-specific context initialization. These are declared in legacy `_internal.h` files but not emitted by the new codegen's internal module output.
Fix: emit forward declarations for `init_ctx` and `cleanup_ctx` in the generated internal module output (the `_internal.c` files that the codegen already generates).

## Dependencies

- **Task:** CG-046 (established type resolution patterns)
- **Task:** CG-047 (established enum/IR patterns)

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md` — specifically the "Foundation Diff Analysis" section

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** cmake build system configured

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/project_ir.py`
- `tools/codegen/common_source.py`

## Steps

### Step 0: Preflight

- [ ] Run `bash tools/codegen/new_codegen.sh --verify foundation` and capture baseline error count
- [ ] Examine legacy `_internal.h` files (e.g. `vscf_ecc_internal.h`, `vscf_sha256_internal.h`) to understand the declaration patterns for:
  - `_api(void)` accessor functions
  - `did_setup_*` / `did_release_*` callbacks
  - `init_ctx` / `cleanup_ctx` lifecycle functions
- [ ] Identify where in the IR/source model these patterns are expressed (dependency properties, interface implementations)
- [ ] Identify which codegen output files should contain these declarations (internal module `.c` or separate header)

### Step 1: Add `_api(void)` accessor declarations (Pattern B)

- [ ] For each implementation that implements interfaces, emit accessor function declarations
- [ ] Match the legacy signature pattern: `VSCF_PUBLIC const vscf_{interface}_api_t * vscf_{impl}_{interface}_api(void);`
- [ ] Verify against legacy headers for representative implementations (e.g. `vscf_aes256_gcm`, `vscf_ecc`)
- [ ] Run targeted test after fix

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 2: Add `did_setup`/`did_release` callback declarations (Pattern D)

- [ ] Parse dependency properties from the source model / IR for classes and implementations
- [ ] Emit `did_setup_{dep}` and `did_release_{dep}` forward declarations
- [ ] Place declarations in the correct output section (internal module preamble or header)
- [ ] Verify against legacy internal headers for representative modules (e.g. `vscf_ecc_internal.h`)
- [ ] Run targeted test after fix

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)
- Possibly `tools/codegen/project_ir.py` (modified — if dependency properties need IR support)
- Possibly `tools/codegen/common_source.py` (modified — if dependency parsing needed)

### Step 3: Add `init_ctx`/`cleanup_ctx` declarations (Pattern H)

- [ ] Emit `init_ctx` and `cleanup_ctx` forward declarations in generated internal module output
- [ ] Match legacy signature: `VSCF_PRIVATE void vscf_{name}_init_ctx(vscf_{name}_t *self);`
- [ ] Verify against legacy internal headers for representative modules
- [ ] Run targeted test after fix

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 4: Testing & Verification

> ZERO test failures allowed.

- [ ] Run FULL Python test suite: `PYTHONPATH=. python3 -m unittest discover -s tools/codegen -p "test_*.py"`
- [ ] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Run foundation build: `bash tools/codegen/new_codegen.sh --verify foundation`
- [ ] Count remaining errors and compare to baseline — document improvement
- [ ] Fix any regressions

### Step 5: Documentation & Delivery

- [ ] Update `taskplane-tasks/codegen/CONTEXT.md` — update diff pattern status for B, D, H
- [ ] Discoveries logged in STATUS.md

## Documentation Requirements

**Must Update:**
- `taskplane-tasks/codegen/CONTEXT.md` — update patterns B, D, H status in Foundation Diff Analysis

**Check If Affected:**
- `docs/codegen-migration/common-direct-foundation-status.md` — update if build error count changes

## Completion Criteria

- [ ] All steps complete
- [ ] All Python tests passing (159+)
- [ ] Common build gate passes
- [ ] `_api(void)` accessors emitted for implementations (pattern B resolved)
- [ ] `did_setup`/`did_release` callbacks declared (pattern D resolved)
- [ ] `init_ctx`/`cleanup_ctx` declared in internal output (pattern H resolved)
- [ ] Documentation updated

## Git Commit Convention

- **Step completion:** `feat(CG-050): complete Step N — description`
- **Bug fixes:** `fix(CG-050): description`
- **Hydration:** `hydrate: CG-050 expand Step N checkboxes`

## Do NOT

- Modify handwritten `.c` files in `library/foundation/src/`
- Commit generated `library/common/**` or `library/foundation/**` outputs
- Generate full `_internal.h` files (that's a future task — only add declarations to existing codegen output)
- Fix patterns A, C, E, F, G (those are CG-049 or future scope)
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
