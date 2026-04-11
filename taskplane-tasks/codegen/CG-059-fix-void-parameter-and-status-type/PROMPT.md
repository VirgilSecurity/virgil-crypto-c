# Task: CG-059 - Fix Bare `void` Parameter and Unresolved `status` Type

**Created:** 2026-04-11
**Size:** M

## Review Level: 1 (Plan Only)

**Assessment:** Two related type resolution bugs in the C backend causing compilation errors. Clear root causes, well-scoped fix in the rendering pipeline.
**Score:** 2/8 — Blast radius: 1, Pattern novelty: 1, Security: 0, Reversibility: 0

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-059-fix-void-parameter-and-status-type/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Fix two type resolution bugs that cause compilation errors in the foundation build:

### Bug 1: Bare `void` as function parameter (6 files, 12 declarations)

Generated code emits `void` as a bare parameter in the middle of argument lists:

```c
// Generated (WRONG):
vscf_compound_key_alg_sign_hash(const vscf_compound_key_alg_t *self, const vscf_impl_t *private_key, void, vsc_data_t digest, vsc_buffer_t *signature);

// Legacy (CORRECT):
vscf_compound_key_alg_sign_hash(const vscf_compound_key_alg_t *self, const vscf_impl_t *private_key, vscf_alg_id_t alg_id, vsc_data_t digest, vsc_buffer_t *signature);
```

The `alg_id` parameter (type `enum` / `vscf_alg_id_t`) is being resolved as `void` instead of its correct type. Affects `sign_hash` and `verify_hash` methods across 6 implementation files: `compound_key_alg`, `ecc`, `ed25519`, `falcon`, `hybrid_key_alg`, and at least one more.

**Root cause hypothesis:** The type resolver doesn't handle enum-typed interface method parameters correctly — when an implementation inherits an interface method with an enum parameter, the type resolves to `void`.

### Bug 2: Bare `status` instead of `vscf_status_t` (1 file, 2 declarations)

In `vscf_ctr_drbg.h`, dependency management methods emit `status` instead of `vscf_status_t`:

```c
// Generated (WRONG):
VSCF_PUBLIC status
vscf_ctr_drbg_use_entropy_source(vscf_ctr_drbg_t *self, vscf_impl_t *entropy_source) VSCF_NODISCARD;

// Legacy (CORRECT):
VSCF_PUBLIC vscf_status_t
vscf_ctr_drbg_use_entropy_source(vscf_ctr_drbg_t *self, vscf_impl_t *entropy_source) VSCF_NODISCARD;
```

**Root cause hypothesis:** The dependency use/take method renderer emits the raw type name `status` without the project prefix (`vscf_`) and `_t` suffix.

## Dependencies

None.

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Specific files to examine:**
- Generated vs legacy headers for affected files
- Type resolution code in `project_c_backend.py` — trace how interface method parameters map to implementation method declarations
- Dependency method rendering in `project_c_backend.py` — return type handling for `use_*`/`take_*`

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** cmake build system configured

## File Scope

- `tools/codegen/project_c_backend.py` (primary)
- `tools/codegen/project_ir.py` (if type resolution info missing from IR)

## Steps

### Step 0: Preflight

- [ ] List all affected declarations (bare `void` + bare `status`)
- [ ] Trace the type resolution for a `sign_hash` alg_id parameter: XML model → IR → C backend → output
- [ ] Trace the return type for `use_entropy_source`: XML model → IR → C backend → output
- [ ] Identify the exact code path that produces the wrong type in each case

### Step 1: Fix bare `void` parameter resolution

> ⚠️ Hydrate: Expand based on root causes identified in Step 0

- [ ] Fix enum parameter type resolution in interface method rendering
- [ ] Verify `sign_hash` and `verify_hash` declarations across all 6 affected implementations
- [ ] Check for similar issues in other interface methods with enum parameters

### Step 2: Fix bare `status` return type

- [ ] Fix dependency method return type to include project prefix and `_t` suffix
- [ ] Verify `use_*` and `take_*` methods across all implementations with dependencies

### Step 3: Verification

> ZERO test failures allowed.

- [ ] Run FULL Python test suite: `PYTHONPATH=. python3 -m unittest discover -s tools/codegen -p "test_*.py"`
- [ ] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Run foundation build: `bash tools/codegen/new_codegen.sh --verify foundation`
- [ ] Confirm 0 errors for bare `void` and bare `status`
- [ ] Fix any regressions

### Step 4: Documentation & Delivery

- [ ] Update `taskplane-tasks/codegen/CONTEXT.md`
- [ ] Discoveries logged in STATUS.md

## Documentation Requirements

**Must Update:**
- `taskplane-tasks/codegen/CONTEXT.md` — update foundation build error status

## Completion Criteria

- [ ] All steps complete
- [ ] All Python tests passing
- [ ] Common build gate passes
- [ ] 0 bare `void` parameter errors
- [ ] 0 bare `status` type errors
- [ ] Documentation updated

## Git Commit Convention

- **Step completion:** `feat(CG-059): complete Step N — description`
- **Bug fixes:** `fix(CG-059): description`
- **Hydration:** `hydrate: CG-059 expand Step N checkboxes`

## Do NOT

- Modify handwritten `.c` files in `library/foundation/src/`
- Commit generated `library/common/**` or `library/foundation/**` outputs
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
