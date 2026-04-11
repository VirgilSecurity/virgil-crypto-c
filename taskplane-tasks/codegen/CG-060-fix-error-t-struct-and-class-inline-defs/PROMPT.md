# Task: CG-060 - Fix `vscf_error_t` Struct Definition and Class Inline Definitions

**Created:** 2026-04-11
**Size:** M

## Review Level: 1 (Plan Only)

**Assessment:** The generated `vscf_error.h` is missing the inline struct definition for `vscf_error_t`, causing "incomplete type" errors when handwritten code uses `vscf_error_t` by value. Also, the generated header adds lifecycle methods (init/cleanup/new/delete) that don't exist in legacy for this class. Related pattern: some class headers may be missing inline enum constants or struct definitions that legacy headers provide.
**Score:** 2/8 — Blast radius: 1, Pattern novelty: 1, Security: 0, Reversibility: 0

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-060-fix-error-t-struct-and-class-inline-defs/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Fix two related issues with class/struct definitions in generated headers:

### Issue 1: Missing `vscf_error_t` struct definition

The legacy `vscf_error.h` includes the struct definition inline in the public header:

```c
// Legacy (CORRECT):
typedef struct vscf_error_t vscf_error_t;
struct vscf_error_t {
    vscf_status_t status;
};
```

The generated header only has the forward declaration:

```c
// Generated (WRONG):
typedef struct vscf_error_t vscf_error_t;
```

This causes 13+ "incomplete type" errors in `vscf_compound_key_alg.c` which uses `vscf_error_t` by value.

**Root cause hypothesis:** `vscf_error` is a special "lightweight" class where the struct is defined in the public header instead of in a private `_defs.h`. The codegen treats all classes uniformly and puts struct definitions in `_defs.h`, but some classes need their struct in the public header.

### Issue 2: Missing inline enum constants

The legacy `vscf_ctr_drbg.h` includes enum constants:

```c
enum {
    vscf_ctr_drbg_RESEED_INTERVAL = 10000,
    vscf_ctr_drbg_ENTROPY_LEN = 48
};
```

The generated header omits these. These are class-level constants defined in the XML model.

### Issue 3: Spurious lifecycle methods on non-lifecycle classes

The generated `vscf_error.h` adds `init`, `cleanup`, `new`, `delete` methods that don't exist in the legacy header. `vscf_error` is a plain struct, not a lifecycle-managed class. The codegen should not emit lifecycle methods for classes that don't have them in the model.

## Dependencies

None.

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Specific files to examine:**
- `library/foundation/include/virgil/crypto/foundation/vscf_error.h` (legacy)
- `build/new-codegen/library/foundation/include/virgil/crypto/foundation/vscf_error.h` (generated)
- `library/foundation/include/virgil/crypto/foundation/vscf_ctr_drbg.h` (legacy — enum constants)
- XML models for `vscf_error` and `vscf_ctr_drbg`
- Class rendering code in `project_c_backend.py`

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** cmake build system configured

## File Scope

- `tools/codegen/project_c_backend.py` (class rendering)
- `tools/codegen/project_ir.py` (class properties, constants)
- `tools/codegen/project_source.py` (class model loading)

## Steps

### Step 0: Preflight

- [ ] Diff `vscf_error.h` legacy vs generated — enumerate all differences
- [ ] Check the XML model for `vscf_error` — identify what marks it as a lightweight/inline struct class
- [ ] Check how `vscf_ctr_drbg` constants are defined in the XML model
- [ ] Scan for other classes with inline struct definitions or constants in the legacy headers
- [ ] Identify what controls whether lifecycle methods are emitted

### Step 1: Fix inline struct definition

> ⚠️ Hydrate: Expand based on root causes identified in Step 0

- [ ] Add support for classes that expose their struct in the public header (not `_defs.h`)
- [ ] Detect the model attribute that indicates inline struct (e.g., `context="none"` or similar)
- [ ] Suppress lifecycle method generation for non-lifecycle classes
- [ ] Verify `vscf_error.h` matches legacy

### Step 2: Fix inline enum constants

- [ ] Add support for class-level enum constants in the header renderer
- [ ] Parse constants from XML model / IR
- [ ] Verify `vscf_ctr_drbg.h` enum constants match legacy

### Step 3: Verification

> ZERO test failures allowed.

- [ ] Run FULL Python test suite: `PYTHONPATH=. python3 -m unittest discover -s tools/codegen -p "test_*.py"`
- [ ] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Run foundation build: `bash tools/codegen/new_codegen.sh --verify foundation`
- [ ] Confirm 0 "incomplete type" errors for `vscf_error_t`
- [ ] Confirm enum constants present in headers
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
- [ ] `vscf_error_t` struct in public header, no spurious lifecycle methods
- [ ] Class-level constants generated
- [ ] Documentation updated

## Git Commit Convention

- **Step completion:** `feat(CG-060): complete Step N — description`
- **Bug fixes:** `fix(CG-060): description`
- **Hydration:** `hydrate: CG-060 expand Step N checkboxes`

## Do NOT

- Modify handwritten `.c` files in `library/foundation/src/`
- Commit generated `library/common/**` or `library/foundation/**` outputs
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
