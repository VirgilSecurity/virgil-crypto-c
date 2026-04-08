# Task: CG-028 - Generate Lifecycle Method Bodies from Class IR

**Created:** 2026-04-08
**Size:** M

## Review Level: 2 (Plan and Code)

**Assessment:** Core code generation logic affecting all classes across all projects. Modifies the shared C backend's class rendering — the function bodies must exactly match legacy GSL output or the compiled C libraries will break. Pattern is adapted from GSL templates but expressed in Python for the first time.
**Score:** 4/8 — Blast radius: 2, Pattern novelty: 1, Security: 0, Reversibility: 1

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-028-lifecycle-method-body-generation/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Replace the signature-only lifecycle method rendering in `_render_reference_class_support()` with parametric body generation that derives method implementations from class IR metadata. This eliminates the need for `.cfrag` files by generating the same method bodies that the legacy GSL templates produced — but driven by the Python IR rather than GSL's resolved XML.

The six core lifecycle methods to generate bodies for:
- **init** — zeroize struct, set refcnt=1, call init_ctx
- **cleanup** — null check, call cleanup_ctx, release each dependency, zeroize struct
- **new** — alloc, call init, set self_dealloc_cb, return
- **delete** — null check, refcount decrement (with atomic CAS path), call cleanup, call self_dealloc_cb
- **destroy** — assert ptr, null out reference, call delete
- **shallow_copy** — assert ptr, refcount increment (with atomic CAS path), return self

Plus constructor variants:
- **init_with_X** — zeroize struct, set refcnt=1, call init_ctx_with_X(self, args...)
- **new_with_X** — alloc, call init_with_X(self, args...), set self_dealloc_cb, return

The reference implementations are in `codegen/c_module_class.gsl` (functions `_X13_add_method_init`, `_X13_add_method_cleanup`, `_X13_add_method_new`, `_X13_add_method_delete`, `_X13_add_method_destroy`, `_X13_add_method_shallow_copy`).

## Dependencies

- **Task:** CG-027 (class dependencies must be in IR for cleanup body generation)

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3 (load only if needed):**
- `docs/adr/0004-universal-model-driven-codegen.md` — motivation
- `codegen/c_module_class.gsl` lines 204-750 — legacy GSL lifecycle method generation (the specification)
- `tools/codegen/support/common_runtime/buffer/*.cfrag` — current static method bodies (verification reference)
- `codegen/generated/common/c_module_vsc_buffer.xml` — resolved XML reference for buffer lifecycle
- `codegen/generated/foundation/c_module_vscf_ecies.xml` — resolved XML reference for a class with dependencies

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** None

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/test_auto_discovery.py`

## Steps

### Step 0: Preflight

- [ ] CG-027 is complete: `IRClass` has `dependencies` field
- [ ] Current `_render_reference_class_support()` understood
- [ ] GSL lifecycle generation functions studied (lines 204-750 of `c_module_class.gsl`)
- [ ] Existing cfrag files read and understood as verification targets

### Step 1: Implement lifecycle body generation helpers

Create helper functions in `project_c_backend.py` that generate C code strings for each lifecycle method body. These functions take class IR metadata (struct type, prefix, method symbols, dependency list) and return the C code string.

Key naming helpers needed:
- Class struct type symbol (e.g., `vsc_buffer_t`)
- Class method symbols (e.g., `vsc_buffer_init`, `vsc_buffer_cleanup`)
- Class assert macros (e.g., `VSC_ASSERT_PTR`, `VSC_ASSERT_ALLOC`, `VSC_ASSERT`)
- Class atomic macros (e.g., `VSC_ATOMIC_COMPARE_EXCHANGE_WEAK`)
- Global method symbols (e.g., `vsc_alloc`, `vsc_dealloc`, `vsc_zeroize`)
- Dealloc callback type (e.g., `vsc_dealloc_fn`)
- Dependency release method symbols (e.g., `vscf_ecies_release_random`)

Functions to create:
- `_lifecycle_init_body(...)` → init body code
- `_lifecycle_cleanup_body(...)` → cleanup body code (iterates dependencies)
- `_lifecycle_new_body(...)` → new body code
- `_lifecycle_delete_body(...)` → delete body code (refcount + CAS)
- `_lifecycle_destroy_body(...)` → destroy body code
- `_lifecycle_shallow_copy_body(...)` → shallow_copy body code (refcount + CAS)
- `_lifecycle_constructor_init_body(...)` → init_with_X body code
- `_lifecycle_constructor_new_body(...)` → new_with_X body code

- [ ] Implement body generation helpers
- [ ] Each helper produces a C code string matching the GSL template output
- [ ] Run targeted test: generate buffer lifecycle bodies and compare to cfrag content

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 2: Integrate body generation into _render_reference_class_support

Modify `_render_reference_class_support()` to call the body generation helpers and pass the code to `_render_ir_method()` via the `code` parameter. This replaces the current signature-only rendering.

The current function renders lifecycle methods without `code=` parameter. After this change, each lifecycle method call to `_render_ir_method()` will include `code=_lifecycle_X_body(...)`.

- [ ] Modify init/cleanup/new/delete/destroy/shallow_copy rendering to include generated bodies
- [ ] Modify constructor variant rendering (init_with_X, new_with_X) to include generated bodies
- [ ] Verify: generated XML for buffer class matches existing cfrag-based output
- [ ] Verify: generated XML for a foundation class (e.g., ecies) has correct lifecycle bodies

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 3: Testing & Verification

> ZERO test failures allowed.

- [ ] Run FULL test suite: `python3 -m py_compile tools/codegen/project_source.py tools/codegen/project_ir.py tools/codegen/project_c_backend.py tools/codegen/common_bootstrap.py`
- [ ] Build passes: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Verify buffer lifecycle methods in generated XML match cfrag content exactly
- [ ] Fix all failures

### Step 4: Documentation & Delivery

- [ ] Discoveries logged in STATUS.md
- [ ] Update CONTEXT.md if needed

## Documentation Requirements

**Must Update:**
- (none — internal codegen changes)

**Check If Affected:**
- `taskplane-tasks/codegen/CONTEXT.md` — update if key files change

## Completion Criteria

- [ ] All 6 core lifecycle methods generate correct bodies from IR
- [ ] Constructor variants (init_with_X, new_with_X) generate correct bodies
- [ ] Buffer lifecycle output matches existing cfrag reference
- [ ] Cleanup body correctly iterates dependencies for classes that have them
- [ ] Delete/shallow_copy include atomic CAS paths
- [ ] Build gate passes with generated lifecycle bodies

## Git Commit Convention

- **Step completion:** `feat(CG-028): complete Step N — description`
- **Tests:** `test(CG-028): description`
- **Hydration:** `hydrate: CG-028 expand Step N checkboxes`

## Do NOT

- Expand task scope — add tech debt to CONTEXT.md instead
- Skip tests
- Modify framework/standards docs without explicit user approval
- Load docs not listed in "Context to Read First"
- Commit without the task ID prefix in the commit message
- Remove cfrag files — that is for CG-030
- Add dependency management methods (use/take/release) — that is CG-029
- Modify `project_source.py` or `project_ir.py` — those were handled by CG-027

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
