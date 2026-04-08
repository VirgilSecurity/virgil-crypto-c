# Task: CG-035 - Render Implementation Main Module and Defs Module

**Created:** 2026-04-08
**Size:** M

## Review Level: 2 (Plan and Code)

**Assessment:** Implementation modules are the most complex entity type — they combine class-like lifecycle methods with interface method implementations and implementation-specific struct definitions. Touches the shared C backend significantly.
**Score:** 5/8 — Blast radius: 2, Pattern novelty: 2, Security: 0, Reversibility: 1

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-035-render-impl-main-defs/
├── PROMPT.md   ← This file
├── STATUS.md   ← Execution state
├── .reviews/   ← Reviewer output
└── .DONE       ← Created when complete
```

## Mission

Implement rendering of implementation main modules (e.g., `vscf_sha256.h/.c`) and defs modules (e.g., `vscf_sha256_defs.h`) in the shared C backend.

An implementation generates two (of three) modules in this task:

**Main module** (`vscf_sha256.h/.c`):
- Lifecycle methods (init, cleanup, new, delete, destroy, shallow_copy) — reuse existing lifecycle body generation from CG-028
- `impl_size()` / `impl()` / `impl_const()` — cast helpers between the public `vscf_impl_t` and the internal impl struct
- Concrete implementations of interface methods (stub bodies — these are filled in by hand)
- Implementation-specific methods
- Feature-gated enum constant for the impl tag

**Defs module** (`vscf_sha256_defs.h`):
- The implementation struct definition — includes `vscf_impl_t` base, properties from the model, and interface-specific properties
- External library includes (e.g., `mbedtls/sha256.h`)

The reference implementations are in `codegen/c_module_implementation.gsl` and `codegen/c_module_impl.gsl`.

Resolved XML references: `codegen/generated/foundation/c_module_vscf_sha256.xml`, `codegen/generated/foundation/c_module_vscf_sha256_defs.xml`.

## Dependencies

- **Task:** CG-032 (implementations must be in IR)
- **Task:** CG-033 (interface dispatch module must exist — implementations reference interface types)

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3 (load only if needed):**
- `codegen/c_module_implementation.gsl` — legacy GSL implementation module generation (1407 lines, the specification)
- `codegen/c_module_impl.gsl` — legacy GSL impl base module
- `codegen/generated/foundation/c_module_vscf_sha256.xml` — resolved XML reference
- `codegen/generated/foundation/c_module_vscf_sha256_defs.xml` — resolved XML reference

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** None

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/test_impl_rendering.py` (new)

## Steps

### Step 0: Preflight

- [ ] CG-032 and CG-033 complete
- [ ] Study resolved XML for `vscf_sha256` — understand method list, includes, struct
- [ ] Study resolved XML for `vscf_sha256_defs` — understand struct definition
- [ ] Study GSL `c_module_implementation.gsl` for main module generation pattern
- [ ] Understand how lifecycle methods (from CG-028) apply to implementations

### Step 1: Implement render_implementation_defs_c_module()

The defs module defines the implementation struct.

Key elements:
- Module with `scope="private"` or as configured
- Struct definition with:
  - `vscf_impl_t` base field (the impl infrastructure)
  - Properties from the implementation model (including external library types)
  - Correct field ordering
- External library includes for properties that reference library types
- Include for the impl private header

- [ ] Implement `render_implementation_defs_c_module()`
- [ ] Generate struct with impl_t base + properties
- [ ] Handle external library type includes
- [ ] Handle property types (primitive, class, library, array)

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 2: Implement render_implementation_c_module()

The main module has lifecycle methods, interface method implementations, and impl helpers.

Key elements:
- Lifecycle methods (init, cleanup, new, delete, destroy, shallow_copy) — adapt existing `_render_reference_class_support()` or reuse lifecycle body generators from CG-028
- `impl_size()`, `impl()`, `impl_const()` cast methods
- Interface method implementations — concrete function stubs for each method from all bound interfaces
- Implementation-specific methods from the model
- Impl tag enum constant
- Correct includes (library, assert, memory, defs header, internal header, interface headers)

- [ ] Implement `render_implementation_c_module()`
- [ ] Generate lifecycle methods with bodies (reuse CG-028 generators)
- [ ] Generate impl_size/impl/impl_const cast helpers
- [ ] Generate interface method stubs
- [ ] Generate implementation-specific methods
- [ ] Generate correct includes

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 3: Add parity tests

Create `test_impl_rendering.py`:

- [ ] Test: `vscf_sha256` main module has lifecycle methods (init, cleanup, new, delete, destroy, shallow_copy)
- [ ] Test: `vscf_sha256` has interface method implementations (hash, start, update, finish from hash interface; alg_id, produce_alg_info, restore_alg_info from alg interface)
- [ ] Test: `vscf_sha256` has impl_size, impl, impl_const methods
- [ ] Test: `vscf_sha256` includes match resolved XML reference
- [ ] Test: `vscf_sha256_defs` struct has impl_t base field + hash_ctx property
- [ ] Test: `vscf_sha256_defs` has correct library include for mbedtls
- [ ] Test: `vscf_aes256_gcm` defs struct has multiple properties (cipher_ctx, key, nonce, etc.)

**Artifacts:**
- `tools/codegen/test_impl_rendering.py` (new)

### Step 4: Testing & Verification

> ZERO test failures allowed.

- [ ] Run: `python3 -m pytest tools/codegen/test_impl_rendering.py -v`
- [ ] Run existing tests: `python3 -m pytest tools/codegen/ -v`
- [ ] Build passes: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Fix all failures

### Step 5: Documentation & Delivery

- [ ] Discoveries logged in STATUS.md
- [ ] Update CONTEXT.md if needed

## Documentation Requirements

**Must Update:**
- (none)

**Check If Affected:**
- `taskplane-tasks/codegen/CONTEXT.md`

## Completion Criteria

- [ ] `render_implementation_defs_c_module()` produces correct defs XML
- [ ] `render_implementation_c_module()` produces correct main module XML
- [ ] Lifecycle methods reuse CG-028 body generators
- [ ] Interface method stubs present for all bound interfaces
- [ ] Struct definitions match resolved XML reference
- [ ] All tests passing, build gate passes

## Git Commit Convention

- **Step completion:** `feat(CG-035): complete Step N — description`
- **Tests:** `test(CG-035): description`
- **Hydration:** `hydrate: CG-035 expand Step N checkboxes`

## Do NOT

- Expand task scope
- Skip tests
- Render the internal module (vtable init) — that is CG-036
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
