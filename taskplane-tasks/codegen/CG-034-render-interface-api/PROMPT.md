# Task: CG-034 - Render Interface API Module (Vtable Struct and Callbacks)

**Created:** 2026-04-08
**Size:** M

## Review Level: 2 (Plan and Code)

**Assessment:** New rendering category — the API module defines the vtable struct and callback typedefs that the dispatch module calls through and implementations populate. Must match GSL output precisely for ABI compatibility.
**Score:** 4/8 — Blast radius: 2, Pattern novelty: 1, Security: 0, Reversibility: 1

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-034-render-interface-api/
├── PROMPT.md   ← This file
├── STATUS.md   ← Execution state
├── .reviews/   ← Reviewer output
└── .DONE       ← Created when complete
```

## Mission

Implement rendering of interface API modules (e.g., `vscf_hash_api.h/.c`) in the shared C backend. Each interface generates a private-scope API module containing:

1. **Callback typedefs** (`c_callback`) — function pointer types for each interface method (e.g., `vscf_hash_api_hash_fn`, `vscf_hash_api_start_fn`)
2. **API struct definition** (`c_struct`) — the vtable struct (`vscf_hash_api_t`) holding the callback pointers, with the base `vscf_api_t` as the first field
3. Correct includes (library, api base, impl)

The API module is scope="private" — it's included by the dispatch module and by implementation internal modules that populate the vtable.

The reference implementation is in `codegen/c_module_interface.gsl`, function `c_module_interface_create_module_api` (line 507) and helpers `_L23_add_interface_api_type`, `_L23_add_interface_api_callbacks`.

The resolved XML reference is `codegen/generated/foundation/c_module_vscf_hash_api.xml`.

## Dependencies

- **Task:** CG-031 (interfaces must be in IR)

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3 (load only if needed):**
- `codegen/c_module_interface.gsl` lines 100-200, 507-550 — GSL API module generation
- `codegen/generated/foundation/c_module_vscf_hash_api.xml` — resolved XML reference

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** None

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/test_interface_rendering.py` (modified — extend from CG-033)

## Steps

### Step 0: Preflight

- [ ] CG-031 complete: `IRInterface` available
- [ ] Study resolved XML for `vscf_hash_api` — understand callback and struct patterns
- [ ] Study GSL `c_module_interface_create_module_api` (line 507)
- [ ] Study GSL `_L23_add_interface_api_type` and `_L23_add_interface_api_callbacks`

### Step 1: Implement render_interface_api_c_module()

Create a `render_interface_api_c_module()` function in `project_c_backend.py`.

Key elements to generate:
- Module with `scope="private"` 
- Correct includes (library, api base, impl)
- `c_callback` elements for each interface method — one typedef per method with correct signature
- `c_struct` element for the API struct — the vtable definition with:
  - Base API field (inherits from `vscf_api_t`)
  - One function pointer field per callback
  - Fields for inherited interface APIs (if the interface inherits others)
  - Constant fields for interface constants

For inherited interfaces: the API struct includes pointers to inherited API structs.

- [ ] Implement `render_interface_api_c_module()`
- [ ] Generate callback typedefs for each method
- [ ] Generate API struct with callback fields and inherited API fields
- [ ] Generate constant fields in the API struct
- [ ] Handle inherited interface API inclusion

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 2: Add parity tests

Extend `test_interface_rendering.py` (created in CG-033) with API module tests:

- [ ] Test: `vscf_hash_api` module has correct scope="private"
- [ ] Test: `vscf_hash_api` has correct callback count (one per method: hash, start, update, finish)
- [ ] Test: `vscf_hash_api` callback names match convention (`vscf_hash_api_hash_fn`, etc.)
- [ ] Test: `vscf_hash_api` struct has correct name (`vscf_hash_api_t`)
- [ ] Test: `vscf_cipher_api` struct includes inherited API fields
- [ ] Test: API struct includes constant fields (digest_len, block_len for hash)

**Artifacts:**
- `tools/codegen/test_interface_rendering.py` (modified)

### Step 3: Testing & Verification

> ZERO test failures allowed.

- [ ] Run: `python3 -m pytest tools/codegen/test_interface_rendering.py -v`
- [ ] Run existing tests: `python3 -m pytest tools/codegen/ -v`
- [ ] Build passes: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Fix all failures

### Step 4: Documentation & Delivery

- [ ] Discoveries logged in STATUS.md
- [ ] Update CONTEXT.md if needed

## Documentation Requirements

**Must Update:**
- (none)

**Check If Affected:**
- `taskplane-tasks/codegen/CONTEXT.md`

## Completion Criteria

- [ ] `render_interface_api_c_module()` produces correct XML for API modules
- [ ] Callback typedefs match resolved XML reference
- [ ] API struct matches resolved XML (fields, types, ordering)
- [ ] Inherited interface API fields present for interfaces with inheritance
- [ ] All tests passing, build gate passes

## Git Commit Convention

- **Step completion:** `feat(CG-034): complete Step N — description`
- **Tests:** `test(CG-034): description`
- **Hydration:** `hydrate: CG-034 expand Step N checkboxes`

## Do NOT

- Expand task scope
- Skip tests
- Render implementation modules — that is CG-035/CG-036
- Modify the dispatch module renderer from CG-033
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
