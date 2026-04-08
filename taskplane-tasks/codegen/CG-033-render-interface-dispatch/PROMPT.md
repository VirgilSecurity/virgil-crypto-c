# Task: CG-033 - Render Interface Public Dispatch Module

**Created:** 2026-04-08
**Size:** M

## Review Level: 2 (Plan and Code)

**Assessment:** New rendering category in the shared C backend. Interface dispatch modules use a vtable-based dispatch pattern not yet implemented in the Python pipeline. Must match GSL output.
**Score:** 4/8 — Blast radius: 2, Pattern novelty: 1, Security: 0, Reversibility: 1

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-033-render-interface-dispatch/
├── PROMPT.md   ← This file
├── STATUS.md   ← Execution state
├── .reviews/   ← Reviewer output
└── .DONE       ← Created when complete
```

## Mission

Implement rendering of interface public dispatch modules (e.g., `vscf_hash.h/.c`) in the shared C backend. Each interface in the project generates a public module containing:

1. **Dispatch methods** — for each interface method, a public function that takes `vscf_impl_t *` as first argument, looks up the API vtable, and calls through the function pointer. These methods have `definition="private"` (meaning generated body, not stub).
2. **Constant getter methods** — for each interface constant, a public getter that retrieves the value from the API vtable.
3. **API accessor method** — `vscf_hash_api()` that returns the API struct from an impl.
4. **Is-implemented check** — `vscf_hash_is_implemented()` that checks if an impl supports this interface.
5. **API tag method** — `vscf_hash_api_tag()` that returns the interface's API tag enum value.

The reference implementation is in `codegen/c_module_interface.gsl`, functions `c_module_interface_create_module_public` (line 448) and helpers `_L23_add_stateful_methods`, `_L23_add_stateless_methods`, `_L23_add_stateless_getters`.

The resolved XML reference is `codegen/generated/foundation/c_module_vscf_hash.xml`.

## Dependencies

- **Task:** CG-031 (interfaces must be in IR)

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3 (load only if needed):**
- `codegen/c_module_interface.gsl` lines 205-506 — GSL interface public module generation
- `codegen/generated/foundation/c_module_vscf_hash.xml` — resolved XML reference (simple interface)
- `codegen/generated/foundation/c_module_vscf_cipher.xml` — resolved XML reference (inherited interface)

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** None

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/test_interface_rendering.py` (new)

## Steps

### Step 0: Preflight

- [ ] CG-031 complete: `IRInterface` available with methods, constants, inherits
- [ ] Study resolved XML for `vscf_hash` — understand struct, method, and include patterns
- [ ] Study resolved XML for `vscf_cipher` — understand how inheritance affects the dispatch module
- [ ] Study GSL `c_module_interface_create_module_public` (line 448)

### Step 1: Implement render_interface_c_module()

Create a `render_interface_c_module()` function in `project_c_backend.py` that produces the public dispatch module XML.

Key elements to generate:
- Correct includes (library, assert, impl, the interface's own api header)
- The API struct declaration (forward reference, definition is in the API module)
- Dispatch methods for each interface method (including inherited methods)
- Constant getter methods for each interface constant
- `_api()` method — returns the interface API from an impl
- `_is_implemented()` method — checks if impl supports this interface
- `_api_tag()` method — returns the API tag

For inherited interfaces: the dispatch module includes methods from all inherited interfaces, flattened.

- [ ] Implement `render_interface_c_module()` 
- [ ] Handle inherited interface method/constant flattening
- [ ] Generate correct dispatch method bodies (vtable lookup + call)
- [ ] Generate constant getter bodies
- [ ] Generate api/is_implemented/api_tag methods

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 2: Add parity tests against resolved XML

Create `test_interface_rendering.py` with tests that compare generated XML output against the legacy resolved XML reference.

- [ ] Test: `vscf_hash` dispatch module has correct method count and names
- [ ] Test: `vscf_hash` methods have correct visibility/declaration/definition attributes
- [ ] Test: `vscf_hash` includes are correct (library, assert, impl, hash_api)
- [ ] Test: `vscf_cipher` dispatch module includes inherited methods from encrypt/decrypt/cipher_info
- [ ] Test: `vscf_hash` struct element matches resolved XML
- [ ] Test: method bodies contain vtable dispatch calls (spot-check c_code elements)

**Artifacts:**
- `tools/codegen/test_interface_rendering.py` (new)

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

- [ ] `render_interface_c_module()` produces correct XML for interface dispatch modules
- [ ] Inherited interface methods are flattened correctly
- [ ] Hash dispatch module matches resolved XML reference (method names, attributes, includes)
- [ ] Cipher dispatch module includes inherited methods
- [ ] All tests passing, build gate passes

## Git Commit Convention

- **Step completion:** `feat(CG-033): complete Step N — description`
- **Tests:** `test(CG-033): description`
- **Hydration:** `hydrate: CG-033 expand Step N checkboxes`

## Do NOT

- Expand task scope
- Skip tests
- Render the API module — that is CG-034
- Render implementation modules — that is CG-035/CG-036
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
