# Task: CG-033 - Render Interface Modules (Dispatch + API)

**Created:** 2026-04-08
**Size:** M

## Review Level: 2 (Plan and Code)

**Assessment:** New rendering category in the shared C backend. Interface modules follow highly regular patterns — dispatch is vtable lookup + callback call, API module is callback typedefs + vtable struct. Must match GSL output.
**Score:** 4/8 — Blast radius: 2, Pattern novelty: 1, Security: 0, Reversibility: 1

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-033-render-interface-modules/
├── PROMPT.md   ← This file
├── STATUS.md   ← Execution state
├── .reviews/   ← Reviewer output
└── .DONE       ← Created when complete
```

## Mission

Implement rendering of both interface C modules — the public dispatch module and the private API module — in the shared C backend.

Each interface generates TWO modules:

**1. API module** (`vscf_hash_api.h/.c`, scope="private"):
- Callback typedefs (`c_callback`) — one per interface method (e.g., `vscf_hash_api_hash_fn`)
- API struct (`c_struct`) — the vtable holding: api_tag, impl_tag, one callback pointer per method, one constant field per interface constant, inherited API pointers

**2. Dispatch module** (`vscf_hash.h/.c`, scope="public"):
- Dispatch methods — each calls through the vtable: `api->method_cb(impl, args...)`
- Constant getters — return `api->constant_name`
- Utility methods: `_api()`, `_is_implemented()`, `_api_tag()`

### Key patterns (from resolved XML reference):

**Dispatch method body pattern (stateful, non-static):**
```c
const vscf_hash_api_t *hash_api = vscf_hash_api(impl);
VSCF_ASSERT_PTR(hash_api);
VSCF_ASSERT_PTR(hash_api->start_cb);
hash_api->start_cb(impl);
```

**Dispatch method body pattern (static):**
```c
VSCF_ASSERT_PTR(hash_api);
VSCF_ASSERT_PTR(hash_api->hash_cb);
hash_api->hash_cb(data, digest);
```

**Constant getter body pattern:**
```c
VSCF_ASSERT_PTR(hash_api);
return hash_api->digest_len;
```

**`_api()` body:**
```c
VSCF_ASSERT_PTR(impl);
const vscf_api_t *api = vscf_impl_api(impl, vscf_api_tag_HASH);
return (const vscf_hash_api_t *) api;
```

**`_is_implemented()` body:**
```c
VSCF_ASSERT_PTR(impl);
return vscf_impl_api(impl, vscf_api_tag_HASH) != NULL;
```

## Dependencies

- **Task:** CG-031 (interfaces must be in IR)

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3 (load only if needed):**
- `codegen/generated/foundation/c_module_vscf_hash.xml` — resolved dispatch module reference
- `codegen/generated/foundation/c_module_vscf_hash_api.xml` — resolved API module reference
- `codegen/generated/foundation/c_module_vscf_cipher.xml` — dispatch with inheritance
- `codegen/c_module_interface.gsl` lines 100-200 (API), 205-506 (dispatch) — GSL reference

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** None

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/test_interface_rendering.py` (new)

## Steps

### Step 0: Preflight

- [ ] CG-031 complete: `IRInterface` available with methods, constants, inherits
- [ ] Read resolved XML for `vscf_hash_api` and `vscf_hash` — note exact element names, attributes, ordering
- [ ] Identify naming conventions: callback names (`{prefix}_{iface}_api_{method}_fn`), struct name (`{prefix}_{iface}_api_t`), dispatch method names (`{prefix}_{iface}_{method}`)

### Step 1: Add interface helper utilities

Add small helpers to `project_c_backend.py` for interface rendering. Commit immediately.

- [ ] Add `interface_ir()` lookup function (like `class_ir()`, `enum_ir()`)
- [ ] Extend `entity_output()` to handle `entity_kind="interface"`
- [ ] Add `interface_api_output()` helper — compute the `_api` module output target (derive from interface output with `_api` suffix)
- [ ] Commit: `feat(CG-033): add interface IR helpers`

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 2: Implement render_interface_api_c_module()

The API module is simpler — no method bodies, just typedefs and a struct. Implement and commit.

Generate:
- Root c_module element with `scope="private"`, correct includes (library, api, impl)
- `c_callback` elements — one per interface method with correct naming
- `c_struct` element with: api_tag field, impl_tag field, one callback pointer field per method, one constant field per interface constant
- For interfaces with inheritance: add inherited API struct pointer fields

- [ ] Implement `render_interface_api_c_module()`
- [ ] Generate callback typedefs
- [ ] Generate API struct with fields
- [ ] Handle inherited API references
- [ ] Commit: `feat(CG-033): implement render_interface_api_c_module`

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 3: Implement render_interface_c_module()

The dispatch module has method bodies. Implement and commit.

Generate:
- Root c_module with `scope="public"`, includes (library, assert, impl, own API header)
- API struct forward declaration
- Dispatch methods — for each interface method (including flattened inherited methods):
  - Stateful (non-static): first arg is impl, body does vtable lookup + assert + callback call
  - Static: first arg is api_t pointer, body does assert + callback call
- Constant getter methods — body returns `api->constant_name`
- Utility methods: `_api()`, `_is_implemented()`, `_api_tag()`

- [ ] Implement `render_interface_c_module()` scaffold (root, includes, struct decl)
- [ ] Implement dispatch method generation with bodies
- [ ] Implement constant getter generation
- [ ] Implement _api(), _is_implemented(), _api_tag() utility methods
- [ ] Handle inherited interface method/constant flattening
- [ ] Commit: `feat(CG-033): implement render_interface_c_module`

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 4: Add parity tests

Create `test_interface_rendering.py`:

- [ ] Test: `vscf_hash_api` has 4 callbacks (hash, start, update, finish)
- [ ] Test: `vscf_hash_api` struct has api_tag, impl_tag, 4 callback fields, 2 constant fields
- [ ] Test: `vscf_hash` dispatch module has 9 methods (4 interface + 2 constants + api + is_implemented + api_tag)
- [ ] Test: `vscf_hash` dispatch methods have `c_code` elements with vtable call bodies
- [ ] Test: `vscf_cipher` dispatch module includes inherited methods from encrypt/decrypt/cipher_info
- [ ] Test: `vscf_hash` and `vscf_hash_api` includes are correct

**Artifacts:**
- `tools/codegen/test_interface_rendering.py` (new)

### Step 5: Testing & Verification

> ZERO test failures allowed.

- [ ] Run: `python3 -m pytest tools/codegen/test_interface_rendering.py -v`
- [ ] Run existing tests: `python3 -m pytest tools/codegen/ -v`
- [ ] Build passes: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Fix all failures

### Step 6: Documentation & Delivery

- [ ] Discoveries logged in STATUS.md
- [ ] Update CONTEXT.md if needed

## Documentation Requirements

**Must Update:**
- (none)

**Check If Affected:**
- `taskplane-tasks/codegen/CONTEXT.md`

## Completion Criteria

- [ ] `render_interface_api_c_module()` produces correct API module XML
- [ ] `render_interface_c_module()` produces correct dispatch module XML
- [ ] Callback typedefs match resolved XML
- [ ] API struct matches resolved XML
- [ ] Dispatch method bodies contain vtable lookup + callback calls
- [ ] Inherited interface methods are flattened in dispatch module
- [ ] All tests passing, build gate passes

## Git Commit Convention

- **Step completion:** `feat(CG-033): complete Step N — description`
- **Tests:** `test(CG-033): description`
- **Hydration:** `hydrate: CG-033 expand Step N checkboxes`

**CRITICAL: Commit after EACH step. Do NOT try to implement multiple steps before committing. Partial progress must survive context resets.**

## Do NOT

- Expand task scope
- Skip tests
- Implement Steps 2 and 3 in the same pass without committing between them
- Render implementation modules — that is CG-035/CG-036
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
