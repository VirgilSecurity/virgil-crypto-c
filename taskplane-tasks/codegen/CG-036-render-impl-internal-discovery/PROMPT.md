# Task: CG-036 - Render Implementation Internal Module and Extend Auto-Discovery

**Created:** 2026-04-08
**Size:** M

## Review Level: 2 (Plan and Code)

**Assessment:** The internal module contains the vtable initialization — the static API tables that wire function pointers to concrete implementations. Also extends auto-discovery to cover the new entity kinds. Touches both rendering and discovery code paths.
**Score:** 4/8 — Blast radius: 2, Pattern novelty: 1, Security: 0, Reversibility: 1

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-036-render-impl-internal-discovery/
├── PROMPT.md   ← This file
├── STATUS.md   ← Execution state
├── .reviews/   ← Reviewer output
└── .DONE       ← Created when complete
```

## Mission

Implement rendering of implementation internal modules (e.g., `vscf_sha256_internal.h/.c`) and extend the auto-discovery system (`discover_renderers`) to cover interfaces and implementations.

**Internal module** (`vscf_sha256_internal.h/.c`):
- Static API table variables — one per implemented interface, each populated with function pointers to the concrete implementations (e.g., `hash_api` variable with pointers to `vscf_sha256_hash`, `vscf_sha256_start`, etc.)
- The `impl_info` variable — describes the implementation (tag, api table list, lifecycle callbacks)
- Registration of the implementation's init/cleanup with the impl infrastructure
- Scope is "private"

This is the glue that connects the interface vtable dispatch to the concrete implementation functions.

The reference implementation is in `codegen/c_module_implementation.gsl` (the `_internal` module generation sections).

Resolved XML reference: `codegen/generated/foundation/c_module_vscf_sha256_internal.xml`.

## Dependencies

- **Task:** CG-033 (interface modules must exist — internal module references API types)
- **Task:** CG-035 (implementation main + defs modules must exist — internal module references implementation functions)

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3 (load only if needed):**
- `codegen/c_module_implementation.gsl` — legacy GSL internal module generation
- `codegen/generated/foundation/c_module_vscf_sha256_internal.xml` — resolved XML reference
- `codegen/generated/foundation/c_module_vscf_aes256_gcm_internal.xml` — more complex reference (multiple interfaces)

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** None

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/test_impl_rendering.py` (modified — extend from CG-035)
- `tools/codegen/test_auto_discovery.py` (modified — extend for interfaces/implementations)

## Steps

### Step 0: Preflight

- [ ] CG-033 and CG-035 complete
- [ ] Study resolved XML for `vscf_sha256_internal` — understand variable, method, and include patterns
- [ ] Study how API table variables are initialized (function pointer assignments)
- [ ] Study `impl_info` variable structure
- [ ] Study current `discover_renderers` implementation to plan extension

### Step 1: Implement render_implementation_internal_c_module()

Create the internal module renderer.

Key elements:
- Module with `scope="private"`
- Includes for: the implementation's own header, defs header, interface API headers, impl infrastructure headers
- Static API table variables — one `const {prefix}_{interface}_api_t` variable per implemented interface, initialized with:
  - Base API fields (api_tag, impl_tag)
  - Function pointers to the implementation's concrete methods
  - Constant values from interface bindings
  - Pointers to inherited API tables
- The `impl_info` variable with implementation metadata
- Lifecycle re-declarations (init/cleanup with definition="private" for internal wiring)

- [ ] Implement `render_implementation_internal_c_module()`
- [ ] Generate API table variables with function pointer initialization
- [ ] Generate impl_info variable
- [ ] Handle constant values from interface bindings
- [ ] Handle inherited API table references
- [ ] Generate correct includes

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 2: Extend auto-discovery for interfaces and implementations

Update `discover_renderers()` in `project_c_backend.py` to include:
- Interface public dispatch modules (from `IRInterface`)
- Interface API modules (from `IRInterface`)
- Implementation main modules (from `IRImplementation`)
- Implementation defs modules (from `IRImplementation`)
- Implementation internal modules (from `IRImplementation`)

Each interface produces 2 renderers; each implementation produces 3 renderers.

- [ ] Extend `discover_renderers()` to handle `entity_kinds={"interface"}` 
- [ ] Extend `discover_renderers()` to handle `entity_kinds={"implementation"}`
- [ ] Each interface maps to dispatch + api renderers
- [ ] Each implementation maps to main + defs + internal renderers
- [ ] Default discovery (no entity_kinds filter) includes all entity kinds

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 3: Add parity and discovery tests

Extend `test_impl_rendering.py` with internal module tests, and extend `test_auto_discovery.py` with interface/implementation discovery tests.

Internal module parity tests:
- [ ] Test: `vscf_sha256_internal` has api table variables (alg_api, hash_api)
- [ ] Test: `vscf_sha256_internal` has impl_info variable
- [ ] Test: `vscf_sha256_internal` includes match resolved XML
- [ ] Test: `vscf_sha256_internal` init/cleanup methods present
- [ ] Test: API table variable for hash has function pointer fields matching sha256's method names

Auto-discovery tests:
- [ ] Test: Foundation discover_renderers with entity_kinds={"interface"} returns 2× interface count
- [ ] Test: Foundation discover_renderers with entity_kinds={"implementation"} returns 3× implementation count
- [ ] Test: Full discovery includes modules + classes + enums + interfaces + implementations
- [ ] Test: Common project discovery is unchanged (no interfaces/implementations)

**Artifacts:**
- `tools/codegen/test_impl_rendering.py` (modified)
- `tools/codegen/test_auto_discovery.py` (modified)

### Step 4: Testing & Verification

> ZERO test failures allowed.

- [ ] Run: `python3 -m pytest tools/codegen/test_impl_rendering.py tools/codegen/test_auto_discovery.py -v`
- [ ] Run existing tests: `python3 -m pytest tools/codegen/ -v`
- [ ] Build passes: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Fix all failures

### Step 5: Documentation & Delivery

- [ ] Update CONTEXT.md: note interface and implementation rendering is complete
- [ ] Discoveries logged in STATUS.md

## Documentation Requirements

**Must Update:**
- `taskplane-tasks/codegen/CONTEXT.md` — update current state to reflect interface/implementation rendering capability

**Check If Affected:**
- `docs/codegen-migration/README.md` — update if it discusses entity kind support

## Completion Criteria

- [ ] `render_implementation_internal_c_module()` produces correct internal module XML
- [ ] API table variables correctly initialized with function pointers
- [ ] impl_info variable matches resolved XML
- [ ] `discover_renderers()` covers interfaces and implementations
- [ ] Foundation full discovery includes all 5 entity kinds
- [ ] Common discovery unchanged
- [ ] All tests passing, build gate passes

## Git Commit Convention

- **Step completion:** `feat(CG-036): complete Step N — description`
- **Tests:** `test(CG-036): description`
- **Hydration:** `hydrate: CG-036 expand Step N checkboxes`

## Do NOT

- Expand task scope
- Skip tests
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
