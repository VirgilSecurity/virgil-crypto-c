# Task: CG-037 - Fix Cross-Project and External Type Resolution

**Created:** 2026-04-08
**Size:** M

## Review Level: 2 (Plan and Code)

**Assessment:** Fixes three distinct type resolution bugs in the shared C backend that cause foundation codegen to fail on 10 modules. Touches argument/return rendering and module include generation — core rendering paths.
**Score:** 4/8 — Blast radius: 2, Pattern novelty: 1, Security: 0, Reversibility: 1

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-037-fix-cross-project-type-resolution/
├── PROMPT.md   ← This file
├── STATUS.md   ← Execution state
├── .reviews/   ← Reviewer output
└── .DONE       ← Created when complete
```

## Mission

Fix three type resolution bugs that cause `bash tools/codegen/new_codegen.sh foundation` to skip 10 modules. After this task, foundation codegen should generate all modules with zero skips.

### Bug 1: External library types not handled (`mbedtls_ecp_group`, `mbedtls_mpi`)

**Affected modules:** `brainkey_client`, `brainkey_server`, `mbedtls_bignum_asn1_reader`, `mbedtls_bignum_asn1_writer`, `mbedtls_ecp`, `simple_swu`

**Root cause:** `argument_from_source()` and `return_from_source()` in `project_c_backend.py` call `class_type_symbol()` for every `class="..."` attribute, which does an IR lookup. But external library types like `mbedtls_ecp_group` (with `library="mbedtls"`) are not project classes — they're raw C types from external libraries.

**How the models express this:**
```xml
<argument name="ecc grp" class="mbedtls_ecp_group" library="mbedtls" access="readwrite"/>
<property name="group" class="mbedtls_ecp_group" library="mbedtls" is_reference="0"/>
```

The `library` attribute signals that this is an external type. The type name should be used as-is (e.g., `mbedtls_ecp_group`) without IR lookup.

**Fix:** In `argument_from_source()` and `return_from_source()`, check if the source dict has a `library` attribute. If it does, use the class name directly as the C type without calling `class_type_symbol()`. The implementation defs renderer already handles this correctly (line ~2501: `if prop.library: # External library type — use as-is`).

### Bug 2: `const` qualifier leaking into class name lookup

**Affected module:** `message_cipher`

**Root cause:** The model has:
```xml
<argument name="key" class="const vscf_group_session_symmetric_key_t" library="internal" is_reference="0"/>
```

The `class` attribute contains `const vscf_group_session_symmetric_key_t` — the `const` qualifier is baked into the class name. When `argument_from_source()` passes this to `class_type_symbol()`, it fails because no class named `const vscf_group_session_symmetric_key_t` exists.

**Fix:** Strip `const ` prefix from class names before lookup. Also note this has `library="internal"` which should be treated similarly to other library types — use the type name as-is.

### Bug 3: Module renderer treats all requires as module includes

**Affected modules:** `mbedtls_bridge_entropy`, `mbedtls_bridge_entropy_poll`, `mbedtls_bridge_random`

**Root cause:** In `render_module_c_module()` (line ~1305), the renderer iterates `module.requires` and calls `include_file_for_entity(entity_kind="module")` for each one. But module requires can also be `<require class="impl">` or `<require interface="...">` or `<require header="...">`. The error "module not found in IR: impl" occurs because `<require class="impl">` is being treated as a module require.

**How models express this:**
```xml
<require module="library"/>
<require class="impl" scope="private"/>
<require interface="entropy source" scope="private"/>
<require header="mbedtls/entropy.h" library="mbedtls" scope="private"/>
```

**Fix:** In the module require rendering loop, check the `attrs` of each require to determine its kind. Only call `include_file_for_entity(entity_kind="module")` for requires that have a `module` attribute (i.e., `attrs.get("module")` is set). For `class` requires, use `entity_kind="class"`. For `interface` requires, use `entity_kind="interface"`. For `header` requires, emit the header include directly. Skip unknown require kinds gracefully.

## Dependencies

- **None**

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3 (load only if needed):**
- `codegen/models/project_foundation/class_brainkey_client.xml` — example with external library type
- `codegen/models/project_foundation/class_message_cipher.xml` — example with const-qualified class
- `codegen/models/project_foundation/module_mbedtls_bridge_random.xml` — example with mixed requires

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** None

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/test_type_resolution.py` (new)

## Steps

### Step 0: Preflight

- [ ] Reproduce all 10 failures: `bash tools/codegen/new_codegen.sh foundation` shows 10 skipped modules
- [ ] Read `argument_from_source()` and `return_from_source()` to understand current class handling
- [ ] Read module require rendering loop (~line 1305)
- [ ] Confirm implementation defs renderer already handles `library` attribute correctly

### Step 1: Fix external library type resolution

Modify `argument_from_source()` and `return_from_source()` to detect the `library` attribute and use the class name directly without IR lookup.

- [ ] In `argument_from_source()`: if `attrs.get("library")` is set and `attrs.get("class")` is not "self", use the class name as-is for the type
- [ ] In `return_from_source()`: same treatment for library-qualified classes
- [ ] Handle `const` prefix stripping: if class name starts with "const ", strip it and set `is_const_type="1"`
- [ ] Verify: brainkey_client, mbedtls_ecp, simple_swu no longer fail
- [ ] Commit

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 2: Fix module require rendering

Modify the module require rendering loop to dispatch by require kind.

- [ ] Check `require.attrs` to determine kind: `module`, `class`, `interface`, `header`, `enum`, `impl`, `library`
- [ ] For `module` requires: existing behavior (entity_kind="module")
- [ ] For `class` requires: use entity_kind="class" (with KeyError fallback for framework types like "impl")
- [ ] For `interface` requires: use entity_kind="interface"
- [ ] For `header` requires: emit direct c_include with the header file
- [ ] For `library` requires: skip (build-system concern, not codegen)
- [ ] For unknown kinds: skip gracefully
- [ ] Verify: mbedtls_bridge_* modules no longer fail
- [ ] Commit

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 3: Add tests

Create `test_type_resolution.py`:

- [ ] Test: rendering brainkey_client class module succeeds (has mbedtls_ecp_group args/returns)
- [ ] Test: rendering message_cipher class module succeeds (has const-qualified class arg)
- [ ] Test: rendering mbedtls_bridge_random module succeeds (has class require for "impl")
- [ ] Test: foundation codegen produces 0 skipped modules (integration test)
- [ ] Test: common codegen still works correctly (no regression)

**Artifacts:**
- `tools/codegen/test_type_resolution.py` (new)

### Step 4: Testing & Verification

> ZERO test failures allowed.

- [ ] Run new tests: `python3 -m unittest tools/codegen/test_type_resolution.py -v`
- [ ] Run all tests: `python3 -m unittest discover -s tools/codegen -p "test_*.py" -v`
- [ ] Build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Foundation gate: `bash tools/codegen/new_codegen.sh foundation` shows 0 skipped
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

- [ ] `bash tools/codegen/new_codegen.sh foundation` generates all modules with 0 skips
- [ ] External library types render as raw C types without IR lookup
- [ ] const-qualified class names handled correctly
- [ ] Module requires dispatch by kind (module/class/interface/header)
- [ ] Common codegen unchanged (no regression)
- [ ] All tests pass

## Git Commit Convention

- **Step completion:** `feat(CG-037): complete Step N — description`
- **Tests:** `test(CG-037): description`
- **Hydration:** `hydrate: CG-037 expand Step N checkboxes`

**CRITICAL: Commit after EACH step.**

## Do NOT

- Expand task scope
- Skip tests
- Change how `entity_output()` fallback works — that was fixed correctly
- Modify model XML files
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
