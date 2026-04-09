# Task: CG-041 - Fix Type Resolution for Foundation Entities

**Created:** 2026-04-09
**Size:** M

## Review Level: 2 (Plan and Code)

**Assessment:** Fixes type resolution bugs affecting ~195 foundation files. Interface-typed properties/args render as `void`, enum returns render as `void`, `vsc_data_t` has wrong access mode, fixed-size arrays render as pointers.
**Score:** 4/8 — Blast radius: 2, Pattern novelty: 1, Security: 0, Reversibility: 1

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-041-fix-type-resolution-foundation/
├── PROMPT.md
├── STATUS.md
├── .reviews/
└── .DONE
```

## Mission

Fix type resolution bugs in the shared C backend that cause incorrect C signatures and struct fields for foundation entities. These bugs affect implementation defs (~46 files) and implementation/class main modules (~149 files).

### Category C — Implementation/class defs issues:

**C1. Missing dependency struct fields**
- Classes/implementations with dependencies (e.g., `vscf_hybrid_key_alg` has `random`, `cipher`, `hash`) don't have dependency fields in the struct
- The dependency fields should appear as `vscf_impl_t *random;` etc. with comments
- Root cause: `render_implementation_defs_c_module()` doesn't emit dependency fields
- Fix: iterate `impl.dependencies` (from the IR, via class model dependencies parsed in CG-027) and emit a `c_property` for each

**C2. Properties with `interface="..."` render as `void` instead of `vscf_impl_t *`**
- Model: `<property name="alg info" interface="alg info"/>`
- Expected: `vscf_impl_t *alg_info;`
- Actual: `void alg_info;`
- Root cause: the property type resolver in the defs/struct renderer only handles `class`, `enum`, `type` attributes but not `interface`. When the interface attribute is present, the type falls through to default `void`.
- Fix: when a property has `interface="..."`, resolve to `{prefix}_impl_t` (e.g., `vscf_impl_t`) as the type with `accessed_by="pointer"`

**C3. Fixed-size arrays render as pointers**
- Model: `<property name="key" type="byte"><array length="fixed" length_constant=".(class_aes256_gcm_constant_key_len)"/></property>`
- Expected: `byte key[vscf_aes256_gcm_KEY_LEN];`
- Actual: `byte *key;`
- Root cause: the array sub-element is not processed; the property renders as a simple pointer
- Fix: detect `<array length="fixed" length_constant="...">`, resolve the constant name, and render as `type name[CONSTANT]`

### Category D — Implementation/class main module issues:

**D2. Missing `const` on interface-typed args**
- Methods taking `const vscf_impl_t *key` render as `vscf_impl_t *key` (missing const)
- Root cause: the `access="readonly"` attribute on interface-typed args should produce `is_const_type="1"`
- Fix: in `argument_from_source()`, when the arg has an interface type and `access="readonly"`, set const

**D3. `vsc_data_t` passed by pointer instead of value**
- `vsc_data_t` is a value type (small struct, always passed by value in C)
- Current rendering passes it by pointer: `vsc_data_t *data`
- Root cause: `argument_from_source()` treats all class-typed args as pointer unless `is_value_type`
- Fix: check if the class is a value type (via IR lookup) and pass by value. `data` is a value type (`is_value_type="1"` in its model)

**D4. Constructor args with interface type render as `void`**
- Same root cause as C2 but in `argument_from_source()` context
- Model: `<argument name="alg info" interface="alg info"/>`
- Fix: when arg has `interface="..."`, resolve to `{prefix}_impl_t *` with appropriate const

**D5. Methods returning enum type render as `void`**
- Model: `<method name="alg id"><return enum="alg id"/></method>`
- Expected return: `vscf_alg_id_t`
- Actual: `void`
- Root cause: `return_from_source()` doesn't handle `enum` attribute
- Fix: detect `enum` in return attrs, resolve via `entity_output(entity_kind="enum")` to get the type name

**D6. Missing VSCF_NODISCARD modifier**
- Methods returning `enum="status"` should have `{PREFIX}_NODISCARD` modifier
- Fix: detect status-returning methods and add the modifier

**D7. Missing enum constant comments**
- Implementation-level enum constants (e.g., `CAN_IMPORT_PUBLIC_KEY`) should have per-constant comments from the interface binding
- Fix: set `.text` on each `c_constant` element from the interface constant description

## Dependencies

- **None** (can run in parallel with CG-040)

## Context to Read First

**Tier 2:**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3:**
- `codegen/generated/foundation/c_module_vscf_sha256.xml` — reference impl main
- `codegen/generated/foundation/c_module_vscf_sha256_defs.xml` — reference impl defs
- `codegen/generated/foundation/c_module_vscf_aes256_gcm_defs.xml` — reference with arrays
- `codegen/models/project_foundation/class_key_info.xml` — class with enum returns

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** None

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/common_bootstrap.py`

## Steps

### Step 0: Preflight

- [ ] Run foundation codegen and diff defs/main files to confirm issues
- [ ] Read `render_implementation_defs_c_module()`, `render_implementation_c_module()`, `render_class_c_module()`
- [ ] Read `argument_from_source()`, `return_from_source()`

### Step 1: Fix defs rendering (C1, C2, C3)

- [ ] Add dependency struct fields to impl defs (C1)
- [ ] Resolve interface-typed properties to `{prefix}_impl_t *` (C2)
- [ ] Resolve fixed-size arrays with constant length (C3)
- [ ] Commit

### Step 2: Fix argument/return type resolution (D2-D6)

- [ ] Fix `argument_from_source()`: handle interface-typed args → `{prefix}_impl_t *` (D4)
- [ ] Fix `argument_from_source()`: respect `access="readonly"` for const (D2)
- [ ] Fix `argument_from_source()`: pass value types (data) by value not pointer (D3)
- [ ] Fix `return_from_source()`: handle `enum` returns (D5)
- [ ] Add `{PREFIX}_NODISCARD` for status-returning methods (D6)
- [ ] Commit

### Step 3: Fix enum constant comments (D7)

- [ ] Add per-constant comments from interface binding descriptions
- [ ] Commit

### Step 4: Testing & Verification

- [ ] `python3 -m unittest discover -s tools/codegen -p "test_*.py" -v`
- [ ] `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Verify: `vscf_sha256.h` diff shows correct signatures
- [ ] Verify: `vscf_aes256_gcm_defs.h` shows `byte key[...]` not `byte *key`
- [ ] Verify: `vscf_key_info.h` methods return `vscf_alg_id_t` not `void`

### Step 5: Documentation & Delivery

- [ ] Discoveries logged

## Completion Criteria

- [ ] Interface-typed properties resolve to `{prefix}_impl_t *`
- [ ] Enum returns resolve to correct type
- [ ] `vsc_data_t` passed by value, `vsc_buffer_t` by pointer
- [ ] Fixed-size arrays render with `[CONSTANT]`
- [ ] Dependency fields present in defs structs
- [ ] const applied for readonly interface args
- [ ] All tests pass

## Git Commit Convention

- `feat(CG-041): complete Step N — description`

**CRITICAL: Commit after EACH step.**

## Do NOT

- Fix interface API/dispatch issues — those are CG-040
- Fix vtable initializer — that is CG-042
- Commit without task ID prefix

---

## Amendments (Added During Execution)
