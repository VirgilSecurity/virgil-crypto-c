# Task: CG-042 - Fix Vtable Struct Initializer in Internal Modules

**Created:** 2026-04-09
**Size:** M

## Review Level: 2 (Plan and Code)

**Assessment:** The implementation internal module renderer produces broken vtable initialization. Affects all 53 implementation internal modules.
**Score:** 4/8 — Blast radius: 2, Pattern novelty: 1, Security: 0, Reversibility: 1

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-042-fix-vtable-initializer/
├── PROMPT.md
├── STATUS.md
├── .reviews/
└── .DONE
```

## Mission

Fix vtable struct initialization in `render_implementation_internal_c_module()`. Currently, API table variables emit a bare value assignment. They need full struct initializers with multiple `c_value` children.

### The XML structure for struct initializers

The C emitter (`common_bootstrap.py` → `render_variable()`) renders struct initializers when a `c_variable` has `array="derived"` and multiple `c_value` children. The format is:

```python
# When array="derived", render_variable produces:
# static const type_t name[] = {
#     value1,
#     value2,
#     ...
# };
```

But for our case we need a single struct (not array), so use direct `c_value` children. Check how `render_variable()` handles `c_value` elements:

```python
# In common_bootstrap.py render_variable():
cval = elem.find("c_value")  # only finds FIRST c_value
if cval is not None:
    value = cval.attrib["value"]
    if elem.attrib.get("array") == "derived":
        initializer = f" = {{\n    {value}\n}}"
    else:
        initializer = f" = {value}"
```

**IMPORTANT**: The current `render_variable()` only reads the FIRST `c_value`. The legacy XML has MULTIPLE `c_value` children for struct initializers. The emitter needs to be updated too — it must iterate ALL `c_value` children and emit them as `{ val1, val2, ... }`.

### What each API table variable needs (example: `hash_api` for sha256):

The `c_variable` element needs these attributes and children:

```xml
<c_variable name="hash_api" type="vscf_hash_api_t" type_is="class" is_const_type="1"
            visibility="public" declaration="private" definition="private" 
            accessed_by="value" array="derived">
  <c_value value="vscf_api_tag_HASH" type="vscf_api_tag_t" type_is="primitive">
    // API's unique identifier
  </c_value>
  <c_value value="vscf_impl_tag_SHA256" type="vscf_impl_tag_t" type_is="primitive">
    // Implementation unique identifier
  </c_value>
  <c_value value="vscf_sha256_hash" type="vscf_hash_api_hash_fn" type_is="callback">
    <c_cast type="vscf_hash_api_hash_fn" type_is="callback"/>
  </c_value>
  <!-- ... one c_value per API struct field ... -->
  <c_value value="vscf_sha256_DIGEST_LEN" type="size_t" type_is="primitive">
    // Length of the digest
  </c_value>
</c_variable>
```

For callback-typed values, the `c_cast` child tells the emitter to wrap the value: `(vscf_hash_api_hash_fn)vscf_sha256_hash`.

### What the `info` variable needs:

```xml
<c_variable name="info" type="vscf_impl_info_t" type_is="class" is_const_type="1"
            declaration="private" definition="private" array="derived">
  <c_value value="vscf_impl_tag_SHA256" type="vscf_impl_tag_t">
    // impl tag
  </c_value>
  <c_value value="vscf_sha256_find_api" type="vscf_impl_find_api_fn" type_is="callback">
    // find_api callback (no cast needed — exact type match)
  </c_value>
  <c_value value="vscf_sha256_cleanup" type="vscf_impl_cleanup_fn" type_is="callback">
    <c_cast type="vscf_impl_cleanup_fn"/>
  </c_value>
  <c_value value="vscf_sha256_delete" type="vscf_impl_delete_fn" type_is="callback">
    <c_cast type="vscf_impl_delete_fn"/>
  </c_value>
</c_variable>
```

### What the `find_api` method needs:

```c
static const vscf_api_t *
vscf_sha256_find_api(vscf_api_tag_t api_tag) {
    switch(api_tag) {
        case vscf_api_tag_ALG:
            return (const vscf_api_t *) &alg_api;
        case vscf_api_tag_HASH:
            return (const vscf_api_t *) &hash_api;
        default:
            return NULL;
    }
}
```

## Dependencies

- **Task:** CG-040 (API struct must have correct field structure)

## Context to Read First

**Tier 2:**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3:**
- `codegen/generated/foundation/c_module_vscf_sha256_internal.xml` — reference (read the c_variable elements)

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** None

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/common_bootstrap.py`

## Steps

### Step 0: Preflight

- [ ] Read current `render_implementation_internal_c_module()` in `project_c_backend.py`
- [ ] Read `render_variable()` in `common_bootstrap.py` to understand c_value handling
- [ ] Confirm: current output has single c_value per variable (the bug)

### Step 1: Fix C emitter to handle multi-value struct initializers

Update `render_variable()` in `common_bootstrap.py` to:
- Find ALL `c_value` children (not just first)
- When multiple c_values exist OR `array="derived"`, render as `{ val1, val2, ... }`
- For each c_value: if it has a `c_cast` child, wrap value as `(cast_type)value`
- Include comments from c_value `.text`

- [ ] Update `render_variable()` to iterate all c_value children
- [ ] Handle c_cast wrapping for callback-typed values
- [ ] Render per-value comments
- [ ] Commit

### Step 2: Fix backend to emit multi-value API table variables

Update `render_implementation_internal_c_module()` in `project_c_backend.py` to emit:

For each interface binding:
- Create `c_variable` with `array="derived"`
- Add `c_value` for api_tag (with comment)
- Add `c_value` for impl_tag (with comment)
- For each interface method: add `c_value` with function pointer name + `c_cast` child
- For each interface constant: add `c_value` with constant name

For impl_info:
- Create `c_variable` with `array="derived"`
- Add `c_value` for impl_tag
- Add `c_value` for find_api (no cast)
- Add `c_value` for cleanup_cb (with cast)
- Add `c_value` for delete_cb (with cast)

- [ ] Fix API table variable emission with multi-value c_values
- [ ] Fix impl_info variable emission
- [ ] Commit

### Step 3: Generate find_api method

Generate the `find_api` static method with a switch statement mapping api_tags to API table pointers.

- [ ] Generate find_api method with switch/case
- [ ] Commit

### Step 4: Testing & Verification

- [ ] `python3 -m unittest discover -s tools/codegen -p "test_*.py" -v`
- [ ] `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Verify: `diff` of `vscf_sha256_internal.c` shows correct struct initializers

### Step 5: Documentation & Delivery

- [ ] Discoveries logged

## Completion Criteria

- [ ] API table variables have full `{ field1, field2, ... }` initializers
- [ ] Function pointers cast to callback types via c_cast
- [ ] impl_info correctly initialized
- [ ] find_api generated with switch statement
- [ ] All tests pass

## Git Commit Convention

- `feat(CG-042): complete Step N — description`

**CRITICAL: Commit after EACH step. Do NOT try to implement multiple steps before committing.**

## Do NOT

- Fix interface API/dispatch — that is CG-040
- Fix type resolution — that is CG-041
- Commit without task ID prefix
- Read `codegen/c_module_implementation.gsl` — the patterns are specified above

---

## Amendments (Added During Execution)
