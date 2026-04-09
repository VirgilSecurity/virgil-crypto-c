# Task: CG-042 - Fix Vtable Struct Initializer in Internal Modules

**Created:** 2026-04-09
**Size:** M

## Review Level: 2 (Plan and Code)

**Assessment:** The implementation internal module renderer produces broken vtable initialization — just assigns the api_tag value instead of a full C struct initializer with function pointers and constants. Affects all 53 implementation internal modules.
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

Fix the vtable struct initialization in `render_implementation_internal_c_module()`. Currently, API table variables are rendered as simple assignments (`static const vscf_alg_api_t alg_api = vscf_api_tag_ALG;`) instead of full C struct initializers with all fields populated.

### Issue E1: API table struct initialization

**Legacy output (correct):**
```c
static const vscf_hash_api_t hash_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'hash' MUST be equal to the 'vscf_api_tag_HASH'.
    //
    vscf_api_tag_HASH,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_SHA256,
    //
    //  Calculate hash over given data.
    //
    (vscf_hash_api_hash_fn)vscf_sha256_hash,
    //
    //  Start a new hashing.
    //
    (vscf_hash_api_start_fn)vscf_sha256_start,
    //
    //  Add given data to the hash.
    //
    (vscf_hash_api_update_fn)vscf_sha256_update,
    //
    //  Accompilsh hashing and return it's result (a message digest).
    //
    (vscf_hash_api_finish_fn)vscf_sha256_finish,
    //
    //  Length of the digest (hashing output) in bytes.
    //
    vscf_sha256_DIGEST_LEN,
    //
    //  Block length of the digest function in bytes.
    //
    vscf_sha256_BLOCK_LEN
};
```

**Current output (broken):**
```c
static const vscf_alg_api_t alg_api = vscf_api_tag_ALG;
```

### Issue E2: impl_info struct initialization

Same problem — should be a full struct initializer with impl_tag, find_api callback, cleanup callback, delete callback.

### Issue E3: find_api callback not generated

Each implementation needs a `find_api` static function that maps api_tags to the implementation's API table pointers. This function is referenced in the `impl_info` struct.

### Issue E4: Missing per-field comments

Each field in the struct initializer should have a comment describing it.

### What the initializer needs (per interface binding):

For each interface an implementation binds to, emit a static const variable:
1. `api_tag` field — the interface's API tag constant (e.g., `vscf_api_tag_HASH`)
2. `impl_tag` field — the implementation's tag (e.g., `vscf_impl_tag_SHA256`)
3. Function pointer fields — cast to callback type, pointing to impl's concrete functions (e.g., `(vscf_hash_api_hash_fn)vscf_sha256_hash`)
4. Constant fields — values from the interface binding (e.g., `vscf_sha256_DIGEST_LEN` for `digest_len`)
5. Inherited API pointers — for interfaces that inherit others

The `find_api` function is a switch on `api_tag` returning the matching API table pointer.

## Dependencies

- **Task:** CG-040 (API struct must have correct field structure for initializer to match)

## Context to Read First

**Tier 2:**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3:**
- `codegen/generated/foundation/c_module_vscf_sha256_internal.xml` — reference with 2 interfaces (alg, hash)
- `codegen/generated/foundation/c_module_vscf_aes256_gcm_internal.xml` — reference with many interfaces
- `codegen/c_module_implementation.gsl` — GSL internal module generation

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** None

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/common_bootstrap.py`

## Steps

### Step 0: Preflight

- [ ] Study legacy resolved XML for `vscf_sha256_internal` — note exact struct initializer format
- [ ] Study `vscf_aes256_gcm_internal` — complex case with many interfaces and constants
- [ ] Read current `render_implementation_internal_c_module()` to understand what's wrong

### Step 1: Fix API table struct initializer

- [ ] Generate full C struct initializer `{ field1, field2, ... }` instead of bare value
- [ ] Include api_tag and impl_tag as first two fields
- [ ] Cast function pointers to callback types: `(vscf_hash_api_hash_fn)vscf_sha256_hash`
- [ ] Include constant values from interface bindings
- [ ] Add per-field comments
- [ ] Commit

### Step 2: Fix impl_info initializer and find_api

- [ ] Generate full impl_info struct initializer with impl_tag, find_api, cleanup_cb, delete_cb
- [ ] Generate static `find_api` function with switch on api_tag
- [ ] Commit

### Step 3: Testing & Verification

- [ ] `python3 -m unittest discover -s tools/codegen -p "test_*.py" -v`
- [ ] `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Verify: `vscf_sha256_internal.c` diff shows correct struct initializers
- [ ] Verify: `vscf_aes256_gcm_internal.c` has all interface API tables

### Step 4: Documentation & Delivery

- [ ] Discoveries logged

## Completion Criteria

- [ ] API table variables have full struct initializers with all fields
- [ ] Function pointers cast to correct callback types
- [ ] Constants from interface bindings present
- [ ] impl_info correctly initialized
- [ ] find_api function generated
- [ ] All tests pass

## Git Commit Convention

- `feat(CG-042): complete Step N — description`

**CRITICAL: Commit after EACH step.**

## Do NOT

- Fix interface API/dispatch — that is CG-040
- Fix type resolution — that is CG-041
- Commit without task ID prefix

---

## Amendments (Added During Execution)
