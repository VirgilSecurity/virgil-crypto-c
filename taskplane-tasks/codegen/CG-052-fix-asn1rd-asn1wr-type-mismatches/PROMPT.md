# Task: CG-052 - Fix `vscf_asn1rd` / `vscf_asn1wr` Type Mismatches

**Created:** 2026-04-11
**Size:** M

## Review Level: 1 (Plan Only)

**Assessment:** Targeted codegen fix for 2 class modules with struct-member type mismatches. The generated `_defs.h` declares struct fields with wrong types (e.g., `byte` instead of `byte *`, `byte` instead of `size_t`), causing 40+ build errors when the legacy handwritten `.c` uses those fields. Requires understanding how class properties map from XML model → IR → C struct fields.
**Score:** 2/8 — Blast radius: 1, Pattern novelty: 1, Security: 0, Reversibility: 0

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-052-fix-asn1rd-asn1wr-type-mismatches/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Fix the 40+ compilation errors in `vscf_asn1rd.c` and `vscf_asn1wr.c` caused by the new codegen generating struct definitions (`_defs.h`) with incorrect member types. The handwritten `.c` files access struct members expecting specific types (pointers, sizes) but the generated `_defs.h` declares them differently.

**Error patterns observed:**

1. **`byte` vs `byte *` / `const byte *`** — struct fields generated as `byte` (single char) but used as pointers in `.c` code. E.g., `self->curr` should be `const byte *` but generated as `byte`.
2. **`byte` vs `size_t`** — struct fields generated as `byte` but used as sizes. E.g., `self->len` should be `size_t`.
3. **Conflicting types for functions** — `vscf_asn1rd_read_int8`, `read_int16`, `read_int64`, `vscf_asn1wr_reset`, `get_current_element_len`, `swap_elements_of_set`, `second_element_of_set_is_less` — generated header declarations have wrong return types or parameter types vs handwritten `.c` definitions.

**Root cause:** The XML model properties for `asn1rd` and `asn1wr` use types like `byte[]` (byte array), `unsigned` (size), and pointer types that are being incorrectly mapped through the IR → C type resolution pipeline. The codegen likely treats these as simple `byte` instead of resolving to the correct C type.

## Dependencies

None — can run independently.

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Specific files to examine:**
- Legacy `_defs.h` for the 2 modules (the correct struct layouts):
  - `library/foundation/include/virgil/crypto/foundation/private/vscf_asn1rd_defs.h`
  - `library/foundation/include/virgil/crypto/foundation/private/vscf_asn1wr_defs.h`
- Generated `_defs.h` (the incorrect versions) — run `bash tools/codegen/new_codegen.sh foundation` and check `build/new-codegen/library/foundation/`
- The XML source models for these modules in `codegen/models/`
- Legacy header declarations:
  - `library/foundation/include/virgil/crypto/foundation/vscf_asn1rd.h`
  - `library/foundation/include/virgil/crypto/foundation/vscf_asn1wr.h`

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** cmake build system configured

## File Scope

- `tools/codegen/project_c_backend.py` (struct field type rendering)
- `tools/codegen/project_ir.py` (property type mapping)
- `tools/codegen/common_source.py` (XML property parsing, if types lost here)

## Steps

### Step 0: Preflight

- [ ] Diff the legacy vs generated `_defs.h` for both modules to identify every struct field type mismatch
- [ ] Diff the legacy vs generated main `.h` headers to identify every function signature mismatch
- [ ] Trace the type pipeline for one mismatched field: XML model → source loader → IR → C backend → output
- [ ] Identify where in the pipeline the type information is lost or incorrectly mapped
- [ ] Check if this affects other class modules beyond `asn1rd`/`asn1wr` (search for similar property types in other models)

### Step 1: Fix type resolution

> ⚠️ Hydrate: Expand based on root causes identified in Step 0

- [ ] Fix the property type mapping so pointer types (`byte[]`, `byte *`) resolve correctly
- [ ] Fix size types (`unsigned`, `size_t`) resolution
- [ ] Fix function return type and parameter type resolution for the affected methods
- [ ] Verify fixes don't break other modules' struct definitions

### Step 2: Verification

> ZERO test failures allowed.

- [ ] Run FULL Python test suite: `PYTHONPATH=. python3 -m unittest discover -s tools/codegen -p "test_*.py"`
- [ ] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Run foundation build: `bash tools/codegen/new_codegen.sh --verify foundation`
- [ ] Confirm `vscf_asn1rd.c` and `vscf_asn1wr.c` compile with 0 errors
- [ ] Diff generated `_defs.h` against legacy to verify struct parity
- [ ] Document any remaining errors (different modules) as discoveries — do NOT expand scope

### Step 3: Documentation & Delivery

- [ ] Update `taskplane-tasks/codegen/CONTEXT.md` — update foundation build error status
- [ ] Discoveries logged in STATUS.md

## Documentation Requirements

**Must Update:**
- `taskplane-tasks/codegen/CONTEXT.md` — update foundation build status, note resolved modules

**Check If Affected:**
- `docs/codegen-migration/common-direct-foundation-status.md`

## Completion Criteria

- [ ] All steps complete
- [ ] All Python tests passing
- [ ] Common build gate passes
- [ ] Foundation build: 0 errors in `vscf_asn1rd` and `vscf_asn1wr`
- [ ] Struct definitions match legacy layout for these 2 modules
- [ ] Any remaining errors in OTHER modules documented as discoveries
- [ ] Documentation updated

## Git Commit Convention

- **Step completion:** `feat(CG-052): complete Step N — description`
- **Bug fixes:** `fix(CG-052): description`
- **Hydration:** `hydrate: CG-052 expand Step N checkboxes`

## Do NOT

- Modify handwritten `.c` files in `library/foundation/src/`
- Commit generated `library/common/**` or `library/foundation/**` outputs
- Fix errors in modules beyond `vscf_asn1rd` and `vscf_asn1wr` — log as discoveries
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
