# Task: CG-055 - Generate Missing `_internal.c` Files

**Created:** 2026-04-11
**Size:** M

## Review Level: 1 (Plan Only)

**Assessment:** Extending existing `_internal.c` generation to cover 4 modules currently skipped by the new codegen. The codegen already generates 53 of 57 `_internal.c` files — this fixes the 4 that are missing. Root cause is likely that these modules use renamed/aliased names (`ec_alg_info` → `ecc_alg_info`, `pkcs8_der_serializer` → `pkcs8_serializer`) or have unusual model structures.
**Score:** 2/8 — Blast radius: 1, Pattern novelty: 1, Security: 0, Reversibility: 0

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-055-generate-missing-internal-c/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Generate the 4 missing `_internal.c` files that the new codegen currently does not produce:

1. `vscf_ec_alg_info_internal.c` — Note: legacy file includes `vscf_ecc_alg_info_internal.h` (renamed from `ec_alg_info` to `ecc_alg_info`)
2. `vscf_ecies_internal.c`
3. `vscf_padding_cipher_internal.c`
4. `vscf_pkcs8_der_serializer_internal.c` — Note: legacy file includes `vscf_pkcs8_serializer_internal.h` (renamed)

The codegen already generates 53 `_internal.c` files successfully. These 4 are likely skipped due to name aliasing, missing model entries, or special structure. Diagnose why they're skipped and fix the codegen to include them.

**Also check:** There are 5 `_internal.h` files not generated (4 matching these modules + `vscf_recipient_cipher_internal.h`). If CG-054 missed these for the same reason, fix them too.

## Dependencies

None.

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Specific files to examine:**
- The 4 legacy `_internal.c` files in `library/foundation/src/`
- The XML models for these modules in `codegen/models/`
- The current `_internal.c` renderer in `project_c_backend.py`
- Check if these modules appear in the IR or are filtered out during loading

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** cmake build system configured

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/project_ir.py`
- `tools/codegen/project_source.py` (if model loading skips these)

## Steps

### Step 0: Preflight

- [ ] Run `bash tools/codegen/new_codegen.sh foundation` and list all generated `_internal.c` files
- [ ] Identify why the 4 modules are missing — check model loading, IR construction, and renderer discovery
- [ ] Check the XML model names vs file names (e.g., `ecc_alg_info` vs `ec_alg_info`, `pkcs8_serializer` vs `pkcs8_der_serializer`)
- [ ] Check if `vscf_recipient_cipher_internal.h` is also missing and why

### Step 1: Fix generation of missing `_internal.c` files

> ⚠️ Hydrate: Expand based on root causes identified in Step 0

- [ ] Fix the root cause for each skipped module (name aliasing, model loading, IR filtering)
- [ ] Verify all 4 `_internal.c` files are now generated
- [ ] Fix `_internal.h` generation for the 5 missing headers if applicable
- [ ] Diff generated files against legacy to verify structural parity

### Step 2: Verification

> ZERO test failures allowed.

- [ ] Run FULL Python test suite: `PYTHONPATH=. python3 -m unittest discover -s tools/codegen -p "test_*.py"`
- [ ] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Run foundation generation: `bash tools/codegen/new_codegen.sh foundation`
- [ ] Verify 57/57 `_internal.c` files now generated
- [ ] Run foundation build: `bash tools/codegen/new_codegen.sh --verify foundation`
- [ ] Fix any regressions

### Step 3: Documentation & Delivery

- [ ] Update `taskplane-tasks/codegen/CONTEXT.md` — update file generation counts
- [ ] Discoveries logged in STATUS.md

## Documentation Requirements

**Must Update:**
- `taskplane-tasks/codegen/CONTEXT.md` — update legacy-only file counts

## Completion Criteria

- [ ] All steps complete
- [ ] All Python tests passing
- [ ] Common build gate passes
- [ ] 57/57 `_internal.c` files generated for foundation
- [ ] Missing `_internal.h` files also addressed
- [ ] Documentation updated

## Git Commit Convention

- **Step completion:** `feat(CG-055): complete Step N — description`
- **Bug fixes:** `fix(CG-055): description`
- **Hydration:** `hydrate: CG-055 expand Step N checkboxes`

## Do NOT

- Modify handwritten `.c` files in `library/foundation/src/`
- Commit generated `library/common/**` or `library/foundation/**` outputs
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
