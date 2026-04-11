# Task: CG-053 - Generate `_defs.h` / `_defs.c` Files

**Created:** 2026-04-11
**Size:** L

## Review Level: 1 (Plan Only)

**Assessment:** New codegen feature — generating struct definition files for all implementations. Large file count (73 files: 37 `_defs.h` + 36 `_defs.c`) but uniform structure. These files follow a rigid template pattern in legacy code.
**Score:** 3/8 — Blast radius: 2, Pattern novelty: 1, Security: 0, Reversibility: 0

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-053-generate-defs-files/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Generate the `_defs.h` and `_defs.c` files that are currently in the 195 legacy-only files not produced by the new codegen. These files provide:

- **`_defs.h`** (in `include/virgil/crypto/foundation/private/`): Private struct layout definitions. Each file defines the concrete struct for an implementation (e.g., `vscf_sha256_t`). Referenced by `_internal.c` and the implementation's own `.c` file.
- **`_defs.c`** (in `src/`): Struct size/alignment exports and compile-time assertions. Each file provides `vscf_<impl>_ctx_size()` and `VSCF_ASSERT_SIZEOF()` checks.

**Scope:** 37 `_defs.h` + 36 `_defs.c` = 73 files for the `foundation` project. The `common` project already has its `_defs` files generated.

**Note:** CG-052 may fix type resolution issues that affect `_defs.h` struct field types (e.g., `asn1rd`, `asn1wr`). This task should benefit from those fixes but is not strictly dependent — it adds the file *generation* capability, while CG-052 fixes the *type mapping* for specific problematic modules.

## Dependencies

None strictly, but runs better after CG-052 (type resolution fixes).

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Specific files to examine:**
- Legacy `_defs.h` examples:
  - `library/foundation/include/virgil/crypto/foundation/private/vscf_sha256_defs.h`
  - `library/foundation/include/virgil/crypto/foundation/private/vscf_aes256_cbc_defs.h`
- Legacy `_defs.c` examples:
  - `library/foundation/src/vscf_sha256_defs.c`
  - `library/foundation/src/vscf_aes256_cbc_defs.c`
- Current codegen output paths in `project_c_backend.py` — check how implementations are rendered

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** cmake build system configured

## File Scope

- `tools/codegen/project_c_backend.py` (primary — add defs renderer)
- `tools/codegen/project_ir.py` (if struct layout info needs IR additions)

## Steps

### Step 0: Preflight

- [ ] Study 3-4 legacy `_defs.h` files to extract the template pattern (struct definition, includes, guards)
- [ ] Study 3-4 legacy `_defs.c` files to extract the template pattern (ctx_size, assertions)
- [ ] Check what struct layout information is already in the IR for implementations
- [ ] Identify what additional IR data (if any) is needed for struct field types, includes, assertions
- [ ] List all implementations that need `_defs` files (cross-reference with legacy file list)

### Step 1: Implement `_defs.h` renderer

> ⚠️ Hydrate: Expand based on patterns identified in Step 0

- [ ] Add a `_defs.h` renderer for implementation struct definitions in `project_c_backend.py`
- [ ] Handle struct fields from class properties (types, names, comments)
- [ ] Handle the `vscf_impl_t` base struct embedding
- [ ] Handle include dependencies for field types
- [ ] Handle header guards and generated block markers
- [ ] Wire into the implementation module output and auto-discovery

### Step 2: Implement `_defs.c` renderer

- [ ] Add a `_defs.c` renderer for struct size exports
- [ ] Generate `vscf_<impl>_ctx_size()` function
- [ ] Generate `VSCF_ASSERT_SIZEOF()` compile-time check
- [ ] Handle includes (the `_defs.h` plus any needed headers)
- [ ] Wire into the implementation module output and auto-discovery

### Step 3: Verification

> ZERO test failures allowed.

- [ ] Run FULL Python test suite: `PYTHONPATH=. python3 -m unittest discover -s tools/codegen -p "test_*.py"`
- [ ] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Run foundation generation: `bash tools/codegen/new_codegen.sh foundation`
- [ ] Verify correct number of `_defs.h` and `_defs.c` files generated
- [ ] Diff 5+ generated `_defs` files against legacy to verify parity
- [ ] Run foundation build: `bash tools/codegen/new_codegen.sh --verify foundation`
- [ ] Fix any regressions

### Step 4: Documentation & Delivery

- [ ] Update `taskplane-tasks/codegen/CONTEXT.md` — update file generation counts, mark `_defs` files resolved
- [ ] Discoveries logged in STATUS.md

## Documentation Requirements

**Must Update:**
- `taskplane-tasks/codegen/CONTEXT.md` — update "Files Not Generated" counts

**Check If Affected:**
- `docs/codegen-migration/common-direct-foundation-status.md`

## Completion Criteria

- [ ] All steps complete
- [ ] All Python tests passing
- [ ] Common build gate passes
- [ ] 37 `_defs.h` + 36 `_defs.c` files generated for foundation
- [ ] Generated files match legacy structure/pattern
- [ ] Documentation updated

## Git Commit Convention

- **Step completion:** `feat(CG-053): complete Step N — description`
- **Bug fixes:** `fix(CG-053): description`
- **Hydration:** `hydrate: CG-053 expand Step N checkboxes`

## Do NOT

- Modify handwritten `.c` files in `library/foundation/src/`
- Commit generated `library/common/**` or `library/foundation/**` outputs
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
