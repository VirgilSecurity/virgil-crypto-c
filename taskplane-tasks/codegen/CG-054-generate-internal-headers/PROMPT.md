# Task: CG-054 - Generate `_internal.h` Headers

**Created:** 2026-04-11
**Size:** M

## Review Level: 1 (Plan Only)

**Assessment:** New codegen feature — generating internal header files for implementations. 58 files, uniform pattern. Depends on `_defs.h` being available (CG-053) since internal headers include it.
**Score:** 2/8 — Blast radius: 1, Pattern novelty: 1, Security: 0, Reversibility: 0

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-054-generate-internal-headers/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Generate the `_internal.h` headers (58 files) that provide forward declarations for implementation lifecycle functions, vtable registration, and context management. These headers are located in `src/` (not the public include directory) and are included by `_internal.c` files.

Each `_internal.h` file typically contains:

1. Forward declarations for `init_ctx` / `cleanup_ctx` (lifecycle)
2. Forward declarations for `init_ctx_with_X` constructors (if any)
3. Vtable registration function declarations
4. `did_setup_*` / `did_release_*` callback declarations (for dependencies with observers)
5. Include of the implementation's `_defs.h`

**Current state:** CG-048 fixed the output path for `_internal.h` (`src/` not `include/private/`). CG-050 added `did_setup`/`did_release` forward declarations to `_internal.c` output. This task generates the standalone `_internal.h` *header* files that `_internal.c` files `#include`.

## Dependencies

- **CG-053** — `_defs.h` generation (internal headers include `_defs.h`)

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Specific files to examine:**
- Legacy `_internal.h` examples:
  - `library/foundation/src/vscf_sha256_internal.h`
  - `library/foundation/src/vscf_aes256_cbc_internal.h`
  - `library/foundation/src/vscf_key_asn1_deserializer_internal.h` (implementation with many interfaces)
- Current `_internal.c` generation in `project_c_backend.py` — see what declarations are already emitted inline

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** cmake build system configured

## File Scope

- `tools/codegen/project_c_backend.py` (primary — add internal header renderer)
- `tools/codegen/project_ir.py` (if lifecycle/vtable info needs new IR fields)

## Steps

### Step 0: Preflight

- [ ] Study 3-4 legacy `_internal.h` files to extract the template pattern
- [ ] Identify what declarations are needed: `init_ctx`, `cleanup_ctx`, constructors, vtable registration, observer callbacks
- [ ] Check what the current `_internal.c` renderer already emits — avoid duplication
- [ ] List all implementations that need `_internal.h` files

### Step 1: Implement `_internal.h` renderer

> ⚠️ Hydrate: Expand based on patterns identified in Step 0

- [ ] Add a `_internal.h` renderer in `project_c_backend.py`
- [ ] Generate `init_ctx` / `cleanup_ctx` forward declarations
- [ ] Generate constructor forward declarations (`init_ctx_with_X`) if implementation has constructors
- [ ] Generate vtable registration function declarations for each implemented interface
- [ ] Generate `did_setup_*` / `did_release_*` declarations for dependencies with observers
- [ ] Handle includes (`_defs.h`, interface API headers)
- [ ] Handle header guards and generated block markers
- [ ] Wire into implementation module output and auto-discovery

### Step 2: Verification

> ZERO test failures allowed.

- [ ] Run FULL Python test suite: `PYTHONPATH=. python3 -m unittest discover -s tools/codegen -p "test_*.py"`
- [ ] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Run foundation generation: `bash tools/codegen/new_codegen.sh foundation`
- [ ] Verify correct number of `_internal.h` files generated (target: 58)
- [ ] Diff 5+ generated files against legacy to verify parity
- [ ] Run foundation build: `bash tools/codegen/new_codegen.sh --verify foundation`
- [ ] Fix any regressions

### Step 3: Documentation & Delivery

- [ ] Update `taskplane-tasks/codegen/CONTEXT.md` — update file generation counts, mark `_internal.h` resolved
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
- [ ] 58 `_internal.h` files generated for foundation
- [ ] Generated files match legacy declaration pattern
- [ ] Documentation updated

## Git Commit Convention

- **Step completion:** `feat(CG-054): complete Step N — description`
- **Bug fixes:** `fix(CG-054): description`
- **Hydration:** `hydrate: CG-054 expand Step N checkboxes`

## Do NOT

- Modify handwritten `.c` files in `library/foundation/src/`
- Commit generated `library/common/**` or `library/foundation/**` outputs
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
