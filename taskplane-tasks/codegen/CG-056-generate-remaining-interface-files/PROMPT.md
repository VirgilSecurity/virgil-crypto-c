# Task: CG-056 - Generate Remaining Interface Dispatch + API Files

**Created:** 2026-04-11
**Size:** L

## Review Level: 1 (Plan Only)

**Assessment:** Extends CG-051's dispatch body generation to cover interface modules that are still missing from the new codegen output. 36 files across 9 interfaces: dispatch `.c`/`.h` pairs and API struct `.c`/`.h` pairs. CG-051 added dispatch body rendering for existing interfaces; this task covers interfaces that aren't being discovered or rendered at all.
**Score:** 3/8 — Blast radius: 2, Pattern novelty: 1, Security: 0, Reversibility: 0

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-056-generate-remaining-interface-files/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Generate the remaining interface-related files that the new codegen does not yet produce. These are 9 interfaces with 4 files each (dispatch `.c` + `.h`, API struct `.c` + `.h`) = 36 files:

**Missing interfaces (all files missing):**
1. `vscf_defaults` (`.c`, `.h`, `_api.c`, `_api.h`)
2. `vscf_generate_ephemeral_key` (`.c`, `.h`, `_api.c`, `_api.h`)
3. `vscf_generate_key` (`.c`, `.h`, `_api.c`, `_api.h`)
4. `vscf_key_alg` (`.c`, `.h`, `_api.c`, `_api.h`)
5. `vscf_key_deserializer` (`.c`, `.h`, `_api.c`, `_api.h`)
6. `vscf_mac_info` (`.c`, `.h`, `_api.c`, `_api.h`)
7. `vscf_mac_stream` (`.c`, `.h`, `_api.c`, `_api.h`)
8. `vscf_sign_hash` (`.c`, `.h`, `_api.c`, `_api.h`)
9. `vscf_verify_hash` (`.c`, `.h`, `_api.c`, `_api.h`)

**Root cause hypothesis:** These interfaces may not be discovered by the codegen's `discover_renderers` function, or they may use model structures that aren't handled. The codegen already generates other interface dispatch + API files (e.g., `vscf_cipher`, `vscf_encrypt`), so the renderers exist — these interfaces just aren't being fed into them.

## Dependencies

None — can run independently. (CG-051 already added dispatch body generation.)

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`
- `taskplane-tasks/codegen/CG-051-generate-interface-dispatch-bodies/STATUS.md`

**Specific files to examine:**
- Legacy files for one of the missing interfaces (e.g., `vscf_generate_key.c`, `.h`, `_api.c`, `_api.h`)
- `discover_renderers` in `project_c_backend.py` — check what interfaces it finds
- XML models for the missing interfaces in `codegen/models/`
- Compare with a working interface (e.g., `vscf_cipher`) to see what's different

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** cmake build system configured

## File Scope

- `tools/codegen/project_c_backend.py` (discovery + rendering)
- `tools/codegen/project_ir.py` (interface IR loading)
- `tools/codegen/project_source.py` (model loading)

## Steps

### Step 0: Preflight

- [ ] List all interfaces the codegen currently discovers and renders
- [ ] Compare with the full set of interfaces in the XML models
- [ ] Identify why the 9 interfaces are not being discovered/rendered
- [ ] Check if these interfaces have different model structures than the working ones
- [ ] Study one legacy `_api.c` / `_api.h` pair to understand the API struct file pattern

### Step 1: Fix interface discovery

> ⚠️ Hydrate: Expand based on root causes identified in Step 0

- [ ] Fix the model loading or IR construction to include the missing interfaces
- [ ] Fix `discover_renderers` if it's filtering them out
- [ ] Verify all 9 interfaces are now discovered

### Step 2: Generate API struct files

- [ ] Ensure `_api.h` (private API struct definition) is rendered for all interfaces
- [ ] Ensure `_api.c` (API struct implementation) is rendered for all interfaces
- [ ] Diff against legacy files to verify parity

### Step 3: Verification

> ZERO test failures allowed.

- [ ] Run FULL Python test suite: `PYTHONPATH=. python3 -m unittest discover -s tools/codegen -p "test_*.py"`
- [ ] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Run foundation generation: `bash tools/codegen/new_codegen.sh foundation`
- [ ] Verify all 36 files are now generated
- [ ] Run foundation build: `bash tools/codegen/new_codegen.sh --verify foundation`
- [ ] Fix any regressions

### Step 4: Documentation & Delivery

- [ ] Update `taskplane-tasks/codegen/CONTEXT.md` — update file generation counts
- [ ] Discoveries logged in STATUS.md

## Documentation Requirements

**Must Update:**
- `taskplane-tasks/codegen/CONTEXT.md` — update legacy-only file counts

## Completion Criteria

- [ ] All steps complete
- [ ] All Python tests passing
- [ ] Common build gate passes
- [ ] All 36 interface files generated for the 9 missing interfaces
- [ ] Generated files match legacy structure
- [ ] Documentation updated

## Git Commit Convention

- **Step completion:** `feat(CG-056): complete Step N — description`
- **Bug fixes:** `fix(CG-056): description`
- **Hydration:** `hydrate: CG-056 expand Step N checkboxes`

## Do NOT

- Modify handwritten `.c` files in `library/foundation/src/`
- Commit generated `library/common/**` or `library/foundation/**` outputs
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
