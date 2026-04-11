# Task: CG-051 - Generate Interface Dispatch `.c` Bodies

**Created:** 2026-04-11
**Size:** L

## Review Level: 1 (Plan Only)

**Assessment:** New codegen feature — generating interface dispatch function implementations. Large surface area (164 functions across ~8 dispatch files) but mechanically uniform. The dispatch pattern is well-established in the legacy code.
**Score:** 3/8 — Blast radius: 2, Pattern novelty: 1, Security: 0, Reversibility: 0

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-051-generate-interface-dispatch-bodies/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Generate the interface dispatch `.c` function bodies that are currently missing from the new codegen output. The legacy codegen produces full dispatch implementations in files like `vscf_generate_key.c`, `vscf_sign_hash.c`, `vscf_cipher.c`, etc. Each dispatch function follows a uniform pattern:

1. Validate arguments (assertions)
2. Look up the API struct from the `impl` pointer
3. Assert the callback pointer is non-NULL
4. Call through the callback (e.g., `api->generate_key_cb(...)`)
5. Return the result

This is Pattern E from the Foundation Diff Analysis — 164 missing function implementations across ~8 interface dispatch `.c` files. These cause **link errors** in the foundation build.

**Current state:** The codegen already generates interface dispatch `.h` headers (CG-033/040). This task adds the corresponding `.c` bodies.

## Dependencies

None — can run independently.

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`
- `taskplane-tasks/codegen/CG-033-render-interface-modules/STATUS.md` — prior interface rendering work

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** cmake build system configured

## File Scope

- `tools/codegen/project_c_backend.py` (primary)
- `tools/codegen/project_ir.py` (if interface IR needs new fields)

## Steps

### Step 0: Preflight

- [ ] Study 2-3 legacy interface dispatch `.c` files to extract the dispatch pattern:
  - `library/foundation/src/vscf_cipher.c` (simple interface)
  - `library/foundation/src/vscf_generate_key.c`
  - `library/foundation/src/vscf_sign_hash.c`
- [ ] Identify the exact dispatch pattern: argument validation, API lookup, callback invocation, return handling
- [ ] Check how the existing header generation in `project_c_backend.py` handles interface methods — locate the renderer
- [ ] Inventory all interface dispatch files that need `.c` body generation (the 8 files from the diff analysis, plus any others)

### Step 1: Implement dispatch body renderer

> ⚠️ Hydrate: Expand based on patterns identified in Step 0

- [ ] Add a `.c` body renderer for interface dispatch functions in `project_c_backend.py`
- [ ] Handle the standard dispatch pattern: validate → lookup API → assert callback → call → return
- [ ] Handle `vscf_status_t` return (with NODISCARD) vs void return vs value return
- [ ] Handle `const` correctness in dispatch arguments
- [ ] Handle `self` parameter casting (from `vscf_impl_t *` to API access)
- [ ] Wire the new renderer into the interface module output (alongside the existing `.h` output)

### Step 2: Verification

> ZERO test failures allowed.

- [ ] Run FULL Python test suite: `PYTHONPATH=. python3 -m unittest discover -s tools/codegen -p "test_*.py"`
- [ ] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Run foundation build: `bash tools/codegen/new_codegen.sh --verify foundation`
- [ ] Diff generated dispatch `.c` files against legacy to verify pattern match
- [ ] Confirm link errors from Pattern E are resolved
- [ ] Fix any regressions

### Step 3: Documentation & Delivery

- [ ] Update `taskplane-tasks/codegen/CONTEXT.md` — mark Pattern E resolved, update file generation counts
- [ ] Update diff analysis table if applicable
- [ ] Discoveries logged in STATUS.md

## Documentation Requirements

**Must Update:**
- `taskplane-tasks/codegen/CONTEXT.md` — update Pattern E status and foundation build status

**Check If Affected:**
- `docs/codegen-migration/common-direct-foundation-status.md`

## Completion Criteria

- [ ] All steps complete
- [ ] All Python tests passing
- [ ] Common build gate passes
- [ ] Foundation build: 0 link errors from missing dispatch function bodies
- [ ] Generated dispatch `.c` files match legacy pattern
- [ ] Documentation updated

## Git Commit Convention

- **Step completion:** `feat(CG-051): complete Step N — description`
- **Bug fixes:** `fix(CG-051): description`
- **Hydration:** `hydrate: CG-051 expand Step N checkboxes`

## Do NOT

- Modify handwritten `.c` files in `library/foundation/src/`
- Commit generated `library/common/**` or `library/foundation/**` outputs
- Change the existing interface `.h` header generation (only add `.c` body generation)
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
