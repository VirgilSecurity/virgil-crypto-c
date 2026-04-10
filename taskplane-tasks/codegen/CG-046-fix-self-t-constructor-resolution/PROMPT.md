# Task: CG-046 - Fix vscf_self_t Constructor Type Resolution

**Created:** 2026-04-10
**Size:** S

## Review Level: 1 (Plan Only)

**Assessment:** Single-file bug fix in codegen backend. Low blast radius, existing patterns, straightforward resolution.
**Score:** 1/8 — Blast radius: 0, Pattern novelty: 1, Security: 0, Reversibility: 0

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-046-fix-self-t-constructor-resolution/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Fix 4 foundation build errors caused by `vscf_self_t` being used in generated public header declarations. The `class="self"` constructor argument attribute resolves to `vscf_self_t` — a type alias that only exists inside legacy internal `.c` files, not in public headers. The codegen must resolve `class="self"` arguments to the concrete implementation type (e.g., `vscf_raw_public_key_t *`) in generated header declarations.

**The 4 errors (all in generated headers after CG-045):**
- `vscf_raw_public_key.h:189` — `vscf_raw_public_key_init_with_redefined_impl_tag` uses `vscf_self_t`
- `vscf_raw_public_key.h:197` — `vscf_raw_public_key_new_with_redefined_impl_tag` uses `vscf_self_t`
- `vscf_raw_private_key.h:189` — `vscf_raw_private_key_init_with_redefined_impl_tag` uses `vscf_self_t`
- `vscf_raw_private_key.h:197` — `vscf_raw_private_key_new_with_redefined_impl_tag` uses `vscf_self_t`

**Root cause:** In `project_c_backend.py`, the argument type resolution for implementation constructors encounters `class="self"` in the XML model (`<argument name="other" class="self" access="readonly"/>`). This must resolve to `const {impl_type_t} *` (e.g., `const vscf_raw_public_key_t *`), not `const vscf_self_t *`.

**Reference:** Check how class constructors handle `class="self"` arguments — they likely resolve to the class's concrete type. Apply the same pattern for implementation constructors.

## Dependencies

- **Task:** CG-045 (implementation constructor generation)

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** cmake build system configured

## File Scope

- `tools/codegen/project_c_backend.py`

## Steps

### Step 0: Preflight

- [ ] Reproduce the 4 build errors: run `bash tools/codegen/new_codegen.sh --verify foundation` and confirm 4 `vscf_self_t` errors
- [ ] Locate where `class="self"` is resolved in argument type generation (search `_render_c_param`, `argument_from_source`, `_arg_from_attrs` in `project_c_backend.py` and `project_ir.py`)
- [ ] Check how class constructors resolve self-referential arguments for comparison

### Step 1: Fix self-type resolution for implementation constructors

- [ ] Modify the argument type resolution so `class="self"` resolves to the implementation's concrete type (e.g., `vscf_raw_public_key_t`) instead of `vscf_self_t`
- [ ] Ensure both `init_with_X` and `new_with_X` declarations use the resolved concrete type
- [ ] Ensure the `const` and pointer qualifiers are preserved correctly (the argument has `access="readonly"`)
- [ ] Run targeted test: `PYTHONPATH=. python3 -m unittest discover -s tools/codegen -p "test_impl_rendering.py"`

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)
- Possibly `tools/codegen/project_ir.py` (modified, if resolution happens at IR level)

### Step 2: Testing & Verification

> ZERO test failures allowed.

- [ ] Run FULL Python test suite: `PYTHONPATH=. python3 -m unittest discover -s tools/codegen -p "test_*.py"`
- [ ] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Run foundation build: `bash tools/codegen/new_codegen.sh --verify foundation` — confirm 0 `vscf_self_t` errors
- [ ] Fix any regressions

### Step 3: Documentation & Delivery

- [ ] Update `taskplane-tasks/codegen/CONTEXT.md` if applicable
- [ ] Discoveries logged in STATUS.md

## Documentation Requirements

**Must Update:**
- `taskplane-tasks/codegen/CONTEXT.md` — update CG-046 status in planned task sequence

**Check If Affected:**
- `docs/codegen-migration/common-direct-foundation-status.md` — update if foundation build errors change

## Completion Criteria

- [ ] All steps complete
- [ ] All 159 Python tests passing
- [ ] Common build gate passes
- [ ] Foundation build: 0 `vscf_self_t` errors (down from 4)
- [ ] Documentation updated

## Git Commit Convention

- **Step completion:** `feat(CG-046): complete Step N — description`
- **Bug fixes:** `fix(CG-046): description`
- **Hydration:** `hydrate: CG-046 expand Step N checkboxes`

## Do NOT

- Change class constructor generation (only fix implementation constructor type resolution)
- Modify IR dataclass structure
- Commit generated `library/common/**` or `library/foundation/**` outputs
- Expand scope beyond the 4 `vscf_self_t` errors
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
