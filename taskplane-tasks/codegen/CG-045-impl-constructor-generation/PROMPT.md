# Task: CG-045 - Implementation Constructor Generation

**Created:** 2026-04-10
**Size:** M

## Review Level: 1 (Plan Only)

**Assessment:** Extends existing class constructor generation pattern to implementations. Low blast radius, established patterns, no security or reversibility concerns.
**Score:** 1/8 — Blast radius: 1, Pattern novelty: 0, Security: 0, Reversibility: 0

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-045-impl-constructor-generation/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Add constructor generation (`init_with_X` and `new_with_X` methods) for `IRImplementation` entities in the C backend. The codegen already generates constructors for `IRClass` — this task extends the same pattern to implementations. Currently, 4 foundation build errors occur because `cipher_alg_info_new_with_members` (and similar implementation constructors) are called but never declared or defined. This is the last remaining blocker for a clean foundation build.

## Dependencies

- **Task:** CG-044 (foundation codegen verification — fixes merged, constructor gap identified)

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3 (load only if needed):**
- `docs/codegen-migration/common-direct-foundation-status.md` — current foundation codegen status

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** cmake build system configured

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/project_ir.py`
- `taskplane-tasks/codegen/CONTEXT.md`
- `docs/codegen-migration/common-direct-foundation-status.md`

## Steps

### Step 0: Preflight

- [ ] Read existing class constructor generation in `project_c_backend.py` (search `class_constructor_symbol`, `_lifecycle_constructor_init_body`, `_lifecycle_constructor_new_body`)
- [ ] Read `IRImplementation` dataclass in `project_ir.py` — confirm `constructors` field is populated from source models
- [ ] Identify which implementations have constructors by examining foundation XML models (e.g. `cipher_alg_info` has `<constructor name="with members">`)
- [ ] Run `bash tools/codegen/build_common_with_new_codegen.sh` to confirm baseline passes
- [ ] Run foundation codegen to confirm the 4 constructor-related errors exist

### Step 1: Generate implementation constructor declarations and definitions

- [ ] Add `impl_constructor_symbol` and `_impl_new_constructor_symbol` helper functions (mirror `class_constructor_symbol` / `_class_new_constructor_symbol` but for `IRImplementation`)
- [ ] Generate `init_with_X` function declarations in implementation header (public API)
- [ ] Generate `new_with_X` function declarations in implementation header (public API)
- [ ] Generate `init_with_X` function definitions in implementation C module
- [ ] Generate `new_with_X` function definitions in implementation C module
- [ ] Ensure constructor parameter types resolve correctly (use existing `_render_c_param` / argument resolution)
- [ ] Run targeted test: `python3 tools/codegen/test_impl_rendering.py` after changes
- [ ] Commit after step

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 2: Testing & Verification

> ZERO test failures allowed. This step runs the FULL test suite as a quality gate.

- [ ] Run FULL Python test suite: `python3 -m pytest tools/codegen/test_*.py -v` (or run each test file individually)
- [ ] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Run foundation codegen and verify the 4 constructor errors are resolved
- [ ] Attempt foundation build — confirm constructor-related errors are gone
- [ ] Fix any new failures introduced by the changes

### Step 3: Documentation & Delivery

- [ ] Update `taskplane-tasks/codegen/CONTEXT.md` — remove impl constructor tech debt item, update foundation status
- [ ] Update `docs/codegen-migration/common-direct-foundation-status.md` if applicable
- [ ] Discoveries logged in STATUS.md

## Documentation Requirements

**Must Update:**
- `taskplane-tasks/codegen/CONTEXT.md` — remove "Implementation constructor generation" from Technical Debt, update Current State

**Check If Affected:**
- `docs/codegen-migration/common-direct-foundation-status.md` — update foundation build status if errors resolved

## Completion Criteria

- [ ] All steps complete
- [ ] All Python tests passing
- [ ] Common build gate passes
- [ ] Foundation constructor-related build errors resolved (specifically `cipher_alg_info_new_with_members`)
- [ ] Documentation updated

## Git Commit Convention

Commits happen at **step boundaries** (not after every checkbox). All commits
for this task MUST include the task ID for traceability:

- **Step completion:** `feat(CG-045): complete Step N — description`
- **Bug fixes:** `fix(CG-045): description`
- **Tests:** `test(CG-045): description`
- **Hydration:** `hydrate: CG-045 expand Step N checkboxes`

## Do NOT

- Expand task scope — add tech debt to CONTEXT.md instead
- Skip tests
- Modify class constructor generation (only add implementation constructor generation)
- Change existing IR dataclass structure (constructors field already exists)
- Commit generated `library/common/**` or `library/foundation/**` outputs
- Load docs not listed in "Context to Read First"
- Commit without the task ID prefix in the commit message

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution.
     Format:
     ### Amendment N — YYYY-MM-DD HH:MM
     **Issue:** [what was wrong]
     **Resolution:** [what was changed] -->
