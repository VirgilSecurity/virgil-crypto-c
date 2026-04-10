# Task: CG-047 - Resolve impl/tag Enum in IR

**Created:** 2026-04-10
**Size:** M

## Review Level: 1 (Plan Only)

**Assessment:** Adds new IR capability (synthetic enum from impl tag). Moderate pattern novelty — extends IR and source parsing, but follows established entity patterns.
**Score:** 2/8 — Blast radius: 1, Pattern novelty: 1, Security: 0, Reversibility: 0

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-047-resolve-impl-tag-enum/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Resolve the `impl/tag` enum so that the 2 currently skipped foundation modules (`c_module_vscf_key.xml` and `c_module_vscf_key_api.xml`) can be generated. These modules skip with the error `'enum not found in IR: impl/tag'` because the `impl/tag` enum is a synthetic/generated enum that lives in the implementation infrastructure (`vscf_impl.h`) rather than being a standalone entity in the XML models.

The legacy codegen generates an `impl_tag` enum from the set of all implementations in a project. The new codegen needs to either:
1. Synthesize this enum in the IR from the set of known implementations, or
2. Register it as a known external type that resolves without being in the IR

**Approach decision:** The worker should investigate both options during preflight and choose the one that best fits the existing IR architecture. Option 1 (synthetic enum) is likely cleaner since other code may need to reference `impl/tag` values.

## Dependencies

- **Task:** CG-045 (implementation constructor generation — establishes impl IR patterns)

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3 (load only if needed):**
- `docs/adr/0002-project-rooted-codegen-pipeline.md` — architecture of the project-rooted pipeline

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** cmake build system configured

## File Scope

- `tools/codegen/project_ir.py`
- `tools/codegen/project_c_backend.py`
- `tools/codegen/common_source.py`
- `tools/codegen/common_bootstrap.py`

## Steps

### Step 0: Preflight

- [ ] Confirm the 2 module skips: run `python3 tools/codegen/common_bootstrap.py --project foundation` and verify `c_module_vscf_key.xml` and `c_module_vscf_key_api.xml` skip with `impl/tag` error
- [ ] Examine how `impl/tag` is referenced in the XML models for these modules
- [ ] Examine how the legacy codegen generates the `vscf_impl_tag_t` enum (look at `library/foundation/include/virgil/crypto/foundation/vscf_impl_tag.h`)
- [ ] Decide approach: synthetic IR enum vs external type registration

### Step 1: Implement impl/tag enum resolution

> ⚠️ Hydrate: Expand based on approach chosen in Step 0

- [ ] impl/tag enum resolves in the IR or type system
- [ ] `c_module_vscf_key.xml` generates successfully
- [ ] `c_module_vscf_key_api.xml` generates successfully
- [ ] No new module skips introduced

**Artifacts:**
- `tools/codegen/project_ir.py` (modified)
- `tools/codegen/project_c_backend.py` (modified — if type resolution changes needed)
- Possibly `tools/codegen/common_source.py` (modified — if source parsing changes needed)

### Step 2: Testing & Verification

> ZERO test failures allowed.

- [ ] Run FULL Python test suite: `PYTHONPATH=. python3 -m unittest discover -s tools/codegen -p "test_*.py"`
- [ ] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Run foundation codegen: `python3 tools/codegen/common_bootstrap.py --project foundation` — confirm 0 unexpected skips
- [ ] Run foundation build: `bash tools/codegen/new_codegen.sh --verify foundation` — check for new errors
- [ ] Fix any regressions
- [ ] Update `KNOWN_SKIPS` in `common_bootstrap.py` if the 2 modules are no longer skipped

### Step 3: Documentation & Delivery

- [ ] Update `taskplane-tasks/codegen/CONTEXT.md` — remove "Known module skips" tech debt item, update status
- [ ] Update `docs/codegen-migration/common-direct-foundation-status.md` if applicable
- [ ] Discoveries logged in STATUS.md

## Documentation Requirements

**Must Update:**
- `taskplane-tasks/codegen/CONTEXT.md` — remove `impl/tag` module skips from tech debt, update CG-047 status

**Check If Affected:**
- `docs/codegen-migration/common-direct-foundation-status.md` — update module coverage numbers

## Completion Criteria

- [ ] All steps complete
- [ ] All Python tests passing
- [ ] Common build gate passes
- [ ] `c_module_vscf_key.xml` and `c_module_vscf_key_api.xml` generate without errors
- [ ] No new unexpected module skips
- [ ] Documentation updated

## Git Commit Convention

- **Step completion:** `feat(CG-047): complete Step N — description`
- **Bug fixes:** `fix(CG-047): description`
- **Hydration:** `hydrate: CG-047 expand Step N checkboxes`

## Do NOT

- Modify the legacy `vscf_impl_tag.h` or any checked-in library files
- Commit generated `library/common/**` or `library/foundation/**` outputs
- Change how other enum types are resolved (only add impl/tag support)
- Remove KNOWN_SKIPS entries until the modules actually generate successfully
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
