# Task: CG-049 - Systematic Header Parity: VSCF_NODISCARD, Visibility, Const Qualifiers

**Created:** 2026-04-10
**Size:** M

## Review Level: 1 (Plan Only)

**Assessment:** Systematic fixes across the C backend for three well-understood diff patterns. Moderate blast radius (affects all generated headers) but all patterns are mechanical fixes.
**Score:** 2/8 — Blast radius: 1, Pattern novelty: 1, Security: 0, Reversibility: 0

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-049-header-parity-nodiscard-visibility-const/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Fix three systematic diff patterns between new codegen output and legacy headers that cause (or will cause) compilation errors across all foundation modules. These are documented as patterns A, F, and G in CONTEXT.md's Foundation Diff Analysis.

**Pattern A — `VSCF_NODISCARD` missing (190 occurrences):**
The legacy codegen emits `VSCF_NODISCARD` on functions that return `vscf_status_t` (error codes that must be checked). The new codegen omits this attribute. Fix: detect methods returning `vscf_status_t` (or the project-specific status type) and append `VSCF_NODISCARD` to the declaration.

**Pattern F — Const qualifier mismatches (~1488 lines):**
Generated header declarations use different `const` qualifiers than legacy. Common cases:
- `const vscf_impl_t *` in generated header vs `vscf_impl_t *` in legacy (or vice versa)
- Method parameters and return types have inconsistent const-ness
Fix: match the const qualifiers from the XML model's `access` attribute (`readonly` → `const`, `readwrite`/`disown` → non-const) to what the legacy code expects. Compare generated vs legacy headers for representative modules to identify the rule.

**Pattern G — Visibility mismatches (~1133 lines, `VSCF_PUBLIC` vs `VSCF_PRIVATE`):**
Generated headers declare functions with different visibility than legacy. The XML model has a `visibility` attribute on methods — the codegen may not be reading or applying it correctly.
Fix: ensure the codegen reads the `visibility` attribute from the model and emits the correct `VSCF_PUBLIC` or `VSCF_PRIVATE` marker. For methods without an explicit visibility, apply the correct default (typically `VSCF_PUBLIC` for interface methods, `VSCF_PRIVATE` for internal helpers).

## Dependencies

- **Task:** CG-046 (established self-type resolution patterns)
- **Task:** CG-047 (established impl/tag enum patterns)

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md` — specifically the "Foundation Diff Analysis" section

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** cmake build system configured

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/project_ir.py`
- `tools/codegen/common_source.py`

## Steps

### Step 0: Preflight

- [ ] Run `bash tools/codegen/new_codegen.sh --verify foundation` and capture baseline error count
- [ ] Diff 3-4 representative module headers (legacy vs new codegen) to confirm the three patterns:
  - A simple class: e.g. `vscf_sha256.h`
  - An implementation: e.g. `vscf_aes256_gcm.h`
  - An interface dispatch: e.g. `vscf_key_alg.h`
  - A complex impl: e.g. `vscf_ecc.h`
- [ ] Trace each pattern to the codegen code that emits declarations
- [ ] Identify the XML model attributes that control NODISCARD, const, and visibility

### Step 1: Fix VSCF_NODISCARD emission (Pattern A)

- [ ] Identify which methods should have `VSCF_NODISCARD` (return `vscf_status_t` or project status type)
- [ ] Emit `VSCF_NODISCARD` in method declarations for those methods
- [ ] Verify against legacy headers for a few representative modules
- [ ] Run targeted test after fix

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 2: Fix const qualifier parity (Pattern F)

- [ ] Identify const rules from XML model `access` attributes and legacy patterns
- [ ] Fix parameter const qualifiers in generated declarations to match legacy
- [ ] Fix return type const qualifiers where applicable
- [ ] Verify against legacy headers for representative modules
- [ ] Run targeted test after fix

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)
- Possibly `tools/codegen/project_ir.py` (modified)

### Step 3: Fix visibility parity (Pattern G)

- [ ] Identify visibility rules from XML model `visibility` attribute
- [ ] Fix `VSCF_PUBLIC` / `VSCF_PRIVATE` emission to match legacy
- [ ] Apply correct defaults for methods without explicit visibility
- [ ] Verify against legacy headers for representative modules
- [ ] Run targeted test after fix

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)
- Possibly `tools/codegen/common_source.py` (modified — if visibility needs parsing)

### Step 4: Testing & Verification

> ZERO test failures allowed.

- [ ] Run FULL Python test suite: `PYTHONPATH=. python3 -m unittest discover -s tools/codegen -p "test_*.py"`
- [ ] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Run foundation build: `bash tools/codegen/new_codegen.sh --verify foundation`
- [ ] Count remaining errors and compare to baseline — document improvement
- [ ] Fix any regressions

### Step 5: Documentation & Delivery

- [ ] Update `taskplane-tasks/codegen/CONTEXT.md` — update diff pattern status
- [ ] Discoveries logged in STATUS.md

## Documentation Requirements

**Must Update:**
- `taskplane-tasks/codegen/CONTEXT.md` — update patterns A, F, G status in Foundation Diff Analysis

**Check If Affected:**
- `docs/codegen-migration/common-direct-foundation-status.md` — update if build error count changes

## Completion Criteria

- [ ] All steps complete
- [ ] All Python tests passing (159+)
- [ ] Common build gate passes
- [ ] VSCF_NODISCARD emitted on status-returning methods (pattern A resolved)
- [ ] Const qualifiers match legacy for generated declarations (pattern F resolved or significantly reduced)
- [ ] Visibility markers match legacy (pattern G resolved or significantly reduced)
- [ ] Documentation updated

## Git Commit Convention

- **Step completion:** `feat(CG-049): complete Step N — description`
- **Bug fixes:** `fix(CG-049): description`
- **Hydration:** `hydrate: CG-049 expand Step N checkboxes`

## Do NOT

- Modify handwritten `.c` files in `library/foundation/src/`
- Commit generated `library/common/**` or `library/foundation/**` outputs
- Change Pattern C behavior (`(void(*)(void))` vtable casts — new codegen is correct)
- Fix patterns B, D, E, H (those are CG-048/CG-050 scope)
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
