# Task: CG-062 - Resolve Model Defaults at Load Time

**Created:** 2026-04-12
**Size:** L

## Review Level: 2 (Plan + Code)

**Assessment:** Structural refactor that moves default resolution from scattered render-time checks in `project_c_backend.py` to a single pass in `project_ir.py`. High impact — touches the data flow between IR and backend. Eliminates ~42 `is_value_type` checks, ~6 duplicated access-default blocks, and multiple `data`/`buffer` special cases in the backend.
**Score:** 4/8 — Blast radius: 2, Pattern novelty: 2, Security: 0, Reversibility: 0

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-062-resolve-defaults-at-load-time/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Move model default resolution from render-time (scattered across `project_c_backend.py`) to load-time (single pass in `project_ir.py`). After this refactor, the IR will have **no None values** for `access`, `is_reference`, or lifecycle attributes — all defaults are resolved when the IR is built.

### Current Problem

The legacy GSL codegen resolves defaults in `component.gsl` before any C code generation happens. The new codegen skips this step — it stores `None` for unset attributes and resolves defaults at render time. This causes:

1. **42+ `is_value_type` checks** scattered across `project_c_backend.py`
2. **6+ duplicated access-default blocks** (buffer→writeonly, data→readonly, etc.)
3. **Hardcoded `data` fallbacks** in 3 places for cross-project value-type resolution
4. **Bugs** when a render path forgets to apply defaults (e.g., the `raw_private_key` const issue)
5. **Fragile code** — every new renderer must re-implement the same default logic

### Legacy GSL Defaults (from `component.gsl`)

The following defaults must be resolved at IR load time:

#### `is_reference` (pointer vs value)

| Type | Default |
|------|---------|
| `class` (general) | `True` (pointer) |
| `class="data"` | `False` (value — `vsc_data_t` passed by value) |
| `class="buffer"` | `True` (pointer) |
| `interface` / `impl` / `api` | `True` (pointer) |
| `type` / `enum` / `callback` | `False` (value) |

#### `access` (ownership/mutability)

| Context | Default |
|---------|---------|
| General | `"readonly"` |
| `class="data"` (any context) | `"readonly"` |
| `class="buffer"` + argument | `"writeonly"` |
| `class="buffer"` + return | `"disown"` |
| `class="buffer"` + property/variable | `"readwrite"` |
| `interface`/`impl` self argument in `is_const` method | `"readonly"` |
| `interface`/`impl` self argument in non-const method | `"readwrite"` |
| `impl` return in `is_const` method | `"readonly"` |
| `impl` return in non-const method | `"readwrite"` |

#### `context` / lifecycle

| Attribute | Default | Notes |
|-----------|---------|-------|
| `context="none"` | No lifecycle methods, no struct, static utility class | `alg_factory`, `base64`, `pem`, etc. |
| `context="public"` (default) | Full lifecycle | Most classes |

### Also Fix: Remaining 23 Build Errors

After resolving defaults, the remaining 23 foundation build errors should be addressed:

1. **`alg_factory` / `base64` (21 errors):** `context="none"` classes should NOT generate lifecycle methods or struct definitions. Currently the codegen emits init/cleanup/new/delete and a struct typedef for these, causing "incomplete type" errors in the handwritten `.c` files that use `sizeof`.
2. **`brainkey_client` (2 errors):** Missing `#include <mbedtls/ecp.h>` for the `mbedtls_ecp_group` library type used in a property.

## Dependencies

None — all prior tasks completed.

## Context to Read First

**Tier 1 (essential):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 2 (reference):**
- `codegen/component.gsl` — legacy default resolution (lines 660-900). This is the source of truth for what defaults should be.
- `codegen/c_component.gsl` — legacy C-layer mapping (lines 478-730). Maps resolved defaults to C attributes.

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** cmake build system configured

## File Scope

- `tools/codegen/project_ir.py` (primary — add default resolution pass)
- `tools/codegen/project_c_backend.py` (simplify — remove scattered default checks)
- `tools/codegen/project_source.py` (if defaults need model-level info)

## Steps

### Step 0: Preflight

- [ ] Catalog all places in `project_c_backend.py` that resolve defaults (search for `is_value_type`, `effective_access`, `access is None`, `access == None`, `buffer.*writeonly`, `data.*readonly`, hardcoded fallback)
- [ ] Map each to the corresponding legacy GSL rule from `component.gsl`
- [ ] Verify the legacy rules against the resolved XML output for 3-4 sample modules
- [ ] Plan the default resolution pass location in `project_ir.py`

### Step 1: Add default resolution pass in `project_ir.py`

> ⚠️ Hydrate: Expand based on catalog from Step 0

- [ ] Add `resolve_defaults()` function that runs after `project_to_ir()` builds the IR
- [ ] Resolve `is_reference` defaults for all arguments, returns, properties
- [ ] Resolve `access` defaults for all arguments, returns, properties (context-aware: argument vs return vs property)
- [ ] Resolve `access` for method self arguments based on `is_const`
- [ ] Resolve `access` for impl method returns based on `is_const` (const method → readonly, non-const → readwrite for class/impl returns)
- [ ] Mark `context="none"` classes with `lifecycle="none"` or equivalent flag
- [ ] Ensure cross-project classes (`data`, `buffer` from common) are handled
- [ ] Run tests after this step to catch any regressions from changed IR

### Step 2: Simplify `project_c_backend.py`

- [ ] Remove all `effective_access` default resolution blocks (6+ occurrences)
- [ ] Remove hardcoded `data` value-type fallbacks (3 occurrences)
- [ ] Simplify `is_value_type` checks — read from IR attribute, don't re-derive
- [ ] Remove buffer/data special-casing in argument/return rendering
- [ ] Simplify `return_from_source` and `argument_from_source` — trust IR defaults
- [ ] Fix `context="none"` class rendering — skip lifecycle methods and struct when context is none
- [ ] Fix `brainkey_client` missing include for library types in properties
- [ ] Ensure no `None` access/is_reference values reach the rendering layer

### Step 3: Verification

> ZERO test failures allowed.

- [ ] Run FULL Python test suite: `PYTHONPATH=. python3 -m unittest discover -s tools/codegen -p "test_*.py"`
- [ ] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Run foundation build: `bash tools/codegen/new_codegen.sh --verify foundation`
- [ ] Verify 0 foundation build errors (down from 23)
- [ ] Diff 10+ generated headers against legacy to verify parity is maintained
- [ ] Fix any regressions

### Step 4: Documentation & Delivery

- [ ] Update `taskplane-tasks/codegen/CONTEXT.md` — document the defaults resolution architecture
- [ ] Document the default rules in a code comment at the top of the resolution function
- [ ] Discoveries logged in STATUS.md

## Documentation Requirements

**Must Update:**
- `taskplane-tasks/codegen/CONTEXT.md` — update architecture section, note defaults refactor

**Check If Affected:**
- `docs/codegen-migration/common-direct-foundation-status.md`

## Completion Criteria

- [ ] All steps complete
- [ ] All Python tests passing
- [ ] Common build gate passes
- [ ] Foundation build: 0 errors (down from 23)
- [ ] No `None` values for `access` or `is_reference` in IR output
- [ ] Backend has zero `effective_access` default blocks
- [ ] Backend has zero hardcoded `data`/`buffer` class special-cases for defaults
- [ ] Documentation updated

## Git Commit Convention

- **Step completion:** `feat(CG-062): complete Step N — description`
- **Bug fixes:** `fix(CG-062): description`
- **Hydration:** `hydrate: CG-062 expand Step N checkboxes`

## Do NOT

- Modify handwritten `.c` files in `library/foundation/src/`
- Commit generated `library/common/**` or `library/foundation/**` outputs
- Change the default RULES — only change WHERE they are applied (load time vs render time)
- Break existing generated output parity (diff before and after for key files)
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
