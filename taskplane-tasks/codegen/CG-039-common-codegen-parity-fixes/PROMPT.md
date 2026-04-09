# Task: CG-039 - Fix Common Project Codegen Parity Issues

**Created:** 2026-04-08
**Size:** M

## Review Level: 2 (Plan and Code)

**Assessment:** Fixes 9 distinct parity issues across the C emitter and backend that cause differences between new codegen output and the legacy GSL output for the `common` project. All changes are in rendering/emitting code. The verification gate is `bash tools/codegen/new_codegen.sh --verify common` with zero diff outside generated blocks.
**Score:** 4/8 — Blast radius: 2, Pattern novelty: 1, Security: 0, Reversibility: 1

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-039-common-codegen-parity-fixes/
├── PROMPT.md   ← This file
├── STATUS.md   ← Execution state
├── .reviews/   ← Reviewer output
└── .DONE       ← Created when complete
```

## Mission

Achieve zero-diff parity between new codegen output and legacy GSL output for the `common` project. Running `bash tools/codegen/new_codegen.sh --verify common` currently shows 8 files with differences outside generated blocks. After this task, the diff check step should report 0 non-generated changes (clang-format whitespace-only changes are acceptable).

### Issue inventory (from `--verify` diff output):

**1. Unresolved placeholder in descriptions** (`vsc_memory.h/.c`)
- `.(c_global_method_erase)()` appears literally instead of being resolved to `vsc_erase()`
- Root cause: module description text contains GSL-style placeholders that the C emitter passes through without resolution
- Fix: resolve placeholders in description text the same way method code is resolved

**2. Macro name-paren spacing** (`vsc_library.h`)
- `VSC_CEIL(x,y)` → `VSC_CEIL (x,y)`, `VSC_UNUSED(x)` → `VSC_UNUSED (x)`
- Space inserted between macro name and `(` in `#define`
- Root cause: macro/code rendering adds space before `(`
- Fix: preserve original macro formatting — no space before `(` in function-like macros

**3. Constant name casing** (`vsc_library.h`)
- `vsc_POINTER_SIZE` → `VSC_POINTER_SIZE`
- Root cause: constant name rendering applies wrong case transformation
- Fix: use the resolved name from the XML, or apply correct casing rules

**4. Missing byte typedef guard** (`vsc_library.h`)
- Legacy: `#ifndef BYTE_DEFINED` / `#define BYTE_DEFINED` / `typedef uint8_t byte;` / `#endif`
- New: bare `typedef uint8_t byte;` without guard
- Root cause: the conditional guard for the byte typedef is not emitted
- Fix: emit the `#ifndef BYTE_DEFINED` guard around the byte typedef

**5. Struct typedef style for value types** (`vsc_data.h`)
- Legacy: `typedef struct vsc_data_t vsc_data_t;` then `struct vsc_data_t { ... };`
- New: `typedef struct vsc_data_t { ... } vsc_data_t;`
- Root cause: the C emitter's `render_struct_full()` uses a different typedef pattern
- Fix: for structs with `declaration="public"` and `definition="public"`, use the legacy two-line pattern

**6. Method ordering — lifecycle vs constructors** (`vsc_buffer.h/.c`)
- Legacy order: init, cleanup, new, init_with_capacity, new_with_capacity, init_with_data, new_with_data, delete, destroy, shallow_copy
- New order: init, cleanup, new, delete, destroy, shallow_copy, init_with_capacity, new_with_capacity, init_with_data, new_with_data
- Root cause: `_render_reference_class_support()` emits delete/destroy/shallow_copy before constructor variants
- Fix: reorder to emit constructor variants between `new` and `delete`, matching GSL output

**7. Destroy method description** (`vsc_buffer.h/.c`)
- Legacy: `This is a reverse action of the function 'vsc_buffer_new ()'.`
- New: `This is a reverse action of the function 'new ()'.`
- Root cause: destroy description uses bare `new` instead of fully-qualified function name
- Fix: use the full `{prefix}_{class}_new ()` name in the destroy description

**8. init_ctx description reference** (`vsc_buffer.c`)
- Legacy: `method vsc_buffer_init() is called`
- New: `method init() is called`
- Root cause: init_ctx description uses bare `init` instead of fully-qualified name
- Fix: use full `{prefix}_{class}_init()` name in init_ctx/cleanup_ctx descriptions

**9. Trailing blank lines** (all files)
- Legacy files end with 2 blank lines after the last `#endif`
- New files end with 0 or 1 blank lines
- Root cause: the C emitter's `generate_block()` doesn't match trailing whitespace
- Fix: ensure generated output preserves original trailing whitespace pattern

## Dependencies

- **None**

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3 (load only if needed):**
- `tools/codegen/common_bootstrap.py` — C emitter with render functions
- `tools/codegen/project_c_backend.py` — backend renderers

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** None

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/common_bootstrap.py`

## Steps

### Step 0: Preflight

- [ ] Run `bash tools/codegen/new_codegen.sh --verify common` and capture the full diff output
- [ ] Catalog each diff and map to the issue list above
- [ ] Identify the exact function/line in the renderer responsible for each issue

### Step 1: Fix backend rendering issues (project_c_backend.py)

Issues 6, 7, 8 are in the backend:

- [ ] Fix method ordering: emit constructor variants (init_with_X, new_with_X) between `new` and `delete` in `_render_reference_class_support()`
- [ ] Fix destroy description: use `{prefix}_{class}_new ()` instead of bare `new ()`
- [ ] Fix init_ctx/cleanup_ctx descriptions: use fully-qualified method names
- [ ] Commit

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 2: Fix C emitter rendering issues (common_bootstrap.py)

Issues 1, 2, 3, 4, 5, 9 are in the emitter:

- [ ] Fix placeholder resolution in description text (issue 1)
- [ ] Fix macro name-paren spacing — no space before `(` in function-like macros (issue 2)
- [ ] Fix constant name casing (issue 3)
- [ ] Fix byte typedef guard emission (issue 4)
- [ ] Fix struct typedef pattern for value types (issue 5)
- [ ] Fix trailing blank lines (issue 9)
- [ ] Commit

**Artifacts:**
- `tools/codegen/common_bootstrap.py` (modified)

### Step 3: Testing & Verification

> ZERO test failures allowed. The gate is `--verify` with zero non-generated diff.

- [ ] Run `bash tools/codegen/new_codegen.sh --verify common` — zero warnings about non-generated changes
- [ ] Run all Python tests: `python3 -m unittest discover -s tools/codegen -p "test_*.py" -v`
- [ ] Build gate passes
- [ ] Fix all failures

### Step 4: Documentation & Delivery

- [ ] Discoveries logged in STATUS.md
- [ ] Update CONTEXT.md if needed

## Documentation Requirements

**Must Update:**
- (none)

**Check If Affected:**
- `taskplane-tasks/codegen/CONTEXT.md`

## Completion Criteria

- [ ] `bash tools/codegen/new_codegen.sh --verify common` shows 0 warnings about changes outside generated blocks
- [ ] All 9 parity issues resolved
- [ ] Common build + tests pass
- [ ] All Python tests pass

## Git Commit Convention

- **Step completion:** `feat(CG-039): complete Step N — description`
- **Hydration:** `hydrate: CG-039 expand Step N checkboxes`

**CRITICAL: Commit after EACH step.**

## Do NOT

- Expand task scope
- Skip tests
- Modify library/common source files — only modify codegen tools
- Commit without the task ID prefix
- Fix foundation-specific issues — this task is common-only

---

## Amendments (Added During Execution)
