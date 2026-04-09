# Task: CG-040 - Fix Interface API and Dispatch Module Rendering

**Created:** 2026-04-09
**Size:** M

## Review Level: 2 (Plan and Code)

**Assessment:** Fixes rendering bugs in interface API and dispatch modules affecting all 33 foundation interfaces. Multiple issues in the shared C backend's interface renderers.
**Score:** 4/8 — Blast radius: 2, Pattern novelty: 1, Security: 0, Reversibility: 1

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-040-fix-interface-api-dispatch/
├── PROMPT.md
├── STATUS.md
├── .reviews/
└── .DONE
```

## Mission

Fix 11 rendering bugs across interface API modules (33 `_api.h` files) and interface dispatch modules (33 `.h/.c` files) in the foundation codegen output. These bugs cause compilation failures and signature mismatches.

### Category A — Interface API module issues:

**A1. Struct declaration/definition swapped**
- We generate: `declaration="public" definition="external"`
- Legacy has: `declaration="external" definition="public"`
- Effect: the C emitter sees `definition="external"` and only emits a forward-decl `typedef`, the full struct body is lost
- Fix: in `render_interface_api_c_module()`, swap to `declaration="external"` `definition="public"`

**A2/A3. Struct body and per-field comments missing**
- Consequence of A1 — once decl/def is corrected, the emitter will render the full struct with fields
- Per-field comments: each `c_property` in the struct needs a `.text` with `comment_text()` (e.g., "Calculate hash over given data." for `hash_cb`)

**A4. Missing struct comment**
- The struct element should have text "Contains API requirements of the interface 'hash'."
- Fix: set struct `.text` via `comment_text()`

**A5. `vsc_buffer_t` passed by value instead of pointer in callback typedefs**
- Callback args with `class="buffer"` should have `accessed_by="pointer"` but render as `accessed_by="value"`
- Root cause: `_interface_argument_from_source()` or `argument_from_source()` doesn't handle `buffer` class correctly — buffer is always passed by pointer
- Reference: in legacy resolved XML, buffer args have `accessed_by="pointer"`
- Fix: ensure buffer-class args get `accessed_by="pointer"`. Same for interface dispatch method args.

### Category B — Interface dispatch module issues:

**B1. Missing VSCF_PUBLIC modifier on methods**
- All dispatch methods should have a `c_modifier` with `value="{PREFIX}_PUBLIC"` (e.g., `VSCF_PUBLIC`)
- Fix: add modifier to each method in `render_interface_c_module()`

**B2. Static methods in wrong position**
- Legacy order: non-static (stateful) methods first, then static methods, then constant getters, then utility methods
- Current order: static methods appear before non-static
- Fix: reorder method rendering in `render_interface_c_module()`

**B3. Missing struct forward-decl comment**
- The `typedef struct vscf_hash_api_t vscf_hash_api_t;` should have comment "Contains API requirements of the interface 'hash'."
- Fix: set comment on the struct forward-declaration element

**B4/B5. Wrong accessed_by for buffer and data args**
- `vsc_buffer_t` should be pointer (`vsc_buffer_t *out`)
- `vsc_data_t` should be value (`vsc_data_t data`)
- Same root cause as A5

**B6. Missing VSCF_NODISCARD modifier**
- Methods returning `enum="status"` should have `VSCF_NODISCARD` modifier
- Fix: detect status-returning methods and add the modifier

## Dependencies

- **None**

## Context to Read First

**Tier 2:**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3:**
- `codegen/generated/foundation/c_module_vscf_hash_api.xml` — reference API module
- `codegen/generated/foundation/c_module_vscf_hash.xml` — reference dispatch module
- `codegen/generated/foundation/c_module_vscf_decrypt.xml` — reference with NODISCARD

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** None

## File Scope

- `tools/codegen/project_c_backend.py`

## Steps

### Step 0: Preflight

- [ ] Run `bash tools/codegen/new_codegen.sh --apply foundation` and diff API/dispatch files to confirm issues
- [ ] Read `render_interface_api_c_module()` and `render_interface_c_module()`
- [ ] Compare with legacy resolved XML for hash_api and hash

### Step 1: Fix interface API module rendering

- [ ] Fix struct declaration/definition: swap to `declaration="external"` `definition="public"` (A1)
- [ ] Add struct comment "Contains API requirements of the interface '{name}'." (A4)
- [ ] Add per-field comments to struct properties (A3)
- [ ] Fix buffer arg accessed_by in callback typedefs (A5)
- [ ] Commit

### Step 2: Fix interface dispatch module rendering

- [ ] Add `{PREFIX}_PUBLIC` modifier to all dispatch methods (B1)
- [ ] Reorder: non-static methods, then static, then constant getters, then utilities (B2)
- [ ] Add struct forward-decl comment (B3)
- [ ] Fix buffer/data accessed_by in dispatch method args (B4/B5) — same fix as A5 if shared
- [ ] Add `{PREFIX}_NODISCARD` modifier for status-returning methods (B6)
- [ ] Commit

### Step 3: Testing & Verification

- [ ] Run `python3 -m unittest discover -s tools/codegen -p "test_*.py" -v`
- [ ] Run `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Verify: `diff` of `vscf_hash_api.h` shows 0 structural differences (only trailing whitespace)
- [ ] Verify: `diff` of `vscf_hash.h` shows 0 structural differences

### Step 4: Documentation & Delivery

- [ ] Discoveries logged in STATUS.md

## Completion Criteria

- [ ] API struct rendered with full body (not just forward-decl)
- [ ] Dispatch methods have VSCF_PUBLIC modifier
- [ ] buffer args are pointer, data args are value
- [ ] Status-returning methods have VSCF_NODISCARD
- [ ] All tests pass, common build gate passes

## Git Commit Convention

- `feat(CG-040): complete Step N — description`

**CRITICAL: Commit after EACH step.**

## Do NOT

- Fix implementation/class module issues — those are CG-041/042/043
- Commit without task ID prefix

---

## Amendments (Added During Execution)
