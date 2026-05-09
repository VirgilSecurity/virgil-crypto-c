---
title: "fix: Automatically resolve and inject all required includes into generated C headers"
type: fix
status: completed
date: 2026-05-05
---

# fix: Automatically resolve and inject all required includes into generated C headers

## Overview

The codegen renderer (`project_c_backend.py`) already computes the complete, correct set of public includes a C header needs — covering struct fields, dependencies, method argument/return types, and interfaces. The problem is that `common_bootstrap.py` was only applying those includes when creating **new** files; for **existing** files it applied nothing, leaving the header incomplete after any model change.

The goal is to make codegen the authoritative source of includes: when a type is used in a module (as a field, dependency, or method arg/return), its include should always appear in the header automatically on the next `--apply` run.

The pending uncommitted diff makes progress on this but takes an unnecessarily narrow approach (only method-arg includes, project-prefix filtered). That approach should be replaced with a simpler, complete one.

## Problem Frame

`render_one` in `common_bootstrap.py` processes a class module XML and merges it into an existing header. The include-merge block (lines 1042–1100) had this logic:

```
renderer_pub_includes = []          # default: nothing
if is_new_file:
    renderer_pub_includes = [all public c_include from renderer]
```

For existing files, `renderer_pub_includes` is always empty. Adding a new method with a class-typed argument requires manually adding the `#include` — codegen doesn't do it.

## Requirements Trace

- R1. Regenerating any header (new or existing) must produce all `#include` directives that the renderer determines are required for types used in the module's struct, dependencies, and public API.
- R2. The injection must be additive only — existing includes already in the header are never removed.
- R3. The header must not include itself (`c_include_file` self-include filtered out).
- R4. System includes (`is_system="1"`) continue to be handled by `generate_header_includes_block` — no change to that path.
- R5. The fix must pass all existing codegen tests and produce a clean idempotent regeneration of `foundation` and `common`.

## Scope Boundaries

- No changes to XML model files, wrapper backends, or any non-C codegen paths.
- The `is_system="1"` (system includes) path in `generate_header_includes_block` is unchanged.
- Private includes (scope=`"private"`) are unchanged.
- No removals from existing headers — additive only.

## Context & Research

### What the renderer already computes

`render_class_c_module` in `project_c_backend.py` builds `resolved_public_includes` covering:

| Source | Code location |
|--------|--------------|
| `{prefix}_library.h` (always) | line 2943–2945 |
| All struct field class types | via `_class_dependency_includes` |
| All dependency class/interface types | via `_class_dependency_includes` |
| All public method arg/return class types | via `_class_dependency_includes` |
| Interface deps → `{prefix}_impl.h` | lines 2989–2992 |
| Self-include (own header) | lines 2993–2994 |

The self-include (`class_output.include_file`) is the same value as `root.attrib.get("c_include_file")`. The private-include path already filters it out (line 983). The same filter applies here.

### Pending diff assessment

The diff introduces `_method_arg_includes()` and `source="method_arg"` tagging to allow selective injection into existing files. This is overly narrow (misses struct-field deps and interface deps) and adds unnecessary complexity. The simpler correct fix is: remove the `is_new_file` guard and apply the full public renderer include list to all files, filtering only the self-include.

The pending diff should be replaced, not extended.

### Relevant patterns

- `common_bootstrap.py:977–983` — `c_include_file` self-include filter for private includes (pattern to mirror for public includes)
- `common_bootstrap.py:1010–1105` — `render_one` include-merge block (the fix target)
- `common_bootstrap.py:741–751` — `generate_header_includes_block` (system includes path, unchanged)
- `tools/codegen/test_type_resolution.py` — existing tests exercising `render_class_c_module` and end-to-end subprocess codegen

## Key Technical Decisions

- **Apply all public non-system non-self renderer includes unconditionally** — this is the simplest expression of "codegen owns includes." The additive-only merge means nothing is lost from existing files.
- **Drop `_method_arg_includes` and `source="method_arg"` entirely** — unnecessary scaffolding; the renderer already computes the complete set.
- **Filter self-include using `root.attrib.get("c_include_file")`** — mirrors the existing pattern at line 983.
- **No project-prefix filter** — all types used in a module should have their includes present, including cross-project ones (`vsc_buffer.h` in a `vscf_` header is correct and needed).

## Open Questions

### Resolved During Planning

- **Does removing the `is_new_file` guard regress new-file generation?** No — the result is identical for new files. Old behavior: all public includes. New behavior: all public non-self non-system includes (system includes are handled by `generate_header_includes_block`, unchanged). Self-include is intentionally excluded from the header's own generated section.
- **Will the full include set contaminate headers with spurious entries?** No. `resolved_public_includes` in the renderer is already carefully computed. Struct-field, dependency, and method-arg types are exactly what belongs in the header.
- **Do end-to-end header diffs appear after applying this fix?** Unknown until the idempotency check in Unit 3. Any diffs that appear represent genuinely missing includes and should be committed.

### Deferred to Implementation

- Whether any currently-compiled headers have a circular include risk once their full set is applied — detectable during the Unit 3 build verification.

## Implementation Units

- [x] **Unit 1: Revert the pending diff and apply the correct fix**

**Goal:** Replace the narrow `method_arg`-only approach with full public-include injection for all files.

**Requirements:** R1, R2, R3, R4

**Dependencies:** None

**Files:**
- Modify: `tools/codegen/common_bootstrap.py`
- Modify: `tools/codegen/project_c_backend.py`

**Approach:**

In `project_c_backend.py`:
- Remove `_method_arg_includes()` function entirely
- Remove `method_arg_incs` computation and `source="method_arg"` attribute from `render_class_c_module`
- Restore the original `text_element(root, "c_include", file=include, is_system="0", scope="public")` call without extra attributes

In `common_bootstrap.py`:
- Replace the `renderer_pub_includes: list[str] = []; if is_new_file: ...` block with an unconditional assignment that applies to all files:
  - Include all `c_include` elements where `scope=="public"` and `is_system!="1"` and `file != c_include_file` (self-include excluded)
  - The `c_include_file` value comes from `root.attrib.get("c_include_file", "")`
- Remove the `self_include_name`, `_pfx_end`, `_project_prefix` variables introduced by the pending diff

**Technical design:** *(directional)*

```
self_include = root.attrib.get("c_include_file", "")
renderer_pub_includes = [
    render_include(c) for c in root
    if c.tag == "c_include"
    and c.attrib.get("scope") == "public"
    and c.attrib.get("is_system") != "1"
    and c.attrib.get("file") != self_include
]
```

This is now unconditional — `is_new_file` is no longer relevant here.

**Patterns to follow:**
- Line 981–983 of `common_bootstrap.py` — private include filter (exact pattern, adapted for public scope)

**Test scenarios:**
- Happy path — existing file, method arg dep missing: render a class whose method takes a class-typed arg whose include is absent from the existing stub; assert the include appears after `render_one`.
- Happy path — existing file, struct-field dep missing: render a class with a buffer-class property; assert `vsc_buffer.h` (or equivalent) is present in the output.
- Happy path — interface dep: render a class with an interface dependency; assert `{prefix}_impl.h` is present.
- Edge case — self-include excluded: assert the header never contains `#include "vscf_sha512.h"` inside `vscf_sha512.h` output.
- Edge case — cross-project include: render a `vscf_` class whose struct field is a `vsc_` type; assert `vsc_*.h` is present.
- Idempotency: run `render_one` twice on the same existing file; assert the output is identical on the second run.

**Verification:**
- `project_c_backend.py` no longer has `_method_arg_includes` or `source="method_arg"`.
- `common_bootstrap.py` apply block has no `is_new_file` guard and no project-prefix filter.
- All six test scenarios pass (see Unit 2).

---

- [x] **Unit 2: Add unit tests for include injection**

**Goal:** Provide regression coverage preventing a future `is_new_file` guard re-introduction and validating all injection scenarios.

**Requirements:** R1, R2, R3, R5

**Dependencies:** Unit 1

**Files:**
- Modify: `tools/codegen/test_type_resolution.py`

**Approach:**
- Add a `TestHeaderIncludeInjection` class.
- Use `tempfile.TemporaryDirectory` and `render_one` with a pre-seeded stub to simulate existing-file and new-file cases.
- Load foundation IR via the existing `_load_foundation_ir()` helper.
- Choose a class with known struct-field deps and a class with known method-arg deps (e.g., `brainkey server` uses `mbedtls_ecp_group`-typed fields; `recipient cipher` has class-typed method args).
- For self-include exclusion: assert the output header text does not contain a self-referential `#include`.

**Test scenarios:** See Unit 1 test scenarios — implement each as a separate `test_*` method.

**Verification:**
- `python3 -m pytest tools/codegen/test_type_resolution.py -v` shows all new `TestHeaderIncludeInjection` tests passing alongside existing tests.

---

- [x] **Unit 3: End-to-end idempotency and build verification**

**Goal:** Confirm the fix is safe to commit: no spurious header diffs and resulting headers compile cleanly.

**Requirements:** R5

**Dependencies:** Unit 1

**Files:** No file changes — verification only.

**Approach:**
- Run `python3 -m tools.codegen.common_bootstrap --project foundation --apply` and `--project common --apply`.
- Run `git diff library/*/include/` to inspect any header changes.
- For each changed header: verify the added includes correspond to types actually used in the class (struct fields, dependencies, or method args).
- Build the library: `cmake -DCMAKE_BUILD_TYPE=Release -Bbuild -S. && cmake --build build -j$(nproc)`.
- Confirm `cd build && ctest --output-on-failure` passes.
- If previously-missing includes appear: commit those header diffs as part of this fix (they are correct, previously-absent entries).

**Verification:**
- Build succeeds with no new compiler errors.
- `ctest` passes.
- Any header diffs are verified as intentional additions.

## System-Wide Impact

- **Interaction graph:** Only `tools/codegen/` Python files change. Generated C headers may gain new `#include` lines — these are compile-time only and have no ABI effect.
- **Unchanged invariants:** `.c` source files, private includes, system includes, `@generated` body sections, and all wrapper backends are unaffected.
- **API surface parity:** No wrapper (Go, Java, Swift, PHP, WASM) changes.
- **Integration coverage:** Unit 3's build + ctest exercises the full C compilation with updated headers.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| A header gains a cross-project include that creates a circular dependency | Detected immediately by Unit 3 build failure. Resolve by adjusting forward-declaration patterns in the affected class. |
| Some existing headers already have manual includes not in the renderer set | Additive-only merge preserves them; no removal occurs. |
| The `include_own_header_public=True` default in `render_class_c_module` means the self-include is in the renderer list | Filtered by `c.attrib.get("file") != self_include` in the injection expression. |

## Sources & References

- Pending diff under evaluation: `git diff tools/codegen/common_bootstrap.py tools/codegen/project_c_backend.py`
- Include merge block: `tools/codegen/common_bootstrap.py:1042–1105`
- Renderer function: `tools/codegen/project_c_backend.py:2903` (`render_class_c_module`)
- IR argument fields: `tools/codegen/project_ir.py:74–99`
- Existing tests: `tools/codegen/test_type_resolution.py`
