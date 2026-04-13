---
title: "feat: Port CMake file generation to Python codegen"
type: feat
status: active
date: 2026-04-13
---

# feat: Port CMake file generation to Python codegen

## Overview

Port the generation of `sources.cmake`, `features.cmake`, and `definitions.cmake` from the legacy GSL templates (`codegen/cmake_files_codegen.gsl`) to the new Python codegen pipeline. These three files per project control which sources are compiled, what feature flags exist, and what compile definitions are set. The new codegen already generates all C source/header files for all 5 projects.

## Problem Frame

The legacy GSL codegen is being replaced by a Python pipeline. C file generation is complete for all 5 projects (common, foundation, phe, pythia, ratchet). The 3 CMake files per project remain GSL-generated. Porting them lets us fully retire the GSL dependency for C library builds.

## Requirements Trace

- R1. Generate `sources.cmake` with correct `target_sources()`, `target_include_directories()`, `configure_file()`, and Apple framework `set_property()` blocks
- R2. Generate `features.cmake` with correct `option()` declarations, `mark_as_advanced()`, and cross-project feature dependency checks
- R3. Generate `definitions.cmake` with correct `target_compile_definitions()` including all feature flags
- R4. Output must match legacy GSL output closely enough that the build produces identical binaries
- R5. Generation must work for all 5 projects via `--project all`
- R6. Follow ADR 0002/0003/0004: model-driven, no per-project branching, shared backend

## Scope Boundaries

- CMake generation only (`sources.cmake`, `features.cmake`, `definitions.cmake`)
- `CMakeLists.txt` is handwritten and NOT generated — do not touch it
- `module.modulemap` (Apple module map) is deferred to a separate task
- Wrapper-language CMake files are out of scope

## Context & Research

### Relevant Code and Patterns

- `tools/codegen/project_c_backend.py::generate_umbrella_headers()` — closest existing pattern: iterates all IR entities, collects paths, produces project-wide output files
- `tools/codegen/project_c_backend.py::collect_umbrella_includes()` — demonstrates gathering entity outputs by visibility/scope
- `tools/codegen/common_bootstrap.py::main()` — umbrella header generation is invoked here after per-module rendering; CMake generation should follow the same integration point
- `tools/codegen/project_ir.py::IRProject` — has all needed fields: `prefix`, `name`, `namespace`, `include_namespace`, `features`, all entity lists
- `tools/codegen/project_ir.py::IROutputTarget` — has `header_visibility`, `include_file`, `source_file`, `header_path`

### Institutional Learnings

- ADR 0003: Do NOT branch on module names — use entity kinds, model attributes, or IR metadata
- ADR 0004: One shared backend handles all projects; entity discovery is automatic from IR
- Risk R3: Hidden GSL semantics must be documented as discovered
- CMake generation is roadmap Phase 6, after C generation parity (Phase 5)

### Entity-to-Feature Mapping Rules

Derived from analyzing all 5 projects' legacy CMake output:

| Entity kind | Feature flag? | Unconditional? | Rule |
|---|---|---|---|
| Shared module (assert, library, memory, atomic) | No | Yes | `from="shared"` in project XML |
| Project-specific module (typedefs, const, platform) | No | Yes | Listed in project XML without `from` |
| Enum (status, msg_type, etc.) | No | Yes | Always unconditional |
| Umbrella header (public, private) | No | Yes | Always unconditional |
| Class | Yes | No | Feature = `{PREFIX}_{SNAKE_NAME(class.name)}` |
| Interface | Yes | No | Feature = `{PREFIX}_{SNAKE_NAME(iface.name)}` |
| Implementation | Yes | No | Feature = `{PREFIX}_{SNAKE_NAME(impl.name)}` |
| Project feature (multi_threading) | Yes | N/A | Only in features.cmake + definitions.cmake |

### File Sets Per Entity

Each entity may produce multiple files in `target_sources()`:

| Entity | Files |
|---|---|
| Shared module | `.h` + `.c` (unconditional) |
| Project module | `.h` + `.c` (unconditional) |
| Enum | `.h` + `.c` (unconditional) |
| Class (with defs) | `.h` + `.c` + `_defs.h` + `_defs.c` (feature-gated) |
| Class (no defs, e.g. lifecycle=none or inlined) | `.h` + `.c` (feature-gated) |
| Interface | dispatch `.h` + `.c` + `_api.h` (feature-gated) |
| Implementation | `.h` + `.c` + `_defs.h` + `_defs.c` + `_internal.h` + `_internal.c` (feature-gated) |
| Implementation (with private methods) | + `_private.h` (feature-gated) |

## Key Technical Decisions

- **New module, not inline in C backend:** Create `tools/codegen/project_cmake_backend.py` as a separate module. It generates CMake, not C — different concern. Follows the pattern of `project_c_backend.py` being the C backend.
- **Pure string generation, not template engine:** Use Python f-strings and list building (same as `generate_umbrella_headers`). Jinja2 is acceptable per ADR but unnecessary for structured CMake output.
- **Feature name derivation is a shared utility:** `feature_flag_name(prefix, entity_name)` returns `{PREFIX}_{SNAKE_NAME}`. Used by all three generators.
- **Integrate via `common_bootstrap.py::main()`:** CMake files are written alongside umbrella headers in the per-project loop, using the same `out_root` / `--apply` logic.
- **CMake files are full-file replace, not merge:** Unlike C files which merge `@generated` blocks, CMake files are fully generated. No preservation logic needed.

## Open Questions

### Resolved During Planning

- **How to determine unconditional vs feature-gated?** Shared modules (from="shared"), project-specific modules, enums, and umbrella headers are unconditional. Classes, interfaces, and implementations are feature-gated. This matches all 5 projects' legacy output.
- **How to get cross-project feature dependencies?** `IRRequirement.attrs["project"]` + requirement kind + name → look up target project prefix → construct feature flag. The prefix mapping (common→vsc, foundation→vscf, etc.) can be derived from `project_ir.fallback_projects`.

### Deferred to Implementation

- **Exact ordering of entries within `target_sources()`:** The legacy output groups headers before sources, unconditional before conditional. Exact per-entity ordering may vary — match legacy output during implementation and adjust.
- **Platform.h.in detection:** Modules with `has_cmakedefine` need `configure_file()` + `check_include_files()`. The exact attribute path in the IR needs verification during implementation.

## Implementation Units

- [ ] **Unit 1: Create project_cmake_backend.py with feature_flag_name utility and definitions.cmake generator**

  **Goal:** Establish the new module and implement the simplest generator first.

  **Requirements:** R3, R6

  **Dependencies:** None

  **Files:**
  - Create: `tools/codegen/project_cmake_backend.py`
  - Test: verify against `library/ratchet/definitions.cmake` and `library/common/definitions.cmake`

  **Approach:**
  - Create `feature_flag_name(prefix: str, entity_name: str) -> str` utility
  - Create `generate_definitions_cmake(project_ir: IRProject, license_text: str) -> str`
  - Iterate: project features, classes, interfaces, implementations → emit `target_compile_definitions()` block
  - Include `INTERNAL_BUILD` and `SHARED_LIBRARY` lines

  **Patterns to follow:**
  - `project_c_backend.py::generate_umbrella_headers()` — function signature pattern
  - `library/ratchet/definitions.cmake` — exact output format

  **Test scenarios:**
  - Happy path: generate for ratchet, diff against legacy `definitions.cmake` — output matches
  - Happy path: generate for common (no interfaces/impls) — output matches
  - Happy path: generate for foundation (has interfaces + impls) — all feature lines present

  **Verification:**
  - Generated `definitions.cmake` for all 5 projects matches legacy output (ignoring whitespace)

- [ ] **Unit 2: Generate features.cmake with options and dependency checks**

  **Goal:** Generate the feature option declarations and cross-project dependency validation.

  **Requirements:** R2, R4

  **Dependencies:** Unit 1 (uses `feature_flag_name`)

  **Files:**
  - Modify: `tools/codegen/project_cmake_backend.py`
  - Test: verify against `library/ratchet/features.cmake` and `library/foundation/features.cmake`

  **Approach:**
  - Create `generate_features_cmake(project_ir: IRProject, license_text: str) -> str`
  - Emit `option()` for: LIBRARY, project features (multi_threading), each class, interface, implementation
  - Emit `mark_as_advanced()` with all feature names
  - Emit dependency checks: iterate each entity's `requirements`, resolve cross-project prefix, emit `if(FEATURE AND NOT DEP_FEATURE) ... FATAL_ERROR`
  - For cross-project resolution: use `project_ir.fallback_projects` to get prefix, or maintain a static prefix map

  **Patterns to follow:**
  - `library/ratchet/features.cmake` — full output reference
  - `library/common/features.cmake` — simplest case

  **Test scenarios:**
  - Happy path: ratchet features.cmake matches legacy — all options, mark_as_advanced, dependency checks
  - Happy path: common features.cmake matches (only LIBRARY + MULTI_THREADING + 2 class options)
  - Edge case: cross-project dependency (VSCR_RATCHET_KEY_UTILS depends on VSCF_KEY_INFO) generates correct check
  - Edge case: common-project dependency (VSCR_RATCHET_COMMON_HIDDEN depends on VSC_BUFFER) uses correct prefix

  **Verification:**
  - Generated `features.cmake` for ratchet and foundation matches legacy output

- [ ] **Unit 3: Generate sources.cmake**

  **Goal:** Generate the most complex CMake file with source listings, include directories, feature conditionals, and Apple framework properties.

  **Requirements:** R1, R4

  **Dependencies:** Unit 1 (uses `feature_flag_name`)

  **Files:**
  - Modify: `tools/codegen/project_cmake_backend.py`
  - Test: verify against `library/ratchet/sources.cmake` and `library/common/sources.cmake`

  **Approach:**
  - Create `generate_sources_cmake(project_ir: IRProject, license_text: str) -> str`
  - Sections to emit in order:
    1. Prologue (license, warning, include_guard, target check)
    2. `check_include_files()` for assert.h and stdatomic.h
    3. `configure_file()` for platform.h.in (when present)
    4. `set_property(MACOSX_PACKAGE_LOCATION)` for each public header
    5. `target_sources()` — headers section (unconditional, then feature-gated), sources section (unconditional, then feature-gated)
    6. `target_include_directories()` with standard paths derived from `project_ir.include_namespace`
  - Path construction: use `${CMAKE_CURRENT_LIST_DIR}` for source-tree files, `${CMAKE_CURRENT_BINARY_DIR}` for configured files
  - Header location: derive from `IROutputTarget.header_visibility` — public→`include/{namespace}/`, private→`include/{namespace}/private/`, internal→`src/`

  **Patterns to follow:**
  - `library/ratchet/sources.cmake` — medium complexity reference
  - `library/common/sources.cmake` — simplest reference
  - `library/foundation/sources.cmake` — most complex (interfaces, impls)

  **Test scenarios:**
  - Happy path: ratchet sources.cmake matches legacy — all entries present, correct feature guards, correct paths
  - Happy path: common sources.cmake matches — only shared modules + 2 classes
  - Happy path: foundation sources.cmake — interfaces produce dispatch + api files, implementations produce main + defs + internal files
  - Edge case: platform.h.in triggers configure_file block
  - Edge case: scope="internal" classes have headers in src/, not include/
  - Edge case: classes with inlined structs (no _defs) don't list _defs files

  **Verification:**
  - Generated `sources.cmake` for all 5 projects matches legacy output (diff has only ordering or whitespace differences)

- [ ] **Unit 4: Integrate into common_bootstrap.py and new_codegen.sh**

  **Goal:** Wire CMake generation into the existing codegen pipeline so `--apply` writes CMake files alongside C files.

  **Requirements:** R5

  **Dependencies:** Units 1-3

  **Files:**
  - Modify: `tools/codegen/common_bootstrap.py` — add CMake generation in the per-project loop
  - Modify: `tools/codegen/new_codegen.sh` — verify CMake files are included in diff check and restore

  **Approach:**
  - In `main()`, after umbrella header generation, call the three CMake generators
  - Write output to `library/{project}/sources.cmake`, `features.cmake`, `definitions.cmake`
  - When `--apply`: write to repo. When `--out`: write to out_root
  - The verify script's restore should cover these files (they're under `library/{project}/`)

  **Patterns to follow:**
  - Umbrella header integration in `common_bootstrap.py::main()` — same write pattern

  **Test scenarios:**
  - Happy path: `bash tools/codegen/new_codegen.sh --verify ratchet` succeeds with CMake files generated
  - Happy path: `--project all` generates CMake for all 5 projects
  - Happy path: `--apply` writes CMake files to the correct paths
  - Integration: verify script restores CMake files after verification

  **Verification:**
  - `new_codegen.sh --verify all` passes for all 5 projects with CMake files included

## System-Wide Impact

- **Interaction graph:** CMake files are consumed by CMakeLists.txt (handwritten) which `include()`s them. No runtime interaction.
- **Error propagation:** Wrong feature flags → compile errors or missing symbols. Wrong source paths → build failure. These are caught by the existing verify pipeline.
- **State lifecycle risks:** None — CMake files are fully regenerated, no merge.
- **API surface parity:** All 5 projects must produce CMake files matching their legacy equivalents.
- **Unchanged invariants:** `CMakeLists.txt` files are NOT touched. The handwritten build logic remains as-is.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Entity ordering in sources.cmake differs from legacy | Compare diff output for each project; adjust ordering to minimize diff |
| Cross-project prefix resolution misses edge cases | Build a prefix lookup from fallback_projects; verify against foundation's complex deps |
| Missing file entries for new entity kinds (e.g. _private.h) | Verify against foundation which has the most entity variety |
| Feature dependency extraction misses requirements | Compare generated features.cmake dependency checks against legacy line-by-line |

## Sources & References

- Legacy GSL templates: `codegen/cmake_files_codegen.gsl`, `codegen/cmake_codegen.gsl`
- IR definitions: `tools/codegen/project_ir.py`
- C backend pattern: `tools/codegen/project_c_backend.py::generate_umbrella_headers()`
- Legacy output references: `library/ratchet/sources.cmake`, `library/ratchet/features.cmake`, `library/ratchet/definitions.cmake`
- ADRs: `docs/adr/0002-project-rooted-codegen-pipeline.md`, `docs/adr/0003-generalize-project-rooted-codegen-beyond-common.md`, `docs/adr/0004-universal-model-driven-codegen.md`
