# Resolved Models Inventory

This document records the current state of legacy resolved/intermediate XML under `codegen/generated/`.

## Purpose

These artifacts are not intended to become a required runtime output of the new generator.

They are useful for:

- reverse-engineering legacy semantics
- parity/debugging
- building test fixtures
- validating the new resolver against the legacy pipeline

## Global observations

- `codegen/generated/main/` contains global artifacts shared across projects
- each generated project directory contains the core resolved artifacts:
  - `root.xml`
  - `meta.xml`
  - `project.xml`
  - `type_resolution_map.xml`
- project directories also contain many `module_*.xml` and `c_module_*.xml` files
- most wrapper-resolved project files appear in the form:
  - `<lang>_project_<project>.xml`
  - `<lang>_project_<project>_unresolved.xml`
- Python wrapper-resolved XML is currently absent / known-bad and should not be treated as a reliable parity source for the first migration steps

## Global artifacts in `codegen/generated/main`

- `features_list.xml`
- `features_list_unresolved.xml`
- `interfaces.xml`
- `projects_api.xml`
- `wrappers.xml`

These appear to capture cross-project state that the new resolver will need to reproduce in memory.

## Project inventory

| project | module_* | c_module_* | wrapper langs with resolved project XML present | core artifacts | notes |
|---|---:|---:|---|---|---|
| common | 10 | 10 | — | `root.xml`, `meta.xml`, `project.xml`, `type_resolution_map.xml` | no wrapper project artifacts here |
| foundation | 329 | 329 | go, java, swift, php, wasm | `root.xml`, `meta.xml`, `project.xml`, `type_resolution_map.xml` | no Python resolved wrapper artifacts |
| phe | 37 | 37 | go, java, php, wasm | `root.xml`, `meta.xml`, `project.xml`, `type_resolution_map.xml` | no Python resolved wrapper artifacts |
| pythia | 10 | 10 | java, swift, php, wasm | `root.xml`, `meta.xml`, `project.xml`, `type_resolution_map.xml` | no Python resolved wrapper artifacts |
| ratchet | 38 | 38 | java, swift, wasm | `root.xml`, `meta.xml`, `project.xml`, `type_resolution_map.xml` | no Python resolved wrapper artifacts |

## Important caveat about Python

Current legacy resolved XML does **not** provide a dependable Python reference surface.

Working assumption for planning:

- resolved XML is available and useful for C and several non-Python wrapper targets
- Python has known issues and should not be the first wrapper parity target
- Go is the preferred first wrapper migration target where wrapper parity is needed early

## Recommended fixture selection

For initial reverse-engineering and tests, start with:

### Global
- `codegen/generated/main/interfaces.xml`
- `codegen/generated/main/projects_api.xml`
- `codegen/generated/main/wrappers.xml`

### Smallest practical project surface
- `codegen/generated/common/project.xml`
- `codegen/generated/common/meta.xml`
- `codegen/generated/common/root.xml`
- `codegen/generated/common/type_resolution_map.xml`

### Broader feature-rich project surface
- `codegen/generated/foundation/project.xml`
- `codegen/generated/foundation/meta.xml`
- `codegen/generated/foundation/root.xml`
- `codegen/generated/foundation/type_resolution_map.xml`
- one or more representative files such as:
  - `module_message_info.xml`
  - `c_module_vscf_message_info.xml`
  - `go_project_foundation.xml`

## Immediate follow-up tasks

1. define a small fixture subset copied into test fixtures for parser/resolver work
2. compare original XML inputs against the selected resolved artifacts
3. document how a few representative entities transform from source XML into resolved module/C-module forms
4. avoid using Python wrapper-resolved XML as a required oracle in early tests
