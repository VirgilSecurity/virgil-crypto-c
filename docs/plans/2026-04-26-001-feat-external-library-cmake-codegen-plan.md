---
title: "feat: Generate thirdparty features.cmake from external library models"
type: feat
status: done
date: 2026-04-26
---

# feat: Generate thirdparty features.cmake from external library models

## Overview

The codegen system generates `library/*/features.cmake` (and `definitions.cmake`, `sources.cmake`) for first-party projects from their IR. External library models in `codegen/models/external/library_*.xml` exist and carry the same feature metadata, but only their `<error_message_getter>` element is ever read — everything else (`path`, `prefix`, `<feature>` children) is ignored. `thirdparty/*/features.cmake` files are handwritten and drift from the XML models over time (liboqs algorithm names are already stale). This plan makes those files generated artifacts.

## Problem Frame

Seven external library XML models (`mbedtls`, `ed25519`, `nanopb`, `falcon`, `round5`, `relic`, `liboqs`) each declare the `path`, optional `prefix`, and `<feature>` options that a `features.cmake` needs. The cmake backend already has all the logic to emit option declarations, `mark_as_advanced`, and dependency checks — it just doesn't know about external library IRs. The gap is: a parser that reads `<library>` roots, an IR type to hold the result, generator functions for the richer requirement model external XMLs use, and a bootstrap hook to run the generation.

## Requirements Trace

- R1. Running `python3 -m tools.codegen.common_bootstrap --project all --apply` regenerates all seven `thirdparty/*/features.cmake` from their XML models.
- R2. Generated `features.cmake` emits correct `default` values: `ON`, `OFF`, or bare CMake variable references (`${VIRGIL_POST_QUANTUM}`) — not hardcoded `ON` for everything.
- R3. Per-feature simple `<require feature="X"/>` emits an `if(FLAG AND NOT DEP)` FATAL_ERROR block.
- R4. Per-feature OR-group `<require><alternative.../><alternative.../></require>` emits an `if(FLAG AND NOT (A OR B OR C))` FATAL_ERROR block.
- R5. Library-level `<require>` groups (ed25519 pattern) emit pairwise mutex checks and an "at least one" check.
- R6. `<feature name="library">` overrides the default value of the `{PREFIX}_LIBRARY` option; its description stays `"Enable build of the '{name}' library"`.
- R7. Libraries without a `prefix` attribute use the library name lowercased as prefix (mbedtls → `MBEDTLS_*`, ed25519 → `ED25519_*`).
- R8. The XML models are the source of truth. Handwritten `thirdparty/*/features.cmake` files are replaced by the generated output.

## Scope Boundaries

- `definitions.cmake` is **not** generated (only ed25519 has one; when to emit it is ambiguous without more context — deferred).
- `sources.cmake` is **not** generated for external libraries (they manage their own build, unlike first-party libraries).
- No changes to first-party project cmake generation.
- `library_liboqs.xml` content update (stale algorithm names) is done as part of Unit 4 validation, not as a separate pre-requisite.

### Deferred to Separate Tasks

- `definitions.cmake` generation for external libraries: separate PR once policy is clear (which libraries use a Virgil-owned CMake target vs. their own build system).

## Context & Research

### Relevant Code and Patterns

- `tools/codegen/project_ir.py` — `IRFeature` (line 38), `IRProject` (line 272+): minimal shape to extend
- `tools/codegen/project_source.py:722-749` — existing `<library>` XML reading (only `error_message_getter`)
- `tools/codegen/project_cmake_backend.py` — `_collect_feature_entities`, `generate_features_cmake`, `_emit_dep_checks`, `generate_cmake_files`: all reusable or adaptable
- `tools/codegen/common_bootstrap.py:1170-1176` — cmake generation loop to mirror for external libraries
- `codegen/models/external/library_mbedtls.xml` — richest external model; has simple requires, OR-group requires, `default="off"` features
- `codegen/models/external/library_ed25519.xml` — only model with library-level `<require>` (mutex group)
- `codegen/models/external/library_nanopb.xml`, `library_falcon.xml` — simple models; good for testing happy paths
- `thirdparty/ed25519/features.cmake`, `thirdparty/nanopb/features.cmake` — reference outputs to verify against

### External References

- No external research needed; local patterns are complete and the cmake output format is established from the handwritten files.

## Key Technical Decisions

- **New `IRExternalLibrary` type, not reuse of `IRProject`**: `IRProject` carries modules, classes, implementations, umbrella headers, wrappers, fallback projects, and many other fields irrelevant to external libraries. A lean `IRExternalLibrary` keeps the external path clean and avoids feeding half-empty `IRProject`s into the existing first-party pipeline accidentally.

- **New generator function, not extending `generate_features_cmake`**: The external library cmake format differs from the first-party format in three ways: (1) feature defaults vary; (2) requirements live on features not on classes/implementations; (3) library-level require groups produce mutex/mandatory-one-of checks that have no first-party equivalent. Separate function avoids branching the existing generator.

- **`IRFeatureRequire` as a list of alternatives**: A single-item list = hard dependency; multi-item = OR group. This unifies both `<require feature="X"/>` and `<require><alternative.../></require>` under one type, keeping the IR flat.

- **Feature default rendering**: `"on"` → `ON`, `"off"` → `OFF`, any value starting with `${` → emitted verbatim without quotes (CMake variable reference). Absent `default` attribute → `ON`.

- **`name="library"` feature handling**: Scan the feature list for a feature named exactly `"library"` before emitting options. If found, use its `default` for the `{PREFIX}_LIBRARY` option and skip it in the main feature loop. If absent, emit `{PREFIX}_LIBRARY "..." ON` as usual.

- **Prefix fallback**: `attrs.get("prefix") or name` — if no `prefix` attribute, the library name itself is the prefix stem (e.g., `"mbedtls"` → `feature_flag_name("mbedtls", "SHA256 C")` → `MBEDTLS_SHA256_C`).

- **Discovery in bootstrap**: Glob `codegen/models/external/library_*.xml` to find all external library models. No explicit registration needed; adding a new XML file auto-includes it.

## Open Questions

### Resolved During Planning

- **Should `definitions.cmake` be generated?** No — only ed25519 has one and the criteria for when to generate it (Virgil-owned CMake target vs. own build system) isn't derivable from the XML. Deferred.
- **Can `generate_cmake_files` be reused?** No — it derives the output path from `project_ir.attrs["path"]` which works fine, but the function also accepts only `IRProject`. Rather than overloading it, a new `generate_external_library_cmake_files` returns just `(path, features_cmake_content)`.
- **Is `feature_flag_name` usable as-is?** Yes — it already handles mixed-case names with underscores (e.g., `"ECP_DP_SECP256R1_ENABLED"`, `"AMD64 RADIX 64 24K"`).

### Deferred to Implementation

- Whether the handwritten `thirdparty/mbedtls/features.cmake` options that have no XML counterpart (`MBEDTLS_SHA224_C`, `MBEDTLS_SHA384_C`) should be added to the XML model or dropped. The XML is authoritative; if they're needed, add them to `library_mbedtls.xml` before running `--apply`.
- Exact OR-group error message wording (the handwritten files use slightly different phrasing than first-party; match the first-party pattern for consistency).

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

```
codegen/models/external/library_*.xml
        │
        ▼
load_external_library_source(path)          ← project_source.py
        │  ExternalLibrarySource
        ▼
external_library_to_ir(source)              ← project_ir.py
        │  IRExternalLibrary
        │    .name, .prefix, .path
        │    .features: list[IRFeature]
        │       .name, .description
        │       .attrs["default"]
        │       .requires: list[IRFeatureRequire]
        │           .alternatives: list[str]   # 1 = hard dep, N = OR group
        │    .library_requires: list[IRFeatureRequire]   # ed25519 mutex groups
        ▼
generate_external_library_features_cmake(lib_ir, license_text)  ← project_cmake_backend.py
        │
        ▼
thirdparty/<name>/features.cmake
```

Data flow within the generator:

```
1. Resolve prefix (attrs.get("prefix") or name)
2. Find optional "library" feature → its default drives PREFIX_LIBRARY option
3. Emit: include_guard() + @prologue
4. Emit: option(PREFIX_LIBRARY "..." DEFAULT)
5. For each non-"library" feature:
     option(PREFIX_FLAGNAME "description" DEFAULT)
6. mark_as_advanced(...) with all flags
7. For each feature with requires:
     for each IRFeatureRequire:
       if 1 alt → if(FLAG AND NOT DEP)...FATAL_ERROR
       if N alt → if(FLAG AND NOT (A OR B OR ...))...FATAL_ERROR
8. For each library_require (IRFeatureRequire, N alts):
     emit pairwise mutex blocks (all pairs)
     emit "at least one" block
```

## Implementation Units

- [ ] **Unit 1: Extend `IRFeature` and add `IRExternalLibrary`**

**Goal:** Give the IR the types needed to model external library feature requirements.

**Requirements:** R3, R4, R5

**Dependencies:** None

**Files:**
- Modify: `tools/codegen/project_ir.py`
- Test: `tools/codegen/test_cmake_external_backend.py` (create, scaffolding only at this stage)

**Approach:**
- Add `IRFeatureRequire` dataclass with a single field `alternatives: list[str]`. One item = hard dependency; multiple = OR group.
- Add `requires: list[IRFeatureRequire]` field to `IRFeature` (default empty list).
- Add `IRExternalLibrary` dataclass with fields: `name: str`, `prefix: str`, `path: str`, `description: str`, `features: list[IRFeature]`, `library_requires: list[IRFeatureRequire]`. No inheritance from `IRProject` needed.

**Patterns to follow:**
- `tools/codegen/project_ir.py` — existing `IRFeature`, `IRCommented`, `IREntityRef` patterns; keep dataclasses minimal and flat.

**Test scenarios:**
- Test expectation: none at this stage — pure data structure, no behavior. Scaffolded test file created for Unit 3.

**Verification:**
- `IRExternalLibrary` and `IRFeatureRequire` importable from `project_ir`; existing `IRFeature` backward-compatible (empty `requires` list by default).

---

- [ ] **Unit 2: Parse `<library>` XML into `ExternalLibrarySource` and build `IRExternalLibrary`**

**Goal:** Read external library XML files fully and produce an `IRExternalLibrary` ready for generation.

**Requirements:** R2, R3, R4, R5, R6, R7

**Dependencies:** Unit 1

**Files:**
- Modify: `tools/codegen/project_source.py`
- Modify: `tools/codegen/project_ir.py`
- Test: `tools/codegen/test_cmake_external_backend.py`

**Approach:**
- Add `ExternalLibrarySource` dataclass to `project_source.py`: `name`, `path`, `prefix` (may be empty string if absent), `description`, `features: list[ProjectFeatureSource]` extended with a `requires` field, `library_requires: list[list[str]]` (each item is a list of alternative feature names).
- Extend `ProjectFeatureSource` or add a parallel `ExternalFeatureSource` that carries `requires: list[list[str]]` alongside `name`, `attrs`, `description`. Prefer extending `ProjectFeatureSource` with a `requires` field (default empty) to avoid a parallel type.
- Add `load_external_library_source(path: Path) -> ExternalLibrarySource` that:
  - Parses `<library>` root (same `_parse_legacy_xml` utility)
  - Reads `name`, `path`, `prefix` from root attributes
  - For each `<feature>` child: reads `name`, `attrs` (includes `default`), `description`, and parses its `<require>` children
    - A `<require feature="X"/>` child → single-item alternatives list `["X"]`
    - A `<require>` with `<alternative feature="Y"/>` children → multi-item list `["Y", ...]`
  - For each top-level `<require>` (direct child of `<library>`, not inside a `<feature>`): parse its `<alternative>` children into a `list[str]` and append to `library_requires`
- Add `external_library_to_ir(source: ExternalLibrarySource) -> IRExternalLibrary` in `project_ir.py`:
  - `prefix = source.prefix or source.name`
  - Maps `ExternalFeatureSource` → `IRFeature` with `requires` populated
  - Maps `source.library_requires` → `list[IRFeatureRequire]`

**Patterns to follow:**
- `project_source.py:722-749` for the XML loading scaffold; `_description()`, `_parse_legacy_xml()` utilities.
- `project_ir.py:697` for how `project_to_ir` maps `feature_refs` to `IRFeature`.

**Test scenarios:**
- Happy path: parse `library_nanopb.xml` → `ExternalLibrarySource` has 6 features, prefix `"pb"`, path `"../thirdparty/nanopb/"`, no library_requires.
- Happy path: parse `library_falcon.xml` → feature `name="library"` present with `default="${VIRGIL_POST_QUANTUM}"`; 2 other features with `default="off"`.
- Happy path: parse `library_ed25519.xml` → 3 features with no per-feature requires; 1 library_require group with 3 alternatives.
- Happy path: parse `library_mbedtls.xml` → feature `ECP C` has 2 require entries: one simple `["BIGNUM C"]` and one OR-group `["ECP_DP_SECP256R1_ENABLED"]`; feature `CTR_DRBG C` has one simple require and one 3-item OR-group.
- Edge case: library without `prefix` attribute (mbedtls) → `external_library_to_ir` sets `lib_ir.prefix == "mbedtls"`.
- Edge case: library with explicit `prefix` (nanopb → `"pb"`) → `lib_ir.prefix == "pb"`.

**Verification:**
- Unit tests pass; can `load_external_library_source` each of the 7 library XML files without error.

---

- [ ] **Unit 3: `generate_external_library_features_cmake` and output wiring**

**Goal:** Produce correct `features.cmake` content from `IRExternalLibrary`.

**Requirements:** R1, R2, R3, R4, R5, R6, R7, R8

**Dependencies:** Unit 2

**Files:**
- Modify: `tools/codegen/project_cmake_backend.py`
- Test: `tools/codegen/test_cmake_external_backend.py`

**Approach:**
- Add `generate_external_library_features_cmake(lib_ir: IRExternalLibrary, license_text: str = "") -> str`:
  1. Calls `_cmake_prologue(license_text)` (reuse existing).
  2. Resolves the `{PREFIX}_LIBRARY` option default: scans `lib_ir.features` for a feature with `name == "library"`; uses its `attrs.get("default", "on")` if found; otherwise `"on"`.
  3. Emits `option({PREFIX}_LIBRARY "Enable build of the '{lib_name}' library" {DEFAULT})`.
  4. For each feature where `name != "library"`: emits `option({FLAG} "{desc}" {DEFAULT})` where DEFAULT is rendered by a helper that converts `"on"` → `ON`, `"off"` → `OFF`, and any `${...}` value verbatim (no quotes around it).
  5. Emits `mark_as_advanced(...)` block with all flags.
  6. Dependency checks — for each feature (including `name="library"` for its requires if any):
     - For each `IRFeatureRequire` with 1 alternative: emits the standard `if(FLAG AND NOT DEP)...FATAL_ERROR` block (same message format as `_emit_dep_checks` in the first-party backend).
     - For each `IRFeatureRequire` with N alternatives: emits `if(FLAG AND NOT (A OR B OR ...))...FATAL_ERROR`.
  7. Library-level mutex checks — for each `IRFeatureRequire` in `lib_ir.library_requires`:
     - Emits all pairwise `if(A AND B)` mutex FATAL_ERROR blocks.
     - Emits one `if(NOT (A OR B OR ...))` "at least one" FATAL_ERROR block.
- Add `generate_external_library_cmake_files(lib_ir: IRExternalLibrary, license_text: str = "") -> list[tuple[str, str]]`:
  - Derives `thirdparty_path` from `lib_ir.path` by stripping leading `../` (e.g. `"../thirdparty/mbedtls/"` → `"thirdparty/mbedtls/"`).
  - Returns `[(f"{thirdparty_path}features.cmake", features_content)]`.

**Patterns to follow:**
- `project_cmake_backend.py` — `_cmake_prologue`, `_cmake_license_block`, `feature_flag_name`, `_collect_feature_entities`, `_emit_dep_checks`, `generate_cmake_files` for structure and message format.

**Test scenarios:**
- Happy path (nanopb): generated `features.cmake` contains `option(PB_LIBRARY "Enable build of the 'nanopb' library" ON)`, 6 feature options with correct ON/OFF defaults, `mark_as_advanced` block; no dependency checks.
- Happy path (falcon): `FALCON_LIBRARY` option has `${VIRGIL_POST_QUANTUM}` as its default (no quotes); `FALCON_ENABLE_TESTING` default is `OFF`.
- Happy path (mbedtls ECP C requires): generated output contains `if(MBEDTLS_ECP_C AND NOT MBEDTLS_BIGNUM_C)` block and `if(MBEDTLS_ECP_C AND NOT (MBEDTLS_ECP_DP_SECP256R1_ENABLED))` block.
- Happy path (mbedtls CTR_DRBG OR group): generated output contains `if(MBEDTLS_CTR_DRBG_C AND NOT (MBEDTLS_TIMING_C OR MBEDTLS_HAVEGE_C OR MBEDTLS_PLATFORM_ENTROPY))` block.
- Happy path (ed25519 mutex): generated output contains all 3 pairwise `if(ED25519_REF10 AND ED25519_AMD64_RADIX_64_24K)` blocks and one `if(NOT (ED25519_REF10 OR ED25519_AMD64_RADIX_64_24K OR ED25519_AMD64_RADIX_51_30K))` block.
- Edge case: `name="library"` feature is not emitted as a regular option; only its default is used for `{PREFIX}_LIBRARY`.
- Edge case: `lib_ir.prefix = "pb"` → all flags prefixed with `PB_`, not `NANOPB_`.
- Integration: generate from parsed `library_nanopb.xml` end-to-end → output matches `thirdparty/nanopb/features.cmake` (modulo license year).

**Verification:**
- Unit tests pass; running `generate_external_library_cmake_files` on each of the 7 parsed IRs produces syntactically valid CMake.

---

- [ ] **Unit 4: Bootstrap wiring, XML model updates, and validation**

**Goal:** Hook external library generation into `common_bootstrap.py`; update stale XML models; validate all 7 outputs regenerate cleanly.

**Requirements:** R1, R8

**Dependencies:** Unit 3

**Files:**
- Modify: `tools/codegen/common_bootstrap.py`
- Modify: `codegen/models/external/library_liboqs.xml` (stale algorithm names)
- Modify: `codegen/models/external/library_mbedtls.xml` (if `SHA224_C`/`SHA384_C` need adding)
- Replace: `thirdparty/*/features.cmake` (all 7, now generated)

**Approach:**
- In `common_bootstrap.py` `main()`, after the existing projects loop, add a new block:
  - Glob `codegen_root / "models" / "external" / "library_*.xml"` for all external library models.
  - For each path: `load_external_library_source(path)` → `external_library_to_ir(source)` → `generate_external_library_cmake_files(lib_ir, license_text)`.
  - Write each output to `out_root / rel_path` using the existing `ensure_parent` + `write_text` pattern.
  - Append written paths to `all_written`.
- Update `library_liboqs.xml`: replace stale algorithm names (`ENABLE_KEM_KYBER`, `ENABLE_SIG_DILITHIUM`, `ENABLE_SIG_FALCON`) with current names from the liboqs release (`ENABLE_KEM_ML_KEM`, `ENABLE_SIG_ML_DSA`, `ENABLE_SIG_FALCON`). Add `OQS_LIBRARY` as `<feature name="library" default="${VIRGIL_POST_QUANTUM}"/>` (already present — verify it matches).
- Decide whether to add `SHA224_C`/`SHA384_C` to `library_mbedtls.xml` or drop them from the handwritten file. Default: add them to the XML so the generated file is a superset of the old handwritten one.
- Run `python3 -m tools.codegen.common_bootstrap --project all --apply` and verify all 7 `thirdparty/*/features.cmake` files are rewritten without error.

**Patterns to follow:**
- `common_bootstrap.py:1170-1176` — existing cmake generation loop.
- `common_bootstrap.py:1142-1143` — `project_dir` + iteration pattern.

**Test scenarios:**
- Integration: `python3 -m tools.codegen.common_bootstrap --project foundation` completes without error (no regression on existing cmake generation).
- Integration: `python3 -m tools.codegen.common_bootstrap --project all --apply` writes all 7 `thirdparty/*/features.cmake` paths; each file begins with `include_guard()`.
- Happy path: `thirdparty/liboqs/features.cmake` after regeneration contains `OQS_ENABLE_KEM_ML_KEM` (new name), not `OQS_ENABLE_KEM_KYBER` (old name).
- Happy path: `thirdparty/nanopb/features.cmake` after regeneration is functionally identical to the current handwritten version (same options, same defaults, no dep checks).
- Regression: `thirdparty/ed25519/features.cmake` contains all mutex checks and the "at least one" check.

**Verification:**
- No existing tests broken; all 7 `thirdparty/*/features.cmake` files are byte-for-byte reproducible by running the bootstrap command twice.

## System-Wide Impact

- **Interaction graph:** `common_bootstrap.py` is the only entry point that calls the new generation path. No other files are affected by runtime.
- **Error propagation:** Failures in parsing or generation raise exceptions inside the `main()` loop; they surface as skipped files with error messages printed to stdout (same as existing unknown-skip handling).
- **Unchanged invariants:** First-party `library/*/features.cmake` generation is unchanged. External library `error_message_getter` parsing in `project_source.py:722-749` continues to work; `load_external_library_source` is a separate function that does not replace the existing `require`-parsing path.
- **API surface parity:** `generate_external_library_cmake_files` follows the same `list[tuple[str, str]]` return shape as `generate_cmake_files` so callers have a consistent contract.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Handwritten `thirdparty/mbedtls/features.cmake` has options not in XML (`SHA224_C`, `SHA384_C`) | Add them to `library_mbedtls.xml` in Unit 4; verify build still passes |
| liboqs algorithm names differ between XML and handwritten file | Update `library_liboqs.xml` in Unit 4; the stale handwritten file is replaced |
| Library-level `<require>` vs per-feature `<require>` parsing ambiguity | Distinguish by parent element tag: top-level = `<library>` child; per-feature = `<feature>` child |
| CMake variable references in `default` (e.g. `${VIRGIL_POST_QUANTUM}`) must not be quoted | Render verbatim when value starts with `${`; test explicitly |

## Sources & References

- Related code: `tools/codegen/project_cmake_backend.py` — `generate_features_cmake`, `_emit_dep_checks`
- Related code: `tools/codegen/project_source.py:722-749` — existing external library XML reading
- Related code: `tools/codegen/common_bootstrap.py:1170-1176` — cmake generation loop
- Existing outputs: `thirdparty/*/features.cmake` (7 handwritten files)
- External models: `codegen/models/external/library_*.xml` (7 XML files)
