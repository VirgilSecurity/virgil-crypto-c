---
title: "feat: Port remaining wrapper codegen from GSL to Python"
type: feat
status: active
date: 2026-04-14
---

# feat: Port remaining wrapper codegen from GSL to Python

## Overview

Migrate the five remaining language wrapper code generators (Python, Java, PHP, Swift, WASM) from the legacy GSL template system (~18,600 lines of GSL across 21 files) to the new Python codegen pipeline. Go wrapper migration is nearly complete and serves as the reference implementation. Each wrapper becomes a new `project_{lang}_backend.py` module consuming the shared `IRProject`.

## Problem Frame

The GSL-based codegen is the last major dependency blocking retirement of the GSL toolchain (Roadmap Phase 7 → Phase 8 cutover). Go was the first wrapper ported, proving the architecture: a Python backend module consumes `IRProject`, produces `list[tuple[str, str]]` of (path, content) pairs, and integrates into `common_bootstrap.py` via the `wrappers` attribute check. Five wrapper languages remain, each with distinct complexity profiles ranging from straightforward single-file-per-entity (Swift) to multi-artifact JNI generation (Java) and two-layer generation with a C extension (PHP).

## Requirements Trace

- R1. Each wrapper backend generates files that are byte-identical (or functionally equivalent) to the current GSL output
- R2. Each backend is a standalone `project_{lang}_backend.py` module consuming `IRProject` — no per-project hardcoding
- R3. Integration into `common_bootstrap.py` via the established `wrappers` attribute pattern
- R4. Handwritten files (tests, manual API layers) are never overwritten
- R5. Generated output compiles/runs for each target language where build tooling is available
- R6. Parity validated against resolved XML oracles (Java, PHP, Swift, WASM) or actual output files (Python)
- R7. IR extensions are minimal and do not break existing C, CMake, or Go backends

## Scope Boundaries

- **Wrapper generation only** — C backend, CMake backend, and Go backend are not in scope
- Each language is an independent deliverable; partial completion (e.g., 3 of 5 languages) is useful
- Test files and handwritten API layers (Go `crypto/`, Python `manual/`) are never touched
- No changes to the XML source models (`codegen/models/`)

### Deferred to Separate Tasks

- Go wrapper completion (platform.go): tracked in `docs/plans/2026-04-14-001-feat-platform-go-codegen-plan.md`
- Phase 8 cutover (making new codegen the default): separate task after all wrappers are ported
- Phase 9 legacy GSL retirement: separate task after cutover

## Context & Research

### Relevant Code and Patterns

- `tools/codegen/project_go_backend.py` — **reference implementation** (2,787 lines): demonstrates the complete pattern for consuming `IRProject`, deriving language-specific names, type mapping, and file generation
- `tools/codegen/common_bootstrap.py` — integration point; Go wiring at lines 1128-1145 shows the pattern
- `tools/codegen/project_ir.py` — shared IR with 942 lines; already contains wrapper-relevant fields (`length_attrs`, `cgo_links`, `framework`, `namespace`)
- `tools/codegen/project_source.py` — XML source loader; `wrappers` attribute parsed from project XML
- `codegen/models/wrapper/` — per-language config XMLs (thin stubs with paths and namespaces)

### Project-to-Wrapper Coverage Matrix

| Project | Python | Java | PHP | Swift | WASM |
|---|---|---|---|---|---|
| foundation | YES | YES | YES | YES | YES |
| phe | YES | YES | YES | — | YES |
| pythia | YES | YES | YES | YES | YES |
| ratchet | — | YES | — | YES | YES |
| common | YES | — | — | — | — |

### Parity Oracle Availability

| Language | Resolved XML available | Oracle strategy |
|---|---|---|
| Java | foundation, phe, pythia, ratchet (all 4) | Excellent — use resolved XML |
| WASM | foundation, phe, pythia, ratchet (all 4) | Excellent — use resolved XML |
| Swift | foundation, pythia, ratchet (3 of 3) | Good — use resolved XML |
| PHP | foundation, phe, pythia (3 of 3) | Good — use resolved XML |
| Python | None | Use actual output files in `wrappers/python/virgil_crypto_lib/` |

### GSL Complexity Per Language

| Language | GSL files | Total GSL lines | Artifact types | Key complexity |
|---|---|---|---|---|
| Swift | 2 | 2,882 | `.swift` | Single file per entity, protocol/class mapping. No CMake (uses SPM/Xcode). |
| WASM | 4 | 2,797 | `.js` + `CMakeLists.txt` | Rich per-project metadata, JS type system. GSL-generated CMakeLists.txt (top-level + 4 per-project). Modern WASM=1 build (no asm.js). |
| PHP | 8 | 3,869 | `.php` + C ext (`.c`/`.h`) + `CMakeLists.txt` | Two-layer (high-level + low-level), C extension. GSL-generated CMakeLists.txt per project (3 files). `_handwritten/` likely not a merge input. |
| Python | 2 | 4,109 | `.py` | Two-layer (_c_bridge + high-level), ctypes mapping, no parity oracle. No CMake (uses setup.py/pyproject.toml). |
| Java | 5 | 4,990 | `.java` + JNI `.c` + JNI `.h` | Three artifact types, JNI naming conventions, largest surface. CMakeLists.txt are **handwritten** (not codegen output). |

### IR Extension Assessment

The current `IRProject` is **substantially wrapper-ready** due to Go backend work. Per-language gaps:

| Language | IR adequacy | Extensions needed |
|---|---|---|
| Swift | Good | `framework` already in IR. Namespace derivable from project attrs. Minimal. |
| WASM | Poor | 6+ project-level identifiers (`module_name`, `error_class_name`, `interface_class_name`, `interface_enum_tag_name`, `impl_tag_enum_name`, CMake targets) not in IR. Needs a WASM config dataclass or IR extension. |
| PHP | Good | Namespace from `wrapper_php.xml`. Cross-project prefix resolution currently hardcoded in GSL — needs generic solution. |
| Python | Moderate | No python-specific IR slots needed. Backend derives low/high-level module names from existing IR + `wrapper_python.xml` paths. |
| Java | Moderate | JNI function names derivable from package + entity. `jni_source_dir` and `class_native_utils` from wrapper config or project attrs. |

## Key Technical Decisions

- **One backend module per language**: `project_{lang}_backend.py` following the Go pattern. Each returns `list[tuple[str, str]]` consumed by `common_bootstrap.py`.
- **Migration order: Swift → WASM → PHP → Python → Java**: Ordered by increasing complexity and risk (see rationale below). This ordering is a **risk-reduction strategy**, not a hard technical dependency — all 5 phases consume `IRProject` independently and could theoretically run in parallel if multiple implementers are available. The sequential ordering is recommended for a single implementer to accumulate pattern knowledge.
- **Cross-project type resolution via `fallback_projects`**: All 5 backends use `IRProject.fallback_projects` for cross-project type lookups, following the Go backend's `_resolve_project_prefix` + `_foreign_projects_for_entity` pattern. Each language adapts the resolution to its own import/reference mechanism (Swift framework imports, Java package imports, PHP prefix-qualified calls, Python cross-package imports, WASM module references).
- **IR extensions over config files**: Where a language needs project-level metadata not in the IR, prefer extending `IRProject.attrs` parsing over creating wrapper-specific config loaders. The XML project files already carry `wrappers=` and framework attributes; adding `wasm_module_name` etc. to project XML attrs is cleaner than a parallel config system.
- **Wrapper XML configs as constants, not runtime input**: The thin `wrapper_{lang}.xml` files carry fixed paths and namespaces. Hardcode these in each backend as module-level constants rather than adding XML loading machinery. They change only across major releases.
- **Python oracle: actual output files + test suite**: For the Python wrapper (which has no resolved XML), parity is validated against the existing generated files in `wrappers/python/virgil_crypto_lib/`. Additionally, run the Python wrapper test suite (`wrappers/python/virgil_crypto_lib/tests/`) against newly generated output as a functional parity gate.
- **Shared type-mapping infrastructure**: Each language has its own type mapping (C types → target types). These are language-specific enough that sharing a base class adds more abstraction than value. Each backend owns its own `_type_map` dict/function, following Go backend precedent.
- **WASM CMake generation is isolated**: The WASM backend owns its CMake file generation entirely within `project_wasm_backend.py`. It does not reuse or extend `project_cmake_backend.py`, which generates C library CMake files with different semantics. The two CMake generation paths are independent.
- **Coexistence during migration**: Each completed backend immediately replaces the corresponding GSL output when `--apply` is run. Both old and new codegen coexist in the repo during migration — the bootstrap dispatches to whichever backends exist. A backend is considered "active" only after its parity validation passes. There is no parallel-run mode; the diff validation in the integration unit is the gate.
- **Bootstrap dispatch pattern**: After all backends are added, consider refactoring the 6 dispatch blocks in `common_bootstrap.py` into a registry dict to keep the bootstrap DRY. This is a cleanup task after migration, not a prerequisite.
- **Generate CMakeLists.txt where GSL currently does**: PHP and WASM have GSL-generated CMakeLists.txt files that must be ported to the Python codegen. Java, Python, and Swift CMake files are either handwritten or nonexistent — no codegen needed for those. Specifically: WASM generates 5 CMakeLists.txt (1 top-level + 4 per-project), PHP generates 3 CMakeLists.txt (1 per project in `extensions/`). Prefer fully generated CMakeLists.txt files over handwritten ones where the GSL already generates them.
- **Build and test each wrapper locally and/or via CI**: Each phase must include build verification, not just file-level parity. See per-phase verification strategy below.

### Build and Test Strategy

Each wrapper has different build/test capabilities. Verification should use the strongest available method:

| Language | Local build/test | CI workflow | Verification approach |
|---|---|---|---|
| Swift | `./scripts/run_spm_tests_with_local_binaries.sh` (macOS, needs Xcode + xcframeworks) | `build-macos.yml` | Build xcframeworks → run SPM tests locally. Push branch to trigger CI. |
| WASM | `emcmake cmake` → `npm test` (needs emsdk 3.1.51 + Node.js 20) | `build-wasm.yml` | Build with Emscripten → run Jest tests locally or via CI. |
| PHP | `cmake` + `ctest --verbose` (needs PHP 8.2+ dev headers) | `build-php-binaries.yml` | Build PHP extension → run PHPUnit via ctest locally. CI covers multi-PHP-version. |
| Python | `cmake` → `python -m unittest discover` (needs cmake + Python 3.8+) | `python-wheels-ci.yml` | Build shared libs → install → run Python unit tests. CI covers multi-platform wheels. |
| Java | `cmake` + `./mvnw clean verify` (needs JDK 11 + cmake) | `build-java-binaries.yml` | Build JNI lib → run Maven tests locally. CI covers multi-platform + Android. |

### WASM Modernness Assessment

The WASM build system is **modern** — no asm.js anywhere:
- `-s WASM=1` hardcoded in all CMakeLists.txt (no `-s WASM=0` / asm.js fallback)
- Uses `MODULARIZE=1` with per-environment builds (node/web/worker)
- Rollup bundles to both CJS and ESM formats
- The only `asmjs` reference is a legacy safeguard name in `wasm_module_is_not_helper()` exclusion list
- Uses older `-s KEY=VALUE` Emscripten flag syntax (vs newer `--KEY=VALUE`) — acceptable, not a migration concern
- No Embind; uses manual C-function exports via `exported_functions.json` + hand-written JS wrappers

### Migration Order Rationale

1. **Swift first** — Simplest: single `.swift` file per entity, no JNI/FFI/extension layer, `framework` already in IR, clean protocol/class mapping. Good oracle coverage (3/3 projects). Low risk, builds confidence.

2. **WASM second** — Medium complexity but excellent oracle (4/4 projects). The JS type system is simpler than Python/Java. The main challenge is WASM-specific project metadata, which is a known, bounded IR extension. Also generates CMake files, but `project_cmake_backend.py` already exists as a pattern.

3. **PHP third** — The handwritten-merge pattern (`_handwritten/` directory) is unique among wrappers and the highest architectural risk. Tackling it third means the team has 2 successful backends for confidence, but it's early enough that surprises don't block the remaining languages. Good oracle (3/3 projects).

4. **Python fourth** — Large (4,109 GSL lines), two-layer output, and the only language with **no resolved XML oracle**. By this point, 3 backends are done and patterns are well-established, reducing the risk from the oracle gap. The ctypes mapping is more complex than Swift/WASM but simpler than JNI.

5. **Java last** — Largest GSL surface (4,990 lines), three distinct artifact types (Java class + JNI C source + JNI header), JNI naming conventions, and the broadest project coverage (all 4 projects). Most complex overall; benefits from all prior experience.

## Open Questions

### Resolved During Planning

- **Should each language get its own detailed plan?** Yes, when that language is next up. This strategic plan covers sequencing, shared patterns, and per-language risk analysis. Per-language plans follow the Go plan template.
- **Does the IR need a major redesign for wrappers?** No. The IR is already substantially wrapper-ready. Extensions are per-language and modest (WASM being the largest).
- **Are PHP `_handwritten/` files consumed by the GSL codegen?** Investigation strongly suggests **no**. The GSL PHP templates (`php.gsl`, `php_codegen.gsl`, `php_map_*.gsl`) contain no references to `_handwritten/`. The files in `_handwritten/foundation/src/` are structurally different from the generated files (different license format, `require_once` vs namespace, different constructor signatures, fewer methods). They appear to be a **legacy manual implementation** predating the codegen, not merge fragments. This must be confirmed at the start of Phase 3 by auditing `_handwritten/CMakeLists` and the PHP build system. If confirmed, Unit 9's merge strategy is unnecessary and PHP's risk profile drops from "highest" to "moderate."
- **Python parity oracle?** Use actual output files in `wrappers/python/virgil_crypto_lib/` as the comparison baseline, supplemented by running the Python wrapper test suite as a functional gate.

### Deferred to Implementation

- **Per-language name derivation edge cases**: Each language has its own PascalCase/camelCase/snake_case rules with abbreviation handling. Discover during implementation, as was done for Go.
- **Cross-project type resolution per language**: How each language resolves types from dependency projects (e.g., foundation types used by phe). Pattern exists in Go backend via `fallback_projects`; adapt per-language.
- **WASM CMake target naming**: Exact derivation rules for `cmake_wasm_target`, `cmake_c_target`, etc. — study resolved XML during WASM implementation.
- **PHP extension C code complexity**: The `php_map_low_level.gsl` (1,631 lines) generates PHP extension C code. The exact FFI patterns need reverse-engineering from the GSL + generated output.

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

```
                    codegen/models/project_*.xml
                              │
                              ▼
                     project_source.py
                              │
                              ▼
                      project_ir.py
                     (IRProject — shared)
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
      project_c_backend  project_cmake_backend  ... (existing)
              │
    ┌─────────┼─────────┬─────────┬─────────┬─────────┐
    ▼         ▼         ▼         ▼         ▼         ▼
  go_backend swift_backend wasm_backend php_backend python_backend java_backend
    │         │         │         │         │         │
    ▼         ▼         ▼         ▼         ▼         ▼
 .go files  .swift    .js +    .php +    .py files  .java +
            files    CMake     C ext.               JNI .c/.h
```

Each `project_{lang}_backend.py` follows the same contract:

```
generate_{lang}_files(project_ir: IRProject, license_text: str) -> list[tuple[str, str]]
```

Integration in `common_bootstrap.py`:

```
wrappers_set = {w.strip() for w in project_ir.attrs.get("wrappers", "").split(",")}
if "{lang}" in wrappers_set:
    from tools.codegen.project_{lang}_backend import generate_{lang}_files
    for rel_path, content in generate_{lang}_files(project_ir, license_text=license_text):
        # write with appropriate guards (skip test files, etc.)
```

## Implementation Units

### Phase 1: Swift Wrapper Backend

- [ ] **Unit 1: Swift backend — name utilities, enum generator, orchestrator**

  **Goal:** Establish `project_swift_backend.py` with Swift naming conventions and the simplest entity type (enums).

  **Requirements:** R1, R2, R7

  **Dependencies:** None

  **Files:**
  - Create: `tools/codegen/project_swift_backend.py`
  - Create: `tools/codegen/test_swift_backend.py`

  **Approach:**
  - Swift name derivation: PascalCase types, camelCase properties/constants, protocol naming for interfaces
  - `framework` attribute from `IRProject` (e.g., `VSCFoundation`), `namespace` derived as `VirgilCrypto{Project}` (e.g., `VirgilCryptoFoundation`)
  - Enum generates a Swift `@objc public enum` with `Int32` raw value
  - Study `wrappers/swift/VirgilCrypto/VirgilCryptoFoundation/AlgId.swift`, `CipherState.swift` for exact format
  - Compare against `codegen/generated/foundation/swift_project_foundation.xml` resolved model

  **Patterns to follow:**
  - `tools/codegen/project_go_backend.py` — module structure, naming utility pattern, `generate_*_files()` API

  **Test scenarios:**
  - Happy path: generate `AlgId.swift` for foundation — enum name, case names, raw values match legacy
  - Happy path: orchestrator produces correct file count for foundation (124 files)
  - Edge case: enum with value=0 sentinel constant

  **Verification:**
  - Generated enum files diff cleanly against legacy output in `wrappers/swift/VirgilCrypto/VirgilCryptoFoundation/`

- [ ] **Unit 2: Swift backend — protocols (interfaces) and class/implementation wrappers**

  **Goal:** Generate Swift protocol declarations for interfaces and class/implementation structs with lifecycle and methods.

  **Requirements:** R1, R3, R4

  **Dependencies:** Unit 1

  **Files:**
  - Modify: `tools/codegen/project_swift_backend.py`
  - Modify: `tools/codegen/test_swift_backend.py`

  **Approach:**
  - Interfaces → Swift `@objc public protocol` declarations with method signatures
  - Classes/implementations → Swift `@objc public class` with `OpaquePointer`/`UnsafeMutablePointer` C context wrapping
  - Type mapping: C types → Swift types (Data for buffers, Int/UInt for integers, Bool, class pointers → class refs, interfaces → protocol refs)
  - Method rendering: marshal args, call C function, check status, marshal returns
  - Memory management: `deinit` calling C delete, `init` from C pointer
  - Study `wrappers/swift/VirgilCrypto/VirgilCryptoFoundation/Hash.swift` (protocol), `Sha256.swift` (implementation), `Base64.swift` (class)

  **Test scenarios:**
  - Happy path: `Hash.swift` — protocol with method signatures matching legacy
  - Happy path: `Sha256.swift` — implementation with lifecycle, interface conformance, methods
  - Happy path: `Base64.swift` — class with static methods
  - Edge case: cross-project type reference (phe using foundation types)
  - Error path: method returning error (Swift throws pattern)

  **Verification:**
  - Generated files compile as part of the Swift package
  - Diff against legacy output shows functional equivalence

- [ ] **Unit 3: Swift backend — pipeline integration, parity validation, and build test**

  **Goal:** Wire Swift generation into `common_bootstrap.py`, validate parity across all 3 projects, and confirm the generated code compiles and passes tests.

  **Requirements:** R3, R5, R6

  **Dependencies:** Unit 2

  **Files:**
  - Modify: `tools/codegen/common_bootstrap.py`
  - Modify: `tools/codegen/project_swift_backend.py`

  **Approach:**
  - Add `"swift" in wrappers_set` block in `common_bootstrap.py` following Go pattern
  - Guard against overwriting test files in `VirgilCryptoTest/`
  - Validate all 3 projects: foundation (124 files), pythia (5 files), ratchet (9 files)
  - Diff against legacy, resolve any remaining discrepancies
  - **Build test (local):** Build xcframeworks via `./scripts/build_apple_frameworks.sh`, then run SPM tests via `./scripts/run_spm_tests_with_local_binaries.sh`
  - **CI gate:** Push branch to trigger `build-macos.yml` SPM job

  **Test scenarios:**
  - Integration: `--apply` generates Swift files to correct paths for foundation
  - Integration: pythia and ratchet projects also generate correctly
  - Integration: test files in `VirgilCryptoTest/` are never overwritten
  - Edge case: project without Swift wrappers (phe, common) skips generation
  - Build: SPM tests pass with generated Swift code

  **Verification:**
  - All Swift wrapper files generated for foundation, pythia, ratchet
  - File-level parity with legacy output
  - `swift test` passes (SPM tests for foundation, pythia, ratchet)

### Phase 2: WASM Wrapper Backend

- [ ] **Unit 4: WASM backend — IR extension for WASM project metadata**

  **Goal:** Add WASM-specific project-level identifiers to the IR so the WASM backend can derive module names, error classes, and CMake targets.

  **Requirements:** R7

  **Dependencies:** None (can be done in parallel with Phase 1)

  **Files:**
  - Modify: `tools/codegen/project_ir.py` or `tools/codegen/project_source.py`
  - Modify: `tools/codegen/test_go_backend.py` (ensure no regression)

  **Approach:**
  - WASM needs: `module_name`, `error_class_name`, `interface_class_name`, `interface_enum_tag_name`, `impl_tag_enum_name`, `cmake_wasm_target`, `cmake_c_target`, `cmake_c_export_target`, `cmake_c_enable_option`
  - These are derivable from project name by convention (e.g., foundation → `FoundationModule`, `FoundationError`, etc.)
  - Best approach: derive in WASM backend from `IRProject.name` using naming conventions rather than extending IR. Validate derivation against resolved WASM XMLs for all 4 projects.
  - Only extend IR if derivation rules prove inconsistent across projects

  **Test scenarios:**
  - Happy path: derived WASM identifiers for foundation match resolved XML values
  - Happy path: derived identifiers for phe, pythia, ratchet also match
  - Edge case: if any project has non-conventional naming, document and handle

  **Verification:**
  - All WASM project-level identifiers derivable correctly for all 4 projects

- [ ] **Unit 5: WASM backend — JS file generation (enums, classes, interfaces)**

  **Goal:** Generate the JavaScript Embind wrapper files for WASM.

  **Requirements:** R1, R2

  **Dependencies:** Unit 4

  **Files:**
  - Create: `tools/codegen/project_wasm_backend.py`
  - Create: `tools/codegen/test_wasm_backend.py`

  **Approach:**
  - JS type mapping: C types → JS types (`number`, `boolean`, `string`, `Uint8Array`, `undefined`, constructor functions)
  - Each entity produces a `.js` file with an Embind class/enum definition
  - Per-project infrastructure files: `index.js` (module exports aggregator — analogous to Python `__init__.py`), `precondition.js` (input validation utilities). These must be generated; they enumerate all entities.
  - Study `wrappers/wasm/foundation/src/` for exact file format
  - Compare against `codegen/generated/foundation/wasm_project_foundation.xml`

  **Patterns to follow:**
  - `tools/codegen/project_go_backend.py` — module structure
  - `wrappers/wasm/foundation/src/Sha256.js` — entity file format

  **Test scenarios:**
  - Happy path: generate enum JS file, diff against legacy
  - Happy path: generate class JS file with constructor and methods
  - Happy path: generate interface JS file
  - Happy path: generate `index.js` with correct exports for all entities
  - Happy path: generate `precondition.js` with validation utilities
  - Edge case: Uint8Array buffer marshalling
  - Edge case: cross-project type references

  **Verification:**
  - Generated JS files diff cleanly against legacy for foundation

- [ ] **Unit 6: WASM backend — CMake generation, pipeline integration, and build test**

  **Goal:** Generate WASM-specific CMakeLists.txt files (5 total: 1 top-level + 4 per-project), wire into `common_bootstrap.py`, validate parity, and build/test.

  **Requirements:** R3, R5, R6

  **Dependencies:** Unit 5

  **Files:**
  - Modify: `tools/codegen/project_wasm_backend.py`
  - Modify: `tools/codegen/common_bootstrap.py`

  **Approach:**
  - Generate 5 CMakeLists.txt files currently produced by `wasm_codegen.gsl`:
    - `wrappers/wasm/CMakeLists.txt` — top-level orchestrator (Emscripten check, file copies, subdirectories)
    - `wrappers/wasm/{foundation,phe,pythia,ratchet}/CMakeLists.txt` — per-project Emscripten builds with 3 targets each (node/browser/worker), link flags (`-s WASM=1`, `-s MODULARIZE=1`, etc.), and exported_functions.json
  - WASM CMake generation is **owned entirely by `project_wasm_backend.py`** — does not reuse `project_cmake_backend.py` (different build domain: Emscripten vs native C)
  - Wire `"wasm" in wrappers_set` into bootstrap
  - Validate file counts: foundation (~93 JS + CMake), phe (~10 + CMake), pythia (~4 + CMake), ratchet (~8 + CMake)
  - **Build test (local, requires emsdk):** `emcmake cmake -Cconfigs/wasm-config.cmake ...` → `cmake --build` → `npm ci && npm run prepare` → `npm test`
  - **CI gate:** Push branch to trigger `build-wasm.yml` (Linux, builds + Jest tests)

  **Test scenarios:**
  - Integration: all 4 projects generate correct file counts for JS and CMake
  - Integration: generated CMakeLists.txt files diff cleanly against legacy
  - Integration: Emscripten flags are correct (`-s WASM=1`, `MODULARIZE=1`, per-environment targets)
  - Edge case: project-specific CMake target names and EXPORT_NAME derived correctly
  - Build: Emscripten build succeeds and Jest tests pass

  **Verification:**
  - Full file parity across all 4 WASM projects (JS + CMakeLists.txt)
  - `npm test` passes (Jest tests for foundation, phe)

### Phase 3: PHP Wrapper Backend

- [ ] **Unit 7: PHP backend — high-level PHP class generation**

  **Goal:** Generate the PHP class files (`VirgilCryptoWrapper/src/{Project}/*.php`) — the high-level OOP API layer.

  **Requirements:** R1, R2

  **Dependencies:** None (can start after Phase 1 if desired)

  **Files:**
  - Create: `tools/codegen/project_php_backend.py`
  - Create: `tools/codegen/test_php_backend.py`

  **Approach:**
  - PHP namespace: `Virgil\CryptoWrapper\{Project}` (from `wrapper_php.xml`)
  - PascalCase class names, camelCase methods
  - Each entity → a PHP class wrapping the C extension functions
  - Study `wrappers/php/VirgilCryptoWrapper/src/Foundation/` for exact format
  - Cross-project prefix resolution: the GSL hardcodes `foundation → vscf`. The Python backend must derive prefix from `IRProject.prefix` (which is already in the IR).

  **Patterns to follow:**
  - `tools/codegen/project_go_backend.py` — module structure
  - `wrappers/php/VirgilCryptoWrapper/src/Foundation/Sha256.php` — entity format

  **Test scenarios:**
  - Happy path: generate `Sha256.php` — class name, methods, namespace match legacy
  - Happy path: generate interface PHP class
  - Edge case: cross-project type references (phe using foundation types)

  **Verification:**
  - Generated PHP class files diff against legacy for foundation

- [ ] **Unit 8: PHP backend — C extension generation (low-level) and CMakeLists.txt**

  **Goal:** Generate the PHP C extension files and per-project CMakeLists.txt (`VirgilCryptoWrapper/extensions/{project}/`). This is the PHP FFI bridge layer.

  **Requirements:** R1, R2

  **Dependencies:** Unit 7

  **Files:**
  - Modify: `tools/codegen/project_php_backend.py`
  - Modify: `tools/codegen/test_php_backend.py`

  **Approach:**
  - The `php_map_low_level.gsl` (1,631 lines) is the largest sub-template — generates C code that registers PHP functions and marshals types between PHP and C
  - Each project produces 3 files: `vsc{prefix}_{project}_php.c`, `vsc{prefix}_{project}_php.h`, `CMakeLists.txt`
  - **CMakeLists.txt generation**: Currently GSL-generated by `php_map_custom_cmakelists()` in `php_map_custom.gsl`. Each CMakeLists.txt builds a SHARED library (e.g., `vscf_foundation_php`), links against `vsc::{project}` + `phplib`, registers PHPUnit test targets, and installs PHP sources. Generate these fully in the Python backend.
  - Study `wrappers/php/VirgilCryptoWrapper/extensions/foundation/` for exact output
  - Compare against `codegen/generated/foundation/php_project_foundation.xml` for entity model

  **Test scenarios:**
  - Happy path: C extension file for foundation matches legacy structure
  - Happy path: PHP function registration block is correct
  - Happy path: CMakeLists.txt for foundation matches legacy (library target, link deps, test target, install rules)
  - Edge case: type marshalling for buffer/data types in C extension
  - Edge case: phe CMakeLists.txt links against `foundation_php` (cross-project extension dependency)

  **Verification:**
  - Generated C extension files and CMakeLists.txt match legacy

- [ ] **Unit 9: PHP backend — `_handwritten/` audit, pipeline integration, and full validation**

  **Goal:** Confirm the `_handwritten/` relationship, wire PHP into `common_bootstrap.py`, and validate parity across all 3 projects.

  **Requirements:** R1, R3, R4, R6

  **Dependencies:** Unit 8

  **Files:**
  - Modify: `tools/codegen/project_php_backend.py`
  - Modify: `tools/codegen/common_bootstrap.py`

  **Approach:**
  - **First**: Audit `_handwritten/` to confirm it is NOT consumed by GSL codegen (see Resolved Questions). Check `_handwritten/CMakeLists/` and the PHP build system. If `_handwritten/` is indeed a legacy manual implementation separate from codegen, no merge logic is needed — the PHP backend is pure generation like Go/Swift/WASM.
  - If `_handwritten/` IS consumed by GSL (unlikely based on investigation), implement a merge strategy and escalate to a detailed sub-plan.
  - Wire `"php" in wrappers_set` into bootstrap
  - Guard: never overwrite test files in `wrappers/php/VirgilCryptoWrapper/tests/`
  - Guard: never overwrite `_handwritten/` directory
  - Validate: foundation (122 files), phe (7 files), pythia (1 file)

  **Test scenarios:**
  - Happy path: all 3 PHP projects generate correct file counts
  - Integration: `_handwritten/` directory is untouched
  - Integration: test files are never overwritten
  - Edge case: project without PHP wrappers (ratchet, common) skips generation

  **Verification:**
  - Full parity with legacy output across all 3 PHP projects
  - `_handwritten/` directory unchanged
  - **Build test (local, needs PHP 8.2+ dev):** `cmake -Cconfigs/php-config.cmake ...` → `cmake --build` → `ctest --verbose` (runs PHPUnit via cmake-registered targets)
  - **CI gate:** Push branch to trigger `build-php-binaries.yml` (multi-PHP-version on Linux/macOS/Windows)

### Phase 4: Python Wrapper Backend

- [ ] **Unit 10: Python backend — low-level ctypes bridge layer (_c_bridge) and `__init__.py` aggregators**

  **Goal:** Generate the `_c_bridge` layer files (e.g., `_vscf_sha256.py`) and package `__init__.py` files that directly map C symbols to Python ctypes.

  **Requirements:** R1, R2

  **Dependencies:** None

  **Files:**
  - Create: `tools/codegen/project_python_backend.py`
  - Create: `tools/codegen/test_python_backend.py`

  **Approach:**
  - ctypes type mapping: C types → Python ctypes (`c_int`, `c_uint`, `c_size_t`, `c_bool`, `c_byte`, `POINTER(c_char)`, etc.)
  - Each entity produces a `_{prefix}_{name}.py` file in the `_c_bridge/` subdirectory
  - These files define `restype` and `argtypes` for each C function
  - **Generate `__init__.py` for each project directory and `_c_bridge/` subdirectory** — these are package aggregators that import and re-export all generated entities. Without correct `__init__.py` files, the Python package is broken. Study existing `__init__.py` files for exact import ordering.
  - **`common` project special case**: The `common` project produces bridge primitives (`Buffer`, `Data` wrapping `vsc_buffer`/`vsc_data`) that are structurally different from the standard entity-per-file pattern used by foundation/phe/pythia. The `common/_c_bridge/` has `_buffer.py`, `_data.py`, `_vsc_buffer.py`, `_vsc_data.py`. These are foundational types imported by all other Python projects. Handle `common` as a distinct code path in the Python backend.
  - Study `wrappers/python/virgil_crypto_lib/foundation/_c_bridge/_vscf_sha256.py` for standard format
  - Study `wrappers/python/virgil_crypto_lib/common/_c_bridge/` for `common` special case
  - **No resolved XML oracle** — compare against actual output files

  **Patterns to follow:**
  - `tools/codegen/project_go_backend.py` — module structure
  - `wrappers/python/virgil_crypto_lib/foundation/_c_bridge/` — exact output format
  - `wrappers/python/virgil_crypto_lib/foundation/__init__.py` — aggregator format

  **Test scenarios:**
  - Happy path: generate `_vscf_sha256.py` bridge file, diff against actual output
  - Happy path: generate bridge for interface entity
  - Happy path: generate `__init__.py` with correct import ordering for foundation
  - Happy path: generate `common` project bridge files (`_buffer.py`, `_data.py`, etc.)
  - Edge case: function with buffer output parameters
  - Edge case: function returning enum type
  - Edge case: `common` project structural difference from foundation pattern

  **Verification:**
  - Generated bridge files match actual output in `wrappers/python/virgil_crypto_lib/`
  - `__init__.py` files contain all expected imports
  - `common` project files match actual output

- [ ] **Unit 11: Python backend — high-level Pythonic class layer**

  **Goal:** Generate the high-level Python wrapper classes (e.g., `Sha256.py`) that provide the clean Python API atop the ctypes bridge.

  **Requirements:** R1, R2

  **Dependencies:** Unit 10

  **Files:**
  - Modify: `tools/codegen/project_python_backend.py`
  - Modify: `tools/codegen/test_python_backend.py`

  **Approach:**
  - PascalCase class names, snake_case methods
  - Each entity produces a high-level `.py` file importing from its `_c_bridge` counterpart
  - Methods: marshal Python args → ctypes, call bridge function, check status, marshal returns
  - Buffer management: Python `bytes`/`bytearray` ↔ ctypes buffers
  - Study `wrappers/python/virgil_crypto_lib/foundation/sha256.py`, `hash.py`

  **Test scenarios:**
  - Happy path: generate `Sha256` class, diff against actual output
  - Happy path: generate interface wrapper class
  - Edge case: method returning tuple (value + error)
  - Edge case: dependency setter methods

  **Verification:**
  - Generated high-level files match actual output

- [ ] **Unit 12: Python backend — pipeline integration and parity validation**

  **Goal:** Wire into pipeline. Validate across foundation, phe, pythia, common.

  **Requirements:** R3, R5, R6

  **Dependencies:** Unit 11

  **Files:**
  - Modify: `tools/codegen/common_bootstrap.py`
  - Modify: `tools/codegen/project_python_backend.py`

  **Approach:**
  - Wire `"python" in wrappers_set` into bootstrap
  - Guard: never overwrite `wrappers/python/manual/` (handwritten high-level API layer)
  - Guard: never overwrite test files in `wrappers/python/virgil_crypto_lib/tests/`
  - Validate: foundation (~214 files), phe (19), pythia (7), common (6)
  - Since there's no resolved XML, validation is file-by-file diff against existing output

  **Test scenarios:**
  - Integration: all 4 Python projects generate correct file counts
  - Integration: `manual/` directory is never touched
  - Integration: test files are never overwritten
  - Edge case: `common` project (only has Python wrapper, not other languages)

  **Verification:**
  - Full file parity with existing output across all 4 projects
  - **Build test (local):** `cmake -Cconfigs/python-config.cmake ...` → `cmake --build --target install` → `python -m unittest discover -s wrappers/python/virgil_crypto_lib/tests -p "*_test.py"`
  - **CI gate:** Push branch to trigger `python-wheels-ci.yml` (cibuildwheel across Linux/macOS/Windows)

### Phase 5: Java/JNI Wrapper Backend

- [ ] **Unit 13: Java backend — Java class generation**

  **Goal:** Generate the Java source files (`src/main/java/.../*.java`).

  **Requirements:** R1, R2

  **Dependencies:** None

  **Files:**
  - Create: `tools/codegen/project_java_backend.py`
  - Create: `tools/codegen/test_java_backend.py`

  **Approach:**
  - Package: `com.virgilsecurity.crypto.{project}` (from `wrapper_java.xml` `package` + project name)
  - PascalCase class names, camelCase methods, UPPER_SNAKE_CASE constants
  - Each entity → a Java class with native method declarations and a high-level Java API
  - Per-project `{Project}JNI.java` aggregator class (e.g., `FoundationJNI.java`)
  - Context pointer stored as `long` in Java
  - Study `wrappers/java/foundation/src/main/java/.../foundation/Sha256.java`
  - Compare against `codegen/generated/foundation/java_project_foundation.xml`

  **Patterns to follow:**
  - `tools/codegen/project_go_backend.py` — module structure
  - `wrappers/java/foundation/src/main/java/` — exact output format

  **Test scenarios:**
  - Happy path: generate `Sha256.java` — class, methods, package declaration match legacy
  - Happy path: generate `FoundationJNI.java` aggregator
  - Edge case: cross-project type references (phe → foundation)
  - Edge case: Java reserved word collision handling

  **Verification:**
  - Generated Java files diff against legacy for foundation

- [ ] **Unit 14: Java backend — JNI C source and header generation**

  **Goal:** Generate the JNI C glue code (`jni/*.c` and `jni/*.h`) that bridges Java ↔ C.

  **Requirements:** R1, R2

  **Dependencies:** Unit 13

  **Files:**
  - Modify: `tools/codegen/project_java_backend.py`
  - Modify: `tools/codegen/test_java_backend.py`

  **Approach:**
  - JNI function naming: `Java_com_virgilsecurity_crypto_{project}_{Class}_{method}` (underscores escaped)
  - Each project produces: `{Project}JNI.c` + `{Project}JNI.h`
  - The JNI C file is the most complex artifact — `java_c.gsl` alone is 1,705 lines
  - Type marshalling: Java `long` → C pointer, Java `byte[]` → C data/buffer, Java `int` → C enum
  - JNI error handling: check C status, throw Java exception on error
  - Study `wrappers/java/foundation/jni/FoundationJNI.c` and `FoundationJNI.h`
  - Compare against resolved XML for entity and method mapping

  **Test scenarios:**
  - Happy path: JNI C file for foundation — function signatures, type marshalling
  - Happy path: JNI header file declarations match C file
  - Edge case: JNI name escaping for special characters in class/method names
  - Edge case: buffer output marshalling (JNI `NewByteArray` pattern)
  - Error path: JNI exception throwing for C error status

  **Verification:**
  - Generated JNI files match legacy structure and function signatures

- [ ] **Unit 15: Java backend — pipeline integration and full validation**

  **Goal:** Wire into pipeline. Validate across all 4 projects (foundation, phe, pythia, ratchet) — the broadest project coverage.

  **Requirements:** R3, R5, R6

  **Dependencies:** Unit 14

  **Files:**
  - Modify: `tools/codegen/common_bootstrap.py`
  - Modify: `tools/codegen/project_java_backend.py`

  **Approach:**
  - Wire `"java" in wrappers_set` into bootstrap
  - Guard: never overwrite test files in `src/test/`
  - Three output paths per project: `src/main/java/.../*.java`, `jni/*.c`, `jni/*.h`
  - **`wrappers/java/common/` is handwritten** (NativeUtils.java, CommonJNI.java), not generated — `project_common.xml` declares `wrappers="python"` only. The `wrappers` attribute guard in bootstrap already protects this, but the backend should not attempt to process `common`.
  - **`wrappers/java/android/`** contains Android-specific build configuration, not generated wrapper code. It mirrors the desktop module structure but is not a codegen output target.
  - Validate: foundation (127 Java + JNI), phe (19 + JNI), pythia (8 + JNI), ratchet (8 + JNI)
  - Java has the broadest project coverage — ratchet is Java-only (no Go, Python, PHP wrapper)

  **Test scenarios:**
  - Integration: all 4 projects generate correct file counts for all 3 artifact types
  - Integration: test files never overwritten
  - Integration: `common` Java files (handwritten) are never touched
  - Integration: `android/` directory is never touched
  - Edge case: ratchet (smallest project, Java + WASM + Swift only)

  **Verification:**
  - Full file parity across all 4 Java projects
  - **Build test (local, needs JDK 11):** `cmake -Cconfigs/java-config.cmake ...` → `cmake --build --target install` → `cd wrappers/java && ./mvnw clean verify -P foundation,phe,pythia,ratchet`
  - **CI gate:** Push branch to trigger `build-java-binaries.yml` (Linux/macOS/Windows + Android)

## System-Wide Impact

- **Interaction graph:** Each wrapper backend depends on `IRProject` produced by `project_source.py` + `project_ir.py`. C backend must complete before wrapper files are written (wrappers reference C headers). Wrapper backends are independent of each other.
- **Error propagation:** Wrong type mapping → target language compile/runtime errors. Caught by parity diff against legacy output. Missing entity → downstream test failures.
- **State lifecycle risks:** All wrappers are likely pure generation (full overwrite). PHP's `_handwritten/` directory appears to be a legacy manual implementation not consumed by codegen (to be confirmed in Phase 3). If `_handwritten/` turns out to be a merge input, it becomes the sole state-preserving operation and the highest-risk unit. Python's `common` project is a structural special case requiring dedicated handling.
- **API surface parity:** Generated wrapper APIs must exactly match legacy for ABI/API compatibility with existing consumers. Any divergence breaks downstream users.
- **Integration coverage:** Each phase includes a pipeline integration unit that validates the full round-trip: XML → IR → backend → file output → diff against legacy.
- **Unchanged invariants:** Source XML models (`codegen/models/`), C backend, CMake backend, Go backend, all test files, handwritten API layers (`crypto/`, `manual/`), pre-built binaries — all untouched.

## Risks & Dependencies

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| PHP `_handwritten/` is actually consumed by GSL (unlikely) | Low | High | Audit at the start of Phase 3. GSL PHP templates contain no `_handwritten` references — if confirmed, no merge logic needed. If wrong, escalate to detailed sub-plan. |
| Python parity validation is weaker without resolved XML oracle | Medium | Medium | Use comprehensive file-by-file diff against actual output. Run Python wrapper test suite as functional parity gate. |
| Python `common` project has structural differences from standard pattern | Medium | Medium | Handle `common` as a distinct code path. Its bridge primitives (`Buffer`, `Data`) are consumed by all other projects — correctness is critical. |
| WASM project metadata derivation rules are inconsistent | Low | Medium | Validate against all 4 resolved XMLs before committing to convention-based derivation. Fall back to IR extension if needed. |
| Java JNI C glue is the most complex single artifact (1,705 lines GSL) | Medium | Medium | Port incrementally: function signatures first, then type marshalling, then error handling. Validate each layer against resolved XML. |
| IR extensions for one language break another | Low | High | Run all existing backend tests (C, CMake, Go) after any IR change. Prefer backend-local derivation over IR extension where possible. |
| Cross-project type resolution differs per language | Medium | Medium | Study resolved XMLs for each language to understand cross-project patterns. Build test cases for foundation→phe and foundation→pythia references. |
| Legacy GSL output contains bugs that the new codegen shouldn't reproduce | Low | Medium | When actual output differs from what the XML model implies, flag for manual review rather than blindly matching the legacy bug. |

## Sources & References

- Legacy GSL templates: `codegen/*.gsl` (63 files, ~38,700 lines total)
- New Python codegen: `tools/codegen/` (Go backend: 2,787 lines, C backend: 6,976 lines, CMake: 470 lines)
- Go wrapper plan (reference): `docs/plans/2026-04-13-002-feat-go-wrapper-codegen-plan.md`
- Resolved wrapper XMLs: `codegen/generated/{project}/{lang}_project_{project}.xml`
- Wrapper output: `wrappers/{lang}/` per language
- XML source models: `codegen/models/project_*/project_*.xml`
- Wrapper config: `codegen/models/wrapper/wrapper_{lang}.xml`
- IR: `tools/codegen/project_ir.py`
- ADRs: `docs/adr/0001-replace-gsl-codegen.md` through `0004-universal-model-driven-codegen.md`
- Roadmap: `docs/codegen-migration/roadmap.md` (Phase 7)
