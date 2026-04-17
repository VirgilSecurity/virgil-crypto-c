---
title: "refactor: Remove pythia from wrapper codegen and delete pythia wrapper trees"
type: refactor
status: superseded
superseded_by: docs/plans/2026-04-17-002-refactor-remove-pythia-wasm-wrapper-plan.md
date: 2026-04-17
---

> **Superseded 2026-04-17.** The full-wrapper-matrix removal in this plan was scoped down after realizing the actual driver was the WASM emsdk 4.x migration (`docs/plans/2026-04-15-001`), which is blocked by `thirdparty/relic` — a dependency pulled in only through pythia. Removing pythia from the WASM build alone lifts relic out of the WASM dependency graph and unblocks the emsdk migration without the relic-patch effort. See `docs/plans/2026-04-17-002-refactor-remove-pythia-wasm-wrapper-plan.md` for the narrower scope actually being executed. The full removal remains viable as a later effort if downstream consumer signals confirm none exist — the research and unit breakdown below is preserved as reference for that future task.


# refactor: Remove pythia from wrapper codegen and delete pythia wrapper trees

## Overview

Pythia is no longer used by downstream consumers. This plan stops the new Python codegen pipeline from emitting pythia wrappers and deletes the existing `wrappers/{python,java,php,swift,wasm}/pythia/` trees, along with all build-system, manifest, and CI references that point at them. The C library (`library/pythia/`), its native test suite (`tests/pythia/`), and the codegen XML model (`codegen/models/project_pythia/`) are intentionally **left in place** so a future reversal — or external use of the C library — remains cheap. After this lands, the WASM emsdk 4.x migration (`docs/plans/2026-04-15-001-refactor-wasm-emsdk-4-migration-plan.md`) has one less wrapper project to validate.

## Problem Frame

The new wrapper codegen migration (Roadmap Phase 7, see `docs/plans/2026-04-14-002-feat-remaining-wrapper-codegen-migration-plan.md`) ports five language wrappers — Python, Java, PHP, Swift, WASM — from GSL to a Python pipeline. Each wrapper currently generates a pythia subtree. Continuing to ship pythia wrappers carries ongoing cost: per-language file-count tests, parity validation, CMake wiring, Maven/npm/Gradle profile entries, Apple xcframework rebuilds, and Maven Central publishing — all for a project that downstream users no longer consume. Removing pythia from the wrapper surface now collapses those costs and shrinks the validation matrix for the upcoming emsdk migration. The C library and its native tests stay so the source-of-truth crypto code is preserved if external use re-emerges.

## Requirements Trace

- R1. The new codegen (`tools/codegen/common_bootstrap.py` and per-language backends) does not enumerate pythia and does not emit pythia wrapper files when run with `--apply`.
- R2. `wrappers/{python,java,php,swift,wasm}/pythia/` directories are deleted, including `wrappers/java/android/pythia/` and `wrappers/php/_handwritten/pythia/`.
- R3. CMake, Maven, Gradle, npm, and Swift Package Manager configuration files do not reference any deleted pythia paths or targets.
- R4. CI workflows (`build-wasm.yml`, `build-java-binaries.yml`, `release-wasm.yml`, `publish-release.yml`, `python-wheels-ci.yml`, `build-php-binaries.yml`, `build-macos.yml`, `build-go.yml`) build green on the migration branch with pythia removed.
- R5. The remaining four wrapper projects (`common`, `foundation`, `phe`, `ratchet`) regenerate, build, and pass their existing test suites.
- R6. `library/pythia/`, `tests/pythia/`, `codegen/models/project_pythia/`, and other non-wrapper pythia C/build artifacts are not modified by this plan.

## Scope Boundaries

- **Wrapper layer only.** The C library, its CMake build, its native `tests/pythia/` test suite, and the codegen IR/source XML for pythia are untouched.
- **No new codegen logic.** This plan only removes existing references; it does not refactor the per-backend prefix/namespace maps beyond deleting the `pythia` entry.
- **No replacement language wrapper.** Pythia simply stops being a wrapper-codegen target.
- **No emsdk version change** in this plan — that's covered separately in `docs/plans/2026-04-15-001-refactor-wasm-emsdk-4-migration-plan.md`.

### Deferred to Separate Tasks

- **WASM emsdk 3.1.51 → 4.x migration:** tracked in `docs/plans/2026-04-15-001-refactor-wasm-emsdk-4-migration-plan.md`. Sequenced **after** this plan so the migration validates against the smaller post-pythia wrapper matrix (3 WASM projects instead of 4).
- **Legacy GSL retirement (Activity 5):** `codegen/main.xml`, `codegen/*.gsl`, and `codegen/generated/pythia/` artifacts will be addressed by the GSL retirement plan tracked in `docs/plans/2026-04-14-003-remaining-codegen-activities-plan.md` (Activity 5). This plan touches the new codegen only.
- **C library deprecation/removal:** if pythia is eventually retired entirely, deleting `library/pythia/`, `tests/pythia/`, `codegen/models/project_pythia/`, `thirdparty/relic` (if pythia is its only consumer), and the `VIRGIL_LIB_PYTHIA` CMake option is a separate, larger effort.
- **Generated GSL artifacts under `codegen/generated/pythia/`:** these are stale GSL outputs not consumed by the new codegen (verify before merge with `grep -rn "generated/pythia" tools/codegen/` — expected zero hits; if any appear, fold them into Unit 1). Their cleanup belongs with GSL retirement.

## Context & Research

### Relevant Code and Patterns

**New codegen pipeline (`tools/codegen/`):**
- `tools/codegen/common_bootstrap.py:53` — `_SUPPORTED_PROJECTS = ("common", "foundation", "phe", "pythia", "ratchet")` is the single hardcoded project list driving orchestration; `supported_projects()`, the `--project` CLI choice list, the iteration loop, and `direct_c_renderers_for_project()` validation all derive from it.
- `tools/codegen/new_codegen.sh:75` — `ALL_PROJECTS="common foundation phe pythia ratchet"` parallels the Python list for shell-driven workflows.
- `tools/codegen/new_codegen.sh:110-117` — `pythia)` case branch supplying `LIB_RESTORE_PATHS`, `CMAKE_TARGET`, and `CMAKE_TEST_TARGET` for the pythia regeneration loop.
- Per-backend prefix/namespace maps:
  - `tools/codegen/project_swift_backend.py:246` — `"pythia": "VirgilCryptoPythia"` namespace mapping for cross-project Swift framework imports.
  - `tools/codegen/project_java_backend.py:572` — `_JAVA_WRAPPER_PROJECTS` set including pythia (filters which projects get Java output).
  - `tools/codegen/project_java_backend.py:978` — cross-project library validation tuple including pythia.
  - `tools/codegen/project_java_backend.py:1124`, `project_php_backend.py:116`, `project_python_backend.py:42`, `project_wasm_backend.py:195`, `project_go_backend.py:1009`, `project_cmake_backend.py:163` — each carries `"pythia": "vscp"` in its `_PROJECT_PREFIX_MAP` (Go's is defensive — pythia has never shipped a Go wrapper).
- Codegen tests with explicit pythia file-count assertions:
  - `tools/codegen/test_swift_backend.py:174-188` — `PythiaTests.test_pythia_file_count()` (4 Swift files).
  - `tools/codegen/test_java_backend.py:55-62` — `PythiaFileCountTests` (10 Java files).
  - `tools/codegen/test_php_backend.py:51-58` — `PythiaFileCountTests` (4 PHP files).
  - `tools/codegen/test_python_backend.py:50-57` — `PythiaFileCountTests` (7 Python files).
  - `tools/codegen/test_wasm_backend.py:71-79` — `PythiaFileCountTests` (5 WASM files = 4 JS + 1 CMake).

**Wrapper directories slated for deletion:**
- `wrappers/python/virgil_crypto_lib/pythia/` — 7 tracked files (`__init__.py`, `pythia.py`, `status.py`, `_c_bridge/` × 4).
- `wrappers/java/pythia/` — 16 files (parent + version-backup `pom.xml`, `CMakeLists.txt`, `jni/PythiaJNI.{c,h}`, 8 Java sources, 2 Java tests).
- `wrappers/java/android/pythia/` — Android library module: `build.gradle`, `.gitignore`, `proguard-rules.pro`, `proguard-rules.txt`, `src/main/AndroidManifest.xml`, `src/main/res/values/strings.xml`.
- `wrappers/php/VirgilCryptoWrapper/src/Pythia/Pythia.php` — single PHP class.
- `wrappers/php/VirgilCryptoWrapper/extensions/pythia/` — `CMakeLists.txt`, `vscp_pythia_php.c`, `vscp_pythia_php.h`.
- `wrappers/php/_handwritten/pythia/` and `wrappers/php/_handwritten/CMakeLists/pythia/` — legacy manual implementation (per `docs/plans/2026-04-14-002` Resolved Question, `_handwritten/` is not a codegen merge input).
- `wrappers/swift/VirgilCrypto/VirgilCryptoPythia/` — 5 files (`CContext.swift`, `Pythia.swift`, `PythiaError.swift`, `PythiaImplementation.swift`, `VirgilCryptoPythia.h`). The first four are codegen-produced; the `.h` is the umbrella header.
- `wrappers/swift/VirgilCryptoTest/VirgilCryptoPythiaTests/VirgilCryptoPythiaTests.swift`.
- `wrappers/wasm/pythia/` — 6 files (`CMakeLists.txt`, `exported_functions.json`, `src/{Pythia.js, PythiaError.js, index.js, precondition.js}`).

**CMake / build / manifest wiring referencing pythia:**
- Top-level `CMakeLists.txt:100,237-239,318,335` — `option(VIRGIL_LIB_PYTHIA …)`, `add_subdirectory("library/pythia")`, `cloc-pythia` target, and its `add_dependencies(cloc …)` entry. **Stays** — the C library is in scope-out.
- `wrappers/java/CMakeLists.txt:68` — `add_subdirectory(pythia)`.
- `wrappers/php/CMakeLists.txt:120` — `add_subdirectory(VirgilCryptoWrapper/extensions/pythia)`.
- `wrappers/wasm/CMakeLists.txt:88` — `add_subdirectory("pythia")`.
- `wrappers/go/CMakeLists.txt:47` — pythia install path reference (Go has no pythia wrapper code; this entry is residual).
- `tests/CMakeLists.txt:54-56` — `if(TARGET vsc::pythia) add_subdirectory(pythia)` for the C library tests. **Stays** — the C library and `tests/pythia/` are scope-out.
- `Package.swift:34-45,72-74,87,106-114` — `vscPythiaBinaryTarget`, `VirgilCryptoPythia` product/library/target, and `VirgilCryptoPythiaTests`.
- `wrappers/java/pom.xml` line 245 (`<module>pythia</module>` in the default `all` profile) and lines 267–272 (the `<profile><id>pythia</id>…</profile>` block).
- `wrappers/java/android/settings.gradle:1` — `include ':pythia'`.
- `wrappers/java/android/{app,benchmark}/build.gradle:33,31` — `implementation project(':pythia')`.
- `wrappers/wasm/package.json:12,15` — `"build:pythia"` script and its invocation in `"prepare"`.
- `wrappers/python/virgil_crypto_lib/_libs/low_level_libs.py:74` — `self.pythia = CDLL(...)` runtime loader for the pythia shared library; needed when the Python wrapper imported pythia.
- `wrappers/php/php_codegen.sh:7` — legacy GSL-era shell loop including pythia (out-of-scope per Deferred Tasks, but cheap to update here).

**CI / release / pre-built binaries:**
- `Jenkinsfile:665` — Windows DLL cleanup `rmdir wrappers\python\virgil_crypto_lib\pythia /s /q`.
- `Jenkinsfile:869` — `./mvnw clean deploy -P foundation,phe,pythia,ratchet,release …`.
- `.github/workflows/build-java-binaries.yml:370` — `./mvnw clean verify -P foundation,phe,pythia,ratchet`.
- `.github/workflows/publish-release.yml:98,167,183,202` — Maven release profile, Android Gradle publication tasks, central-bundle aggregation, and `pythia-android` artifact loop.
- `binaries/VSCPythia.xcframework.zip` and `binaries/VSCPythia.xcframework.zip.sha256sum` — Git LFS pre-built Apple xcframework + checksum referenced by `Package.swift`.
- `README.md:58` — wrapper-language matrix row listing pythia's wrapper languages.

### Institutional Learnings

- **From `docs/plans/2026-04-14-002` Resolved Question on `_handwritten/`:** the PHP `_handwritten/` directory is a legacy manual implementation predating the codegen, not a merge input consumed by GSL. Deleting `_handwritten/pythia/` and `_handwritten/CMakeLists/pythia/` is safe and parallels the rest of the pythia wrapper deletion.
- **From `docs/plans/2026-04-14-002` Coverage Matrix:** Go has no pythia wrapper; the `_PROJECT_PREFIX_MAP` entry in `project_go_backend.py` is defensive. Removing it cannot regress generation.
- **From `docs/plans/2026-04-15-001` Scope Boundaries:** the WASM emsdk migration explicitly does not refactor wrapper layout; sequencing pythia removal first means the emsdk plan sees a 3-project WASM matrix (foundation/phe/ratchet) instead of 4.
- **From `CLAUDE.md`:** the C library has a known Windows-incompatibility note for pythia (`-DVIRGIL_LIB_PYTHIA=OFF` for Windows builds). The library stays, so this note remains relevant and is **not** edited by this plan.
- **From `tools/codegen/CONTRIBUTING.md`:** the new codegen is the source of truth for wrapper output — hand-editing generated files drifts. Removing pythia at the codegen layer (Unit 1) before deleting wrapper files (Units 2–6) prevents a mid-stream regeneration from re-creating the trees.

### External References

- None gathered — this is internal refactoring with strong local patterns. The GSL-to-Python migration plan (`docs/plans/2026-04-14-002`) and the codegen architecture docs in `tools/codegen/` provide all needed context.

## Key Technical Decisions

- **Codegen-first ordering.** Unit 1 disables pythia in the new codegen *before* any wrapper directory is deleted. This guarantees that an accidental `common_bootstrap.py --apply` between units does not regenerate the trees we are about to delete.
- **One unit per wrapper.** Each language wrapper is a self-contained deletion unit that bundles wrapper-tree removal, CMake/manifest cleanup, and that language's CI workflow edits. This keeps each commit atomic, independently revertable, and CI-green at every step.
- **Each wrapper unit owns its CI updates.** Maven profile entries (`-P …pythia…`), Gradle publication tasks, and npm `build:pythia` scripts ride along with the wrapper deletion in the same unit. Splitting CI into a separate trailing unit creates intermediate commits where workflows reference deleted code.
- **Keep the prefix-map deletion conservative.** Only the literal `"pythia"` key is removed from each `_PROJECT_PREFIX_MAP`. The rest of the map and its lookup logic is left intact — no opportunistic refactoring.
- **Delete the codegen file-count tests rather than skip them.** A skipped test signals "intentionally disabled, may re-enable" — wrong for a permanent removal. Deletion makes the absence explicit.
- **Apple xcframework binary is deleted, not regenerated.** With the Swift wrapper sources gone, `VSCPythia.xcframework.zip` cannot be rebuilt by `./scripts/build_apple_frameworks.sh`. Removing the LFS file plus its `.sha256sum` and the matching `Package.swift` entries keeps the SwiftPM manifest consistent.
- **`codegen/main.xml` is left alone.** Its pythia entry is GSL-only orchestration; the new codegen reads `codegen/models/project_*/` directly via `project_source.py`. Editing `main.xml` is bundled with the GSL retirement task in `docs/plans/2026-04-14-003`.
- **`wrappers/php/php_codegen.sh:7` is updated as a courtesy.** It's a legacy GSL-era script, but the one-token edit is trivially included in the PHP unit so the file doesn't reference deleted pythia paths in the meantime.
- **Validation runs at the end, per-wrapper, not after every unit.** Building each wrapper between deletions would slow execution dramatically. Unit 7 runs the full per-wrapper build/test sweep once at the end; mid-stream confidence comes from the codegen test suite (`python -m unittest discover -s tools/codegen`) which is fast.

## Open Questions

### Resolved During Planning

- **Does removing pythia from `_PROJECT_PREFIX_MAP` in `project_go_backend.py` regress Go generation?** No. Pythia has never shipped a Go wrapper (per the wrapper coverage matrix in `docs/plans/2026-04-14-002`). The map entry is defensive and unused.
- **Is `wrappers/php/_handwritten/pythia/` consumed by anything?** No — per the `_handwritten/` audit in `docs/plans/2026-04-14-002`, it is a legacy manual implementation not consumed by codegen. Safe to delete.
- **Should `codegen/models/project_pythia/` be deleted?** No — explicitly out of scope per user direction. Keeps the door open for re-enabling pythia wrappers if downstream demand returns.
- **Should `library/pythia/` and `tests/pythia/` be deleted?** No — out of scope. The C library remains a buildable target via `VIRGIL_LIB_PYTHIA=ON`; native tests still cover it.
- **Is the existing emsdk 3→4 plan invalidated by removing pythia?** No. It still applies; it just gets a smaller WASM project matrix to validate. No edits to `docs/plans/2026-04-15-001` are required by this plan.
- **Does any production downstream consume pythia wrappers today?** No (per user direction — this is the trigger for the work).

### Deferred to Implementation

- **Are there orphaned LFS pointers or git-attributes entries for `binaries/VSCPythia.*`?** Inspect during Unit 3 — `git lfs ls-files | grep -i pythia` and `.gitattributes` should both be checked before committing the binary deletion.
- **Does `wrappers/go/CMakeLists.txt:47` need a more invasive edit, or just the pythia path entry removed?** Determine during Unit 4/5 (whichever lands first to touch Go-adjacent CMake) by reading the surrounding install logic.
- **Do any per-language test suites reference pythia indirectly** (e.g., a foundation test that imports a pythia type)? Discover during Unit 7's per-wrapper validation. Foundation/PHE/Ratchet do not depend on pythia per `codegen/models/project_pythia/project_pythia.xml` (one-way `pythia → common` dep), so direct fallout is unlikely.
- **Exact behavior of `mvn -P pythia` after profile removal:** confirm during Unit 6 that no other profile or workflow line silently references the deleted profile.

## Implementation Units

- [ ] **Unit 1: Disable pythia in the new codegen pipeline**

  **Goal:** Make `tools/codegen/` stop enumerating pythia so any future `--apply` does not regenerate the wrapper trees we are about to delete.

  **Requirements:** R1.

  **Dependencies:** None. Must land first.

  **Files:**
  - Modify: `tools/codegen/common_bootstrap.py` — remove `"pythia"` from `_SUPPORTED_PROJECTS` (line 53).
  - Modify: `tools/codegen/new_codegen.sh` — remove `pythia` from `ALL_PROJECTS` (line 75) and delete the `pythia)` case branch (lines ~110–117).
  - Modify: `tools/codegen/project_swift_backend.py` — remove `"pythia": "VirgilCryptoPythia"` from `_ns_map` (line ~246).
  - Modify: `tools/codegen/project_java_backend.py` — remove `pythia` from `_JAVA_WRAPPER_PROJECTS` (line ~572) and from the cross-project library validation tuple (line ~978); remove `"pythia": "vscp"` from the prefix map (line ~1124).
  - Modify: `tools/codegen/project_php_backend.py` — remove `"pythia": "vscp"` from `_PROJECT_PREFIX_MAP` (line ~116).
  - Modify: `tools/codegen/project_python_backend.py` — remove `"pythia": "vscp"` (line ~42).
  - Modify: `tools/codegen/project_wasm_backend.py` — remove `"pythia": "vscp"` (line ~195).
  - Modify: `tools/codegen/project_go_backend.py` — remove `"pythia": "vscp"` (line ~1009).
  - Modify: `tools/codegen/project_cmake_backend.py` — remove `"pythia": "vscp"` from the fallback prefix map (line ~163).
  - Delete (per-test-class blocks, not whole files):
    - `tools/codegen/test_swift_backend.py` lines ~174–188 (`PythiaTests`).
    - `tools/codegen/test_java_backend.py` lines ~55–62 (`PythiaFileCountTests`).
    - `tools/codegen/test_php_backend.py` lines ~51–58 (`PythiaFileCountTests`).
    - `tools/codegen/test_python_backend.py` lines ~50–57 (`PythiaFileCountTests`).
    - `tools/codegen/test_wasm_backend.py` lines ~71–79 (`PythiaFileCountTests`).

  **Approach:**
  - Single-key removals across the prefix maps; preserve the rest of each map unchanged.
  - For `common_bootstrap.py`, `_SUPPORTED_PROJECTS` is the canonical project list and is consumed by the CLI `choices=` (line ~1043) and the iteration loop (line ~1053) — no other callers need editing.
  - For `new_codegen.sh`, the `pythia)` case branch supplies project-specific paths; deleting the whole branch is cleaner than gutting it.
  - Test classes are deleted whole rather than skipped; do not leave `@unittest.skip` markers.

  **Patterns to follow:**
  - The hardcoded-list editing pattern is mechanical — pattern matches `"pythia"` in tuples/sets/dicts. Use `grep -n` to find each, edit, and verify with the codegen test suite.

  **Test scenarios:**
  - Happy path: `python3 -m unittest discover -s tools/codegen -p "test_*.py" -v` passes (the prior 153 tests minus the 5 deleted pythia file-count tests).
  - Happy path: `tools/codegen/common_bootstrap.py --help` shows `--project` choices `{common,foundation,phe,ratchet,all}` (no pythia).
  - Happy path: `tools/codegen/common_bootstrap.py --project foundation --apply` regenerates foundation wrappers and does not touch any `wrappers/*/pythia/` directory (verify via `git status`).
  - Edge case: `tools/codegen/common_bootstrap.py --project pythia --apply` exits with a CLI choice error (argparse rejects unknown choice).
  - Edge case: `bash tools/codegen/new_codegen.sh` (no args) iterates the four remaining projects and never references `pythia` in its output.

  **Verification:**
  - All non-pythia codegen tests pass.
  - Regenerating each remaining project (`common`, `foundation`, `phe`, `ratchet`) produces a clean diff (no incidental changes from removing pythia from cross-project resolution helpers).
  - `git grep -n pythia tools/codegen/` returns zero hits.

- [ ] **Unit 2: Delete WASM pythia wrapper, CMake/npm wiring**

  **Goal:** Remove `wrappers/wasm/pythia/` and every WASM build/manifest reference to it.

  **Requirements:** R2, R3, R4.

  **Dependencies:** Unit 1.

  **Files:**
  - Delete: `wrappers/wasm/pythia/` (6 files including `CMakeLists.txt`, `src/`, `exported_functions.json`).
  - Modify: `wrappers/wasm/CMakeLists.txt` — remove `add_subdirectory("pythia")` (line ~88).
  - Modify: `wrappers/wasm/package.json` — remove the `"build:pythia"` script (line ~12) and remove its invocation from `"prepare"` (line ~15).
  - If any `wrappers/wasm/tests/pythia/` subdirectory exists, delete it. (Verify; per Phase-1 investigation only foundation/phe Jest tests are exercised by CI today.)
  - Update the deleted `tools/codegen/test_wasm_backend.py` `PythiaFileCountTests` constant if Unit 1 retained an interim assertion: actual count is 6 (4 JS + CMakeLists + exported_functions.json), not 5. Unit 1 deletes the test class outright, so this is informational only.

  **Approach:**
  - Delete the directory tree first, then prune CMake and `package.json` references in the same commit so the build state is consistent.
  - The `prepare` script edit removes the `&& npm run build:pythia` token while leaving the surrounding `&&` chain intact for the remaining three projects.

  **Patterns to follow:**
  - The WASM codegen plan (`docs/plans/2026-04-14-002` Phase 2) and the existing per-project layout in `wrappers/wasm/{foundation,phe,ratchet}/` confirm what the directory shape looks like and which files are project-local.

  **Test scenarios:**
  - Happy path: from a clean tree, `emcmake cmake -Cconfigs/wasm-config.cmake -Bbuild-wasm -S.` configures successfully without referencing `pythia`.
  - Happy path: `cmake --build build-wasm` produces the three remaining wrappers (foundation/phe/ratchet) and skips pythia entirely.
  - Happy path: `cd build-wasm/wrappers/wasm && npm install && npm run prepare` succeeds; the resulting `dist/` contains `{foundation,phe,ratchet}/` but no `pythia/`.
  - Happy path: `npm test` passes the existing Jest suite (no pythia tests exist in `wrappers/wasm/tests/` today, so the count is unchanged).
  - Edge case: `git grep -n -i pythia wrappers/wasm/` returns zero hits after deletion.

  **Verification:**
  - `wrappers/wasm/dist/pythia/` does not exist after a clean build.
  - `build-wasm.yml` job passes when pushed to the migration branch.

- [ ] **Unit 3: Delete Swift pythia wrapper, Package.swift entries, and pre-built xcframework binary**

  **Goal:** Remove `wrappers/swift/VirgilCrypto/VirgilCryptoPythia/`, the matching test target, all `Package.swift` entries, and the LFS-stored `binaries/VSCPythia.xcframework.zip` + checksum.

  **Requirements:** R2, R3, R4.

  **Dependencies:** Unit 1.

  **Files:**
  - Delete: `wrappers/swift/VirgilCrypto/VirgilCryptoPythia/` (5 files: `CContext.swift`, `Pythia.swift`, `PythiaError.swift`, `PythiaImplementation.swift`, `VirgilCryptoPythia.h`).
  - Delete: `wrappers/swift/VirgilCryptoTest/VirgilCryptoPythiaTests/VirgilCryptoPythiaTests.swift` (and the containing directory if empty after deletion).
  - Delete: `binaries/VSCPythia.xcframework.zip`.
  - Delete: `binaries/VSCPythia.xcframework.zip.sha256sum`.
  - Delete: `carthage-specs/VSCPythia.json`.
  - Modify: `Package.swift` — remove `vscPythiaBinaryTarget` closure (lines ~34–45), the `VirgilCryptoPythia` `.library` product (lines ~72–74), the entry from the targets array (line ~87), and both `.target` / `.testTarget` definitions (lines ~106–114).
  - Modify: `.gitattributes` — remove the two `binaries/VSCPythia.xcframework.zip*` LFS rules (the entries are present today; the edit is required, not conditional).
  - Modify: `scripts/build_apple_frameworks.sh` line 236 — remove the hardcoded `make_xcarchive VSCPythia "${DESTINATION_DIR}" "${XCFRAMEWORKS_DESTINATION_DIR}"` invocation. The script does not derive its target list from `Package.swift`; without this edit the post-deletion build will fail trying to archive a non-existent target.
  - Modify: `scripts/bumpver.sh` line 176 — remove `VSCPythia` from the `for PROJ in VSCCommon VSCFoundation VSCPythia VSCRatchet` loop. Without this edit, every future `bumpver.sh` run would regenerate `carthage-specs/VSCPythia.json` pointing at a non-existent release asset.

  **Approach:**
  - Run `git lfs ls-files | grep -i pythia` before deletion to confirm what LFS tracks; remove all matches.
  - Each `Package.swift` removal is a contiguous block — read the file once, plan the four edits, apply them in descending line order so earlier line numbers stay stable.
  - Confirm no remaining `.target` or `.testTarget` lists `VirgilCryptoPythia` or `VSCPythia` in its dependencies (grep `Package.swift` for both symbols after edit — expect zero hits).
  - The Apple framework script (`scripts/build_apple_frameworks.sh`) and the Carthage-spec generator (`scripts/bumpver.sh`) are hand-maintained, not derived from `Package.swift`. Their pythia entries must be removed explicitly or the next build/release run will fail or regenerate the deleted carthage spec.

  **Patterns to follow:**
  - The `Package.swift` block layout for the remaining wrappers (`VirgilCryptoFoundation`, `VirgilCryptoRatchet`) is the template — keep their entries unchanged.

  **Test scenarios:**
  - Happy path: `swift package describe` (or `swift package show-dependencies`) lists `VirgilCryptoFoundation` and `VirgilCryptoRatchet` but not `VirgilCryptoPythia`.
  - Happy path: `./scripts/build_apple_frameworks.sh` succeeds without attempting to build `VSCPythia.xcframework`.
  - Happy path: `./scripts/run_spm_tests_with_local_binaries.sh` passes existing SPM tests; `VirgilCryptoPythiaTests` no longer appears in the test output.
  - Edge case: `git lfs ls-files` returns no `VSCPythia*` entries.
  - Error path: if `Package.swift` is missing one of the four edits, `swift package resolve` fails fast with a clear "missing target" error — that's the signal to fix before merging.

  **Verification:**
  - `binaries/` directory contains no `VSCPythia*` files.
  - `swift build` and `swift test` succeed against the remaining targets.
  - `build-macos.yml` job passes when pushed to the migration branch.

- [ ] **Unit 4: Delete Python pythia wrapper and Jenkinsfile cleanup line**

  **Goal:** Remove `wrappers/python/virgil_crypto_lib/pythia/` and the runtime CDLL loader entry, plus the Windows-DLL Jenkinsfile cleanup that targeted it.

  **Requirements:** R2, R3, R4.

  **Dependencies:** Unit 1.

  **Files:**
  - Delete: `wrappers/python/virgil_crypto_lib/pythia/` (7 tracked files).
  - Modify: `wrappers/python/virgil_crypto_lib/_libs/low_level_libs.py` — remove the entire `if platform.system() != "Windows":` block (~lines 73–77) that constructs `self.pythia = CDLL(...)`. Removing only the `self.pythia` line leaves an empty `if` body and produces a Python `SyntaxError`. Also chase any imports/refs that become unused as a result.
  - Modify: `Jenkinsfile` — remove the Windows DLL cleanup line `rmdir wrappers\python\virgil_crypto_lib\pythia /s /q` (line ~665).
  - If `wrappers/python/virgil_crypto_lib/__init__.py` re-exports `pythia` (verify), prune the import.

  **Approach:**
  - The `low_level_libs.py` edit is one line plus possibly an unused `pythia_lib_name`/`PYTHIA_LIB_NAME` constant — chase imports until the deletion is clean.
  - Python wrapper has no Maven/Gradle/npm profile entries to worry about; its CI is `python-wheels-ci.yml` which uses cibuildwheel and does not name pythia.

  **Patterns to follow:**
  - The other CDLL loader entries (`self.foundation`, `self.phe`, `self.ratchet`) in `low_level_libs.py` confirm the shape; remove only the pythia entry.

  **Test scenarios:**
  - Happy path: `cmake -Cconfigs/python-config.cmake -Bbuild-python -S. && cmake --build build-python --target install` succeeds.
  - Happy path: `python -m unittest discover -s wrappers/python/virgil_crypto_lib/tests -p "*_test.py"` passes.
  - Happy path: `from virgil_crypto_lib import foundation, phe` works; `from virgil_crypto_lib import pythia` raises `ImportError`.
  - Edge case: `low_level_libs.py` does not crash at import time when no pythia shared library is present on disk.
  - Error path: a stale `.pyc` referencing `virgil_crypto_lib.pythia` is regenerated correctly on next import (clear `__pycache__` if needed during local validation).

  **Verification:**
  - `wrappers/python/virgil_crypto_lib/pythia/` does not exist.
  - `python-wheels-ci.yml` job passes when pushed.
  - `git grep -n -i pythia wrappers/python/` returns zero hits.

- [ ] **Unit 5: Delete PHP pythia wrapper, extension, `_handwritten/`, and CMake wiring**

  **Goal:** Remove every PHP-side reference to pythia: the high-level class, the C extension, the legacy `_handwritten/` tree, the per-project CMake wiring, and the legacy GSL shell-loop entry.

  **Requirements:** R2, R3, R4.

  **Dependencies:** Unit 1.

  **Files:**
  - Delete: `wrappers/php/VirgilCryptoWrapper/src/Pythia/` (1 file: `Pythia.php`).
  - Delete: `wrappers/php/VirgilCryptoWrapper/extensions/pythia/` (3 files).
  - Delete: `wrappers/php/VirgilCryptoWrapper/tests/Pythia/` (PHPUnit tests of the deleted `Virgil\CryptoWrapper\Pythia\*` classes — leaving them creates a class-not-found failure in `build-php-binaries.yml`).
  - Delete: `wrappers/php/_handwritten/pythia/` (3 entries: `CMakeLists.txt`, `extension/`, `tests/`).
  - Delete: `wrappers/php/_handwritten/CMakeLists/pythia/` (sibling directory; contains `CMakeLists.txt`).
  - Modify: `wrappers/php/CMakeLists.txt` — remove `add_subdirectory(VirgilCryptoWrapper/extensions/pythia)` (line ~120).
  - Modify: `wrappers/php/php_codegen.sh` — remove `pythia` from the `for project in …` loop (line ~7). Out-of-scope per Deferred Tasks (legacy GSL), but the one-token edit is included so the file does not reference deleted paths in the meantime.

  **Approach:**
  - PHP is the only wrapper with both a generated extension and a `_handwritten/` parallel tree. Both are pythia-specific and both go.
  - PHP CI (`build-php-binaries.yml`) does not name pythia by profile (PHP build picks up whatever `add_subdirectory` declares); no workflow edits beyond the CMake change.

  **Patterns to follow:**
  - Other wrappers' `extensions/` entries (`foundation/`, `phe/`) remain — confirm by inspection that the deletion does not also remove their `add_subdirectory` lines.

  **Test scenarios:**
  - Happy path: `cmake -Cconfigs/php-config.cmake -Bbuild-php -S.` configures without referencing pythia.
  - Happy path: `cmake --build build-php` builds the foundation and phe PHP extensions.
  - Happy path: `cd build-php && ctest --verbose` passes (PHPUnit via cmake-registered targets); no pythia test target appears.
  - Edge case: `wrappers/php/_handwritten/CMakeLists/pythia/` deletion does not orphan a parent CMakeLists.txt that referenced it. Verify by reading `wrappers/php/_handwritten/CMakeLists/CMakeLists.txt` (if present) before deleting.
  - Edge case: `git grep -n -i pythia wrappers/php/` returns zero hits.

  **Verification:**
  - `build-php-binaries.yml` passes when pushed.
  - PHP extensions build and load with `php -dextension=…`.

- [ ] **Unit 6: Delete Java pythia wrapper, Android module, Maven/Gradle profiles, and CI publishing entries**

  **Goal:** The largest deletion unit — Java desktop wrapper, Android library, Maven parent pom and per-profile entries, Gradle includes/dependencies, and every CI workflow line that references pythia for build, verify, or publish.

  **Requirements:** R2, R3, R4.

  **Dependencies:** Unit 1.

  **Files:**
  - Delete: `wrappers/java/pythia/` (16 files including `pom.xml`, `pom.xml.versionsBackup`, `CMakeLists.txt`, `jni/`, `src/main/java/…`, `src/test/java/…`, `src/test/resources/…`).
  - Delete: `wrappers/java/android/pythia/` (Android library module).
  - Modify: `wrappers/java/CMakeLists.txt` — remove `add_subdirectory(pythia)` (line ~68).
  - Modify: `wrappers/java/pom.xml` — remove `<module>pythia</module>` from the default `all` profile (line ~245) and remove the entire `<profile><id>pythia</id>…</profile>` block (lines ~267–272).
  - Modify: `wrappers/java/android/settings.gradle` — remove `':pythia'` from the `include` directive (line ~1).
  - Modify: `wrappers/java/android/app/build.gradle` — remove `implementation project(':pythia')` (line ~33).
  - Skip `wrappers/java/android/benchmark/build.gradle`: the `:benchmark` module is currently commented out of `settings.gradle` (`//, ':benchmark'`), so the Gradle resolver never reaches it. Editing a dormant module adds no verification value and the proposed `./gradlew :benchmark:assembleDebug` test scenario would fail with "project not found" regardless of pythia state. If `:benchmark` is later re-enabled, the pythia dependency goes with the rest of this commit's git history.
  - Modify: `Jenkinsfile` line ~869 — change `-P foundation,phe,pythia,ratchet,release` → `-P foundation,phe,ratchet,release`.
  - Modify: `.github/workflows/build-java-binaries.yml` line ~370 — change `-P foundation,phe,pythia,ratchet` → `-P foundation,phe,ratchet`.
  - Modify: `.github/workflows/publish-release.yml`:
    - Line ~98 — Maven release profile: `-P foundation,phe,pythia,ratchet,release` → `-P foundation,phe,ratchet,release`.
    - Lines ~167 and ~183 — remove `:pythia:publishReleasePublicationToCentralBundleRepository` from the Gradle help check and from the aggregate publish task list.
    - Line ~202 — remove `pythia-android` from the artifact-directory loop (or adjust loop logic so the remaining entries are intact).

  **Approach:**
  - Run all CI/Maven/Gradle edits and the directory deletions in the same commit. Splitting them creates a window where CI references deleted paths.
  - Verify each edited workflow file with `actionlint` (if available) or by visual diff against the previous green commit.
  - The Maven `pythia` profile block is contiguous; copy the whole block out before deletion to confirm no other profile inherits from it.

  **Patterns to follow:**
  - Other Maven module entries in the parent `pom.xml` and other Android `include` entries in `settings.gradle` show the surrounding shape; do not remove sibling entries.

  **Test scenarios:**
  - Happy path: `cmake -Cconfigs/java-config.cmake -Bbuild-java -S. && cmake --build build-java --target install` succeeds.
  - Happy path: `cd wrappers/java && ./mvnw clean verify -P foundation,phe,ratchet` passes for all three remaining modules.
  - Happy path: `./mvnw -pl pythia ...` fails fast with "module not found" (signal that the profile/module entries are gone).
  - Happy path: from `wrappers/java/android`, `./gradlew :app:assembleDebug` succeeds without referencing `:pythia`. (`:benchmark` is dormant and not exercised; see Files notes.)
  - Edge case: `./gradlew help --task :pythia:publishReleasePublicationToCentralBundleRepository` fails fast (signal that the Android module is gone).
  - Edge case: `git grep -n -i pythia wrappers/java/` returns zero hits.
  - Edge case: `git grep -n -i pythia .github/workflows/ Jenkinsfile` returns zero hits.

  **Verification:**
  - `build-java-binaries.yml` job passes when pushed to the migration branch.
  - `publish-release.yml` dry-run (manual trigger or branch test, since real trigger is `v*` tag) runs to the publish step without errors related to pythia targets.

- [ ] **Unit 7: End-to-end validation, README and grep audit**

  **Goal:** Prove the post-pythia state builds and tests cleanly across all remaining wrappers, and update documentation that promised pythia wrapper coverage.

  **Requirements:** R4, R5.

  **Dependencies:** Units 1–6.

  **Files:**
  - Modify: `README.md` line ~58 — update the `pythia` row in the language-coverage table to reflect that pythia ships only as a C library now (or remove the wrapper-language links). Keep the `library/pythia/` description (lines ~44–46) intact.
  - No source changes beyond the README.
  - Reference paths for validation:
    - WASM: `wrappers/wasm/tests/**`
    - Swift: `wrappers/swift/VirgilCryptoTest/**`
    - PHP: `wrappers/php/VirgilCryptoWrapper/tests/**`
    - Python: `wrappers/python/virgil_crypto_lib/tests/**`
    - Java: `wrappers/java/{foundation,phe,ratchet}/src/test/**`
    - Go: `wrappers/go/**` (Go was unaffected by codegen prefix-map removal but build-green check is cheap).

  **Approach:**
  - From a freshly cloned worktree, regenerate all wrappers via `bash tools/codegen/new_codegen.sh` (or per-project `--apply`) and confirm zero changes touch any deleted pythia path.
  - Run each wrapper's local build + test recipe (per the table in `docs/plans/2026-04-14-003` Activity 1):
    - Go: `cd wrappers/go && go test ./...`.
    - Swift: `./scripts/build_apple_frameworks.sh && ./scripts/run_spm_tests_with_local_binaries.sh`.
    - WASM: `emcmake cmake -Cconfigs/wasm-config.cmake -Bbuild-wasm -S. && cmake --build build-wasm && (cd build-wasm/wrappers/wasm && npm install && npm run prepare && npm test)`.
    - PHP: `cmake -Cconfigs/php-config.cmake -Bbuild-php -S. && cmake --build build-php && (cd build-php && ctest --verbose)`.
    - Python: `cmake -Cconfigs/python-config.cmake -Bbuild-python -S. && cmake --build build-python --target install && python -m unittest discover -s wrappers/python/virgil_crypto_lib/tests -p "*_test.py"`.
    - Java: `cmake -Cconfigs/java-config.cmake -Bbuild-java -S. && cmake --build build-java --target install && (cd wrappers/java && ./mvnw clean verify -P foundation,phe,ratchet)`.
  - Push the branch and confirm every CI workflow listed under R4 goes green.
  - Final `git grep -n -i pythia wrappers/ tools/codegen/ Package.swift Jenkinsfile .github/workflows/ scripts/ carthage-specs/` returns zero hits. Legitimate remaining pythia references live outside those paths: `library/pythia/`, `tests/pythia/`, `codegen/models/project_pythia/`, `codegen/generated/pythia/` (deferred to GSL retirement), top-level `CMakeLists.txt` `VIRGIL_LIB_PYTHIA` lines, `CLAUDE.md` C-library notes, `README.md` C-library prose, and the plan/review documents under `docs/plans/` and `memory/`. Audit any hit that falls outside this enumerated set.

  **Execution note:** This is the safety net. If any wrapper's tests fail, open a follow-up unit rather than papering over with skips or `--no-verify`.

  **Patterns to follow:**
  - The validation pattern from `docs/plans/2026-04-14-003` Activity 1 is the closest precedent — same per-wrapper build/test commands.

  **Test scenarios:**
  - Happy path: every CI workflow listed under R4 passes on the migration branch.
  - Happy path: every local per-wrapper build + test command above exits 0.
  - Happy path: `bash tools/codegen/new_codegen.sh` with no args produces a clean `git status` (no drift) — confirms the codegen no longer treats pythia as in-scope.
  - Edge case: an `import virgil_crypto_lib.pythia` from a downstream Python script raises `ImportError` (functional confirmation that the wrapper is gone, not that the package is broken).
  - Edge case: a Maven build with `-P pythia` fails fast (functional confirmation that the profile is gone).
  - Integration: pulling the migration branch in a fresh worktree, running `git lfs pull`, and inspecting `binaries/` confirms no `VSCPythia*` LFS objects.

  **Verification:**
  - All CI workflows green.
  - `git grep -n -i pythia` returns only the scope-out paths (`library/pythia/`, `tests/pythia/`, `codegen/models/project_pythia/`, `codegen/generated/pythia/`, top-level CMake `VIRGIL_LIB_PYTHIA` references, `CLAUDE.md` notes, `README.md` C-library prose, and plan/review documents under `docs/plans/` and `memory/`).
  - README accurately describes pythia's new "C library only" status.

## System-Wide Impact

- **Interaction graph:** Six surfaces — the new codegen pipeline, five wrapper trees, and the CI/release pipelines. Unit 1 (codegen) gates all later units; Units 2–6 are independent of each other and could land in any order or in parallel commits. Unit 7 is the final integration check across all six.
- **Error propagation:** Most failures will surface at CMake configure time (missing `add_subdirectory` target), Maven/Gradle resolution time (missing module/profile), or Jest/PHPUnit/JUnit/unittest time (missing wrapper class import). The codegen test suite (Unit 1) catches map-removal regressions before any wrapper-level breakage.
- **State lifecycle risks:** Build artifacts in `build-*/`, `wrappers/*/dist/`, and Maven local repository may contain stale pythia entries from prior runs. Unit 7's clean-tree validation explicitly tests this. Git LFS objects for `VSCPythia*` need to be removed alongside the working-tree files; orphaned LFS pointers would otherwise show up in `git lfs ls-files`.
- **API surface parity:** Pythia wrapper APIs (`virgil_crypto_lib.pythia.*`, `com.virgilsecurity.crypto.pythia.*`, `Virgil\CryptoWrapper\Pythia\*`, `VirgilCryptoPythia`, WASM `Pythia`/`PythiaError`) all disappear. This is an intentional **breaking change** for any downstream consumer that still imports them — the user has confirmed there are no such consumers in production.
- **Integration coverage:** Per-wrapper Jest/PHPUnit/JUnit/unittest/SPM suites run end-to-end in Unit 7, covering the cross-wrapper integration that mocks alone could not prove (e.g., pythia-removal does not silently break foundation/phe/ratchet imports).
- **Unchanged invariants:**
  - `library/pythia/` C library, its CMake, its `tests/pythia/` native tests, the `VIRGIL_LIB_PYTHIA` build option, and the `cloc-pythia` aggregate-LOC target.
  - `codegen/models/project_pythia/` XML model, untouched.
  - `codegen/main.xml` pythia entry — left for the GSL retirement plan.
  - All four remaining wrapper projects (`common`, `foundation`, `phe`, `ratchet`) — generated bytes, build outputs, and test results unchanged.
  - The Apple xcframework binaries for non-pythia frameworks (`VSCFoundation`, `VSCRatchet`, etc.) in `binaries/`.
  - The codegen contract `generate_*_files(project_ir, …) -> list[(path, content)]` for each remaining backend.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| A workflow file (`publish-release.yml`, `build-java-binaries.yml`) references pythia in a way the agent's grep missed (e.g., a matrix entry, an env var, a step `if:` condition). | Unit 6 includes a `git grep -n -i pythia .github/workflows/ Jenkinsfile` check before commit; Unit 7 confirms all workflows pass green on the branch push. |
| Deleting `binaries/VSCPythia.xcframework.zip` LFS object in the working tree leaves a dangling pointer or `.gitattributes` rule. | Unit 3 explicitly inspects `git lfs ls-files | grep -i pythia` and `.gitattributes` before committing the deletion. |
| `Package.swift` four-edit sequence shifts line numbers and one of the four blocks is partially deleted, breaking SPM. | Unit 3 reads the full `Package.swift` once, plans the four edits in descending-line order, and validates with `swift package describe` before commit. |
| Removing pythia from `_PROJECT_PREFIX_MAP` in a wrapper backend silently changes generated output for another project (e.g., a foundation cross-project resolver fell back through pythia somewhere). | Unit 1 regenerates each remaining project after the map removals and diffs against `git status`; any unexpected output flags the regression. |
| The `_handwritten/CMakeLists/pythia/` deletion orphans a parent `_handwritten/CMakeLists/CMakeLists.txt` that called `add_subdirectory(pythia)`. | Unit 5 explicitly reads the parent CMakeLists (if present) before deleting and prunes any reference. |
| Maven `pythia` profile removal regresses another profile that inherited or referenced it. | Unit 6 inspects the full `<profiles>` block and runs `./mvnw help:active-profiles -P foundation,phe,ratchet` against the remaining modules. |
| A future GSL run still reads `codegen/main.xml`'s pythia entry and re-emits files into deleted directories. | Out of scope for this plan, but the GSL retirement plan (`docs/plans/2026-04-14-003` Activity 5) handles `main.xml`. As mitigation in the meantime, do not run the GSL pipeline against pythia after this lands. |
| Downstream consumers we did not anticipate import a deleted pythia API and break. | User has confirmed no production consumers. If wrong, reverting one wrapper unit is a single-commit operation; full revert is N+1 commits. |
| WASM emsdk migration plan (`docs/plans/2026-04-15-001`) was written assuming a 4-project WASM matrix; references like "all 4 projects" become inaccurate. | Cosmetic — the plan's mechanics (relic patch, `--llvm-lto` removal, version bump) do not depend on project count. The plan's deepening pass can be re-run later if precision matters; not blocking. |

## Documentation / Operational Notes

- Update `README.md` line ~58 in Unit 7 to remove the wrapper-language links from the `pythia` row (or replace with a note that pythia ships as a C library only). Keep lines ~44–46 (the C-library description) intact.
- `CLAUDE.md` is **not** edited — its references to pythia (`library/` table row, Windows compilation note) describe the C library, which remains in scope.
- After merge, capture the change in `memory/project_pythia_removal.md` (auto-memory) noting: pythia wrappers removed 2026-04-17, C library and codegen XML model retained for possible reactivation, GSL pythia entries deferred to retirement plan.
- The next emsdk migration (`docs/plans/2026-04-15-001`) should now expect a 3-project WASM matrix (`foundation`, `phe`, `ratchet`) — communicate this to anyone picking up that plan, but do not edit it now.
- No monitoring or rollout — this is a pure source/build cleanup; the npm package contents change (pythia subdir gone), but the package version bump and publish remain on the existing release cadence.

## Sources & References

- Related plans:
  - `docs/plans/2026-04-14-002-feat-remaining-wrapper-codegen-migration-plan.md` — wrapper codegen migration that originally added pythia generation.
  - `docs/plans/2026-04-14-003-remaining-codegen-activities-plan.md` — GSL retirement (Activity 5) covers `codegen/main.xml` and `codegen/generated/pythia/`.
  - `docs/plans/2026-04-15-001-refactor-wasm-emsdk-4-migration-plan.md` — WASM emsdk 3.1.51 → 4.x migration, sequenced after this plan.
- Codegen orchestration: `tools/codegen/common_bootstrap.py`, `tools/codegen/new_codegen.sh`.
- Per-language backends: `tools/codegen/project_{swift,wasm,php,python,java,go,cmake}_backend.py`.
- Codegen tests: `tools/codegen/test_{swift,wasm,php,python,java}_backend.py`.
- Wrapper trees slated for deletion: `wrappers/{python,java,php,swift,wasm}/pythia/` and `wrappers/java/android/pythia/`.
- CMake: top-level `CMakeLists.txt`, `wrappers/{java,php,wasm,go}/CMakeLists.txt`, `tests/CMakeLists.txt`.
- Manifests: `Package.swift`, `wrappers/java/pom.xml`, `wrappers/java/android/{settings.gradle,app/build.gradle,benchmark/build.gradle}`, `wrappers/wasm/package.json`.
- CI / release: `.github/workflows/{build-wasm,build-java-binaries,build-macos,build-php-binaries,build-go,publish-release,release-wasm,python-wheels-ci}.yml`, `Jenkinsfile`.
- Pre-built binaries: `binaries/VSCPythia.xcframework.zip(.sha256sum)`.
- XML source models retained: `codegen/models/project_pythia/{project_pythia.xml,class_pythia.xml,enum_status.xml}`.
