---
title: "refactor: Remove Pythia and Relic libraries completely"
type: refactor
status: active
date: 2026-05-06
---

# refactor: Remove Pythia and Relic libraries completely

## Overview

Pythia is a verifiable oblivious pseudorandom function (vOPRF) library that depends exclusively on Relic (a pairing-based cryptography toolkit). No other library in this repo depends on either. This plan removes both libraries in their entirety — C source, thirdparty build, all seven language wrappers, codegen models, CI/CD references, pre-built binaries, and scripts.

## Problem Frame

Pythia and Relic represent a niche cryptographic primitive (BLS12-381 pairing curves, vOPRF protocol) that is no longer required. Maintaining them incurs ongoing cost: Relic is fetched via `ExternalProject_Add` at build time (network dependency, slow CI), Pythia requires an explicit `-DVIRGIL_LIB_PYTHIA=OFF` workaround in Windows CI jobs, Apple framework build scripts carry Relic-specific flags, and all seven language wrappers must track Pythia releases. Complete removal eliminates the workaround and the entire maintenance surface.

## Requirements Trace

### Deletion & Removal
- R1. All Pythia C source, headers, CMake targets, and tests are deleted.
- R2. Relic thirdparty directory and all fetched artifacts are deleted.
- R3. All seven language wrapper Pythia modules are deleted (Python, Java, Android, PHP, Swift, Go pre-builts; WASM already excluded).
- R5. CI/CD workflows and release scripts no longer reference Pythia or Relic.
- R6. Pre-built binary artifacts (xcframework, static libs, JNI .so, Python dylib) are deleted.

### Build & Integration
- R7. The project builds successfully for all remaining libraries (foundation, phe, ratchet, common) after removal.

### Codegen & Source of Truth
- R4. The codegen system (models, backends, tests) no longer references Pythia or Relic.
- R8. Re-running codegen (`--project all --apply`) produces no Pythia output.

## Scope Boundaries

- WASM already excluded Pythia via `configs/wasm-config.cmake` — no WASM wrapper changes needed beyond removing that now-dead `VIRGIL_LIB_PYTHIA OFF` line.
- Go has no Go-language source for Pythia (only pre-built C static libs); only the pre-built artifacts and CMakeLists reference need removal.
- `ChangeLog.md` human authoring is out of scope — implementer may add a changelog entry as a courtesy but it is not required.
- No replacement or alternative for Pythia's functionality is in scope.

## Context & Research

### Relevant Code and Patterns

- `library/pythia/CMakeLists.txt` — defines `vsc::pythia` target linking `vsc::common mbed::crypto relic`; no other library links `vsc::pythia`
- `thirdparty/relic/CMakeLists.txt` — fetches Relic via `ExternalProject_Add` from a pinned GitHub tag; exclusively consumed by Pythia
- `CMakeLists.txt` lines 100, 197-206, 254-256, 335-352 — master `VIRGIL_LIB_PYTHIA` option; combined MbedTLS guard `if(VIRGIL_LIB_FOUNDATION OR VIRGIL_LIB_PYTHIA)` must simplify to `if(VIRGIL_LIB_FOUNDATION)`; `cloc-pythia` custom target
- `tools/codegen/common_bootstrap.py` line 54 — `_SUPPORTED_PROJECTS` tuple includes `"pythia"`
- `codegen/models/external/library_relic.xml` — Relic external library IR; `codegen/models/project_pythia/` — Pythia IR models (3 files)
- `scripts/build_apple_frameworks.sh` — carries `-DRELIC_USE_PTHREAD` flags and `make_xcarchive VSCPythia` call
- `docs/solutions/best-practices/external-library-cmake-codegen-2026-04-26.md` — confirms that `thirdparty/*/features.cmake` is generated from `codegen/models/external/library_*.xml`; removing the XML and deleting the directory in tandem is correct

### Institutional Learnings

- Removing an external library requires deleting both the codegen XML model and the generated thirdparty directory; these must be done together or CMake will find orphaned targets.
- Codegen re-run after model removal verifies no Pythia output is regenerated (R8).

### External References

None needed — this is pure deletion with no replacement technology.

## Key Technical Decisions

- **Delete directories wholesale rather than file-by-file**: All five Pythia directories (`library/pythia/`, `thirdparty/relic/`, `tests/pythia/`, plus all wrapper subdirs) are fully owned by Pythia. Deleting the directory is faster, less error-prone, and leaves no orphaned files.
- **Simplify MbedTLS CMake guard**: The combined guard `if(VIRGIL_LIB_FOUNDATION OR VIRGIL_LIB_PYTHIA)` reduces to `if(VIRGIL_LIB_FOUNDATION)` once the option is removed; MbedTLS remains required by Foundation.
- **Remove `VIRGIL_LIB_PYTHIA OFF` lines from go and wasm configs**: These override lines become dead code once the option no longer exists; removing them is cleaner than leaving unreferenced cache entries.
- **Codegen models drive wrapper generation**: The Python codegen backends reference `"pythia"` in their prefix maps. Removing `"pythia"` from all prefix maps and from `_SUPPORTED_PROJECTS` ensures `--project all` never regenerates Pythia outputs.
- **Delete pre-built binaries from the repository**: The xcframework zip, Go static libs, Java JNI .so, and Python dylib are tracked in git (some via Git LFS). They must be deleted with `git rm`.

## Open Questions

### Resolved During Planning

- **Does any other library depend on Pythia or Relic?** No. Confirmed by scanning all CMakeLists.txt — dependency graph is strictly one-directional: `pythia → vsc::common + mbed::crypto + relic`. Foundation, PHE, Ratchet, and Common are unaffected.
- **Is Pythia Go wrapper source-code present?** No Go source files exist for Pythia. Only pre-built static libs in `wrappers/go/pkg/darwin_arm64/` and a CMakeLists install directory reference.
- **Does WASM need changes?** Minor: `configs/wasm-config.cmake` has a now-dead `VIRGIL_LIB_PYTHIA OFF` override to remove. No WASM wrapper source changes needed.

### Deferred to Implementation

- **Other go/pkg arch directories**: Research found only `darwin_arm64` has Pythia pre-builts; implementer should verify by scanning all `wrappers/go/pkg/*/lib/` directories for `libvsc_pythia.a` or `librelic_s.a`.
- **Legacy GSL codegen (`codegen/python.gsl`)**: Line 2617 generates a CDLL load block for Pythia; exact surrounding context should be verified before editing to avoid breaking adjacent templates.

## Implementation Units

- [ ] **Unit 1: Delete C core, thirdparty, and tests directories**

**Goal:** Remove all Pythia C source, Relic build system, and C test suite from the repository.

**Requirements:** R1, R2

**Dependencies:** None

**Files:**
- Delete: `library/pythia/` (entire directory — ~30 source/header files + CMakeLists)
- Delete: `thirdparty/relic/` (entire directory — 6 files, fetched sources are in build dir)
- Delete: `tests/pythia/` (entire directory — 5 test executables + CMakeLists)

**Approach:**
- Use `git rm -r` for tracked files; confirm `.gitignore` has no stale Pythia entries to clean up.
- Relic fetched sources land in the build directory (`build/_deps/`) and are not tracked; no cleanup needed beyond the thirdparty directory.

**Test scenarios:**
- Test expectation: none — pure deletion; build verification is the gate (Unit 2 verification)

**Verification:**
- `git status` shows all three directories staged for deletion with no unexpected files.

---

- [ ] **Unit 2: Update CMake build system**

**Goal:** Remove all `VIRGIL_LIB_PYTHIA` and Relic references from CMake files so the project configures and builds cleanly.

**Requirements:** R1, R2, R7

**Dependencies:** Unit 1 (directories deleted; CMake subdirectory calls must not point to absent dirs)

**Files:**
- Modify: `CMakeLists.txt`
- Modify: `configs/go-config.cmake`
- Modify: `configs/wasm-config.cmake`

**Approach:**
- `CMakeLists.txt` changes:
  - Remove `option(VIRGIL_LIB_PYTHIA "Build 'pythia' library" ON)` (line ~100)
  - Remove `add_subdirectory("thirdparty/relic")` block guarded by `if(VIRGIL_LIB_PYTHIA)` (lines ~204-206)
  - Remove `add_subdirectory("library/pythia")` block (lines ~254-256)
  - Simplify MbedTLS guard from `if(VIRGIL_LIB_FOUNDATION OR VIRGIL_LIB_PYTHIA)` to `if(VIRGIL_LIB_FOUNDATION)` (lines ~197-199)
  - Remove `cloc-pythia` custom target definition and its `add_dependencies(cloc ... cloc-pythia ...)` reference (lines ~335-352)
- `configs/go-config.cmake`: remove `set(VIRGIL_LIB_PYTHIA OFF CACHE BOOL "")` line (~line 40)
- `configs/wasm-config.cmake`: remove `set(VIRGIL_LIB_PYTHIA OFF CACHE BOOL "")` line (~line 42)

**Test scenarios:**
- Happy path: CMake configuration succeeds with default options; no `vsc::pythia` or `relic` targets generated
- Happy path: CMake configuration with `-DVIRGIL_LIB_FOUNDATION=ON` succeeds and MbedTLS is still included
- Edge case: building with `-DVIRGIL_LIB_PYTHIA=ON` (unknown option) emits a CMake warning or is silently ignored — acceptable; no crash

**Verification:**
- `cmake -DCMAKE_BUILD_TYPE=Release -Bbuild -S.` completes without errors
- `cmake --build build -j$(nproc)` builds successfully for the remaining libraries

---

- [ ] **Unit 3: Remove Python wrapper**

**Goal:** Delete the Python Pythia module and remove the Pythia CDLL loader from the shared library bootstrap.

**Requirements:** R3, R4

**Dependencies:** None (independent of other units)

**Files:**
- Delete: `wrappers/python/virgil_crypto_lib/pythia/` (entire directory — `__init__.py`, `pythia.py`, `status.py`, `_c_bridge/`, `_libs/libvsc_pythia.dylib`)
- Modify: `wrappers/python/virgil_crypto_lib/_libs/low_level_libs.py` (remove Pythia CDLL loading block, ~line 74)

**Approach:**
- `git rm -r` the pythia directory.
- In `low_level_libs.py`, locate and remove the block that dynamically loads `libvsc_pythia.{ext}` — this is a generated block from `codegen/python.gsl` line 2617. Removing it is safe because the pythia module that uses it is also deleted.

**Test scenarios:**
- Happy path: `from virgil_crypto_lib import foundation` imports without error
- Error path: `from virgil_crypto_lib.pythia import pythia` raises `ModuleNotFoundError` (module no longer exists — expected post-removal)

**Verification:**
- `wrappers/python/virgil_crypto_lib/pythia/` directory does not exist in `git ls-files`
- `low_level_libs.py` contains no reference to `libvsc_pythia`

---

- [ ] **Unit 4: Remove Java and Android wrappers**

**Goal:** Delete all Java/Android Pythia source and remove Pythia from the Maven and Gradle build configurations.

**Requirements:** R3

**Dependencies:** None

**Files:**
- Delete: `wrappers/java/pythia/` (entire directory — Maven module with JNI bridge, Java classes, tests)
- Delete: `wrappers/java/android/pythia/` (entire directory — Gradle module)
- Delete: `wrappers/java/binaries/macos_arm64/lib/libvscp_pythia_java.so`
- Modify: `wrappers/java/CMakeLists.txt` — remove `add_subdirectory(pythia)` (~line 68)
- Modify: `wrappers/java/pom.xml` — remove `<module>pythia</module>` (~line 245) and the `pythia` Maven profile
- Modify: `wrappers/java/android/settings.gradle` — remove `':pythia'` from include list (~line 1)
- Modify: `wrappers/java/android/app/build.gradle` — remove `implementation project(':pythia')` (~line 33)
- Modify: `wrappers/java/android/benchmark/build.gradle` — remove `implementation project(':pythia')` (~line 31)

**Approach:**
- `git rm -r` both Java module directories and the binary .so.
- In `pom.xml`, remove the `<module>pythia</module>` element from the modules list and the `<profile>` block that activates it — both are needed for clean Maven builds.
- In `settings.gradle`, the include list is comma-separated; removing `':pythia'` must not leave a trailing comma or syntax error.

**Test scenarios:**
- Happy path: `./mvnw clean verify -P foundation,phe,ratchet` succeeds (Pythia profile absent)
- Error path: `./mvnw ... -P foundation,phe,pythia,ratchet` fails with "Unknown lifecycle phase" or profile-not-found error — acceptable, confirms removal
- Happy path: Android Gradle sync completes without unresolved project reference

**Verification:**
- `wrappers/java/pythia/` absent from `git ls-files`
- `wrappers/java/pom.xml` contains no `pythia` string
- `wrappers/java/android/settings.gradle` contains no `:pythia`

---

- [ ] **Unit 5: Remove PHP wrapper**

**Goal:** Delete all PHP Pythia extension files (both handwritten and generated) and remove the PHP CMakeLists subdirectory reference.

**Requirements:** R3

**Dependencies:** None

**Files:**
- Delete: `wrappers/php/_handwritten/pythia/` (entire directory)
- Delete: `wrappers/php/_handwritten/CMakeLists/pythia/` (entire directory)
- Delete: `wrappers/php/VirgilCryptoWrapper/extensions/pythia/` (CMakeLists + .c + .h)
- Delete: `wrappers/php/VirgilCryptoWrapper/src/Pythia/` (Pythia.php)
- Delete: `wrappers/php/VirgilCryptoWrapper/tests/Pythia/` (PythiaTest.php)
- Modify: `wrappers/php/CMakeLists.txt` — remove `add_subdirectory(VirgilCryptoWrapper/extensions/pythia)` (~line 120)

**Approach:**
- `git rm -r` all five directories.
- Edit `wrappers/php/CMakeLists.txt` to remove the single subdirectory line.

**Test scenarios:**
- Test expectation: none — no PHP build or test suite can be run in this context; verification is `git ls-files` and CMake configure

**Verification:**
- None of the deleted paths appear in `git ls-files`
- `wrappers/php/CMakeLists.txt` contains no `pythia` string

---

- [ ] **Unit 6: Remove Swift wrapper**

**Goal:** Delete the Swift VirgilCryptoPythia module and its test suite.

**Requirements:** R3

**Dependencies:** None

**Files:**
- Delete: `wrappers/swift/VirgilCrypto/VirgilCryptoPythia/` (Pythia.swift, PythiaError.swift, PythiaImplementation.swift, CContext.swift, VirgilCryptoPythia.h)
- Delete: `wrappers/swift/VirgilCryptoTest/VirgilCryptoPythiaTests/` (VirgilCryptoPythiaTests.swift)

**Approach:**
- `git rm -r` both directories.
- Check whether the Swift package manifest (`Package.swift` if present, or Xcode project file) references `VirgilCryptoPythia` as a target — if so, remove the target declaration.

**Test scenarios:**
- Test expectation: none — no Swift build available; verification is `git ls-files`

**Verification:**
- Neither path appears in `git ls-files`
- No remaining `VirgilCryptoPythia` or `VSCPythia` references in Swift build configuration files

---

- [ ] **Unit 7: Remove Go pre-built artifacts**

**Goal:** Delete Pythia and Relic pre-built static libraries and headers from the Go wrapper package directory.

**Requirements:** R3, R6

**Dependencies:** None

**Files:**
- Delete: `wrappers/go/pkg/darwin_arm64/lib/libvsc_pythia.a`
- Delete: `wrappers/go/pkg/darwin_arm64/lib/librelic_s.a`
- Delete: `wrappers/go/pkg/darwin_arm64/include/virgil/crypto/pythia/` (16 header files)
- Modify: `wrappers/go/CMakeLists.txt` — remove `"${CMAKE_CURRENT_LIST_DIR}/pythia"` from install `DIRECTORY` list (~line 47)

**Approach:**
- Scan all directories under `wrappers/go/pkg/` for `libvsc_pythia.a` or `librelic_s.a` (e.g., `find wrappers/go/pkg -name "libvsc_pythia.a" -o -name "librelic_s.a"`). Research found only `darwin_arm64` has these, but delete every match found. Similarly scan `wrappers/go/pkg/*/include/virgil/crypto/pythia/` and delete all matches.
- Use `git rm` for each artifact; these may be tracked directly or via Git LFS.

**Test scenarios:**
- Test expectation: none — pre-built artifact deletion; verification is `git ls-files`

**Verification:**
- No `libvsc_pythia.a`, `librelic_s.a`, or `pythia` include headers remain under `wrappers/go/pkg/`
- `wrappers/go/CMakeLists.txt` contains no `pythia` path string

---

- [ ] **Unit 8: Update codegen system**

**Goal:** Remove Pythia and Relic from the codegen model IR, all language backend prefix maps, codegen tests, and the legacy GSL template so that re-running codegen produces no Pythia output.

**Requirements:** R4, R8

**Dependencies:** Units 3-7 completed (wrapper source already deleted; codegen update finalizes the source of truth)

**Files:**
- Delete: `codegen/models/project_pythia/` (project_pythia.xml, class_pythia.xml, enum_status.xml)
- Delete: `codegen/models/external/library_relic.xml`
- Modify: `codegen/main.xml` — remove `<library name="relic"/>` and `<project name="pythia" .../>` declarations
- Modify: `codegen/python.gsl` — remove Pythia CDLL template block (~line 2617)
- Modify: `tools/codegen/common_bootstrap.py` — remove `"pythia"` from `_SUPPORTED_PROJECTS` tuple (~line 54); also remove any `pythia`-specific comment at line 1295
- Modify: `tools/codegen/project_cmake_backend.py` — remove `"pythia": "vscp"` from prefix map (~line 164)
- Modify: `tools/codegen/project_python_backend.py` — remove `"pythia": "vscp"` from prefix map (~line 42)
- Modify: `tools/codegen/project_java_backend.py` — remove `"pythia"` entries from prefix maps and wrapper project set (~lines 547, 994, 1143)
- Modify: `tools/codegen/project_php_backend.py` — remove `"pythia": "vscp"` (~line 63)
- Modify: `tools/codegen/project_go_backend.py` — remove `"pythia": "vscp"` (~line 1009)
- Modify: `tools/codegen/project_swift_backend.py` — remove `"pythia": "VirgilCryptoPythia"` (~line 221)
- Modify: `tools/codegen/project_wasm_backend.py` — remove `"pythia": "vscp"` (~line 144)
- Modify: `tools/codegen/test_python_backend.py` — remove `PythiaFileCountTests` class (~lines 50-53)
- Modify: `tools/codegen/test_java_backend.py` — remove `PythiaFileCountTests` class (~lines 55-58)
- Modify: `tools/codegen/test_php_backend.py` — remove `PythiaFileCountTests` class (~lines 51-54)
- Modify: `tools/codegen/test_swift_backend.py` — remove `PythiaTests` class (~lines 174-187)
- Modify: `tools/codegen/README.md` — remove `pythia` from project loop example and supported-projects table

**Approach:**
- Delete the codegen model directories first, then edit the main.xml and all backend files.
- For `tools/codegen/test_*_backend.py`, the `Pythia*Tests` classes typically use `_SUPPORTED_PROJECTS` or load the Pythia IR model — removing the class is safe once the model files are gone.
- After all edits, run `python3 -m tools.codegen.common_bootstrap --project all --apply` and verify no Pythia files appear in the output.

**Test scenarios:**
- Happy path: `python3 -m tools.codegen.common_bootstrap --project all --apply` exits zero and produces no files under any `pythia/` path
- Happy path: `python3 -m pytest tools/codegen/` passes (or at minimum, no `Pythia*Tests` class failures remain)
- Edge case: running `python3 -m tools.codegen.common_bootstrap --project pythia --apply` should fail with "unknown project" error, not silently succeed

**Verification:**
- `grep -r "pythia\|relic" codegen/ tools/codegen/` returns only incidental string matches (not structural references)
- Codegen `--project all` run produces no Pythia output files

---

- [ ] **Unit 9: Update CI/CD workflows and build scripts**

**Goal:** Remove all Pythia and Relic references from GitHub Actions workflows and shell scripts.

**Requirements:** R5

**Dependencies:** None (independent of other units)

**Files:**
- Modify: `.github/workflows/build-java.yml` — remove `-DVIRGIL_LIB_PYTHIA=OFF` from Windows build step (~line 174); remove `pythia` from Maven profile string `-P foundation,phe,pythia,ratchet` (~line 370)
- Modify: `.github/workflows/build-php.yml` — remove `-DVIRGIL_LIB_PYTHIA=OFF` from Windows build step (~line 169)
- Modify: `.github/workflows/build-python.yml` — remove `"-DVIRGIL_LIB_PYTHIA=OFF"` from matrix extra_cmake_args (~line 39)
- Modify: `.github/workflows/release-java.yml` — remove `pythia` from Maven profile in clean verify command (~line 92); remove Gradle `:pythia:publishReleasePublicationToCentralBundleRepository` tasks (~lines 160, 176); remove `pythia-android` from Android deploy loop (~line 195)
- Modify: `scripts/build_apple_frameworks.sh` — remove all `-DRELIC_USE_PTHREAD=ON/OFF` flags (~lines 143, 150, 169, 176, 195, 202, 221); remove `make_xcarchive VSCPythia ...` call (~line 236)
- Modify: `scripts/bumpver.sh` — remove `VSCPythia` from the Carthage spec loop (~line 176)

**Approach:**
- In `build-java.yml`, the Maven profile string becomes `-P foundation,phe,ratchet`; ensure no leading/trailing comma remains.
- In `release-java.yml`, the Android deploy loop iterates a space-separated list; removing `pythia-android` must not break list structure.
- In `build_apple_frameworks.sh`, verify that no other library uses `-DRELIC_USE_PTHREAD` before blanket-removing these flags.

**Test scenarios:**
- Test expectation: none — CI verification happens when these workflows run; local verification is grep-based

**Verification:**
- `grep -r "pythia\|PYTHIA\|relic\|RELIC" .github/workflows/ scripts/` returns no results (case-insensitive, excluding `ChangeLog.md` and this plan)

---

- [ ] **Unit 10: Delete pre-built binaries and update documentation**

**Goal:** Remove Apple xcframework archive, Carthage spec, and remaining pre-built binary artifacts; update README to remove Pythia from the library table.

**Requirements:** R6, R7

**Dependencies:** None

**Files:**
- Delete: `binaries/VSCPythia.xcframework.zip` (Git LFS tracked)
- Delete: `binaries/VSCPythia.xcframework.zip.sha256sum`
- Delete: `carthage-specs/VSCPythia.json`
- Modify: `README.md` — remove Pythia row from the library support matrix (~lines 44-58)

**Approach:**
- Use `git rm` for LFS-tracked files; this stages both the pointer and removes local cache.
- The `carthage-specs/VSCPythia.json` is generated by `bumpver.sh`; deleting it after updating the script (Unit 9) ensures it won't be regenerated.
- README edit removes one table row; verify surrounding Markdown table syntax remains valid.

**Test scenarios:**
- Test expectation: none — documentation and binary cleanup; verification is `git ls-files`

**Verification:**
- `git ls-files binaries/ | grep -i pythia` returns empty
- `git ls-files carthage-specs/ | grep -i pythia` returns empty
- `README.md` contains no `Pythia` or `pythia` string

## System-Wide Impact

- **Build system**: After removal, `cmake ... -S.` no longer accepts `VIRGIL_LIB_PYTHIA` as a known option. Any external build scripts passing this flag will get a CMake warning (not an error), which is acceptable.
- **Windows builds**: `build-php.yml` and `build-java.yml` previously added `-DVIRGIL_LIB_PYTHIA=OFF` on Windows to work around the no-Windows-compile restriction. Once Pythia is gone, these flags become unnecessary and their removal is safe.
- **MbedTLS**: Remains included for Foundation — only the compound CMake guard changes.
- **Unchanged invariants**: Foundation, PHE, Ratchet, and Common libraries are entirely unaffected; their CMakeLists, wrappers, codegen models, and CI workflows require no changes.
- **API surface parity**: No public API parity concern — Pythia is self-contained with no shared header types used by other libraries.
- **Integration coverage**: Running `cmake --build build && ctest` after removal proves the remaining test suite passes without Pythia.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| LFS-tracked binary deletion leaves stale LFS pointers | Use `git rm` (not `rm`) for all binaries; verify with `git lfs ls-files` post-removal |
| `codegen/python.gsl` template removal breaks adjacent GSL template rendering | Read surrounding context before editing; confirm adjacent templates are unrelated to Pythia |
| Android Gradle sync fails if `':pythia'` removal leaves a trailing comma in `settings.gradle` | Edit carefully; validate Groovy list syntax after removal |
| Other `wrappers/go/pkg/` arch directories have Pythia pre-builts beyond `darwin_arm64` | Scan all arch dirs before committing; add to deletion if found |
| CMake cache from a prior build retains `VIRGIL_LIB_PYTHIA` — causes confusing re-configure errors | Document that users should delete `build/CMakeCache.txt` after pulling this change |

## Documentation / Operational Notes

- Users with existing build directories should delete `CMakeCache.txt` or their full build directory after pulling this change.
- The `configs/go-config.cmake` and `configs/wasm-config.cmake` removals of `VIRGIL_LIB_PYTHIA OFF` are safe — CMake silently ignores unknown cache entries set by `-D` flags but having dead `set(... CACHE ...)` lines is confusing.
- Git LFS: after `git rm` on `binaries/VSCPythia.xcframework.zip`, run `git lfs prune` (optional, housekeeping) to release local LFS cache space.

## Sources & References

- Related code: `library/pythia/CMakeLists.txt`, `thirdparty/relic/CMakeLists.txt`, `CMakeLists.txt`
- Related plan: `docs/plans/2026-04-26-001-feat-external-library-cmake-codegen-plan.md` (external library codegen pattern)
- Learnings: `docs/solutions/best-practices/external-library-cmake-codegen-2026-04-26.md`
- CLAUDE.md note: "Pythia does not compile on Windows. Use `-DVIRGIL_LIB_PYTHIA=OFF` for Windows builds." — this guidance becomes moot post-removal
