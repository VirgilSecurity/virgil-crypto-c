---
title: "Remaining codegen migration activities"
type: refactor
status: active
date: 2026-04-14
---

# Remaining codegen migration activities

## Context

All 6 wrapper backends (Go, Swift, WASM, PHP, Java, Python) now generate
purely from the IR — no resolved XML dependency. 153 tests pass. This
document tracks the remaining work to complete the GSL retirement
(Roadmap Phases 7-9).

## Activity 1: Parity validation (build + test each wrapper)

**Goal:** Regenerate all wrapper sources with `--apply`, then build and
run each wrapper's test suite to validate functional correctness.

**Approach:** For each language, regenerate → build → test:

| Language | Regenerate | Build | Test | CI workflow |
|----------|-----------|-------|------|-------------|
| Go | `common_bootstrap.py --project foundation --apply` | pre-built libs in `wrappers/go/pkg/` | `cd wrappers/go && go test ./...` | `build-go.yml` |
| Swift | same | `./scripts/build_apple_frameworks.sh` | `./scripts/run_spm_tests_with_local_binaries.sh` | `build-macos.yml` |
| WASM | same | `emcmake cmake -Cconfigs/wasm-config.cmake ...` | `npm test` (Jest) | `build-wasm.yml` |
| PHP | same | `cmake -Cconfigs/php-config.cmake ...` | `ctest --verbose` | `build-php-binaries.yml` |
| Python | same | `cmake -Cconfigs/python-config.cmake ... && cmake --build --target install` | `python -m unittest discover -s wrappers/python/virgil_crypto_lib/tests` | `python-wheels-ci.yml` |
| Java | same | `cmake -Cconfigs/java-config.cmake ...` | `cd wrappers/java && ./mvnw clean verify` | `build-java-binaries.yml` |

**Fix any failures** by iterating on the backend code until tests pass.
This is the most labor-intensive remaining activity — each wrapper may
have edge cases in method body generation that only surface at compile/
runtime.

## Activity 2: Top-level WASM CMakeLists.txt generation

**Goal:** Generate `wrappers/wasm/CMakeLists.txt` from IR instead of
relying on the existing file. This is a small, mostly-static file that
lists the project subdirectories and copies config files.

**Approach:** Add a `_generate_toplevel_cmake()` function to the WASM
backend that emits the Emscripten toolchain check, configure_file calls,
and add_subdirectory entries derived from the project list.

## Activity 3: PHP extension CMakeLists.txt refinement

**Goal:** Validate that the IR-generated PHP CMakeLists.txt files
(in `VirgilCryptoWrapper/extensions/{project}/`) match the legacy
structure closely enough for the PHP extension to build.

**Approach:** Diff generated vs legacy CMakeLists.txt, fix any
structural issues (link targets, install rules, test registration).

## Activity 4: Phase 8 cutover — make new codegen the default

**Goal:** Make `common_bootstrap.py --apply` the standard generation
path. Remove any remaining GSL invocation scripts or documentation.

**Approach:**
- Update `tools/codegen/new_codegen.sh` to be the sole entry point
- Update CI workflows to use the new codegen
- Update CLAUDE.md / README with new codegen instructions
- Verify `--verify` mode works (generate to temp, diff against repo)

## Activity 5: Phase 9 legacy retirement

**Goal:** Remove GSL files and resolved XML from the repo.

**Approach:**
- Archive `codegen/*.gsl` (63 files, ~38K lines)
- Archive `codegen/generated/` (resolved XML artifacts)
- Remove GSL dependency from build instructions
- Update docs to remove GSL references
- Keep XML source models (`codegen/models/`) — these are the IR input

**Prerequisite:** Activity 1 (parity validation) must be complete, and
all CI workflows must pass with the new codegen.
