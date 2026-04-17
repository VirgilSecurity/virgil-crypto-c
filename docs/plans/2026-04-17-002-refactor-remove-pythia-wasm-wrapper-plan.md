---
title: "refactor: Remove pythia from WASM wrapper codegen to unblock emsdk 4.x"
type: refactor
status: active
date: 2026-04-17
---

# refactor: Remove pythia from WASM wrapper codegen to unblock emsdk 4.x

## Overview

Drop the pythia project from the WASM wrapper surface only. `library/pythia/`, `codegen/models/project_pythia/`, and every other language wrapper for pythia (Python, Java, PHP, Swift) stay untouched. The narrow goal is to lift `thirdparty/relic` out of the WASM build's dependency graph — relic is only reachable from the WASM binary through pythia, and it is the single hardest blocker on the emsdk 4.x migration (`docs/plans/2026-04-15-001-refactor-wasm-emsdk-4-migration-plan.md` Units 1–2). Removing pythia here turns that plan's relic patch unit into a nice-to-have that can be deferred or skipped entirely.

## Problem Frame

The WASM toolchain is pinned to emsdk 3.1.51 (LLVM 15) because `thirdparty/relic`'s `src/ep/relic_ep2_curve.c:448` fails to compile under LLVM 16+'s stricter `-Wincompatible-pointer-types` default. The existing emsdk-migration plan works around this with a targeted patch in `thirdparty/relic/CMakeLists.txt`, but that plan still has to own the patch, its warm-rebuild behavior, and any future relic tag bumps. Since the WASM build only compiles libraries that a wrapped project transitively requires, and pythia is relic's sole consumer in the WASM graph, dropping WASM pythia removes relic from the WASM binary entirely and collapses the hardest migration risk to zero. Pythia stays shipped on the other wrappers, so the external API surface shrinks by one target (`@virgilsecurity/crypto` loses the pythia subdir) but the rest of the pythia wrapper matrix is intact.

## Requirements Trace

- R1. `codegen/models/project_pythia/project_pythia.xml` no longer lists `wasm` in its `wrappers` attribute, so the new codegen generates no WASM output for pythia.
- R2. `wrappers/wasm/pythia/` is deleted along with the WASM-side wiring that references it (`wrappers/wasm/CMakeLists.txt` subdirectory entry, `wrappers/wasm/package.json` build script + `prepare` invocation).
- R3. The `PythiaFileCountTests` class in `tools/codegen/test_wasm_backend.py` is removed; all remaining codegen tests pass.
- R4. Pythia wrappers for Python, Java, PHP, and Swift continue to regenerate, build, and pass their existing test suites — the change is strictly WASM-scoped.
- R5. `build-wasm.yml` CI passes without pulling in `thirdparty/relic`, and a `cmake --build` of the WASM tree shows no `relic` target in the WASM dependency graph.

## Scope Boundaries

- **WASM surface only.** Python, Java, PHP, Swift pythia wrappers remain on disk and continue to be generated.
- **No codegen-wide project removal.** `_SUPPORTED_PROJECTS` in `common_bootstrap.py` stays; per-backend `_PROJECT_PREFIX_MAP` entries for pythia stay; other backends' `PythiaFileCountTests` stay.
- **No C library change.** `library/pythia/` and `tests/pythia/` are not touched.
- **No deprecation or external-consumer communication work.** The `@virgilsecurity/crypto` npm package loses the `pythia/` subdir in the next release. Pythia is still available via Python (`virgil-crypto-lib`), Maven, Cocoapods/SPM, and PHP. Use the CHANGELOG entry in Unit 3 to communicate; no SemVer-major bump is needed for other wrappers.

### Deferred to Separate Tasks

- **WASM emsdk 3.1.51 → 4.x migration** (`docs/plans/2026-04-15-001`): sequenced after this plan. With relic out of the WASM dependency graph, that plan's Unit 2 (relic patch) should be re-evaluated — either skipped or kept as defense-in-depth if the `thirdparty/relic/CMakeLists.txt` subdir still gets added through the top-level CMake regardless of whether the WASM build consumes it.
- **Full pythia wrapper removal** (the earlier, broader 2026-04-17-001 plan, now superseded): viable later if downstream consumer signals confirm pythia has no users on Python/Java/PHP/Swift either. Not in scope here.
- **Legacy GSL cleanup** (`codegen/main.xml`, `codegen/*.gsl`, `codegen/generated/pythia/`): handled by `docs/plans/2026-04-14-003-remaining-codegen-activities-plan.md` Activity 5.

## Context & Research

### Relevant Code

- `codegen/models/project_pythia/project_pythia.xml:9` — `wrappers="java,swift,python,wasm,php"`. Removing `wasm` is the single lever that stops the WASM backend from emitting pythia output, via the `if "wasm" in wrappers_set:` gate in `tools/codegen/common_bootstrap.py:1214`.
- `wrappers/wasm/pythia/` — 6 files to delete: `CMakeLists.txt`, `exported_functions.json`, `src/{Pythia.js, PythiaError.js, index.js, precondition.js}`.
- `wrappers/wasm/CMakeLists.txt:88` — `add_subdirectory("pythia")` to remove.
- `wrappers/wasm/package.json:12,15` — `"build:pythia"` rollup script and its `npm run build:pythia` invocation in the `"prepare"` chain.
- `tools/codegen/test_wasm_backend.py:71-79` — `PythiaFileCountTests` class to delete (only the WASM-specific one; the Python/Java/PHP/Swift equivalents stay).
- `thirdparty/relic/CMakeLists.txt` — left alone. The WASM build simply won't pull in the relic target once pythia is not a subdirectory target; verification is part of Unit 2.

### Dependency chain (why this works)

- pythia (`library/pythia/CMakeLists.txt`) → `PUBLIC mbedtls relic` (relic is a pythia-only transitive dep in the WASM build).
- WASM build (`wrappers/wasm/CMakeLists.txt` + per-project `wrappers/wasm/{foundation,phe,pythia,ratchet}/CMakeLists.txt`) → only the subdirectories it `add_subdirectory`s get compiled and linked.
- Remove `wrappers/wasm/pythia/CMakeLists.txt`, remove its `add_subdirectory("pythia")` call, and the pythia library (and therefore relic) is no longer reachable from the Emscripten link step.
- Native builds (configs/config.cmake, host tests in `tests/pythia/`) still compile pythia + relic — that path is unchanged.

### Institutional Learnings

- **Earlier 2026-04-17-001 plan (now superseded):** Produced a much broader audit of pythia's footprint across every wrapper. Its findings on Python `low_level_libs.py`, Apple xcframeworks, Maven profiles, and Android Gradle modules are NOT applicable here — all of those live outside the WASM surface. What carries over: the mechanics of the codegen's `wrappers` attribute gate and the WASM file enumeration.
- **Adversarial reviewer of the superseded plan** flagged `scripts/build_apple_frameworks.sh` and `scripts/bumpver.sh` as places the script would regenerate or fail post-deletion. Neither is relevant here — those scripts touch Apple artifacts, not WASM.
- **`docs/plans/2026-04-15-001` Key Technical Decisions:** patches relic in `thirdparty/relic/CMakeLists.txt` via `PATCH_COMMAND` on the existing GIT_TAG. This plan's Unit 3 validation should confirm the relic target is no longer built for WASM; that is the signal the emsdk plan's relic patch can be skipped.

## Key Technical Decisions

- **Edit the project XML, not the codegen code.** The `wrappers` attribute is the canonical declaration of which targets a project supports. Removing `wasm` there keeps the backend, `_SUPPORTED_PROJECTS`, and per-language prefix maps unchanged, and keeps the edit reversible with a one-line revert.
- **Keep `_PROJECT_PREFIX_MAP["pythia"]` in `project_wasm_backend.py` as-is.** It's a cross-project resolution fallback. Removing it would be a separate concern and would drift the WASM backend away from the other backends' shape; leave it dormant.
- **Delete `PythiaFileCountTests` in `test_wasm_backend.py` rather than skip.** Consistent with the superseded plan's rationale: skipped tests lie about intent.
- **No deprecation cycle for the npm package.** A deprecation release for a single wrapper subdir in a polyglot SDK would be cosmetically odd — pythia stays available via other wrappers. CHANGELOG entry carries the communication.
- **Leave `thirdparty/relic` out of this plan entirely.** Whether relic stays pinned at `7a604a93…`, gets patched later, or gets removed is a follow-up decision owned by the emsdk plan.

## Open Questions

### Resolved During Planning

- **Is relic reachable through anything other than pythia in the WASM build?** No. `grep -rn relic wrappers/wasm/ library/foundation/CMakeLists.txt library/phe/CMakeLists.txt library/ratchet/CMakeLists.txt` shows only `library/pythia/CMakeLists.txt` linking against relic. Confirmed at planning time.
- **Does removing the WASM pythia subdirectory implicitly turn off relic's ExternalProject?** Not automatically — `thirdparty/relic/CMakeLists.txt` is `add_subdirectory`'d from the top-level `CMakeLists.txt` whenever `VIRGIL_LIB_PYTHIA=ON`. But the WASM build's Emscripten link step only links targets that per-project `wrappers/wasm/*/CMakeLists.txt` declares; without pythia's subdir, the relic object files are compiled but never linked into a `.wasm`. The emsdk plan's relic patch is still needed IF the relic compile itself is what fails under LLVM 19. Unit 3 confirms which.

### Deferred to Implementation

- **Exact posture on the emsdk plan's relic patch after this lands:** the answer depends on whether relic's compile (not link) fails under emsdk 4.x. If the native relic compile still fails because `VIRGIL_LIB_PYTHIA=ON` triggers its ExternalProject, the patch stays needed. If the WASM toolchain only compiles what it links, the patch becomes optional. Determined in Unit 3's emsdk-4.x spike, feeding back into the 2026-04-15-001 plan.
- **Whether to also set `VIRGIL_LIB_PYTHIA=OFF` in `configs/wasm-config.cmake`** as a belt-and-braces guard so the WASM build never even compiles the pythia C library or its relic dep: possibly cleaner, but changes native/library behavior for WASM configs specifically. Decide during Unit 2 after observing whether the relic compile still runs.

## Implementation Units

- [ ] **Unit 1: Remove `wasm` from pythia's wrappers attribute and drop the WASM file-count test**

  **Goal:** Stop the new codegen from emitting any WASM output for pythia.

  **Requirements:** R1, R3.

  **Dependencies:** None. Must land first so a subsequent `--apply` does not re-emit `wrappers/wasm/pythia/`.

  **Files:**
  - Modify: `codegen/models/project_pythia/project_pythia.xml` line 9 — change `wrappers="java,swift,python,wasm,php"` to `wrappers="java,swift,python,php"`.
  - Delete: the `PythiaFileCountTests` class in `tools/codegen/test_wasm_backend.py` (lines ~71–79).

  **Approach:**
  - Single-token XML edit; no other `wrappers` values reordering needed.
  - Test-class deletion is block-contiguous; drop it outright rather than skip.
  - Do not touch `_SUPPORTED_PROJECTS`, the WASM backend's `_PROJECT_PREFIX_MAP`, or any other backend's pythia file-count test.

  **Patterns to follow:**
  - The `wrappers="…"` attribute on `codegen/models/project_foundation/project_foundation.xml:9` shows the canonical attribute shape for projects with a subset of targets.

  **Test scenarios:**
  - Happy path: `python3 -m unittest discover -s tools/codegen -p "test_*.py" -v` passes (previous test count minus the deleted WASM pythia file-count test). The remaining backends' `PythiaFileCountTests` still pass — confirms the XML edit did not affect non-WASM generation.
  - Happy path: `python3 tools/codegen/common_bootstrap.py --project pythia --apply` regenerates Python/Java/PHP/Swift pythia wrappers and writes nothing under `wrappers/wasm/pythia/`. Verify with `git status` — `wrappers/wasm/pythia/` is unchanged.
  - Happy path: `python3 tools/codegen/common_bootstrap.py --project foundation --apply` still writes `wrappers/wasm/foundation/` (sanity check that the WASM backend itself still functions).
  - Edge case: `grep -rn "wasm" codegen/models/project_pythia/` returns zero hits after the edit (guards against the attribute appearing elsewhere in the model).

  **Verification:**
  - All codegen tests pass.
  - `git grep -n "pythia" tools/codegen/test_wasm_backend.py` returns zero hits.
  - Regenerating pythia produces no `wrappers/wasm/pythia/` output.

- [ ] **Unit 2: Delete `wrappers/wasm/pythia/` and its WASM-side wiring**

  **Goal:** Remove the already-generated WASM pythia wrapper files and every CMake/npm reference that points at them.

  **Requirements:** R2, R5.

  **Dependencies:** Unit 1.

  **Files:**
  - Delete: `wrappers/wasm/pythia/` (6 files: `CMakeLists.txt`, `exported_functions.json`, `src/Pythia.js`, `src/PythiaError.js`, `src/index.js`, `src/precondition.js`).
  - Modify: `wrappers/wasm/CMakeLists.txt` — remove `add_subdirectory("pythia")` (line ~88).
  - Modify: `wrappers/wasm/package.json` — remove the `"build:pythia"` script (line ~12) and remove ` && npm run build:pythia` from the `"prepare"` chain (line ~15).

  **Approach:**
  - Delete the directory tree and prune CMake + `package.json` in the same commit so the working tree is never in a broken state.
  - The `"prepare"` edit removes exactly one `&&`-joined token, leaving foundation/phe/ratchet build commands and ordering intact.
  - Optional (decide in-unit): add `set(VIRGIL_LIB_PYTHIA OFF CACHE BOOL "" FORCE)` to `configs/wasm-config.cmake` so the WASM build doesn't even compile pythia's C library or its relic dep. Verify this does not break any CI workflow that shares the WASM config.

  **Patterns to follow:**
  - The `wrappers/wasm/{foundation,phe,ratchet}/` layout shows the expected shape of the other three remaining per-project subdirectories — no changes to them.

  **Test scenarios:**
  - Happy path: `emcmake cmake -Cconfigs/wasm-config.cmake -Bbuild-wasm -S.` configures successfully without any pythia reference.
  - Happy path: `cmake --build build-wasm` builds foundation, phe, and ratchet WASM wrappers; no `libpythia_s.*` or `librelic_s.*` artifacts are produced under `build-wasm/` (check with `find build-wasm -name '*pythia*' -o -name '*relic*'` → only the pythia C library artifacts under the native tree, if the optional `VIRGIL_LIB_PYTHIA=OFF` guard wasn't applied).
  - Happy path: `cd build-wasm/wrappers/wasm && npm install && npm run prepare` produces `dist/{foundation,phe,ratchet}/` but not `dist/pythia/`.
  - Happy path: `npm test` (Jest) passes with no pythia test references failing to load — no WASM Jest tests exist for pythia today, so the count is unchanged.
  - Edge case: `git grep -n -i pythia wrappers/wasm/` returns zero hits after deletion.
  - Error path: if `add_subdirectory("pythia")` is not removed cleanly (typo, duplicated line), the configure step fails fast with "directory does not exist" — the signal to re-check the CMake edit before committing.

  **Verification:**
  - `wrappers/wasm/dist/pythia/` is absent after a clean build.
  - Top-level `cmake --build` does not emit any WASM-targeted relic object files (Emscripten verbose link log can be inspected).
  - `build-wasm.yml` CI job passes when pushed.

- [ ] **Unit 3: CHANGELOG, emsdk-plan note, and relic-footprint validation**

  **Goal:** Communicate the npm surface change, verify the intended consequence (relic dropped from the WASM link), and leave a breadcrumb for the emsdk-migration plan.

  **Requirements:** R4, R5.

  **Dependencies:** Units 1 and 2.

  **Files:**
  - Modify: `ChangeLog.md` — add an entry under the next release heading noting "WASM wrapper: pythia module removed. Pythia remains available via Python (`virgil-crypto-lib`), Java/Android, PHP, and Swift."
  - Modify: `docs/plans/2026-04-15-001-refactor-wasm-emsdk-4-migration-plan.md` — add a one-paragraph note at the top of the Overview or Scope Boundaries recording that, post-merge of this plan, the WASM toolchain no longer links relic and Unit 2 (relic patch) may be skippable. Do not restructure that plan's implementation units; its maintainer can re-evaluate when they pick it up.
  - Modify: `README.md` — if the wrapper-language matrix row for pythia (line ~58) enumerates WASM/JS, strike the JS reference. Other wrapper links stay.
  - No changes to `CLAUDE.md` — it speaks about the C library, which is unchanged.

  **Approach:**
  - Spike an emsdk 4.0.x local build under `VIRGIL_LIB_PYTHIA=OFF` (or whatever Unit 2 chose) to verify the relic source does not get compiled during the WASM build. If it still compiles (because the top-level `add_subdirectory("thirdparty/relic")` is reached via another path), note that in the 2026-04-15-001 breadcrumb so the maintainer knows the patch is still required.
  - Use `find build-wasm -name 'librelic*' -o -name '*relic*.o'` after a clean WASM build to confirm the relic objects are absent.

  **Test scenarios:**
  - Happy path: post-merge WASM build under emsdk 3.1.51 still succeeds (no regression; we are not migrating emsdk in this plan).
  - Happy path: the emsdk 4.0.x spike configures and compiles the WASM build without invoking the relic `-Wincompatible-pointer-types` failure — that's the signal the relic patch is unneeded.
  - Edge case: if the emsdk 4.0.x spike still hits the relic compile error because top-level `VIRGIL_LIB_PYTHIA=ON` defaults bring relic in, the 2026-04-15-001 note records that the patch is still required; Unit 2's optional `VIRGIL_LIB_PYTHIA=OFF` knob (if not already applied) becomes the clean alternative.

  **Verification:**
  - `ChangeLog.md` carries an entry describing the WASM surface change.
  - `docs/plans/2026-04-15-001` has a clearly-marked post-2026-04-17 addendum with the relic footprint result.
  - README's wrapper-language row reflects the change.

## System-Wide Impact

- **Interaction graph:** Three surfaces: the codegen XML model (1 line), the WASM wrapper tree (delete + 2 wiring edits), and the documentation (changelog + emsdk-plan breadcrumb + README). No other wrapper tree, CI workflow, or language publishing pipeline is touched.
- **Error propagation:** Most failure modes surface at `emcmake cmake` (configure) or `cmake --build` (compile/link) time — fast and local. Jest runtime failures are not expected since no WASM pythia Jest test exists today.
- **API surface parity:** `@virgilsecurity/crypto` npm package loses the `pythia/` subdir. Python/Java/PHP/Swift pythia APIs are unchanged. Communicated via ChangeLog.
- **Unchanged invariants:** `library/pythia/` C library, `tests/pythia/` native tests, non-WASM wrapper trees, `_SUPPORTED_PROJECTS`, per-backend prefix maps for pythia, `thirdparty/relic` CMakeLists, `codegen/models/project_pythia/class_pythia.xml`, `codegen/main.xml`, Apple xcframeworks, Maven profiles, Android modules, `binaries/` LFS objects.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| A downstream npm consumer imports `@virgilsecurity/crypto/pythia` and breaks silently on next release. | ChangeLog entry in Unit 3 is the primary comms. Follow-up: if this turns out to have real users, the minimal revert is restoring `wasm` to the XML attribute and re-running `--apply`. |
| Top-level `VIRGIL_LIB_PYTHIA=ON` default still triggers relic compile even in WASM builds, so the emsdk plan's relic patch remains needed. | Unit 2's optional `VIRGIL_LIB_PYTHIA=OFF` guard in `configs/wasm-config.cmake`; Unit 3 spike verifies. |
| Per-backend prefix maps retaining `"pythia": "vscp"` becomes stale/confusing over time as other backends potentially drop pythia too. | Out of scope here; revisit only if the superseded plan's full removal is revived. |
| A Jest test somewhere imports pythia indirectly through a shared fixture. | Unit 2 Happy Path `npm test` catches this; grep confirms no current reference. |
| The XML attribute change re-surfaces when another engineer refreshes `codegen/models/project_pythia/project_pythia.xml` from an upstream source and reintroduces `wasm`. | Unit 1's regeneration check (`git status` post-`--apply`) would catch regression on next run. No automated guard; the attribute is the source of truth. |

## Sources & References

- Superseded: `docs/plans/2026-04-17-001-refactor-remove-pythia-wrappers-plan.md` — full-matrix removal. Its Unit 2 (WASM deletion) is the structural template for this plan's Unit 2; most of its other units are out of scope here.
- Related: `docs/plans/2026-04-15-001-refactor-wasm-emsdk-4-migration-plan.md` — the reason this narrow scope exists. Unit 3 of this plan writes a breadcrumb into it.
- Codegen model: `codegen/models/project_pythia/project_pythia.xml`.
- Codegen orchestration: `tools/codegen/common_bootstrap.py` (specifically the `if "wasm" in wrappers_set:` gate around line 1214).
- WASM build: `wrappers/wasm/CMakeLists.txt`, `wrappers/wasm/package.json`, `wrappers/wasm/pythia/`.
- Relic footprint: `thirdparty/relic/CMakeLists.txt`, `library/pythia/CMakeLists.txt`.
