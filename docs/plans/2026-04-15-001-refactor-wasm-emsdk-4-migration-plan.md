---
title: "refactor: Migrate WASM build from emsdk 3.1.51 to 4.x"
type: refactor
status: active
date: 2026-04-15
---

# refactor: Migrate WASM build from emsdk 3.1.51 to 4.x

> **2026-04-17 addendum (post `docs/plans/2026-04-17-002-refactor-remove-pythia-wasm-wrapper-plan.md`):**
> The WASM toolchain no longer links `thirdparty/relic`. Pythia was relic's only path into the WASM build; with the WASM pythia wrapper removed and `configs/wasm-config.cmake` now defaulting `VIRGIL_LIB_PYTHIA=OFF`, neither relic's compile nor its link runs during a WASM build.
>
> **Implication for this plan:** Unit 2 (the relic `PATCH_COMMAND` for the EP2 pointer-type fix) should be re-evaluated when this plan is picked up. If the emsdk 4.0.x spike confirms relic is not invoked during the WASM build path, Unit 2 can likely be skipped entirely — that was the single hardest unit in this plan. The patch may still be worth carrying for the *native* relic compile if it also fails under LLVM 19+ when `VIRGIL_LIB_PYTHIA=ON` (the default for non-WASM configs), but that's a separate, lower-stakes concern.
>
> Run the Unit 1 spike first, then decide whether to keep, narrow, or drop Unit 2 based on what the spike actually surfaces.

## Overview

The WASM wrapper toolchain is pinned to Emscripten SDK 3.1.51 (LLVM 15) in CI. That pin is now two years old, aging against the rest of the build stack, and blocks adoption of newer Emscripten features, optimizer improvements, and browser support updates. This plan migrates the CI toolchain to the 4.0.x line (LLVM 19–20), updates the codegen backend that emits WASM build flags, and resolves known thirdparty breakage — primarily the `thirdparty/relic` EP2 curve pointer-type compilation failure triggered by stricter clang ≥16 diagnostics.

Emsdk 5.x is **out of scope**: the VirgilSecurity/relic fork pinned in `thirdparty/relic/CMakeLists.txt` does not compile under LLVM 21 even after the 4.x pointer-type fixes land. 5.x migration will be a separate effort once relic has been refreshed or replaced.

## Problem Frame

- **Current state:** `.github/workflows/build-wasm.yml` and `.github/workflows/release-wasm.yml` pin emsdk to `3.1.51`. Local developer attempts on emsdk 5.0.5 (LLVM 21) fail compiling `thirdparty/relic/src/ep/relic_ep2_curve.c:448` with `incompatible pointer types passing 'fp2_st' to 'fp_t *'`. A 4.x attempt has not been made but is expected to hit the same class of diagnostic because clang started enforcing `-Wincompatible-pointer-types` as an error in LLVM 16.
- **Why now:** The wrapper codegen migration has just landed (see recent commits on `feature/new-generator`). The newly generated `wrappers/wasm/*/CMakeLists.txt` still emit `--llvm-lto 1` — a flag that emsdk 4.x ignores/deprecates when the LLVM upstream backend is used. Aligning the codegen and CI together avoids a second flag churn when someone else bumps the CI pin.
- **User/business impact:** None at API surface. This is a build-system refresh that keeps the WASM npm artifact shippable on modern developer machines and unblocks later 5.x work. The `@virgilsecurity/crypto` npm package behavior must not change.

## Requirements Trace

- R1. CI (`build-wasm.yml` and `release-wasm.yml`) builds and tests WASM artifacts successfully using an emsdk 4.0.x version.
- R2. `thirdparty/relic` compiles under the migrated toolchain without waiving `-Werror=incompatible-pointer-types`.
- R3. Generated `wrappers/wasm/*/CMakeLists.txt` files (and the codegen backend that produces them) use emscripten 4.x-compatible link flags.
- R4. The existing Jest test suite (`wrappers/wasm/tests/**`) passes without source changes — WASM factory promise semantics remain compatible.
- R5. The npm artifact contract (`@virgilsecurity/crypto` package layout under `wrappers/wasm/dist/`) is bit-for-bit structurally identical (same files, same export shapes); binary contents will differ.
- R6. `configs/wasm-config.cmake` continues to work from the `EMSDK` environment variable without hard-coded version assumptions.

## Scope Boundaries

- **Not migrating to emsdk 5.x.** Relic is not compatible with LLVM 21 and this plan does not attempt to modernize relic beyond what is needed for LLVM 19–20.
- **Not bumping Node.js.** CI already uses Node 20, which satisfies the 4.x minimum (v18.3). Node version stays at 20 for this plan.
- **Not rewriting Jest tests or the rollup config.** Both already use the factory-as-promise pattern compatible with 4.x MODULARIZE behavior.
- **Not changing the `@virgilsecurity/crypto` npm package version, name, registry, or publish flow.** The `release-wasm.yml` publish steps are untouched except for the emsdk version line.
- **Not touching non-WASM wrappers** (Go, Swift, Python, Java, PHP) even though some of their generators live next to the WASM backend.
- **Not expanding test coverage.** Existing Jest tests are the acceptance bar.

### Deferred to Separate Tasks

- **Emsdk 5.x migration:** Requires refreshing `VirgilSecurity/relic` to a newer upstream-tracking commit (or replacing it). Track as a follow-up once 4.x has stabilized.
- **Browser-side smoke test harness:** Jest `testEnvironment: node` only exercises the `node.cjs`/`node.es` bundles; real `browser.*` and `worker.*` bundles are copied into `dist/` but not loaded by CI. Out of scope here.

## Context & Research

### Relevant Code and Patterns

- `.github/workflows/build-wasm.yml:33-36` — emsdk pin used by PR/branch builds.
- `.github/workflows/release-wasm.yml:26-29` — emsdk pin used by `v*` tag releases (publishes to npm).
- `configs/wasm-config.cmake:36-40` — reads `EMSDK` env var, sets `CMAKE_TOOLCHAIN_FILE` to `$EMSDK/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake`. Version-agnostic; no change needed.
- `wrappers/wasm/foundation/CMakeLists.txt:57-70` (and siblings in `phe/`, `pythia/`, `ratchet/`) — per-project wrapper build that currently emits `--llvm-lto 1 -Os --closure 1` in the Release config.
- `tools/codegen/project_wasm_backend.py:1252-1280` — Python codegen that produces those CMakeLists; the `--llvm-lto 1` string lives at line 1256 and must be updated once. Regeneration propagates the change to all four projects.
- `thirdparty/relic/CMakeLists.txt:53-65` — pulls `VirgilSecurity/relic.git` at GIT_TAG `7a604a93192c8ba5986146a472d238406e6ef133`. Patching here (or bumping the tag) is the lever for the EP2 pointer-type fix.
- `wrappers/wasm/foundation/src/index.js:131-134` — uses `FoundationModule(options).then(...)`. Already compatible with 4.x factory-always-returns-promise semantics.
- `wrappers/wasm/tests/foundation/Sha256.test.js:8-10` — representative Jest test; uses `await initFoundation()`, no `new FoundationModule()` pattern that 4.x forbids.
- `wrappers/wasm/package.json:10-13` — rollup build scripts; `node --max-old-space-size=4096` flag survives the Node 20/emsdk 4 combination.
- `tools/codegen/CONTRIBUTING.md:44-50` — documents the local WASM build recipe. Needs the new emsdk version noted.
- `CLAUDE.md` lines 34-36 — also references emsdk 3.1.51; update after migration to avoid onboarding confusion.

### Institutional Learnings

- **Memory note `project_emsdk_migration.md`:** "WASM CI uses emsdk 3.1.51; local 5.0.5 fails `relic_ep2_curve.c:448` fp2_st vs fp_t *." Confirms the EP2 pointer-type regression is the main blocker for modern LLVM.
- **Prior codegen migration (2026-04-14 plan):** The WASM codegen backend was just ported from resolved-XML reads to pure IR. The generated CMakeLists should be treated as generator output — don't hand-edit; change the backend and regenerate.
- **`docs/solutions/` search:** No prior documented solution for emsdk version migrations in this repo.

### External References

- **Emscripten ChangeLog (fetched 2026-04-15):**
  - 3.1.51 ships LLVM 15; 4.0.0 ships LLVM 19.1.6; 4.0.12 ships LLVM 20.1.8; 5.0.0 ships LLVM 21.1.8. Our pinned VirgilSecurity/relic fork does not compile under LLVM 21.
  - `--llvm-lto <n>` is ignored by the upstream LLVM backend; LTO is controlled via `-flto`. We currently pass `--llvm-lto 1` in Release config — safe to drop (we're not setting `-flto`, so we lose LTO; see R1/verification).
  - `-s MODULARIZE=1` factory now always returns a promise (landed 4.0.12), and `new FoundationModule(...)` is forbidden (4.0.0). Our generated `index.js` uses `FoundationModule(options).then(...)` and tests `await initFoundation()` — compatible.
  - Module argument no longer mutated in place (3.1.58). Generated `index.js` passes `options` by value; no mutation expected.
  - Node minimum v18.3 on 4.0.x — CI is already on Node 20.
  - `--closure 1` still supported; no change needed.
  - Stricter `-Wincompatible-pointer-types` has been an error default since clang 16 (shipped in LLVM 16).

### Related Issues / Prior Art

- Emscripten issue #10324 "Simplify LTO flags?" confirms `--llvm-lto` is ignored on the upstream backend.
- VirgilSecurity/relic fork is not tracked in this repo's issues; upstream relic has merged fixes for clang 16+ pointer diagnostics. The cheapest path is a minimal patch applied by the superbuild rather than refreshing the whole fork.

## Key Technical Decisions

- **Target version: pin to a specific emsdk `4.0.x` tag.** Rationale: 4.0 is the earliest release that moves to LLVM 19+ and stabilizes the promise-returning factory contract. Pinning to a single version across both workflows keeps CI and release reproducible; using "latest 4.x" risks surprise breakage when point releases drop support (e.g., `MAYBE_WASM2JS` removed at 4.0.10, `PROXY_TO_WORKER` at 4.0.21). The exact point release (e.g., `4.0.12` vs `4.0.21`) is deferred to implementation — pick the newest stable 4.0.x available at migration time that builds cleanly with the relic fix.
- **Fix relic via a patch applied in the ExternalProject step, not by bumping the GIT_TAG.** Rationale: the VirgilSecurity/relic fork has not been updated in years; a blind tag bump risks picking up unrelated regressions. A targeted `PATCH_COMMAND` on the existing tag keeps the change narrow and reviewable. The patch casts the `fp2_st` local to `fp_t *` (or equivalent) at the offending call site in `src/ep/relic_ep2_curve.c`. Document the patch alongside the CMakeLists.
- **Drop `--llvm-lto 1` from the codegen emission entirely; do not substitute `-flto`.** Rationale: the current CI has been shipping without real LTO since Emscripten moved to the upstream backend years ago — the flag has been a no-op. Adding `-flto` now is a behavior change (artifact size, compile time) that is out of scope for a toolchain migration. If LTO is wanted later, that's a separate decision.
- **Keep `--closure 1 -Os` as-is.** Rationale: still supported, and it's what produces the size numbers the downstream npm package has been shipping.
- **Apply the WASM codegen change once and regenerate all four projects.** Rationale: hand-editing the four generated CMakeLists drifts from the codegen source of truth — the newly landed pure-IR backend is authoritative.
- **Update both workflow files in lockstep.** Rationale: `build-wasm.yml` (PR gate) and `release-wasm.yml` (npm publish) must agree on toolchain version or releases will differ from what CI validated.

## Open Questions

### Resolved During Planning

- **Do Jest tests need source updates for the 4.x factory contract?** No. They already use `await initFoundation()` and the generated `index.js` uses `.then(...)`. No `new FoundationModule()` pattern exists in the codebase.
- **Does Node 20 satisfy emsdk 4.x?** Yes. Min is v18.3.
- **Is `--closure 1` removed?** No — only `--llvm-lto` is the deprecated flag in our current flag set.
- **Does `configs/wasm-config.cmake` need changes?** No. It reads `$EMSDK` and derives `upstream/emscripten/cmake/...` — that layout is unchanged in 4.x.

### Deferred to Implementation

- **Exact emsdk point release (4.0.12 vs 4.0.21 vs latest stable 4.0.x).** Pick the newest 4.0.x that builds end-to-end with the relic patch; surface the chosen version in the PR description.
- **Exact relic patch diff.** The file and symptom are known (`relic_ep2_curve.c:448`, `fp2_st → fp_t *`); the minimal C cast or signature update is a write-and-try task. May turn out to need 2–3 sites fixed, not 1.
- **Whether to pin `setup-emsdk` action version.** Currently `mymindstorm/setup-emsdk@v14`. Upgrade opportunistically if v14 is incompatible with a 4.x emsdk release, but don't treat as a required bump.

## Implementation Units

- [ ] **Unit 1: Spike — build locally with emsdk 4.0.x to surface all breakage**

**Goal:** Before touching CI, confirm the 4.x toolchain works end-to-end on a developer machine and produce a concrete failure list to drive Units 2–4.

**Requirements:** R1, R2.

**Dependencies:** None.

**Files:**
- No source changes. Local environment only: install an emsdk 4.0.x via `emsdk install X.Y.Z && emsdk activate X.Y.Z`, source `emsdk_env.sh`, then run the build recipe from `tools/codegen/CONTRIBUTING.md:44-50`.

**Approach:**
- Run the documented WASM build recipe against emsdk 4.0.x.
- Capture the first N compilation errors, at minimum: the relic EP2 pointer-type site(s) and any `--llvm-lto` warning/ignore output. Note any new warning-as-error sites elsewhere in the tree (mbedtls, round5, falcon, ed25519).
- If non-relic thirdparty also fails, expand Unit 2's scope before starting it.

**Execution note:** Characterization-first — this unit exists to derive the ground truth for Unit 2. No code changes in this unit.

**Patterns to follow:**
- The build recipe in `tools/codegen/CONTRIBUTING.md:44-50`.
- Failure triage pattern from prior wrapper validation (capture stderr, group by file, flag novel vs known).

**Test expectation:** none — characterization unit. Output is a failure inventory captured in the PR description or a scratch note, not tests.

**Verification:**
- A concrete list of files/lines that fail under 4.0.x LLVM, signed off by reading the compiler output.
- Confirmation that the EP2 site is the dominant failure; if other thirdparty libraries also break, Unit 2's scope is expanded to cover them before implementation begins.

- [ ] **Unit 2: Patch `thirdparty/relic` to compile under LLVM 19+ pointer-type strictness**

**Goal:** Make `thirdparty/relic` build cleanly with the 4.0.x clang without disabling the warning globally.

**Requirements:** R2.

**Dependencies:** Unit 1 (need the exact failing sites confirmed).

**Files:**
- Create: `thirdparty/relic/patches/0001-ep2-curve-pointer-types.patch` (path indicative — implementer may choose `thirdparty/relic/patches/` or adjacent convention).
- Modify: `thirdparty/relic/CMakeLists.txt` — add `PATCH_COMMAND` to the `ExternalProject_Add(relic-ext ...)` call that applies the patch file after source checkout.

**Approach:**
- Write a minimal patch against the pinned relic revision (`7a604a93...`) that resolves the `fp2_st` vs `fp_t *` mismatch at `src/ep/relic_ep2_curve.c:448` (and any siblings Unit 1 surfaced).
- Prefer an explicit cast at the call site or a local alias, not a signature change to the called function — keeps blast radius small and upstreamable.
- Wire the patch in via `PATCH_COMMAND ${CMAKE_COMMAND} -E ... patch -p1 < <patch>` or the equivalent portable invocation. Guard on "applied cleanly" — re-running CMake should not re-apply onto an already-patched tree (ExternalProject's stamp files normally handle this, but verify).
- Do not mutate `GIT_TAG`. A tag bump is a deferred task.

**Patterns to follow:**
- ExternalProject `PATCH_COMMAND` conventions; `thirdparty/relic/CMakeLists.txt` already has the project wired up — keep the edits minimal.

**Test scenarios:**
- Happy path: `cmake --build build-wasm` compiles `librelic_s.a` cleanly under emsdk 4.0.x.
- Edge case: a clean `rm -rf build-wasm && cmake --build build-wasm` (fresh checkout of the external project) still applies the patch and builds.
- Edge case: a warm rebuild (`cmake --build build-wasm` without nuking the external project) does not attempt to re-apply the patch and does not error.
- Error path (documented, not tested): if a future relic tag bump is done, the patch may fail to apply — verify the PATCH_COMMAND surfaces the error loudly rather than silently skipping.

**Verification:**
- Fresh WASM build on emsdk 4.0.x compiles relic without `-Wincompatible-pointer-types` errors.
- A warm rebuild of the same build tree succeeds without re-patching.
- The native (non-WASM) build on a host compiler also still compiles relic (smoke check — patches must not regress the Linux/macOS builds).

- [ ] **Unit 3: Update WASM codegen backend and regenerate per-project CMakeLists**

**Goal:** Replace the obsolete `--llvm-lto 1` flag in the codegen backend and propagate to all four generated `wrappers/wasm/*/CMakeLists.txt`.

**Requirements:** R3.

**Dependencies:** Unit 1 (confirms only `--llvm-lto` needs to go — Unit 1 may surface additional flag deprecations).

**Files:**
- Modify: `tools/codegen/project_wasm_backend.py` at line ~1256 — remove the `--llvm-lto 1` token from the Release generator expression. Leave `-Os --closure 1` intact.
- Modify: `tools/codegen/test_wasm_backend.py` — update any assertion that checks for the `--llvm-lto` string in generated output.
- Regenerate (via `common_bootstrap.py --project {foundation,phe,pythia,ratchet} --apply`):
  - `wrappers/wasm/foundation/CMakeLists.txt`
  - `wrappers/wasm/phe/CMakeLists.txt`
  - `wrappers/wasm/pythia/CMakeLists.txt`
  - `wrappers/wasm/ratchet/CMakeLists.txt`
- Test: `tools/codegen/test_wasm_backend.py` — extend assertions to pin absence of `--llvm-lto` and presence of `-Os --closure 1`.

**Approach:**
- Single-token removal in the codegen string list. Do not substitute `-flto` (see Key Technical Decisions).
- Run the full codegen test suite after the edit: `python3 -m unittest tools.codegen.test_wasm_backend -v`.
- Regenerate all four projects; the four CMakeLists changes should be identical in shape (same line removed).
- If Unit 1 discovered additional deprecated flags beyond `--llvm-lto`, extend this unit's file list rather than creating a new unit.

**Patterns to follow:**
- Prior codegen regeneration workflow from `tools/codegen/CONTRIBUTING.md:1-10`.
- Pure-IR backend edit pattern from recent commits on `feature/new-generator` (e.g., `74ffc21d7 fix(codegen): dependency setter returns error`).

**Test scenarios:**
- Happy path: after the edit, `python3 -m unittest tools.codegen.test_wasm_backend -v` passes and the updated assertions see `-Os --closure 1` but not `--llvm-lto`.
- Happy path: regenerating each of the four projects produces CMakeLists that differ from the committed versions only by the removal of the `--llvm-lto` token.
- Edge case: running `python3 -m unittest discover -s tools/codegen -p "test_*.py"` (the full 153-test suite) shows no regressions in any other backend.
- Integration: after regeneration, `emcmake cmake -Cconfigs/wasm-config.cmake -Bbuild-wasm -S.` under emsdk 4.0.x surfaces no "unknown flag" warnings for the WASM link step.

**Verification:**
- All codegen tests pass.
- The four regenerated CMakeLists differ only in the expected way, confirmed by reading the diff.
- Fresh emcmake configure under emsdk 4.0.x produces no deprecation warnings for the modified flag set.

- [ ] **Unit 4: Bump emsdk version in CI workflows**

**Goal:** Flip both CI workflows from `3.1.51` to the chosen 4.0.x pin.

**Requirements:** R1.

**Dependencies:** Units 2 and 3 merged (must not break CI by flipping before the source tree is ready).

**Files:**
- Modify: `.github/workflows/build-wasm.yml` line 36 — `version: '3.1.51'` → `version: '4.0.x'` (exact pin chosen during Unit 1).
- Modify: `.github/workflows/release-wasm.yml` line 29 — same change.
- Modify: `tools/codegen/CONTRIBUTING.md` line 44 — update the "requires emsdk 3.1.51" comment to reflect the new pin.
- Modify: `CLAUDE.md` — update any emsdk version reference (currently mentions 3.1.51 in WASM build notes).

**Approach:**
- Single-line replacements in two workflow files.
- The `mymindstorm/setup-emsdk@v14` action accepts exact version strings. Keep the exact version pinned — avoid wildcards like `latest`.
- Keep Node.js at 20 unchanged.
- Docs updates are informational; match the pin chosen in the workflows.

**Patterns to follow:**
- The workflow file style (4-space YAML, quoted string versions) as it exists today.

**Test scenarios:**
- Integration: a push to the migration branch triggers `build-wasm.yml`; the `Install Emscripten SDK` step reports the 4.0.x version; the `Build C libraries` step succeeds; `Run Jest tests` passes.
- Integration: simulating a tag push (dry run or a branch-only test, since `release-wasm.yml` triggers on `v*`) — verify the `Build and test WASM` job logic is structurally unchanged. Do not run `publish-npm` until an actual release tag.
- Error path: if the `mymindstorm/setup-emsdk@v14` action cannot resolve the pinned 4.0.x version, the job fails fast at the setup step rather than later in the build — confirmed by CI log.

**Verification:**
- `build-wasm.yml` job completes green on the migration branch.
- Emsdk version in the setup step log matches the committed pin exactly.
- Docs reference the same version as the workflows.

- [ ] **Unit 5: End-to-end wrapper validation (Jest + artifact shape)**

**Goal:** Prove the migrated toolchain produces a working, contract-compatible WASM npm artifact.

**Requirements:** R4, R5.

**Dependencies:** Units 2, 3, 4.

**Files:**
- No source changes.
- Reference tests: `wrappers/wasm/tests/foundation/*.test.js`, `wrappers/wasm/tests/phe/*.test.js` (and any others present).

**Approach:**
- Locally run the full build + test pipeline under emsdk 4.0.x: `emcmake cmake ... && cmake --build build-wasm && (cd build-wasm/wrappers/wasm && npm install && npm run prepare && npm test)`.
- Confirm the Jest suite passes end to end — this exercises factory promise semantics, memory growth, exported functions, and cross-project crypto (Ed25519, RSA, AES, SHA, KDF, RecipientCipher, KeyProvider).
- Snapshot the `wrappers/wasm/dist/` layout: expected files are `{foundation,phe,pythia,ratchet}/{node,browser,worker}.{cjs,es}.{js,mjs}` plus `.wasm` binaries. File presence/count must match pre-migration; binary contents naturally differ (different LLVM).
- Confirm the generated `index.js` factory pattern still works — if the 4.x `MODULARIZE` factory-as-promise semantics surfaced a latent issue, it would show here as a Jest failure.

**Execution note:** This unit is the safety net. If any Jest test fails, open a new unit — do not paper over failures with retries, skips, or `console.log` debugging in the test source.

**Patterns to follow:**
- The validation pattern used during the wrapper codegen migration: build + run test suite per language + manual artifact inspection.

**Test scenarios:**
- Happy path: all Jest tests in `wrappers/wasm/tests/**` pass (same pass count as on the pre-migration `main`).
- Happy path: each of `foundation`, `phe`, `pythia`, `ratchet` produces node/browser/worker bundles in both `cjs` and `es` formats (12 JS files per project), plus the matching `.wasm` binaries.
- Edge case: `wrappers/wasm/dist/foundation/node.cjs.js` loads via `require()` from a plain Node 20 REPL and exposes `Sha256`, `Ed25519PrivateKey`, etc.
- Edge case: `ALLOW_MEMORY_GROWTH=1` still functions — a Jest test that allocates a large buffer (e.g., RSA keygen) succeeds without OOM.
- Integration: cross-module call path from foundation → phe (or wherever the cross-project import chain runs) produces the same crypto outputs as pre-migration — sampled by running a known-answer Jest test and comparing hex output literals.

**Verification:**
- `npm test` under `build-wasm/wrappers/wasm` exits 0 with the same test count as pre-migration.
- Dist directory layout matches pre-migration structurally (same files, not same bytes).
- A sanity check Jest run loads the `node.cjs` bundle directly (outside the suite) and computes a known-answer SHA-256 to confirm the factory + WASM init path.

## System-Wide Impact

- **Interaction graph:** CI (`build-wasm.yml` gates every PR), release pipeline (`release-wasm.yml` publishes to npm on tag push), local developer flow (`tools/codegen/CONTRIBUTING.md` recipe), and the downstream npm consumer contract (`@virgilsecurity/crypto`). A broken toolchain blocks every one.
- **Error propagation:** Compile failures in `thirdparty/relic` surface at `cmake --build` time; link flag deprecations surface at `emcc` link time; runtime factory contract changes surface at Jest time. Unit 1's spike front-loads all three.
- **State lifecycle risks:** ExternalProject stamp files mean a warm build tree after a patch change may not re-apply patches cleanly. Unit 2's verification explicitly covers a warm-rebuild case. No persistent-state risk beyond build trees.
- **API surface parity:** None at the wrapper API level — C types, generated `index.js`, and wrapper classes are unchanged. Binary ABI of the `.wasm` file will change (expected).
- **Integration coverage:** Unit tests under `wrappers/wasm/tests/**` cover the factory init path and crypto primitives end to end; no mocks. Unit 5's known-answer checks provide the cross-layer guarantee.
- **Unchanged invariants:**
  - The `@virgilsecurity/crypto` npm package name, version cadence, and `dist/` layout are untouched.
  - `configs/wasm-config.cmake` continues to derive the toolchain path from `$EMSDK`.
  - The codegen contract `generate_wasm_files(project_ir, ...) -> list[(path, content)]` is unchanged.
  - Non-WASM wrappers (Go, Swift, Python, Java, PHP) and their generators are not touched.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Emsdk 4.0.x surfaces additional thirdparty breakage beyond relic (e.g., in `round5`, `falcon`, `mbedtls`, `ed25519`, `nanopb`). | Unit 1 is explicitly a characterization spike designed to enumerate all failure sites before committing to a patch strategy. If other thirdparty libs break, expand Unit 2's scope. |
| Chosen 4.0.x point release has regressions in another dimension (artifact size, optimizer bug). | Pin to a specific point release, not "latest"; record the version in PR description and `tools/codegen/CONTRIBUTING.md`. If a regression is found mid-migration, step down one point release and re-validate. |
| `mymindstorm/setup-emsdk@v14` action does not support the chosen 4.0.x version. | Upgrade the action version as part of Unit 4 if needed (low likelihood — the action is version-string driven). |
| Relic patch applies cleanly in Unit 2 but silently breaks non-WASM builds (host compiler, different warnings). | Unit 2's verification includes a host-build smoke check. If the patch regresses the host build, widen the patch or guard it with a clang-version check. |
| ExternalProject re-applies a patch on warm builds, causing "already patched" errors. | Unit 2 explicitly tests the warm-rebuild case; if CMake stamp files don't suffice, switch to an idempotent patch script. |
| The `--llvm-lto` removal silently changes artifact size (no LTO happening previously, but an implicit optimizer-behavior shift). | Compare `.wasm` file sizes pre- and post-migration in Unit 5; if size changes dramatically, investigate before merging. Size change from LLVM 15→19 is expected; dramatic means orders of magnitude. |
| CI passes but local developers on older emsdk versions can't build. | `configs/wasm-config.cmake` is version-agnostic — it reads `$EMSDK`. Update `tools/codegen/CONTRIBUTING.md` to specify the required minimum (4.0.x). |
| The npm publish step runs on a future tag push with mismatched emsdk (e.g., a hotfix branch pinning 3.1.51). | Both `build-wasm.yml` and `release-wasm.yml` get the same pin in Unit 4 — this is why they're a single unit. |

## Documentation / Operational Notes

- Update `tools/codegen/CONTRIBUTING.md:44` WASM recipe block to state the required emsdk version.
- Update `CLAUDE.md` WASM note (currently references emsdk 3.1.51 obliquely via the build notes).
- Record the chosen 4.0.x point release in the PR description so it's discoverable from `git log` later.
- After merge, update the auto-memory note `memory/project_emsdk_migration.md` to reflect the new state: 4.x live in CI, v5 still blocked by relic.
- No monitoring/rollout beyond CI green; the npm package is re-built on next release tag automatically.

## Sources & References

- Memory: `memory/project_emsdk_migration.md` — prior context on 3.1.51 pin and 5.0.5 failure.
- Code: `.github/workflows/build-wasm.yml`, `.github/workflows/release-wasm.yml`, `configs/wasm-config.cmake`, `tools/codegen/project_wasm_backend.py`, `thirdparty/relic/CMakeLists.txt`.
- Emscripten ChangeLog (fetched 2026-04-15): https://github.com/emscripten-core/emscripten/blob/main/ChangeLog.md
- Emscripten `--llvm-lto` deprecation discussion: https://github.com/emscripten-core/emscripten/issues/10324
- VirgilSecurity/relic fork (pinned): `GIT_TAG 7a604a93192c8ba5986146a472d238406e6ef133` at https://github.com/VirgilSecurity/relic
