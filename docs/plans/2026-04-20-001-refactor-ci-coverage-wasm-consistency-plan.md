---
title: "refactor: CI coverage, workflow naming, and WASM toolchain alignment"
type: refactor
status: active
date: 2026-04-20
---

# refactor: CI coverage, workflow naming, and WASM toolchain alignment

## Overview

Four concrete problems make CI unreliable and releases inconsistent:

1. `bumpver.sh` strips the pre-release label from the npm version (sets `0.17.3` instead of `0.17.3-rc1` in `wrappers/wasm/package.json`).
2. `build-macos.yml` and `python-wheels-ci.yml` do not run on `feature/**` branches or on all expected PR targets — so those builds are invisible to contributors until they hit `develop`.
3. `build-wasm.yml` (CI) and `release-wasm.yml` (release) pin different Emscripten versions (4.0.4 vs 3.1.51) — the toolchain that ships is not the one that was tested.
4. `release-wasm.yml` duplicates the entire WASM build instead of calling `build-wasm.yml` as a reusable workflow. Java and PHP already use the reusable pattern via `workflow_call`; WASM should match.

## Problem Frame

The project ships 7 language wrappers (C, Go, Java/Android, Python, PHP, WASM, Swift) and maintains 13 workflow files. The Java and PHP build workflows are already callable reusable workflows (`workflow_call`), and `publish-release.yml` composes them. WASM, Go, macOS, and Linux do not follow this pattern. The WASM divergence is the most risky because it means the npm release is built with an older Emscripten than what CI tested.

## Requirements Trace

- R1. `bumpver.sh` sets full version (including pre-release label) in `wrappers/wasm/package.json`.
- R2. Every push to any branch (`feature/**`, `develop`, `main`, `release/**`, `hotfix/**`) and every PR targeting `develop` or `main` triggers all build workflows.
- R3. The WASM build used for npm publish is identical in toolchain and configuration to the WASM build tested in CI.
- R4. `release-wasm.yml` calls `build-wasm.yml` as a reusable workflow rather than duplicating build logic, matching the Java/PHP pattern.

## Scope Boundaries

- Go release workflow (`release-go.yml`) builds 5 cross-compiled platform targets that differ from CI's 2 native targets — keeping them separate is intentional and out of scope.
- No consolidation of the 13 workflow files into fewer files beyond what's described here.
- No changes to publish logic, credentials, or signing.
- `build-linux.yml` is C-only (memcheck, benchmarks) by design — not changing its scope.
- Updating bumpver for any language other than WASM is out of scope.

## Context & Research

### Relevant Code and Patterns

- `scripts/bumpver.sh:172` — `sed_replace "(\"version\")[^,]+([,]?)" "\1: \"${VERSION}\"\2"` — uses `${VERSION}` not `${VERSION_FULL}`.
- `.github/workflows/build-wasm.yml` — `on: push/pull_request` only; `mymindstorm/setup-emsdk@v14` version `4.0.4`; no artifact upload; no `workflow_call`.
- `.github/workflows/release-wasm.yml` — `mymindstorm/setup-emsdk@v14` version `3.1.51`; owns its own `build-and-test` job followed by `publish-npm` and `publish-npm-prerelease` jobs; uses `actions/upload-artifact` / `actions/download-artifact` internally.
- `.github/workflows/build-java-binaries.yml` — reference for `workflow_call` pattern with outputs; called by `publish-release.yml`.
- `.github/workflows/build-php-binaries.yml` — reference for `workflow_call: {}` with matrix; called by `publish-release.yml`.
- `.github/workflows/build-macos.yml` — `on: push` to `main`, `develop`, `release/**`, `hotfix/**` only; no PR trigger, no `feature/**`.
- `.github/workflows/python-wheels-ci.yml` — `on: push: branches: [develop]` and `pull_request: branches: [develop]` only; no `feature/**`, no PR against `main`.
- `.github/workflows/build-go.yml` — already has `feature/**` and `pull_request` targeting `develop` ✓ (no change needed).
- `.github/workflows/build-java-binaries.yml`, `build-php-binaries.yml` — already have `feature/**` and PR triggers ✓.

### Key CI trigger summary (current state)

| Workflow | `feature/**` | PR→develop | PR→main |
|---|:---:|:---:|:---:|
| build-linux.yml | ✓ (all branches) | ✓ | ✓ |
| build-macos.yml | ✗ | ✗ | ✗ |
| build-go.yml | ✓ | ✓ | ✗ |
| build-java-binaries.yml | ✓ | ✓ | ✗ |
| build-php-binaries.yml | ✓ | ✓ | ✗ |
| build-wasm.yml | ✓ | ✓ | ✓ |
| python-wheels-ci.yml | ✗ | ✓ | ✗ |

## Key Technical Decisions

- **Use `${VERSION_FULL}` in bumpver.sh for npm**: npm semver fully supports hyphen pre-release identifiers (`0.17.3-rc1`). `release-wasm.yml` already distinguishes stable vs pre-release by checking for a hyphen in the tag, so package.json carrying the full version is consistent with that logic.
- **Add `workflow_call` to `build-wasm.yml` and upload dist artifacts**: When triggered via `workflow_call`, the build job uploads the Rollup-bundled `dist/` output as an artifact. The `release-wasm.yml` `build-and-test` job is replaced by `uses: ./.github/workflows/build-wasm.yml`. The publish jobs then download the artifact produced by the reusable call. This eliminates the Emscripten version fork permanently — one file to update.
- **Standardize PR triggers to both `develop` and `main`**: PRs targeting `main` (hotfixes, releases) should also run full build checks. Added to all workflows that currently only check PRs against `develop`.
- **Emscripten version lives only in `build-wasm.yml` after the refactor**: `release-wasm.yml` no longer specifies it.

## Open Questions

### Resolved During Planning

- **Should Go release be made reusable?** No — `release-go.yml` cross-compiles 5 platforms using `aarch64-linux-gnu-gcc` and `mingw`, while `build-go.yml` only does 2 native platforms. The matrices are fundamentally different; reuse would require significant parameterization for no practical gain.
- **Is `${VERSION_FULL}` valid npm semver?** Yes — `0.17.3-rc1` is valid semver. `release-wasm.yml` already identifies pre-releases by checking for a hyphen, and uses `--tag next` for pre-release npm publishes.

### Deferred to Implementation

- Whether to add `pull_request` targeting `main` to `build-go.yml` and `build-java-binaries.yml`/`build-php-binaries.yml` as well (currently they only target `develop`). The pattern is consistent with the plan but outside stated scope.
- Exact artifact name and retention days for the WASM dist artifact produced by `build-wasm.yml` under `workflow_call` — choose a short retention (e.g., 1 day, matching Java/PHP pattern) since it is only used within the same release run.

---

## Implementation Units

- [ ] **Unit 1: Fix bumpver.sh — use full version in wasm/package.json**

**Goal:** `wrappers/wasm/package.json` receives the full version string (e.g., `0.17.3-rc1`) rather than the stripped base version (`0.17.3`) when `bumpver.sh` is run with a pre-release label.

**Requirements:** R1

**Dependencies:** None

**Files:**
- Modify: `scripts/bumpver.sh`

**Approach:**
- Line 172: change `${VERSION}` to `${VERSION_FULL}` in the sed replacement targeting `wrappers/wasm/package.json`.
- No other changes to the script.

**Patterns to follow:**
- Same file: Android version at line 168 already uses `${VERSION_FULL}` (`"version \"${VERSION_FULL}\""`).

**Test scenarios:**
- Happy path: `./scripts/bumpver.sh 0.17.4` → `wrappers/wasm/package.json` version is `"0.17.4"` (no label, unchanged behavior).
- Happy path pre-release: `./scripts/bumpver.sh 0.17.4-rc1` → `wrappers/wasm/package.json` version is `"0.17.4-rc1"`.
- Edge case: `./scripts/bumpver.sh 0.17.4-dev.2` → `wrappers/wasm/package.json` version is `"0.17.4-dev.2"`.

**Verification:**
- Run `./scripts/bumpver.sh 0.17.4-rc1` in a dry-run (or on a throwaway branch) and confirm `wrappers/wasm/package.json` contains `"version": "0.17.4-rc1"`.
- Run `./scripts/bumpver.sh 0.17.4` and confirm `"version": "0.17.4"` (no label, backwards-compatible).

---

- [ ] **Unit 2: Standardize CI triggers — macOS and Python**

**Goal:** Every push to `feature/**` and every PR targeting `develop` or `main` runs the macOS and Python wheel builds, matching the trigger pattern of the other build workflows.

**Requirements:** R2

**Dependencies:** None

**Files:**
- Modify: `.github/workflows/build-macos.yml`
- Modify: `.github/workflows/python-wheels-ci.yml`

**Approach:**
- `build-macos.yml`: add `feature/**` to push branches; add `pull_request: branches: [develop, main]`.
- `python-wheels-ci.yml`: add `feature/**` to push branches; add `main` to pull_request branches.
- Target trigger pattern (to match `build-go.yml`, `build-java-binaries.yml`, etc.):
  ```
  push:
    branches: [develop, main, 'release/**', 'hotfix/**', 'feature/**']
  pull_request:
    branches: [develop, main]
  ```

**Patterns to follow:**
- `.github/workflows/build-go.yml` — current reference trigger pattern.
- `.github/workflows/build-java-binaries.yml` — same pattern.

**Test scenarios:**
- Test expectation: none — trigger changes have no unit-testable behavior; verified by observing workflow runs on a feature branch push and a PR against `main`.

**Verification:**
- Push a commit to a `feature/` branch and confirm both `build-macos.yml` and `python-wheels-ci.yml` appear in the Actions run list.
- Open a PR targeting `main` and confirm the same.

---

- [ ] **Unit 3: Add `workflow_call` to build-wasm.yml and wire release-wasm.yml to call it**

**Goal:** `build-wasm.yml` becomes a reusable workflow (matching the Java/PHP pattern). `release-wasm.yml` calls it instead of duplicating the build. The Emscripten version fork is eliminated — only `build-wasm.yml` specifies it.

**Requirements:** R3, R4

**Dependencies:** None

**Files:**
- Modify: `.github/workflows/build-wasm.yml`
- Modify: `.github/workflows/release-wasm.yml`

**Approach:**

**`build-wasm.yml` changes:**
- Add `workflow_call: {}` to the `on:` section (alongside existing push/pull_request triggers).
- After the Rollup build step, add `actions/upload-artifact@v4` to upload the bundled `dist/` directory when triggered via `workflow_call` (use a condition: `if: ${{ github.event_name == 'workflow_call' }}`). Artifact name: `wasm-dist`, retention: 1 day.

**`release-wasm.yml` changes:**
- Replace the entire `build-and-test` job body with:
  ```yaml
  build-and-test:
    uses: ./.github/workflows/build-wasm.yml
  ```
- Remove the inline `setup-emsdk` step and Emscripten version pin from `release-wasm.yml` entirely.
- The `publish-npm` and `publish-npm-prerelease` jobs already use `actions/download-artifact@v4` to fetch `wasm-dist` — they continue to do so (artifact name unchanged).

**Patterns to follow:**
- `.github/workflows/publish-release.yml` calling `build-java-binaries.yml` — reference for how a release workflow calls a build workflow and then downloads its artifacts.
- `.github/workflows/build-php-binaries.yml:1-5` — reference for minimal `workflow_call: {}` declaration.

**Test scenarios:**
- Happy path: push to `develop` → `build-wasm.yml` runs normally (no artifact upload in push-triggered run).
- Happy path release: push tag `v0.17.4` → `release-wasm.yml` triggers → its `build-and-test` job calls `build-wasm.yml` which runs the full build and uploads `wasm-dist` artifact → `publish-npm` job downloads artifact and publishes to npm.
- Edge case: `workflow_call` from `release-wasm.yml` uses the same Emscripten version as a standalone `build-wasm.yml` push run (confirmed by inspecting the workflow YAML — only one version pin exists).

**Verification:**
- After the change, `release-wasm.yml` contains no `setup-emsdk` step and no Emscripten version number.
- `build-wasm.yml` contains exactly one Emscripten version pin.
- Trigger `release-wasm.yml` manually via `workflow_dispatch` on a test tag and confirm the npm publish step receives the artifact.

---

## System-Wide Impact

- **Interaction graph:** `release-wasm.yml` gains a `needs: build-and-test` dependency on the reusable build. The `is-prerelease`, `publish-npm`, and `publish-npm-prerelease` jobs already depend on `build-and-test`; their dependency structure is unchanged.
- **Error propagation:** If `build-wasm.yml` fails in a reusable call context, `release-wasm.yml` fails before reaching publish — no partial npm publish.
- **Unchanged invariants:** Java, PHP, Python, Go, Apple publishing workflows are not touched. `publish-release.yml` orchestration is unchanged. The npm publish logic (stable vs `--tag next`) in `release-wasm.yml` is unchanged.
- **bumpver.sh rollback risk:** The version sed pattern at line 172 is isolated — a test run on a scratch branch confirms the replacement before merging.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| `workflow_call` artifact upload condition (`github.event_name == 'workflow_call'`) adds complexity to build-wasm.yml | Keep the condition minimal and well-commented; reference the Java pattern as precedent |
| Trigger changes to python-wheels-ci.yml may cause it to run on every feature push (cibuildwheel is slow) | Accept — consistency is more valuable than saving runner minutes on feature branches; the workflow already uses cibuildwheel's fast path for test builds |
| macOS build is expensive (macos-26 runner); running on every feature push increases cost | Accept — same tradeoff as Java/PHP; macos runners are already used this way for other builds |

- [ ] **Unit 4: Rename workflow files and standardize workflow names**

**Goal:** All workflow file names follow a consistent `{verb}-{lang}.yml` convention. Workflow `name:` fields use a consistent human-readable style. The two stray Python files (`python-wheels-build.yml` + `python-wheels-ci.yml`) are merged into one. Internal `uses:` references and documentation are updated.

**Requirements:** Naming consistency (user request)

**Dependencies:** Units 1–3 (complete file changes before renaming to avoid stale references)

**Files:**
- Rename: `.github/workflows/build-java-binaries.yml` → `.github/workflows/build-java.yml`
- Rename: `.github/workflows/build-php-binaries.yml` → `.github/workflows/build-php.yml`
- Rename: `.github/workflows/python-wheels-release.yml` → `.github/workflows/release-python.yml`
- Rename: `.github/workflows/publish-release.yml` → `.github/workflows/release.yml`
- Rename: `.github/workflows/release-apple-binaries.yml` → `.github/workflows/release-swift.yml`
- Merge + rename: `python-wheels-build.yml` (content) + `python-wheels-ci.yml` (triggers) → `.github/workflows/build-python.yml`; delete both originals.
- Modify: `.github/workflows/release.yml` — update two `uses:` lines to reference new names (`build-java.yml`, `build-php.yml`)
- Modify: `.github/workflows/release-python.yml` — update `uses:` to reference `build-python.yml`
- Modify: `.claude/skills/release/SKILL.md` — update references to old names
- Modify: `CLAUDE.md` — update `python-wheels-build.yml` reference to `build-python.yml`

**Final workflow file inventory after rename:**

| File | Trigger | Purpose |
|---|---|---|
| `build-linux.yml` | push/PR | C core (valgrind, memcheck) |
| `build-macos.yml` | push/PR | macOS + Swift SPM |
| `build-go.yml` | push/PR | Go wrapper |
| `build-java.yml` | push/PR + workflow_call | Java JVM + Android binaries |
| `build-php.yml` | push/PR + workflow_call | PHP extension binaries |
| `build-wasm.yml` | push/PR + workflow_call | WASM (after Unit 3) |
| `build-python.yml` | push/PR + workflow_call | Python wheels (cibuildwheel) |
| `release.yml` | tags `v*` | GitHub Release + Java + Android + PHP publish |
| `release-go.yml` | tags `v*` | Go module tag + static libs commit |
| `release-python.yml` | tags `v*` | PyPI / TestPyPI publish |
| `release-swift.yml` | tags | xcframeworks to GitHub Release |
| `release-wasm.yml` | tags `v*` | npm publish |

**Approach:**
- Use `git mv` for renames so git history is preserved.
- `build-python.yml` is the content of `python-wheels-build.yml` with its `on:` section replaced by the combined triggers: `push: branches: [develop, main, 'release/**', 'hotfix/**', 'feature/**']` and `pull_request: branches: [develop, main]` plus `workflow_call: {}` (already present). Delete `python-wheels-ci.yml`.
- Update each workflow's `name:` field to match: `"Build Java"`, `"Build PHP"`, `"Build Python"`, `"Build WASM"`, `"Release"`, `"Release Python"`, `"Release Swift"`.
- Existing workflows whose names are already consistent (`build-linux`, `build-macos`, `build-go`, `release-go`, `release-wasm`) need only a `name:` field check.

**Patterns to follow:**
- `build-wasm.yml` `name: "Build WASM"` — reference style for the `name:` field.

**Test scenarios:**
- Test expectation: none — this is a pure rename/reference update with no behavioral change. Verified by confirming Actions tab shows renamed workflow names after the first push.

**Verification:**
- `.github/workflows/` contains exactly 12 files matching the table above; no old names remain.
- `grep -r "python-wheels-build\|python-wheels-ci\|build-java-binaries\|build-php-binaries\|publish-release\|release-apple-binaries" .github/ .claude/ CLAUDE.md` returns no results.
- All `uses:` references within workflow files resolve to existing file names.

---

## Sources & References

- Related code: `scripts/bumpver.sh:172`
- Related code: `.github/workflows/build-wasm.yml`, `.github/workflows/release-wasm.yml`
- Pattern reference: `.github/workflows/build-java-binaries.yml` (workflow_call with outputs)
- Pattern reference: `.github/workflows/build-php-binaries.yml` (workflow_call: {})
- Pattern reference: `.github/workflows/publish-release.yml` (orchestrator calling reusable builds)
