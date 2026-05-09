---
title: "feat: Unified CI-driven release workflow"
type: feat
status: active
date: 2026-05-09
---

# feat: Unified CI-driven release workflow

## Overview

Replace two manual local build steps (Apple xcframeworks, Go static libs) and the fragile `release-go.yml` with a single `workflow_dispatch` (`release.yml`) that builds everything in CI, bumps the version, commits all binaries to the source branch, and creates both version tags atomically. Releasing from any branch becomes: `gh workflow run release.yml --field version=X.Y.Z --field branch=<branch>`.

(see origin: `docs/brainstorms/unified-release-workflow-requirements.md`)

## Problem Frame

Three problems motivate this change:

1. Apple xcframeworks are built locally via `./scripts/build_apple_frameworks.sh` before tagging and committed. This ties every release to a specific macOS machine and produces unverified framework zips in the source tree before CI has a chance to validate them.
2. `release-go.yml` always checks out `develop` regardless of the tagged branch. Go module tags for non-develop releases (`main`, `release-x.x.x`) therefore point to source code that doesn't match the tagged branch — a correctness bug.
3. There is no supported path to release from a branch other than `develop`.

## Requirements Trace

| ID | Requirement | Implementation Unit |
|----|-------------|---------------------|
| R1 | `workflow_dispatch` inputs: `version` (required) and `branch` (optional, default `develop`) | IU-2 |
| R2 | Build Go static libs for all 5 platforms in CI | IU-1, IU-2 |
| R3 | Build Apple xcframeworks in CI on a macOS runner | IU-2 |
| R4 | Version bump (`./scripts/bumpver.sh`) as part of the workflow, not a pre-commit | IU-1, IU-2 |
| R5 | Swift `build` + `test` verification after xcframeworks are assembled | IU-2 |
| R6 | Single atomic commit: version bump + all binaries on the source branch | IU-2 |
| R7 | Go module tag (`wrappers/go/vX.X.X`) points to the release commit on the source branch | IU-2 |
| R8 | Main release tag (`vX.X.X`) triggers existing publish workflows unchanged | IU-2 |
| R9 | Delete `release-go.yml` | IU-3 |
| R10 | Update `/release` skill to use `gh workflow run release.yml` | IU-4 |
| R11 | Update `CLAUDE.md` to remove local Apple frameworks and Go build check requirements | IU-5 |

## Scope Boundaries

**In scope:** New `release.yml`, extension of `build-go.yml`, deletion of `release-go.yml`, skill update, `CLAUDE.md` update.

**Out of scope:**
- Changes to `release-swift.yml`, `release-java.yml`, `release-php.yml`, `release-wasm.yml`, `release-python.yml` — these remain tag-triggered and unchanged.
- Local build scripts (`build_apple_frameworks.sh`, `bumpver.sh`) — kept for manual use.
- WASM pre-build — remains tag-triggered.
- Branch protection configuration changes — `develop` is already configured; operator responsibility for `main` / `release-*` branches before releasing from them.

## Context & Research

### Relevant Code and Patterns

**`build-go.yml`** (`.github/workflows/build-go.yml`)
- Reusable via `workflow_call`; currently has one input: `upload_artifacts: boolean`
- Matrix: 5 targets (`linux_amd64`, `linux_arm64`, `darwin_amd64`, `darwin_arm64`, `windows_amd64`)
- `checkout@v6` with no explicit `ref` — defaults to calling workflow's context ref
- Artifacts uploaded as `go-libs-<target>/` containing `lib/*.a` and `include/`
- Needs two new inputs: `version` (optional string) and `ref` (optional string) — see IU-1

**`build_apple_frameworks.sh`** (`scripts/build_apple_frameworks.sh`)
- Called WITHOUT a version arg in the new workflow (bumpver.sh is called first; the script only updates checksums in Package.swift — it does not touch `let version`)
- Updates `binaries/*.xcframework.zip`, `binaries/*.sha256sum`, and the three checksum constants in `Package.swift` (lines 12, 25, 38) via `sed_replace "(let +vsc${short_name}Checksum.+)" ...`
- Does NOT update `let version` (line 5) — that is `bumpver.sh`'s job

**`bumpver.sh`** (`scripts/bumpver.sh`)
- Takes `VERSION_FULL` as `$1`
- Updates: `VERSION` file, `CMakeLists.txt`, `let version = "..."` in `Package.swift` (line 5), and all language wrapper version files

**`Package.swift`** — three independent edit zones:
- Line 5: `let version = "..."` — written by `bumpver.sh`
- Line 6: `let useLocalBinaries = false` — toggled for Swift verification (must be restored)
- Lines 12, 25, 38: `let vscCommonChecksum`, `let vscFoundationChecksum`, `let vscRatchetChecksum` — written by `build_apple_frameworks.sh`

**`release-swift.yml`** (`.github/workflows/release-swift.yml`)
- Tag-triggered on `v*.*.*`; runs on `macos-26`
- Calls `./scripts/check_spm_xcframeworks.sh` then `./scripts/run_spm_tests_with_local_binaries.sh` before publishing xcframeworks to GitHub Release
- Already validates the committed xcframeworks; the new workflow's Swift verification is an earlier gate, not a replacement

**`release-go.yml`** (`.github/workflows/release-go.yml`)
- Always checks out `develop` regardless of source branch — the correctness bug motivating this work
- Creates a temp branch `go-libs/vX.X.X` for the lib commit, pushes, tags, deletes branch
- Entire file is replaced and deleted by this plan

**`.claude/skills/release/SKILL.md`** — current manual steps; will be replaced with `gh workflow run` invocation

### Institutional Learnings

- Concurrent push protection must use `--force-with-lease`; plain `--force` would silently overwrite concurrent work on a protected branch (learned during Go release workflow debugging)
- `github-actions[bot]` requires `restrictions.apps: ["github-actions"]` on the source branch to push directly; `develop` is already configured; operator must configure `main` / `release-*` before using them
- Swift verification must use `trap` to guarantee `useLocalBinaries = false` is restored on any exit, including failures (from `feedback_swift_check_policy.md`)
- Artifact download from a reusable workflow is available within the same workflow run context via `actions/download-artifact@v4`

## Key Technical Decisions

### 1. `release-commit` runs on `macos-26`
Swift verification (`swift build` + `swift test`) requires macOS with Xcode. `ubuntu-latest` cannot run it. `macos-26` is already used by `release-swift.yml` for the same reason.

### 2. Version bump without a pre-commit
Each build job runs `./scripts/bumpver.sh $version` in its own checkout without committing. This ensures compiled binaries embed the correct version string. The single atomic commit in `release-commit` includes the version bump alongside all binaries. No dangling version-bump commit is created if builds fail mid-flight.

### 3. `build-go.yml` needs `ref` and `version` inputs
Without a `ref` input, reusable workflow checkouts use the calling workflow's context ref (the branch hosting `release.yml`, typically `develop`). When releasing from a non-develop branch, this would build Go libs from the wrong source. Adding `ref` fixes the source branch; adding `version` enables bumpver inside the matrix jobs.

### 4. `Package.swift` merge in `release-commit`
`bumpver.sh` writes `let version` (line 5); `build_apple_frameworks.sh` writes the three checksum constants (lines 12, 25, 38). In `release-commit`, bumpver runs first on the workspace copy, then the three checksum values are extracted from the `build-apple` artifact's `Package.swift` and `sed`-patched into the workspace file. The version line is intentionally preserved from bumpver, not overwritten.

### 5. No waiting for CI workflows triggered by the release commit
`build-linux` and `build-macos` are triggered by the binary commit, but they test C source which is unchanged by that commit. Swift correctness is already gate-checked in step 5 of `release-commit`. Waiting would add 20–40 min for no additional signal.

### 6. `--force-with-lease` as the concurrent-push gate
If anyone pushes to the source branch during the build, the push in step 7 of `release-commit` fails and the job aborts before creating any tags. This is the desired "fail cleanly" behavior described in the requirements.

### 7. Partial-failure runbook documented in SKILL.md
If steps 8–9 (tag pushes) fail after step 7 (branch push) succeeds, the operator can push the missing tags manually: `git tag wrappers/go/vX.X.X <SHA> && git push origin refs/tags/wrappers/go/vX.X.X` and the same for `vX.X.X`. The skill update documents this.

## Implementation Units

### IU-1: Extend `build-go.yml` with `ref` and `version` inputs

**File:** `.github/workflows/build-go.yml`

Changes to `workflow_call.inputs`:
- Add `ref` (optional string): branch/SHA for checkout; empty means use calling workflow's ref
- Add `version` (optional string): when set, each matrix job runs `./scripts/bumpver.sh "$version"` after checkout and before the CMake build

Changes to the `build` job `steps`:
- Update `actions/checkout@v6` to add `with: ref: ${{ inputs.ref }}` (empty string is safe — GitHub Actions treats it as "default ref")
- Add a new step between checkout and the CMake build:
  ```
  name: Bump version (release builds only)
  if: inputs.version != ''
  run: ./scripts/bumpver.sh "${{ inputs.version }}"
  ```

No changes to the push/PR triggers — those remain as-is and leave `ref` and `version` empty.

**Test scenarios for IU-1:**
- Normal CI push: `ref` and `version` are empty; checkout uses triggering ref; bumpver step is skipped
- Called from `release.yml`: `ref=develop` and `version=0.19.0`; checkout targets develop; bumpver runs before CMake
- Called from `release.yml` with `ref=release-0.19.x`: Go libs are built from `release-0.19.x` source

---

### IU-2: Create `.github/workflows/release.yml`

**File:** `.github/workflows/release.yml` (new file)

**Trigger:** `workflow_dispatch` only

**Inputs:**

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `version` | yes | — | Version string, e.g. `0.19.0` or `0.19.0-dev.7` |
| `branch` | no | `develop` | Source branch to release from |

**Job: `build-go`**
```
uses: ./.github/workflows/build-go.yml
with:
  upload_artifacts: true
  version: ${{ inputs.version }}
  ref: ${{ inputs.branch || 'develop' }}
```
No `needs` — runs in parallel with `build-apple`.

**Job: `build-apple`**
- Runner: `macos-26`
- Permissions: none (read-only; artifacts go to GitHub Actions storage)
- Steps:
  1. `actions/checkout@v6` with `ref: ${{ inputs.branch || 'develop' }}` and `lfs: true`
  2. `git lfs install`
  3. `./scripts/bumpver.sh "${{ inputs.version }}"` (no commit)
  4. `./scripts/build_apple_frameworks.sh` (no args — bumpver already ran; script updates checksums + zip artifacts)
  5. Upload artifact `apple-release-files` containing: `binaries/*.xcframework.zip`, `binaries/*.sha256sum`, `Package.swift`

**Job: `release-commit`**
- Runner: `macos-26`
- Permissions: `contents: write`
- `needs: [build-go, build-apple]`
- Steps:
  1. `actions/checkout@v6` with `ref: ${{ inputs.branch || 'develop' }}`, `lfs: true`, `fetch-depth: 0`; record `BASE_SHA=$(git rev-parse HEAD)`
  2. `git lfs install && git lfs track "wrappers/go/pkg/**/*.a"`
  3. Git config: `user.name "github-actions[bot]"` / `user.email "github-actions[bot]@users.noreply.github.com"`
  4. `./scripts/bumpver.sh "${{ inputs.version }}"` (sets `let version` in Package.swift and all other wrapper version files)
  5. Download artifact `apple-release-files` into a staging directory; copy `binaries/*.xcframework.zip` and `binaries/*.sha256sum` into `$GITHUB_WORKSPACE/binaries/`; extract only the three checksum constants from the artifact `Package.swift` and patch them into the workspace `Package.swift` (the `let version` line from bumpver is preserved)
     - Implementation: `grep -E 'let vsc(Common|Foundation|Ratchet)Checksum' <artifact>/Package.swift | while read line; do name=$(echo "$line" | grep -oE 'vsc\w+Checksum'); val=$(echo "$line" | grep -oE '"[a-f0-9]+"'); sed -i "" "s/let $name = .*/let $name = $val/" Package.swift; done`
  6. Download all `go-libs-*` artifacts into `wrappers/go/pkg/`; restructure: `for dir in go-libs-*; do mv "$dir" "${dir#go-libs-}"; done`
  7. Swift verification with guaranteed restore:
     ```
     trap 'sed -i "" "s/let useLocalBinaries = true/let useLocalBinaries = false/" Package.swift' EXIT
     sed -i "" 's/let useLocalBinaries = false/let useLocalBinaries = true/' Package.swift
     swift build
     swift test
     ```
  8. `git add -A && git commit -m "chore(release): bump version and update pre-built binaries for v${{ inputs.version }}"`
  9. `git push --force-with-lease origin HEAD:refs/heads/${{ inputs.branch || 'develop' }}`
  10. `git tag "wrappers/go/v${{ inputs.version }}" && git push origin "refs/tags/wrappers/go/v${{ inputs.version }}"`
  11. `git tag "v${{ inputs.version }}" -m "v${{ inputs.version }}" && git push origin "refs/tags/v${{ inputs.version }}"`

**Test scenarios for IU-2:**
- Happy path from `develop`: all jobs succeed, commit on develop, both tags `wrappers/go/v0.19.0` and `v0.19.0` created
- Happy path from `release-0.19.x`: Go module tag points to release-0.19.x source, not develop
- Swift test failure: job fails, `useLocalBinaries = false` restored via trap, no commit or tags created
- Concurrent push during build: `--force-with-lease` in step 9 fails with non-zero exit, job fails cleanly before any tags are created
- Go build matrix failure: `build-go` fails, `release-commit` never starts (it `needs` build-go)
- Apple framework build failure: `build-apple` fails, `release-commit` never starts
- Partial failure — commit pushed (step 9 ok) but tag push (steps 10–11) fails: commit is on branch, tags missing; operator recovery documented in IU-4

---

### IU-3: Delete `release-go.yml`

**File:** `.github/workflows/release-go.yml` (delete)

No replacement — `release.yml` subsumes all functionality. `build-go.yml` retains its `workflow_call` interface for use by the new workflow; the tag-trigger path in `build-go.yml` does not exist (verified: `build-go.yml` has no tag trigger).

---

### IU-4: Update `/release` skill

**File:** `.claude/skills/release/SKILL.md`

Replace the multi-step manual procedure with:

1. **Ask for version** if not provided
2. **Ask for branch** (default `develop`) if the user wants to release from a non-default branch
3. **Trigger workflow**: `gh workflow run release.yml --field version=X.Y.Z --field branch=<branch> --repo VirgilSecurity/virgil-crypto-c`
4. **Monitor**: `gh run watch --repo VirgilSecurity/virgil-crypto-c` (or `gh run list --workflow release.yml --limit 1`)
5. **Partial failure recovery** (document): if the workflow log shows the commit pushed but tags failed, run manually:
   ```
   git fetch origin
   git tag wrappers/go/vX.Y.Z <commit-sha>
   git push origin refs/tags/wrappers/go/vX.Y.Z
   git tag vX.Y.Z -m "vX.Y.Z" <commit-sha>
   git push origin refs/tags/vX.Y.Z
   ```

Remove all references to `release-go.yml`. Keep the "What the tag triggers" table but replace the `release-go.yml` row with a note that Go libs are now committed as part of `release.yml`.

Remove the macOS and Java prerequisites from the edge cases section — these are no longer local requirements.

---

### IU-5: Update `CLAUDE.md`

**File:** `CLAUDE.md`

Remove from the **Important Notes** section:
- `"Apple frameworks: run ./scripts/build_apple_frameworks.sh on macOS before tagging a release."`

Replace the **Forbidden** section's Swift verification paragraph with a scoped version that fires only when Swift wrapper source has changed:

> **Verify Swift build and tests before pushing if `*.swift` files were modified**: If any unpushed commits modify files matching `wrappers/swift/**/*.swift`, run the Swift package verification before pushing:
> 1. `sed -i '' 's/let useLocalBinaries = false/let useLocalBinaries = true/' Package.swift`
> 2. `swift build`
> 3. `swift test`
> 4. `sed -i '' 's/let useLocalBinaries = true/let useLocalBinaries = false/' Package.swift`
>
> Check with: `git diff origin/<branch>..HEAD -- 'wrappers/swift/**/*.swift'`
> Fix any errors before pushing. (Release-time xcframework correctness is verified by CI in `release.yml`.)

The distinction: the old rule fired after every `build_apple_frameworks.sh` run (i.e., only during releases). The new rule fires when Swift source itself changes on any branch — which is the scenario where a local check is most valuable and CI does not automatically cover it before push.

Update the **Quick Reference** → **Release** line to reflect `gh workflow run release.yml` as the primary path.

## Open Questions

### Resolved During Planning

- **Does `build-go.yml` have a tag trigger that would run parallel to `release.yml`?** No. Confirmed: triggers are `push.branches` and `pull_request.branches` only. Deleting `release-go.yml` is the only workflow_call consumer; after IU-3, `workflow_call` is only used by `release.yml`.
- **Does `build_apple_frameworks.sh` update `let version` in Package.swift?** No. Confirmed by script source: it only patches lines matching `(let +vsc${short_name}Checksum.+)`. `bumpver.sh` owns the version line. The two scripts edit non-overlapping regions of `Package.swift`.
- **Will `build-go` matrix artifacts be accessible to `release-commit` across a reusable workflow boundary?** Yes. Artifacts uploaded by a reusable workflow job are available to `actions/download-artifact` within the same parent workflow run.
- **Will existing publish workflows break?** No. They are all triggered by `push: tags: v*.*.*` which `release-commit` step 11 creates. Their internal logic is unchanged.

### Deferred to Implementation

- **Exact `sed` command for checksum patching on macOS**: `sed -i ""` (BSD sed) is required on `macos-26`; verify the grep+sed pipeline handles the double-quote escaping in the checksum value strings correctly before committing.
- **`gh workflow run` remote repo flag**: Confirm whether `--repo` is needed or if the workflow file is found automatically when run from within the repo checkout.
- **LFS pointer tracking for `wrappers/go/pkg/**/*.a`**: Verify `git lfs track` in `release-commit` does not produce a dirty `.gitattributes` diff if the pattern is already tracked from a prior release run.
