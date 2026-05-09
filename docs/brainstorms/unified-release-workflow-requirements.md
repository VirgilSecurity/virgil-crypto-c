# Unified Release Workflow Requirements

**Date:** 2026-05-09
**Status:** Draft

## Problem

The current release process has two manual local build steps and a fragile Go release workflow:

1. **Apple xcframeworks** are built locally via `./scripts/build_apple_frameworks.sh` before tagging, then committed. This ties releases to a specific macOS machine.
2. **Go static libs** are built by CI after tagging, but the commit-back step always uses `develop` as source regardless of the tagged branch, so Go module tags for non-develop releases contain the wrong source code.
3. **Releasing from a non-develop branch** (`main`, `release-x.x.x`) is not properly supported.

## Goal

A single `workflow_dispatch` (`release.yml`) that handles the entire release end-to-end:
- Builds Go static libs for all platforms in CI
- Builds Apple xcframeworks in CI (macOS runner)
- Bumps version, commits all binaries to the source branch, creates the version tag
- Pushes the tag to trigger existing publish workflows unchanged

Releasing any version from any branch becomes:
```
gh workflow run release.yml --field version=X.Y.Z --field branch=<branch>
```

## Scope

### In scope
- New `release.yml` workflow_dispatch with `version` and `branch` inputs
- Parallel build jobs: Go libs (all 5 platforms) + Apple xcframeworks (macOS)
- Version bump (`./scripts/bumpver.sh`) as part of the workflow
- Swift build + test verification after xcframeworks are built (CI equivalent of current local check)
- Commit of Go libs to `wrappers/go/pkg/` and xcframeworks to `binaries/` on the source branch
- Go module tag (`wrappers/go/vX.X.X`) pointing to the commit with libs
- Main release tag (`vX.X.X`) that triggers existing publish workflows
- Removal of `release-go.yml` (replaced by new workflow)
- Update `/release` skill to: `gh workflow run release.yml ...` + monitor
- Update `CLAUDE.md` to remove local Apple frameworks and Go build check requirements

### Out of scope
- Changes to existing publish workflows (`release-swift.yml`, `release-java.yml`, `release-php.yml`, `release-wasm.yml`, `release-python.yml`)
- Local build scripts (`build_apple_frameworks.sh`, `bumpver.sh`) — kept for manual use
- WASM pre-build (remains tag-triggered)

## Workflow Design

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `version` | yes | — | Version string, e.g. `0.19.0` or `0.19.0-dev.7` |
| `branch` | no | `develop` | Source branch to release from |

### Job Graph

```
                    ┌─▶ build-go (matrix: 5 platforms) ─┐
bumpver (no commit) │                                    ├─▶ release-commit (macOS)
                    └─▶ build-apple (macOS)  ────────────┘        │
                                                                    ▼
                                                         push commit + tags (--force-with-lease)
                                                                    │
                                                                    ▼
                                                   release-swift / release-java /
                                                   release-php / release-wasm /
                                                   release-python  (existing, tag-triggered)
```

### Version bump strategy

Each build job runs `./scripts/bumpver.sh $version` locally on its own checkout **without committing**. This ensures compiled binaries embed the correct version. The single atomic commit in `release-commit` includes the version bump + all binaries together. No dangling version-bump commit is created if builds fail.

### `build-apple` job

- Runner: `macos-26`
- Checkout `branch` with LFS (`lfs: true`)
- Run `./scripts/bumpver.sh $version` locally (no commit)
- Run `./scripts/build_apple_frameworks.sh` in full — builds xcframeworks, zips them into `binaries/`, updates SHA256 digests in `binaries/*.sha256sum`, and updates the three checksum constants in `Package.swift`
- Upload artifacts: `binaries/*.xcframework.zip`, `binaries/*.sha256sum`, and the modified `Package.swift`

### `build-go` job

- Reuse `.github/workflows/build-go.yml` via `workflow_call` with `upload_artifacts: true`
- Each matrix job checks out `branch` and runs `./scripts/bumpver.sh $version` before building
- Artifacts are named `go-libs-<target>` (e.g. `go-libs-linux_amd64`) and contain `lib/*.a` and `include/`

### `release-commit` job

- Runner: `macos-26` (required for `swift build` and `swift test`)
- `needs: [build-go, build-apple]`

Steps:
1. Checkout `branch` with LFS and full history (`fetch-depth: 0`); record the current HEAD SHA as `$BASE_SHA`
2. Run `./scripts/bumpver.sh $version` — modifies `Package.swift` version constant and all other wrapper version files
3. Download Apple artifacts: place `binaries/*.xcframework.zip` and `binaries/*.sha256sum` into the workspace. Apply only the three checksum constants from the artifact `Package.swift` into the workspace `Package.swift` (preserve bumpver's `let version` line). Implementation: `sed` the three checksum values from the artifact file into the workspace file.
4. Download Go lib artifacts into a staging directory; rename each `go-libs-<target>` → `<target>` and move into `wrappers/go/pkg/`; run `git lfs track "wrappers/go/pkg/**/*.a"` to update `.gitattributes`
5. Swift verification:
   - Set `useLocalBinaries = true` in `Package.swift`
   - Use `trap` to guarantee `useLocalBinaries = false` is restored on any exit
   - Run `swift build` then `swift test`; fail the job if either fails
6. `git add -A && git commit -m "chore(release): bump version and update pre-built binaries for v$version"`
7. Concurrent-push guard: `git push --force-with-lease origin HEAD:refs/heads/$branch`
   - `--force-with-lease` fails automatically if anyone pushed to `$branch` during the build; no tags are created and the release aborts cleanly
8. `git tag wrappers/go/v$version && git push origin refs/tags/wrappers/go/v$version`
9. `git tag v$version -m "v$version" && git push origin refs/tags/v$version`

**CI workflows triggered by the binary commit** (`build-linux`, `build-macos`) test the C source, which is unchanged by the binary commit. There is no reason to wait for them before pushing the tag. Swift correctness is already verified in step 5.

**Partial failure paths** (steps 8-9 fail after step 7 succeeds): the commit is on the branch but no tags exist. The operator pushes the missing tags manually. Document this in the operator runbook.

## Branch Protection Requirement

The source branch must allow `github-actions[bot]` to push directly (no PR review requirement, `github-actions` in `restrictions.apps`). `develop` is already configured. For `main` or `release-*`, apply the same settings before running a release from those branches. The workflow should fail with a clear error message on push rejection rather than silently retrying.

## Key Implementation Notes

- **`Package.swift` has two separate edits**: bumpver writes `let version = "..."` (line 5); `build_apple_frameworks.sh` writes three checksum constants (lines 12, 25, 38). Apply bumpver first, then patch only the checksum lines from the `build-apple` artifact.
- **Go artifact directory layout**: `actions/download-artifact` produces `go-libs-<target>/` subdirectories; these must be renamed to `<target>/` before staging. Replicate the "Restructure artifacts" step from the current `release-go.yml`.
- **Swift test failure handling**: use `trap 'sed -i "" "s/let useLocalBinaries = true/let useLocalBinaries = false/" Package.swift' EXIT` to guarantee the flag is restored regardless of outcome.
- **`release-go.yml` removal**: delete the file and remove the `build-go.yml` trigger for tag pushes if it has one.
- **`build-go.yml` needs a `version` input**: add an optional `version` workflow_call input; when set, each matrix job runs `./scripts/bumpver.sh $version` before the CMake build. When unset (normal CI runs), skip the bump.

## Success Criteria

- `gh workflow run release.yml --field version=0.19.0 --field branch=develop` completes without any manual steps
- Go module tag `wrappers/go/v0.19.0` contains source code from the specified branch
- Apple xcframeworks in the release are built from CI, not a local machine
- Swift tests pass in CI before tagging
- All existing publish workflows continue to work unchanged after the tag is pushed

## Non-Goals

- Removing the ability to run local builds manually
- Automating WASM pre-build or commit
- Changing how publish workflows distribute artifacts
