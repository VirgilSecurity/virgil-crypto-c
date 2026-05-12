---
name: pre-release
aliases: [prerelease, pre release]
description: Cut the first RC pre-release directly from develop. Use when the user says "pre-release", "prerelease", "cut an RC", or "start a release".
compatibility: Requires gh CLI authenticated to the VirgilSecurity/virgil-crypto-c repo.
allowed-tools: Bash Read
---

# Pre-release

Trigger the first release candidate (`MAJOR.MINOR.PATCH-rc.1`) directly from `develop` via the unified `release.yml` workflow. No release branch is created — `develop` is the release branch.

## When to use

Use this skill when you are ready to cut the first RC for a version. Subsequent RCs and the final production release all run from `develop` via `/release`.

## Pre-flight checklist

- Confirm `develop` is in the expected state (CI green, no stale WIP commits)
- `ChangeLog.md` and `README.md` do **not** need entries yet — required only before the final production release

## Steps

### 1. Determine the version

If the user provided a version argument, parse it. Acceptable forms: `0.19.0`, `v0.19.0`, `19.0`, `0.19`. Normalize to bare `MAJOR.MINOR.PATCH` — no leading `v`, no label suffix. If not provided, ask:

> "What version are you releasing? (e.g. `0.19.0`)"

The first RC label will be appended automatically: `MAJOR.MINOR.PATCH-rc.1`.

### 2. Confirm the plan

Show the user what will happen and ask for confirmation before proceeding:

```
Release: X.Y.Z-rc.1  (from develop, via release.yml workflow)
Tags:    wrappers/go/vX.Y.Z-rc.1  and  vX.Y.Z-rc.1
```

### 3. Trigger the release workflow

```bash
gh workflow run release.yml \
  --field version=X.Y.Z-rc.1 \
  --field branch=develop
```

### 4. Find and monitor the run

```bash
# Wait a moment for the run to appear, then get its ID
gh run list --workflow release.yml --limit 1

# Watch it to completion
gh run watch <run-id>
```

### 5. Verify on success

```bash
git fetch --tags
git tag | grep "X.Y.Z-rc.1"
```

Both tags should be present:
- `vX.Y.Z-rc.1`
- `wrappers/go/vX.Y.Z-rc.1`

## What the workflow does

| Step | Action |
|------|--------|
| `build-go` (parallel) | Cross-compiles Go static libs for 5 platforms |
| `build-apple` (parallel) | Builds Apple xcframeworks on `macos-26` |
| `release-commit` | Bumps version, assembles artifacts, runs `swift build` + `swift test`, commits to `develop`, pushes both tags |

## What the tags trigger

| Workflow | Action |
|----------|--------|
| `release-python.yml` | Wheels to TestPyPI (pre-release label present) |
| `release-java.yml` | Java/Android to Maven Central staging + GitHub Release |
| `release-php.yml` | PHP packages to GitHub Release |
| `release-swift.yml` | XCFrameworks to GitHub Release |
| `release-wasm.yml` | WASM bundle to npm (with `rc` dist-tag) |

## Subsequent RCs

When fixes land on `develop` and a new RC is needed, use `/release` directly:

```bash
gh workflow run release.yml \
  --field version=X.Y.Z-rc.2 \
  --field branch=develop
```

Or just run `/release` and specify the version and branch when prompted.

## Promoting to production

When the RC is stable, run `/release X.Y.Z` (branch defaults to `develop`). Before doing so, ensure `ChangeLog.md` has an entry for `X.Y.Z` and `README.md` is current.

## Partial failure recovery

If the workflow pushed the release commit but failed to push the tags:

```bash
git fetch origin develop
SHA=$(git rev-parse origin/develop)

git tag "wrappers/go/vX.Y.Z-rc.1" "$SHA"
git push origin "refs/tags/wrappers/go/vX.Y.Z-rc.1"

git tag "vX.Y.Z-rc.1" -m "vX.Y.Z-rc.1" "$SHA"
git push origin "refs/tags/vX.Y.Z-rc.1"
```
