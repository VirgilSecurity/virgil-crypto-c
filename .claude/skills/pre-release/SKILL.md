---
name: pre-release
aliases: [prerelease, pre release]
description: Create a release branch from develop and cut the first RC pre-release. Use when the user says "pre-release", "prerelease", "cut an RC", or "start a release branch".
compatibility: Requires gh CLI authenticated to the VirgilSecurity/virgil-crypto-c repo.
allowed-tools: Bash Read
---

# Pre-release

Create a `release/MAJOR.MINOR.PATCH` branch from `develop`, configure its branch protection so CI can push, and trigger the first release candidate (`MAJOR.MINOR.PATCH-rc.1`) via the unified `release.yml` workflow.

## When to use

Use this skill when you are ready to stabilize a release. It:

1. Branches `develop` → `release/X.Y.Z`
2. Configures branch protection so `github-actions[bot]` can push the release commit
3. Runs the release workflow for `X.Y.Z-rc.1` from the new branch

Subsequent RCs on the same branch: use `/release X.Y.Z-rc.2 --branch release/X.Y.Z` directly (or just `/release` and specify both fields when prompted).

## Pre-flight checklist

- Confirm `develop` is in the expected state (CI green, no stale WIP commits)
- `ChangeLog.md` and `README.md` do **not** need entries yet — that is required only before the final production release

## Steps

### 1. Determine the version

If the user provided a version argument, parse it. Acceptable forms: `0.19.0`, `v0.19.0`, `19.0`, `0.19`. Normalize to bare `MAJOR.MINOR.PATCH` — no leading `v`, no label suffix. If not provided, ask:

> "What version are you releasing? (e.g. `0.19.0`)"

The first RC label will be appended automatically: `MAJOR.MINOR.PATCH-rc.1`.

### 2. Confirm the plan

Show the user the three actions that will happen and ask for confirmation before proceeding:

```
Branch:  release/X.Y.Z  (from develop)
Release: X.Y.Z-rc.1     (via release.yml workflow)
Tags:    wrappers/go/vX.Y.Z-rc.1  and  vX.Y.Z-rc.1
```

### 3. Create and push the release branch

```bash
# Ensure develop is up to date
git fetch origin develop

# Create the branch from develop tip
git checkout -b release/X.Y.Z origin/develop

# Push the branch
git push origin release/X.Y.Z

# Return to the original branch so local state is clean
git checkout -
```

### 4. Configure branch protection

The release branch must allow `github-actions[bot]` to push the release commit back.
**Do not use `restrictions.apps: ["github-actions"]`** — that pattern silently breaks `GITHUB_TOKEN` pushes since GitHub's 2023 token changes. Use `restrictions: null` with force-pushes enabled:

```bash
gh api -X PUT repos/VirgilSecurity/virgil-crypto-c/branches/release%2FX.Y.Z/protection \
  --input - <<'EOF'
{
  "required_status_checks": null,
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null
}
EOF
```

Note the URL-encoded slash: `release%2FX.Y.Z`.

### 5. Trigger the release workflow

```bash
gh workflow run release.yml \
  --field version=X.Y.Z-rc.1 \
  --field branch=release/X.Y.Z
```

### 6. Find and monitor the run

```bash
# Wait a moment for the run to appear, then get its ID
gh run list --workflow release.yml --limit 1

# Watch it to completion
gh run watch <run-id>
```

### 7. Verify on success

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
| `release-commit` | Bumps version, assembles artifacts, runs `swift build` + `swift test`, commits to `release/X.Y.Z`, pushes both tags |

## What the tags trigger

| Workflow | Action |
|----------|--------|
| `release-python.yml` | Wheels to TestPyPI (pre-release label present) |
| `release-java.yml` | Java/Android to Maven Central staging + GitHub Release |
| `release-php.yml` | PHP packages to GitHub Release |
| `release-swift.yml` | XCFrameworks to GitHub Release |
| `release-wasm.yml` | WASM bundle to npm (with `rc` dist-tag) |

## Subsequent RCs

When fixes land on `release/X.Y.Z` and a new RC is needed, trigger directly:

```bash
gh workflow run release.yml \
  --field version=X.Y.Z-rc.2 \
  --field branch=release/X.Y.Z
```

Or use `/release` and specify both the version and branch when prompted.

## Promoting to production

When the RC is stable, use `/release` with the bare `X.Y.Z` version from the `release/X.Y.Z` branch. Before doing so, ensure `ChangeLog.md` has an entry for `X.Y.Z` and `README.md` is current (the `/release` skill enforces this for production releases).

## Partial failure recovery

If the workflow pushed the release commit but failed to push the tags:

```bash
git fetch origin release/X.Y.Z
SHA=$(git rev-parse origin/release/X.Y.Z)

git tag "wrappers/go/vX.Y.Z-rc.1" "$SHA"
git push origin "refs/tags/wrappers/go/vX.Y.Z-rc.1"

git tag "vX.Y.Z-rc.1" -m "vX.Y.Z-rc.1" "$SHA"
git push origin "refs/tags/vX.Y.Z-rc.1"
```
