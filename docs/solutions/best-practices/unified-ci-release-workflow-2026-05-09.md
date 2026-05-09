---
title: Unified CI release workflow — single workflow_dispatch replacing tag-triggered and local builds
date: 2026-05-09
category: docs/solutions/best-practices
module: ci
problem_type: best_practice
component: release
severity: high
applies_when:
  - Cutting a new version of virgil-crypto-c
  - Adding a new release target (platform, language wrapper)
  - Debugging a failed release run
  - Understanding why release-go.yml was removed
resolution_type: architectural_decision
tags:
  - ci
  - release
  - github-actions
  - go
  - swift
  - xcframework
  - workflow_dispatch
  - bumpver
---

## Problem

Before this workflow, releasing a new version required coordinating three separate systems:

- A **local macOS build** (`./scripts/build_apple_frameworks.sh`) that could only run on the developer's machine
- A **`release-go.yml`** triggered by pushing a `v*` tag — which meant the tag had to exist before the Go libs were compiled, and the workflow pushed a new commit back to the branch after the tag, leaving history where the tagged commit did not contain the final binaries
- **Manual CLAUDE.md rules** ("run `build_apple_frameworks.sh` before tagging") that were easy to skip and had no CI enforcement

Over `v0.19.0-dev.1` through `v0.19.0-dev.6`, `release-go.yml` accumulated 10+ fix commits addressing: detached HEAD during tag-triggered runs, protected branch push failures, force-add bypasses for `.gitignore`, and temp-branch workarounds. The fundamental issue was that a tag-triggered workflow can't cleanly push binaries back to the branch and also create a clean tag pointing at those binaries — the tag comes first, then the binary commit, making the tag reference the wrong commit.

## Solution

Replace everything with a single `workflow_dispatch` workflow (`release.yml`) that:

1. Validates the version string format before any build starts
2. Runs `build-go` (5-platform matrix) and `build-apple` (xcframeworks) in parallel, both checking out the source branch and bumping the version locally before compiling
3. In `release-commit`, assembles all artifacts, verifies checksums, runs `swift build` + `swift test`, commits, pushes to the source branch with `--force-with-lease`, then creates both tags atomically

The workflow is triggered manually — no tag push required. Triggering it is the release act.

## Key design decisions

### `workflow_dispatch` instead of tag-triggered

Tag-triggered workflows run after the tag commit, so any binary commit they push back creates a second commit the tag doesn't reference. `workflow_dispatch` inverts this: the workflow *creates* the tag, so the tag always points at the commit that contains the binaries.

### Version bumped in parallel build jobs, not just in `release-commit`

`build-go` and `build-apple` each run `bumpver.sh` locally before compiling. This ensures the version string is baked into the compiled artifacts (C headers embed major/minor/patch). The bump is not committed in those jobs — only in `release-commit`.

### `--force-with-lease` for the branch push

The parallel build jobs take several minutes. If someone pushes to the source branch during that window, `--force-with-lease` fails cleanly rather than silently overwriting their work.

### Atomic tag push

Both tags (`wrappers/go/vX.Y.Z` and `vX.Y.Z`) are pushed in a single `git push origin refs/tags/A refs/tags/B` call. If either tag already exists on the remote (re-run after partial failure), the push is a no-op for that tag without failing.

### `trap ... EXIT` for `useLocalBinaries` flag

`Package.swift` has a `let useLocalBinaries = false` flag that must never be committed as `true`. The Swift verification step flips it to `true`, runs `swift build` + `swift test`, then restores it via a `trap ... EXIT` handler — guaranteeing restoration even if the build or tests fail.

### `check_spm_xcframeworks.sh` before Swift build

The xcframework checksums in `Package.swift` are patched from the `build-apple` artifact. Running `check_spm_xcframeworks.sh` immediately after catches any extraction failure (e.g., empty checksum due to grep returning nothing) before `swift build` starts — giving a clearer error message than a Swift build failure.

## Breaking change: `release-go.yml` removed

`release-go.yml` no longer exists. It was tag-triggered (`on: push: tags: ['v*']`) and compiled Go static libs after the tag was created. That trigger no longer fires for anything — the unified `release.yml` workflow now handles Go lib compilation as part of the release run.

Any CI configuration, scripts, or documentation in downstream repositories that expected `release-go.yml` to run on `v*` tag pushes will see no effect. The downstream release workflows (`release-python.yml`, `release-java.yml`, `release-php.yml`, `release-swift.yml`, `release-wasm.yml`) are still triggered by the `v*` tag pushed by `release.yml` — only Go lib compilation moved.

## How to trigger a release

```bash
# Using the /release skill (recommended):
/release 0.19.0

# Using gh CLI directly:
gh workflow run release.yml \
  --field version=0.19.0 \
  --field branch=develop

# Monitor:
gh run list --workflow release.yml --limit 1
gh run watch <run-id>
```

Version format: bare `MAJOR.MINOR.PATCH` or `MAJOR.MINOR.PATCH-LABEL` (e.g. `0.19.0-dev.7`). No leading `v` — the workflow adds that when creating the tag.

## Re-run safety

The workflow is designed to be re-run after partial failure at any point in `release-commit`:

- `bumpver.sh` is idempotent (all sed replacements, version already set = same result)
- `git commit` is skipped with `git diff --cached --quiet` if the release commit already exists
- Tags are created with an existence check (`git tag -l ... | grep -q .`) to avoid duplicate-tag errors
- `git push --force-with-lease` succeeds when HEAD is already at or ahead of the remote tip
- Both tags pushed atomically; if already on the remote pointing to the same SHA, the push is a no-op

## Partial failure recovery (manual)

If the workflow log confirms the release commit was pushed but the tag push failed entirely:

```bash
git fetch origin develop
SHA=$(git rev-parse origin/develop)

git tag "wrappers/go/v0.19.0" "$SHA"
git push origin "refs/tags/wrappers/go/v0.19.0"

git tag "v0.19.0" -m "v0.19.0" "$SHA"
git push origin "refs/tags/v0.19.0"
```

## Workflow file location

`.github/workflows/release.yml`

Requires `github-actions[bot]` write access to the source branch. `develop` is pre-configured. For `main` or `release-*` branches, apply branch protection settings per the instructions in `.claude/skills/release/SKILL.md`.
