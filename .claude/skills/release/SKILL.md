---
name: release
description: Trigger a CI release for virgil-crypto-c. Runs the unified release.yml workflow_dispatch that builds Go static libs and Apple xcframeworks in CI, bumps the version, commits binaries, and creates both version tags. Use when the user says "release", "tag", or "cut a release".
compatibility: Requires gh CLI authenticated to the VirgilSecurity/virgil-crypto-c repo.
allowed-tools: Bash Read Edit
---

# Release

Trigger the unified CI release workflow and monitor it to completion. All releases — RCs and production — run from `develop`.

## Steps

1. **Ask for version** if not provided (e.g., `0.19.0`, `0.19.0-rc.2`, `0.19.0-dev.1`)

2. **Update ChangeLog.md** — production releases only (skip for any version containing `-`):

   a. Get today's date and list commits since the last release tag:
      ```bash
      date +%Y-%m-%d
      git log $(git describe --tags --abbrev=0 --match 'v[0-9]*' --exclude 'wrappers/*')..HEAD --oneline
      ```

   b. Read `ChangeLog.md` and check the top section:
      - If `## Unreleased` exists: rename it to `## Version X.Y.Z released YYYY-MM-DD` using the date from above. Review the existing bullets against the commit list — add any user-visible commits that are missing. Omit chore/CI/docs-only commits.
      - If no `## Unreleased` section: the entry is missing entirely. Draft one from the commit list, grouping into `### Breaking changes`, `### Changes`, and `### Bugfix` sections as appropriate. Omit chore/CI/docs-only commits.

   c. Show the drafted or updated entry to the user and ask for approval before writing. If the user requests changes, revise and show again until explicitly approved.

   d. After approval, write the changes and commit (replace `X.Y.Z` with the version from step 1):
      ```bash
      git add ChangeLog.md
      git commit -m "docs: update ChangeLog for vX.Y.Z [skip ci]"
      git push origin develop
      ```

3. **Trigger the workflow** (always from `develop` unless the user specifies otherwise):
   ```bash
   gh workflow run release.yml \
     --field version=X.Y.Z \
     --field branch=develop
   ```

4. **Find and monitor the run**:
   ```bash
   # Get the run ID (wait a moment for it to appear)
   gh run list --workflow release.yml --limit 1
   # Watch it to completion
   gh run watch <run-id>
   ```

5. **Verify on success**: confirm both tags were created:
   ```bash
   git fetch --tags
   git tag | grep "X.Y.Z"
   ```

## What the workflow does

| Step | Action |
|------|--------|
| `build-go` (parallel) | Cross-compiles Go static libs for 5 platforms using CI matrix |
| `build-apple` (parallel) | Builds Apple xcframeworks on `macos-26` |
| `release-commit` | Bumps version, merges all binaries, runs `swift build` + `swift test`, commits to `develop` with `--force-with-lease`, pushes `wrappers/go/vX.Y.Z` and `vX.Y.Z` tags |
| `create-gh-release` (production only) | Extracts ChangeLog entry and creates/updates the GitHub Release with title and description |
| `merge-to-main` (production only) | Opens and auto-merges a PR from `develop` to `main` after all publish jobs complete |

## What the release tag triggers

| Workflow | Action |
|----------|--------|
| `release-python.yml` | Wheels to TestPyPI (pre-release) or PyPI (production) |
| `release-java.yml` | Java/Android to Maven Central |
| `release-php.yml` | PHP packages uploaded to GitHub Release |
| `release-swift.yml` | XCFrameworks to GitHub Release |
| `release-wasm.yml` | WASM bundle to npm |

## Version format

- Production: `MAJOR.MINOR.PATCH` (e.g., `0.19.0`)
- Pre-release: `MAJOR.MINOR.PATCH-LABEL` (e.g., `0.19.0-rc.2`, `0.19.0-dev.1`)
- Python PEP 440 conversion is automatic (`0.19.0-dev.1` becomes `0.19.0.dev1`)

## Partial failure recovery

If the workflow pushed the release commit but one or both tag pushes failed:

```bash
git fetch origin develop
SHA=$(git rev-parse origin/develop)

# If Go module tag is missing:
git tag "wrappers/go/vX.Y.Z" "$SHA"
git push origin "refs/tags/wrappers/go/vX.Y.Z"

# If release tag is missing:
git tag "vX.Y.Z" -m "vX.Y.Z" "$SHA"
git push origin "refs/tags/vX.Y.Z"
```
