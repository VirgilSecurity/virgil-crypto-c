---
name: release
description: Create a versioned release for virgil-crypto-c. Bumps version, builds Apple frameworks, updates Go module, creates annotated tag, and pushes. Use when the user says "release", "tag", or "cut a release".
compatibility: Requires macOS with Xcode (for Apple frameworks), Java (for Maven version bump).
allowed-tools: Bash Read
---

# Release

Create a versioned release with separate commits for each step.

## Steps

1. **Ask the user for the version** if not provided (e.g., `0.18.0`, `0.18.0-rc1`, `0.18.0-dev.1`)

2. **Bump version** across all wrappers:
   ```bash
   ./scripts/bumpver.sh $VERSION
   git add -A
   git commit -m "Bump version to v$VERSION"
   ```

3. **Build Apple xcframeworks**:
   ```bash
   ./scripts/build_apple_frameworks.sh
   git add -A
   git commit -m "Build Apple xcframeworks for v$VERSION"
   ```

4. **Update Go module** version references in `wrappers/go/` if needed:
   ```bash
   git add -A
   git commit -m "Update Go module for v$VERSION"
   ```
   Skip this commit if there are no Go module changes.

5. **Create annotated tag**:
   ```bash
   git tag -a v$VERSION -m "v$VERSION"
   ```

6. **Push current branch and tags**:
   ```bash
   git push origin HEAD --tags
   ```

## Version format

- Production: `MAJOR.MINOR.PATCH` (e.g., `0.18.0`)
- Pre-release: `MAJOR.MINOR.PATCH-LABEL` (e.g., `0.18.0-rc1`, `0.18.0-dev.1`)
- Python PEP 440 conversion is automatic (`0.18.0-dev.1` becomes `0.18.0.dev1`)

## What the tag triggers

| Workflow | Action |
|----------|--------|
| `python-wheels-release.yml` | Wheels to TestPyPI (pre-release) or PyPI (production) |
| `publish-release.yml` | Java/Android to Maven Central |
| `release-apple-binaries.yml` | XCFrameworks to GitHub Release |
| `release-go.yml` | Go static libs cross-compile, commit, Go module tag |

## Edge cases

- If Java is not installed, `bumpver.sh` will fail on Maven version update. Warn the user and suggest manually updating `wrappers/java/` POM versions.
- If not on macOS, skip the Apple frameworks step and warn the user.
- Pre-release tags (containing `-`) route Python wheels to TestPyPI. Production tags route to PyPI.
