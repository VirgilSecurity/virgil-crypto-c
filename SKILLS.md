# Skills

## Version Bump & Release Tag

Bump the project version across all language wrappers, build Apple frameworks,
commit, create an annotated tag, and push.

### Usage

```bash
# 1. Bump version (updates VERSION, CMakeLists.txt, Python, Java, PHP, Swift, WASM, codegen XML)
./scripts/bumpver.sh <version>

# Examples:
./scripts/bumpver.sh 0.18.0           # production release
./scripts/bumpver.sh 0.18.0-rc1       # release candidate
./scripts/bumpver.sh 0.18.0-dev.1     # dev pre-release
./scripts/bumpver.sh 0.18.0-alpha1    # alpha
./scripts/bumpver.sh 0.18.0-beta1     # beta
```

### Version Format

- Base version: `MAJOR.MINOR.PATCH` (e.g., `0.17.3`)
- With label: `MAJOR.MINOR.PATCH-LABEL` (e.g., `0.17.3-dev.2`, `0.17.3-rc1`)
- Python PEP 440 conversion is automatic: `0.17.3-dev.2` becomes `0.17.3.dev2`

### Full Release Process

```bash
# Step 1: Bump version and commit
./scripts/bumpver.sh 0.17.3-dev.2
git add -A
git commit -m "Bump version to v0.17.3-dev.2"

# Step 2: Build Apple xcframeworks and commit
./scripts/build_apple_frameworks.sh
git add -A
git commit -m "Build Apple xcframeworks for v0.17.3-dev.2"

# Step 3: Create annotated tag and push
git tag -a v0.17.3-dev.2 -m "v0.17.3-dev.2"
git push origin develop --tags
```

### What the Tag Triggers (GitHub Actions)

| Workflow | What it does |
|----------|-------------|
| `python-wheels-release.yml` | Builds wheels, publishes to TestPyPI (pre-release) or PyPI (production) |
| `publish-release.yml` | Builds and publishes Java/Android to Maven Central |
| `release-apple-binaries.yml` | Creates GitHub Release with xcframework zips |
| `release-go.yml` | Cross-compiles Go static libs, commits, creates Go module tag |

### Notes

- `bumpver.sh` requires Java for Maven version update. If Java is not installed,
  manually update `wrappers/java/` POM versions.
- Apple frameworks build requires macOS with Xcode.
- The tag format must be `v<version>` (e.g., `v0.17.3-dev.2`).
- Pre-release tags (containing `-`) route Python wheels to TestPyPI.
- Production tags (no `-`) route Python wheels to PyPI.
