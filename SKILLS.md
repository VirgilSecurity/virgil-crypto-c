# Skills

## /release — Create a versioned release

Interactive release workflow. Ask the user for the version, then execute each
step with a separate commit.

### Steps

1. **Ask user for version** (e.g., `0.18.0`, `0.18.0-rc1`, `0.18.0-dev.1`)
2. **Bump version** — run `./scripts/bumpver.sh <version>`, commit:
   ```
   Bump version to v<version>
   ```
3. **Build Apple xcframeworks** — run `./scripts/build_apple_frameworks.sh`, commit:
   ```
   Build Apple xcframeworks for v<version>
   ```
4. **Update Go module tag** — update `wrappers/go/` version references if needed, commit:
   ```
   Update Go module for v<version>
   ```
5. **Create annotated tag**:
   ```bash
   git tag -a v<version> -m "v<version>"
   ```
6. **Push current branch + tags**:
   ```bash
   git push origin <current-branch> --tags
   ```

### Version Format

- Production: `MAJOR.MINOR.PATCH` (e.g., `0.18.0`)
- Pre-release: `MAJOR.MINOR.PATCH-LABEL` (e.g., `0.18.0-rc1`, `0.18.0-dev.1`)
- Python PEP 440 conversion is automatic (`0.18.0-dev.1` → `0.18.0.dev1`)

### What the Tag Triggers (GitHub Actions)

| Workflow | What it does |
|----------|-------------|
| `python-wheels-release.yml` | Wheels → TestPyPI (pre-release) or PyPI (production) |
| `publish-release.yml` | Java/Android → Maven Central |
| `release-apple-binaries.yml` | XCFrameworks → GitHub Release |
| `release-go.yml` | Go static libs cross-compile → commit + Go module tag |

### Notes

- `bumpver.sh` requires Java for Maven version update. If Java is unavailable,
  manually update `wrappers/java/` POM versions.
- Apple frameworks build requires macOS with Xcode.
- Tag format: `v<version>` (e.g., `v0.18.0-rc1`).
- Pre-release tags (containing `-`) route Python wheels to TestPyPI.
- Production tags (no `-`) route Python wheels to PyPI.

---

## Version Bump (standalone)

If you only need to bump the version without the full release flow:

```bash
./scripts/bumpver.sh <version>
```

This updates: VERSION, CMakeLists.txt, Python `__init__.py`, Java POM,
PHP extensions, Swift Package.swift, WASM package.json, codegen XML files,
C library headers, Carthage specs, Android build.gradle.
