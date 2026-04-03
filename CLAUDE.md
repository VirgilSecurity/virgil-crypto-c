# VirgilCryptoC

C crypto library with language wrappers for Python, Java, Android, Swift, PHP, Go, WASM.

## Quick Reference

- **Release**: Use `/release` skill (see [SKILLS.md](SKILLS.md)). Asks for version, then runs: bumpver → build Apple frameworks → update Go module → tag → push. Each step is a separate commit.
- **Version bump only**: `./scripts/bumpver.sh <version>`

## Build

```bash
cmake -DCMAKE_BUILD_TYPE=Release -Bbuild -S.
cmake --build build -j$(nproc)
```

## Test

```bash
cd build && ctest --output-on-failure
```

## Key Directories

| Directory | Purpose |
|-----------|---------|
| `library/` | Core C crypto libraries (common, foundation, pythia, phe, ratchet) |
| `thirdparty/` | External deps (mbedtls, ed25519, relic, round5, falcon, nanopb) |
| `wrappers/` | Language wrappers (python, java, go, php, wasm, swift) |
| `configs/` | CMake config presets per language |
| `scripts/` | Build and release scripts |
| `binaries/` | Pre-built Apple xcframeworks (Git LFS) |

## Important Notes

- mbedTLS was upgraded to 3.6.5 LTS. RSA operations require real RNG (no fake random in tests).
- Pythia does not compile on Windows. Use `-DVIRGIL_LIB_PYTHIA=OFF` for Windows builds.
- Python wheels use cibuildwheel. CI workflow: `.github/workflows/python-wheels-build.yml`.
- Go wrapper uses pre-built static libs in `wrappers/go/pkg/<os>_<arch>/`. Use `-DVIRGIL_WRAP_GO=OFF` when building C libs for Go to avoid gosrc/ install conflicts.
- Apple frameworks: run `./scripts/build_apple_frameworks.sh` on macOS before tagging a release.
