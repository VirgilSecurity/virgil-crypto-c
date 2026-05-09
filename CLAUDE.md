# VirgilCryptoC

C crypto library with language wrappers for Python, Java, Android, Swift, PHP, Go, WASM.

## Quick Reference

- **Release**: Use `/release` skill. Asks for version, then runs: bumpver → build Apple frameworks → update Go module → tag → push. Each step is a separate commit.
- **Version bump only**: Use `/bumpver` skill or `./scripts/bumpver.sh <version>`
- Skills are in `.claude/skills/`

## Codegen

Regenerate all language wrappers from the IR models:

```bash
python3 -m tools.codegen.common_bootstrap --project all --apply
```

To regenerate a single project (e.g. `foundation`):

```bash
python3 -m tools.codegen.common_bootstrap --project foundation --apply
```

Output goes to the repo root (same paths as the checked-in files). License text is read from the repo root `LICENSE` file automatically.

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

| Directory         | Purpose                                                                                                                                        |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `library/`        | Core C crypto libraries (common, foundation, phe, ratchet)                                                                                     |
| `thirdparty/`     | External deps (mbedtls, ed25519, falcon, mlkem-native, mldsa-native, nanopb)                                                                    |
| `wrappers/`       | Language wrappers (python, java, go, php, wasm, swift)                                                                                         |
| `configs/`        | CMake config presets per language                                                                                                              |
| `scripts/`        | Build and release scripts                                                                                                                      |
| `binaries/`       | Pre-built Apple xcframeworks (Git LFS)                                                                                                         |
| `docs/solutions/` | Documented solutions (bugs, best practices, workflow patterns), organized by category with YAML frontmatter (`module`, `tags`, `problem_type`) |

## Important Notes

- mbedTLS was upgraded to 3.6.5 LTS. RSA operations require real RNG (no fake random in tests).
- Python wheels use cibuildwheel. CI workflow: `.github/workflows/build-python.yml`.
- Go wrapper uses pre-built static libs in `wrappers/go/pkg/<os>_<arch>/`. Use `-DVIRGIL_WRAP_GO=OFF` when building C libs for Go to avoid gosrc/ install conflicts.
- Apple frameworks: run `./scripts/build_apple_frameworks.sh` on macOS before tagging a release.
- Ask for approval to push changes.

## Forbidden

- **Do not push without a local build and test check**: Before any `git push`, run the C build (`cmake --build build -j$(nproc)`) and test suite (`cd build && ctest --output-on-failure`). For codegen changes, also run `python3 -m pytest tools/codegen/ -q`. Push only after confirming no regressions.
- **Verify Swift build and tests after each Apple frameworks build**: After running `./scripts/build_apple_frameworks.sh`, set `useLocalBinaries = true` in `Package.swift`, run `swift build` and `swift test`, then restore `useLocalBinaries = false`. Fix any Swift errors before proceeding to tag and push.
- **CMake in-source builds**: Always pass `-B<builddir> -S.` to keep build artifacts out of the
  source tree. Never run `cmake .` or `cmake <srcdir>` without a `-B` flag. Build dirs to use:
  - Default C: `build/`
  - WASM: `build-wasm/` (via `emcmake cmake ... -Bbuild-wasm -S.`)
  - Never commit or gitignore CMake artifacts (`CMakeFiles/`, `cmake_install.cmake`,
    `CTestTestfile.cmake`, `fake.c`, `CMakeCache.txt`) — their presence in `wrappers/` or
    the repo root means an in-source build happened and must be cleaned up with
    `git rm -r --cached <dirs>`.
  - Do not add yourself as co-author.
  - Do not create feature PRs to `main` branch.
