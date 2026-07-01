# VirgilCryptoC

C crypto library with language wrappers for Python, Java, Android, Swift, PHP, Go, WASM.

## Quick Reference

- **Release**: Use `/release` skill. Triggers `release.yml` workflow_dispatch in CI: builds Go static libs + Apple xcframeworks, bumps version, commits binaries, tags. No local build required.
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

### Adding a new class/algorithm — the skeleton is generated, not hand-written

Do **not** hand-author the C class files. Every new foundation class/algorithm (cipher, hash, MAC, etc.)
is declared in the IR models under `codegen/models/project_foundation/` and the **entire skeleton** is
produced by `tools/codegen`:

- **public header** `library/foundation/include/.../vscf_<name>.h`
- **generated defs** `vscf_<name>_defs.{c,h}` (struct layout, constants, vtable)
- **internal** `vscf_<name>_internal.{c,h}`
- **implementation stub** `library/foundation/src/vscf_<name>.c` with empty method bodies
- **factory/registry wiring** (`vscf_alg_factory.c`, `vscf_alg_id.h`, etc.) and **all language wrappers**

Workflow to add one:

1. Declare the class in `codegen/models/project_foundation/` — typically an `<implementation>` block in
   `implementor_<backend>.xml` (e.g. `implementor_mbedtls.xml`), an entry in `enum_alg_id.xml`, and any
   needed interface references (`interface_cipher_auth.xml`, etc.).
2. Run `python3 -m tools.codegen.common_bootstrap --project foundation --apply` to generate the skeleton.
3. **Fill only the algorithm logic** into the generated `vscf_<name>.c` (and `_internal.c`) method bodies.
   The headers/defs/factory wiring are generated — re-running codegen regenerates them, so never edit
   generated regions by hand.

Reference patterns in-repo: `vscf_aes256_gcm*` (AEAD / `cipher_auth`), `vscf_hmac*` (stateful keyed MAC),
`codegen/models/project_foundation/class_shamir.xml` (a recently added class with a dependency). Gotchas
for new classes (MSVC has no VLAs; `context="public"` + const-length helper methods) are documented in
`docs/solutions/best-practices/codegen-class-context-and-const-length-methods-2026-06-18.md`.

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
- Ask for approval to push changes.

## Forbidden

- **Every bug fix must include a regression test**: When fixing a bug, add a test that reproduces the exact failure scenario (the test must fail before the fix and pass after). The test must cover the specific combination of inputs that triggered the bug, not just the general happy path. Commit the test in the same commit as the fix.
- **Append `[skip ci]` to docs-only commit messages**: When a commit touches only documentation files (`.md`, `docs/`, `CLAUDE.md`, `README.md`, `ChangeLog.md`, `*.txt`), append `[skip ci]` at the end of the commit message to avoid triggering CI builds unnecessarily.
- **Do not push without a local build and test check**: Before any `git push`, run the C build (`cmake --build build -j$(nproc)`) and test suite (`cd build && ctest --output-on-failure`). For codegen changes, also run `python3 -m pytest tools/codegen/ -q`. Push only after confirming no regressions. (This applies to direct pushes from Claude Code sessions; CI-driven releases via `release.yml` are exempt.)
- **Verify Swift build and tests before pushing if `wrappers/swift/` was modified**: If any unpushed commits touch `wrappers/swift/**/*.swift`, run the Swift package verification before pushing: (1) `sed -i '' 's/let useLocalBinaries = false/let useLocalBinaries = true/' Package.swift`, (2) `swift build`, (3) `swift test`, (4) `sed -i '' 's/let useLocalBinaries = true/let useLocalBinaries = false/' Package.swift`. Check with: `git diff origin/<branch>..HEAD -- 'wrappers/swift/**/*.swift'`. Fix any errors before pushing. Release-time xcframework correctness is verified by CI in `release.yml`.
- **Verify Go build and tests after any Go wrapper changes**: After modifying Go wrapper files or pre-built static libs in `wrappers/go/pkg/`, run `go build ./...` and `go test ./...` from `wrappers/go/`. Fix any errors before pushing. The duplicate-library linker warning from `ld` is benign and can be ignored.
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
