# ce:review Run Summary

**Run ID:** 20260506-082850-aeea7020  
**Mode:** autofix  
**Branch:** refactor/remove-pythia-relic  
**Base:** 2a7065962b085beaa4d2b4de05650f9b0708fcbe  
**HEAD at review start:** cc88461050731f4231e6da42df2d69739595d4ff  
**HEAD after fixes:** 986bd2769  
**Plan:** docs/plans/2026-05-06-001-refactor-remove-pythia-relic-libraries-plan.md  
**Reviewers:** correctness, testing, maintainability, project-standards, agent-native, learnings-researcher, adversarial (7 of 7 returned)  
**Scope:** 141 files changed, 435 insertions, 12,583 deletions

---

## Findings Applied (safe_auto)

| Sev | Finding | File | Fix |
|-----|---------|------|-----|
| P0 | Package.swift still declared full VirgilCryptoPythia SPM product/targets pointing to deleted source directories — any `swift package resolve` would hard-fail | Package.swift:34-114 | Removed vscPythiaBinaryTarget closure, VirgilCryptoPythia product, and both SPM targets |
| P1 | VSCP_MULTI_THREADING orphan CMake variable set for deleted Pythia library | CMakeLists.txt:232 | Removed the dead CACHE FORCE line |
| P2 | Orphaned LFS path rules in .gitattributes for VSCPythia files | .gitattributes:4,9 | Removed both dead LFS routing entries |
| P2 | mbedtls/config.h.in comment attributing CTR_DRBG/ENTROPY to deleted vsc::pythia | thirdparty/mbedtls/config.h.in:94 | Changed to vsc::foundation |
| P2 | ChangeLog.md Unreleased section had false claims about Pythia availability | ChangeLog.md:7,11 | Rewrote to accurately describe full removal |
| P2 | README.md build examples used deprecated -H. instead of required -S. | README.md:75,85 | Changed to -S. per CLAUDE.md standard |
| P2 | new_codegen.sh header comment listed only common/foundation as valid projects | new_codegen.sh:9 | Updated to list all four valid projects and added phe/ratchet examples |

**Commit:** 986bd2769 — `fix(review): remove Package.swift Pythia SPM targets and clean up stale references`

---

## Residual Findings (not auto-applied)

| Sev | Finding | File | Owner | Notes |
|-----|---------|------|-------|-------|
| P2 | R8 invariant (--project pythia rejected) has no automated test | tools/codegen/ | downstream-resolver | Argparse enforces it at runtime; add a negative test to prevent regression |
| P2 | build_apple_frameworks.sh sha256sum loop uses `find binaries/ -name "*.xcframework.zip"` with no allowlist; if VSCPythia zip reappears, it silently patches a stale Package.swift variable | scripts/build_apple_frameworks.sh:256 | downstream-resolver | Low risk now that Package.swift is fixed; consider switching to an explicit allowlist |
| P3 | CLAUDE.md codegen section does not enumerate valid --project values | CLAUDE.md | downstream-resolver | Minor discoverability gap for agents |
| P3 | Go backend codegen test has no file-count test for PHE/Ratchet | tools/codegen/test_go_backend.py | downstream-resolver | Pre-existing gap, not introduced by this PR |

---

## Advisory Outputs

- **Stale build caches**: Users with existing `build/CMakeCache.txt` containing `VIRGIL_LIB_PYTHIA=ON` should delete their build directory after pulling this change. CMake silently ignores stale cache entries for removed options.
- **Go pre-built artifacts**: `wrappers/go/pkg/` is gitignored. Local Pythia static libs (`libvsc_pythia.a`, `librelic_s.a`) were removed from the filesystem but existing clones won't see them removed by git pull. Developers should manually clean `wrappers/go/pkg/*/lib/libvsc_pythia.a` and `librelic_s.a` if they existed locally.
- **LFS cleanup** (optional): Run `git lfs prune` to release local LFS cache space after removing the VSCPythia.xcframework.zip pointer.

---

## Plan Requirements Coverage

| Req | Status |
|-----|--------|
| R1 — Pythia C source/headers/targets/tests deleted | ✅ Complete |
| R2 — Relic thirdparty deleted | ✅ Complete |
| R3 — All 7 language wrapper Pythia modules deleted | ✅ Complete |
| R4 — Codegen system (models, backends, tests) clean | ✅ Complete |
| R5 — CI/CD workflows and release scripts clean | ✅ Complete |
| R6 — Pre-built binary artifacts deleted | ✅ Complete (Package.swift P0 fixed in this review) |
| R7 — Project builds successfully after removal | ✅ CMake configure verified |
| R8 — `--project pythia` fails with clear error | ✅ Verified at CLI; no automated test (P2 residual) |
