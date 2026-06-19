---
title: "New foundation symbol invisible to Go cgo: cmake install skips up-to-date committed pkg headers"
date: 2026-06-18
category: docs/solutions/build-errors
module: go-wrapper
problem_type: build_error
component: wrappers/go
severity: high
symptoms:
  - "Go build fails: could not determine kind of name for C.vscf_status_ERROR_SHAMIR_RECOVERY_FAILED"
  - "A new constant added to an existing header (vscf_status.h) is missing from the Go cgo include path"
  - "CI 'cmake --build build --target install' logs '-- Up-to-date: .../vscf_status.h' and does not overwrite it"
  - "Brand-new headers (e.g. vscf_shamir.h) ARE installed; only pre-existing changed headers go stale"
root_cause: cmake_install_skips_up_to_date_existing_headers_committed_pkg_goes_stale
resolution_type: code_fix
tags:
  - go-wrapper
  - cgo
  - cmake-install
  - prebuilt
  - headers
  - foundation
---

# New foundation symbol invisible to Go cgo: cmake install skips up-to-date committed pkg headers

## Problem
The Go wrapper compiles cgo against the **committed** headers under `wrappers/go/pkg/<target>/include` (`#cgo CFLAGS: -I${SRCDIR}/../pkg/<target>/include`). When a feature adds a new C symbol to an *existing* header — here, the new status constant `vscf_status_ERROR_SHAMIR_RECOVERY_FAILED` in `vscf_status.h` — CI's install step does not refresh that committed header, so cgo compiles against the stale copy that lacks the symbol.

## Symptoms
```
could not determine kind of name for C.vscf_status_ERROR_SHAMIR_RECOVERY_FAILED
```
Brand-new header *files* (e.g. `vscf_shamir.h`) install fine — only pre-existing files are stale. CI's `cmake --build build --target install` (go-config) logs the tell:
```
-- Up-to-date: .../include/virgil/crypto/foundation/vscf_status.h
```
CMake's `install(FILES)` treats the existing committed file as up-to-date and never overwrites it.

## What Didn't Work
- **Assuming `--target install` refreshes the committed headers.** It skips files it deems up-to-date (`-- Up-to-date: ...`), so an edited-in-place existing header is never republished into `pkg/`. (`pkg/` is `.gitignore`d locally but force-committed by the release workflow, so the tracked copies persist and are what cgo sees.)
- **Reverting all `pkg/` changes as "drift."** That also reverts the *legitimate* header updates the feature needs. Not every `pkg/` diff is noise — distinguish real header changes from per-target `*_platform.h` whitespace/line-ending drift.

## Solution
In the feature PR, force-commit the refreshed **platform-independent** foundation headers across all 5 Go pkg targets. They are byte-identical across targets, so build once and copy:
```bash
cmake -Cconfigs/go-config.cmake \
      -DCMAKE_INSTALL_PREFIX="$(pwd)/wrappers/go/pkg/darwin_arm64" \
      -DVIRGIL_POST_QUANTUM=ON -DENABLE_CLANGFORMAT=OFF -Bbuild-go -S.
cmake --build build-go --target install
# then copy the changed headers to darwin_amd64, linux_amd64, linux_arm64, windows_amd64
git add --force wrappers/go/pkg/*/include/.../vscf_status.h \
                wrappers/go/pkg/*/include/.../vscf_<class>.h \
                wrappers/go/pkg/*/include/.../private/vscf_<class>_defs.h \
                wrappers/go/pkg/*/include/.../vscf_foundation_public.h \
                wrappers/go/pkg/*/include/.../private/vscf_foundation_private.h
```
Do **not** commit per-target `*_platform.h` (drift) or `.a` libraries (produced by the release pipeline).

## Why This Works
cgo's include path points at the committed `pkg/<target>/include`, so the source of truth for the Go build is git, not what CI installs at build time. Republishing the changed, platform-independent headers makes the new symbol present in the committed tree. Build-once-copy keeps all 5 targets consistent without 5 cross-builds.

## Prevention
- When a foundation change adds/renames any C symbol in an *existing* header (enum constant, struct, function decl), assume the committed Go `pkg/<target>/include` headers are stale and refresh them in the same PR.
- Verify locally: rebuild the local target's libs and run `go build ./...` + `go test ./...` from `wrappers/go/` (per `CLAUDE.md`). The duplicate-library `ld` warning is benign.
- Never blanket-revert a `pkg/` diff — separate real header changes from `*_platform.h` drift.

## Related Issues
- `docs/solutions/build-errors/go-wrapper-linux-arm64-wrong-arch-prebuilt-2026-05-15.md` — sibling "committed `wrappers/go/pkg/` artifacts drift from a fresh build"; that doc's `Verify binary architecture` step catches wrong-arch *libs* but not stale *headers*.
- `docs/solutions/logic-errors/oid-enum-missing-from-codegen-model-2026-04-26.md` — sibling "new enum constant silently missing downstream" (different cause: codegen overwrite).
- Surfaced shipping `vscf_shamir` (PR #207).
