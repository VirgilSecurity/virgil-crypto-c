---
title: "Building Apple xcframeworks: use scripts/build_apple_frameworks.sh, not hand-rolled cmake/xcodebuild"
date: 2026-07-01
category: docs/solutions/best-practices
module: build
problem_type: best_practice
component: build_script
severity: medium
symptoms:
  - "Unsure how to produce the VSCCommon/VSCFoundation/VSCRatchet xcframeworks for Swift/Apple"
  - "Hand-running cmake + xcodebuild -create-xcframework and getting the platform/slice set wrong"
  - "Package.swift binaryTarget checksum mismatch after rebuilding frameworks"
  - "binaries/*.xcframework.zip in Git LFS out of sync with the .sha256sum / SPM checksum"
  - "Swift verification (useLocalBinaries=true) needs local xcframeworks that don't exist yet"
root_cause: wrong_api
resolution_type: documentation
tags:
  - build
  - apple
  - xcframework
  - swift
  - spm
  - package-swift
  - git-lfs
  - release
  - cmake
---

# Building Apple xcframeworks: use scripts/build_apple_frameworks.sh

To build the Apple frameworks, run **`scripts/build_apple_frameworks.sh`**. Do
not hand-roll `cmake` + `xcodebuild -create-xcframework` — the script encodes the
exact platform matrix, CMake flags, toolchain, packaging, and checksum wiring
that the release path and `Package.swift` depend on. Getting any of those wrong
by hand produces xcframeworks that link but fail at integration or trip the SPM
checksum check.

```bash
# From the repo root (macOS host with Xcode + cmake):
./scripts/build_apple_frameworks.sh                 # outputs under build_apple/VSCFrameworks
./scripts/build_apple_frameworks.sh /path/to/outdir # optional custom destination
```

## What the script actually does

1. **Wipes and recreates `build_apple/`** and per-platform destination dirs.
2. **Builds the C libraries as shared frameworks for every Apple platform**, each
   with a device slice (`dev`) and a simulator slice (`sim`), via CMake using
   `cmake/apple.cmake` as the toolchain:
   - iOS (`IOS` + `IOS_SIM`)
   - tvOS (`TVOS` + `TVOS_SIM`)
   - watchOS (`WATCHOS` + `WATCHOS_SIM`)
   - macOS (`MACOS`)
   Fixed CMake flags include `-DCMAKE_BUILD_TYPE=Release`,
   `-DBUILD_SHARED_LIBS=YES`, `-DVIRGIL_LIB_RATCHET=YES`, `-DAPPLE_BITCODE=NO`,
   and the `VIRGIL_INSTALL_*=NO` set (frameworks only, no headers/cmake install).
   Parallelism is `-j$(sysctl -n hw.physicalcpu)`.
3. **Assembles three xcframeworks** with `xcodebuild -create-xcframework`, one per
   library, gathering all platform/slice `.framework`s found:
   `VSCCommon`, `VSCFoundation`, `VSCRatchet` → `VSCCrypto-XCFrameworks/`.
4. **Packages for release** (`PREPARE_RELEASE=YES`):
   - zips each `*.xcframework` (with `--symlinks`) into `binaries/` (Git LFS),
   - also zips an all-in-one `VSCCrypto.xcframework.zip` (bundling the LICENSE),
   - writes a `*.sha256sum` next to each zip, and
   - **rewrites the matching `let vsc<Name>Checksum = "..."` line in
     `Package.swift`** via `sed_replace`.

So one run refreshes: `binaries/*.xcframework.zip`, `binaries/*.sha256sum`, and
the SPM checksums in `Package.swift` — all consistent with each other.

## Where it fits

- **CI / release:** `.github/workflows/release.yml` runs
  `./scripts/build_apple_frameworks.sh` on a macOS runner. The tag-triggered
  release path builds frameworks in CI — you do **not** need to build them
  locally just to cut a release (see `CLAUDE.md` → Release / the `/release`
  skill).
- **Checksum verification:** `scripts/check_spm_xcframeworks.sh` (used by
  `build-macos.yml` and `release-swift.yml`) confirms `Package.swift` checksums
  match the committed `binaries/` zips. If it fails, the frameworks and the SPM
  manifest drifted — rebuild with this script rather than editing the checksum
  by hand.
- **Swift source verification (`useLocalBinaries` dance):** `Package.swift`
  defaults to `useLocalBinaries = false` (remote release URLs). CLAUDE.md's
  policy for verifying `wrappers/swift/**/*.swift` changes flips it to `true`,
  builds/tests against local `binaries/*.xcframework.zip`, then flips it back.
  Those local zips are exactly what this script produces — if they are stale or
  missing, run `build_apple_frameworks.sh` first.

## Gotchas / rules

- **macOS + Xcode + cmake required.** The script `show_error`s if `cmake` is
  absent and relies on `xcodebuild`; it cannot run on Linux CI. It sources
  `scripts/helpers.sh` (`show_info`/`show_error`/`abspath`/`sed_replace`) — run
  it from within the repo so those resolve.
- **It is destructive:** `rm -fr build_apple` and per-xcframework `rm -fr` on the
  output. Don't point the destination at anything you care about.
- **It mutates tracked files:** `Package.swift` (checksums) and `binaries/`
  (LFS zips + sha256sum). Expect a diff there after running; commit those
  together so SPM stays consistent. Never edit a `vsc<Name>Checksum` value by
  hand — regenerate it.
- **Don't reinvent the platform/slice list or CMake flags.** If a new library or
  platform is needed, extend this script (and its `make_xcarchive` calls), not an
  ad-hoc build.
- **Ratchet is included** (`-DVIRGIL_LIB_RATCHET=YES`) and gets its own
  `VSCRatchet.xcframework`; keep the three `make_xcarchive` calls in sync with
  the libraries you actually ship.
