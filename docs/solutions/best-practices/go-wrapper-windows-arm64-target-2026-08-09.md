---
title: Windows ARM64 Go target — MSYS2 CLANGARM64 toolchain, PE arch verification, and the nanopb generator trap
date: 2026-08-09
category: docs/solutions/best-practices
module: go-wrapper
problem_type: best_practice
component: ci
severity: high
applies_when:
  - Adding or debugging the windows_arm64 Go build target
  - Adding any MSYS2-based job to CI
  - Adding a new architecture target that needs binary verification
  - Diagnosing "nanopb generator 'protoc-gen-nanopb' not found" on Windows
resolution_type: architectural_decision
tags:
  - go
  - cgo
  - windows
  - arm64
  - msys2
  - mingw
  - ci
  - codegen
  - post-quantum
---

# Windows ARM64 Go target

Everything below was observed on a Windows 11 ARM64 VM building
`feat/ci-go-windows-arm64`, not inferred.

## The preinstalled `gcc` on `windows-11-arm` cannot be used

The runner image ships `gcc` from niXman mingw-builds, which publishes
**x86_64/i686 only**. On an ARM64 host it runs under emulation and cannot emit
aarch64 objects. Upstream MinGW-w64 GCC has no aarch64-windows target at all.

Clang is currently the only compiler producing GNU-ABI aarch64 Windows objects.
MSYS2 **CLANGARM64** provides it: `clang -dumpmachine` reports
`aarch64-w64-windows-gnu`, which is mingw-w64's GNU ABI — `lib<name>.a`
archives linked with `-l<name>`, exactly what the committed cgo directives
expect. MSVC/clang-cl is not usable: cgo requires a GCC-compatible driver.

**CLANGARM64 provides no `gcc` shim.** cgo defaults `CC` to `gcc`, and with
`path-type: inherit` the emulated x86_64 gcc is reachable on PATH. Exporting
`CC=clang` is therefore load-bearing, not defensive — without it cgo silently
selects the wrong-architecture compiler. Because step environments are not
inherited in GitHub Actions, the export must go through `$GITHUB_ENV`.

## The nanopb generator trap (cost the most time)

Symptom: configure dies with
`nanopb generator 'protoc-gen-nanopb' not found`.

Three compounding causes, none obvious from the error:

1. MSYS2 prepends its own bin dirs, so `python3` inside the msys2 shell is
   MSYS2's — **not** the interpreter `actions/setup-python` installed.
2. MSYS2's `clangarm64` Python ships **no pip**, so
   `pip3 install -r requirements.txt` cannot run.
3. `CMakeLists.txt` runs that install through `execute_process` with no
   `RESULT_VARIABLE`, so the failure is **silent** and only surfaces later as
   the missing generator.

Installing pip is not enough: `grpcio-tools` has no mingw aarch64 wheel, tries
to build from source, fails, and aborts the whole pip transaction before
`nanopb` is installed. The Go target does not need `grpcio-tools` — install
`protobuf` and `nanopb` alone.

CMake finds the generator through **PATH**, not through its
`$VIRTUAL_ENV` hints: those hints are POSIX paths that the native
`cmake.exe` cannot resolve. Putting the venv's `bin` on PATH in the build step
is what actually makes configure succeed.

Related but distinct: `thirdparty/nanopb/CMakeLists.txt` keys the protoc
download on `CMAKE_HOST_SYSTEM_PROCESSOR` and fetches `protoc-28.3-win64.zip`.
Protobuf publishes no win-arm64 protoc; the x64 binary runs under emulation,
which is correct for a host-side code generator. This is **not** a problem —
rule it out early rather than chasing it.

## The post-quantum AArch64 assembly works under COFF

`mlkem-native` and `mldsa-native` guard their `.S` sources behind `if(MSVC)`
only, so a Clang/COFF build attempts the AArch64 assembly. It **succeeds**:
both `mlkem_native.S` and `mldsa_native_asm.S` compiled, zero `NO_ASM`
fallbacks were taken, and `go test ./...` passed with the crypto package
exercising ML-KEM/ML-DSA for 23s — functional validation, not just compilation.

No `if(MSVC)` guard widening is required for Windows-on-ARM64. If a future
toolchain bump breaks this, the fallback is `MLK_CONFIG_NO_ASM` /
`MLD_CONFIG_NO_ASM`, but note the upstream comment: those flags substitute C
fallbacks for the assembly's **value barriers**, a side-channel construct. That
trades side-channel assurance, so gate any such fallback on known-answer tests
rather than build success alone.

The wider signal: the same AArch64 assembly already builds for `linux_arm64`,
`darwin_arm64`, and the `linux-aarch64` Python wheels. Only object format, ABI
variant, and assembler differ on Windows — treat failure as the exception.

## PE architecture verification

`readelf` is ELF-only, so both Windows targets shipped unverified until now.
Use `llvm-readobj --file-headers`, which reads `.a` archive members directly
and prints the full constant (`IMAGE_FILE_MACHINE_ARM64 (0xAA64)`). Match the
**full constant** — it never prints a bare `ARM64`, so the ELF step's
exact-equality comparison cannot be copied verbatim.

Three failure modes worth designing against, all found by review and confirmed
locally:

- GitHub runs bash with `-eo pipefail`, so `actual=$(llvm-readobj ... | ...)`
  aborts the step with **no diagnostic** when the tool fails. Capture the exit
  status explicitly.
- Folding stderr into the parsed stream (`2>&1`) lets a **partial read** look
  like a clean single-architecture result.
- A hand-maintained library list drifts. The install prefix ships 13 archives;
  a five-entry list left 8 unchecked, including `libmldsa65.a`. Glob the
  install directory instead.

Aggregate across members with `sort -u`; stopping at the first match lets a
mixed-architecture archive pass. The pre-existing ELF step had exactly that
defect and was brought to parity.

## Verifying without a runner

`prlctl exec "<vm>" --current-user 'C:\msys64\usr\bin\bash.exe' <script>` drives
a Parallels Windows ARM64 VM from macOS. Pass a **script file** through a shared
folder rather than an inline command string — quoting through
zsh -> prlctl -> bash mangles backslashes and silently truncates commands.

Two gotchas: `git clone` from a shared folder needs
`git config --global --add safe.directory`, and any MSI install (e.g. `winget
install GoLang.Go`) blocks on an invisible UAC prompt under a non-elevated
`prlctl exec` — use the Go **zip** archive, or approve the prompt in the VM UI.
