---
title: "linux_arm64 prebuilt .a files in rc.8 contain x86-64 ELF objects"
date: 2026-05-15
category: docs/solutions/build-errors
module: go-wrapper
problem_type: packaging_bug
component: wrappers/go
severity: high
symptoms:
  - "Go wrapper build fails or produces incorrect binaries when targeting linux/arm64"
  - "docker build on linux/arm64 host picks up x86-64 ELF objects from wrappers/go/pkg/linux_arm64/lib/"
  - "runtime crashes or 'exec format error' when loading the Go shared library on arm64 Linux"
  - "file wrappers/go/pkg/linux_arm64/lib/libvirgil_crypto_foundation.a shows 'ELF 64-bit LSB ... x86-64' instead of 'aarch64'"
root_cause: packaging_bug_rc8_linux_arm64_contains_amd64_objects
resolution_type: workaround_and_build_fix
tags:
  - go-wrapper
  - prebuilt
  - linux-arm64
  - docker
  - cross-compilation
  - elf
  - packaging
---

# linux_arm64 prebuilt .a files in rc.8 contain x86-64 ELF objects

## Root cause

The `wrappers/go/pkg/linux_arm64/lib/` static libraries shipped in rc.8 are actually x86-64 ELF objects — a packaging bug in that release. The arm64 build artifacts were not correctly collected and a previous linux_amd64 set was bundled instead.

Verify with:

```bash
file wrappers/go/pkg/linux_arm64/lib/libvirgil_crypto_foundation.a
# Should print: ELF 64-bit LSB relocatable, ARM aarch64
# If it prints: ELF 64-bit LSB relocatable, x86-64 — this is the bug
```

## Fix (rc.14+)

`build-go.yml` now has a **Verify binary architecture** step that runs after the CMake build and before the artifact upload. It reads the ELF architecture from `libvsc_foundation.a` via `objdump -f` and fails the job if it doesn't match the expected value:

```yaml
- name: Verify binary architecture
  if: matrix.expected_elf_arch != ''
  shell: bash
  run: |
    lib="wrappers/go/pkg/${{ matrix.target }}/lib/libvsc_foundation.a"
    actual=$(objdump -f "$lib" 2>&1 | awk '/^architecture:/{print $2; exit}')
    expected="${{ matrix.expected_elf_arch }}"
    if [ "$actual" != "$expected" ]; then
      echo "ERROR: $lib has ELF architecture '$actual', expected '$expected'"
      exit 1
    fi
```

`expected_elf_arch` is declared in the matrix: `x86_64` for `linux_amd64`, `aarch64` for `linux_arm64`. A cross-compilation misconfiguration will now fail the build immediately rather than silently shipping wrong-arch objects.

## Workaround (if pinned to rc.8 and cannot upgrade)

Add `--platform linux/amd64` to every `docker build` invocation so the build environment matches the x86-64 objects that were accidentally bundled:

```dockerfile
FROM --platform=linux/amd64 golang:1.22-bookworm AS builder
```

```bash
docker build --platform linux/amd64 -t myapp .
```

The resulting image will run under emulation on arm64 hosts (e.g. Apple Silicon), not natively. Upgrade to rc.14+ for a proper fix.
