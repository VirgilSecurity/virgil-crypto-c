---
name: bumpver
description: Bump the project version across all language wrappers (Python, Java, PHP, Swift, Go, WASM, C headers). Use when the user says "bump version", "update version", or "set version".
allowed-tools: Bash Read
---

# Version Bump

Bump the version across all project files without committing.

## Usage

Ask the user for the version string if not provided as an argument.

```bash
./scripts/bumpver.sh $VERSION
```

## What it updates

- `VERSION` file
- `CMakeLists.txt` (project version + label)
- `codegen/main.xml` and `codegen/models/project_*.xml`
- C library headers (`library/*/include/*_library.h`)
- Python `wrappers/python/virgil_crypto_lib/__init__.py`
- Java POM via Maven wrapper (requires Java)
- Android `wrappers/java/android/build.gradle`
- PHP extension source files (`wrappers/php/`)
- WASM `wrappers/wasm/package.json`
- Swift `Package.swift`
- Carthage spec files

## Version format

- Production: `MAJOR.MINOR.PATCH` (e.g., `0.18.0`)
- Pre-release: `MAJOR.MINOR.PATCH-LABEL` (e.g., `0.18.0-rc1`, `0.18.0-dev.1`)
- Python PEP 440 conversion is automatic (`0.18.0-dev.1` becomes `0.18.0.dev1`)

## After running

Show `git diff --stat` to the user so they can review what changed. Do NOT commit automatically.
