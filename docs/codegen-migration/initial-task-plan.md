# Initial Task Plan

This document breaks the first implementation stretch into concrete near-term tasks.

## Current assumptions

- original XML remains the source of truth
- legacy resolved XML is available for analysis/parity for all language paths except Python
- Python legacy resolved output currently has issues, so Python should not be the first wrapper migration target
- handwritten-code preservation is mandatory

## Sprint 1 — Analysis baseline

### T1. Snapshot legacy resolved XML
Goal: record the current legacy-resolved state before new implementation starts.

Outputs:
- inventory of available resolved XML artifacts
- note of Python gaps/issues
- selection of representative fixtures from `common` and `foundation`

### T2. Build generated-output inventory
Goal: understand what final outputs must be reproduced.

Outputs:
- generated file family list
- preserved/manual-merge file list
- chosen parity baseline set

### T3. Map original XML to effective resolved entities
Goal: understand transformation rules instead of depending on resolved XML as runtime input.

Outputs:
- mapping notes for project/module/class/interface/enum resolution
- preliminary IR field list

## Sprint 2 — Preservation and parser foundations

### T4. Implement preservation parser
Goal: safely preserve manual content around generated sections.

Outputs:
- parser for generated boundaries
- manual-content extraction
- handwritten-body extraction tests

### T5. Implement original XML parser
Goal: parse `main.xml` and model XML into source-model objects.

Outputs:
- parser for main config
- parser for project/model/wrapper XML files
- source-model tests

### T6. Define typed IR
Goal: lock the normalized shape consumed by emitters.

Outputs:
- IR schema/dataclasses
- naming/path conventions
- stable IDs for future incremental generation

## Sprint 3 — Resolver and first output

### T7. Implement first-pass resolver
Goal: resolve enough semantics to emit a small C surface.

Outputs:
- project resolution
- enum/module/class/interface references as needed for the first target
- comparison against legacy resolved fixtures

### T8. Emit one simple enum/header path
Goal: prove end-to-end new pipeline from original XML to final file.

Outputs:
- first emitter
- parity test against legacy output

### T9. Add deterministic regeneration test
Goal: ensure repeatable output.

Outputs:
- idempotence test for the first migrated surface

## Recommended first technical targets

1. project: `common`
2. then project: `foundation`
3. first wrapper target later: `go`

## Deferred for later

- Python wrapper migration
- full wrapper migration set
- default cutover of `codegen.sh`
- GSL removal
