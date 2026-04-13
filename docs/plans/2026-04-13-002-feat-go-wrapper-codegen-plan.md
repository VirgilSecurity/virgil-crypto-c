---
title: "feat: Port Go wrapper generation to Python codegen"
type: feat
status: active
date: 2026-04-13
---

# feat: Port Go wrapper generation to Python codegen

## Overview

Port Go wrapper file generation from the legacy GSL templates (`codegen/go.gsl`, `codegen/go_codegen.gsl`) to the new Python codegen pipeline. Go is the first wrapper language to be ported. Only foundation and phe projects currently have Go wrappers (`wrappers/go/foundation/` — 141 files, `wrappers/go/phe/` — 15 files).

## Problem Frame

The legacy GSL codegen generates Go wrapper files from a resolved XML IR (`go_project_foundation.xml` — 46K lines). The new Python codegen has a rich typed IR (`IRProject`) that already drives C and CMake generation. Go wrappers need to be generated from this same IR, completing another step toward retiring the GSL dependency.

Go wrapper files are **fully generated** — no handwritten code preservation needed (unlike C files). Each entity (class, interface, implementation, enum) produces one `.go` file. Infrastructure files (`context.go`, `helper.go`, `foundation_error.go`) are per-project support files.

## Requirements Trace

- R1. Generate one `.go` file per class, interface, implementation, and enum — matching legacy output
- R2. Generate per-project infrastructure files: `context.go`, `helper.go`, `{project}_error.go`
- R3. Reproduce exact CGo patterns: cCtx pointer wrapping, SetFinalizer, KeepAlive, Delete/delete split
- R4. Reproduce exact type mapping: C types → Go types, data marshalling, buffer management
- R5. Generate correct CGo header includes and link flags per project/platform
- R6. Output must compile and pass existing Go tests (`wrappers/go/foundation/*_test.go`)
- R7. Work for both foundation and phe projects via shared backend (no per-project branching)

## Scope Boundaries

- **Go wrappers only** — other languages (Java, Swift, Python, PHP, WASM) are separate tasks
- **foundation and phe only** — the only projects declaring `go` in their `wrappers=` attribute
- Do not touch `wrappers/go/crypto/` (high-level API layer, handwritten)
- Do not touch `wrappers/go/pkg/` (pre-built static libs)
- Do not touch `wrappers/go/go.mod`, `go.sum`
- Test files (`*_test.go`) are handwritten and must NOT be overwritten

### Deferred to Separate Tasks

- Other wrapper languages: separate per-language tasks
- Adding Go wrappers to projects that don't have them (pythia, ratchet, common)

## Context & Research

### Relevant Code and Patterns

- `tools/codegen/project_cmake_backend.py` — recently created, demonstrates the pattern: separate backend module consuming `IRProject`, returning `list[tuple[str, str]]` of (path, content) pairs
- `tools/codegen/project_c_backend.py::generate_umbrella_headers()` — iterates IR entities, produces project-wide files
- `codegen/go.gsl` (2929 lines) — legacy Go template with type mapping, name derivation, CGo patterns
- `codegen/go_codegen.gsl` (596 lines) — Go-specific emission functions
- `codegen/generated/foundation/go_project_foundation.xml` (46K lines) — resolved Go IR (reference for parity)
- `wrappers/go/foundation/` — 141 generated files showing exact output format

### Entity-to-File Mapping

| Entity kind | Go file | Go type | Example |
|---|---|---|---|
| Enum | `{snake_name}.go` | `type {PascalName} int` + `const` block | `alg_id.go` → `AlgId` |
| Interface | `{snake_name}.go` | `type {PascalName} interface` | `hash.go` → `Hash` |
| Class | `{snake_name}.go` | `type {PascalName} struct` + methods | `base64.go` → `Base64` |
| Implementation | `{snake_name}.go` | `type {PascalName} struct` + interface methods | `sha256.go` → `Sha256` |
| Error handler | `{project}_error.go` | `FoundationError` struct + status constants | `foundation_error.go` |
| Context | `context.go` | `context` interface with `Ctx()` | `context.go` |
| Helper | `helper.go` | Buffer/data marshalling utilities | `helper.go` |

### Institutional Learnings

- ADR 0004: C backend resolved output serves as input for wrapper backends — `IRProject` is the shared contract
- ADR 0003: No per-project branching — one shared Go backend for all projects
- Risk R4: Wrapper-specific behavior is under-specified, document as discovered
- Roadmap Phase 7: Go recommended as first wrapper target (resolved XML available for parity)
- Go wrapper files are fully generated — no preservation/merge logic needed
- Jinja2 is acceptable for wrappers per ADR 0001 and implementation notes

### Key CGo Patterns to Reproduce

**Struct lifecycle:**
```
NewXxx() → C.vscf_xxx_new() + SetFinalizer
newXxxWithCtx(ctx) → wraps existing C context + SetFinalizer (unexported)
newXxxCopy(ctx) → C.vscf_xxx_shallow_copy() + SetFinalizer (unexported)
Delete() → exported, calls delete()
delete() → C.vscf_xxx_delete(obj.cCtx), sets nil
```

**Method call pattern:**
```
func (obj *Xxx) Method(args...) (result, error) {
    // Marshal Go args → C types
    // Call C function
    // runtime.KeepAlive(obj)
    // Check status, return error
    // Marshal C result → Go types
}
```

**Type mapping (Go ← C):**
- `[]byte` ← `vsc_data_t` (via `helperWrapData`/`helperExtractData`)
- `[]byte` ← `vsc_buffer_t` (via `newBuffer`/`getData`)
- `uint` ← `size_t`
- `int` ← `int`, `int32_t`
- `bool` ← `bool`
- `*Xxx` ← `vscf_xxx_t *` (class/impl pointer)
- `Interface` ← `vscf_impl_t *` (interface pointer, needs cast)
- `error` ← `vscf_status_t` (via error handler)

## Key Technical Decisions

- **New module `tools/codegen/project_go_backend.py`:** Separate from C backend, consumes same `IRProject`. Follows `project_cmake_backend.py` pattern.
- **Jinja2 vs f-strings:** Use f-strings for now (consistent with C and CMake backends). Jinja2 can be introduced later if templates become unwieldy. The Go output is structured enough that f-strings work.
- **Full file generation, no merge:** Each `.go` file is written from scratch — no `@generated` block preservation needed.
- **Name derivation in Python:** Port the GSL name transformation rules (snake_case → PascalCase for Go types, camelCase for Go methods) as utility functions.
- **Integration point:** Wire into `common_bootstrap.py::main()` alongside CMake generation. New `--go` flag or automatic when project declares `go` in wrappers.

## Open Questions

### Resolved During Planning

- **Which projects need Go wrappers?** Only foundation and phe (from `wrappers=` attribute in project XMLs).
- **Are Go files fully generated?** Yes — no handwritten code to preserve. But test files (`*_test.go`) must not be overwritten.
- **How does the Go backend get cross-project type info?** Via `fallback_projects` on `IRProject`, same as C backend uses for cross-project includes.

### Deferred to Implementation

- **Exact Go name derivation rules for all edge cases:** The GSL `go.gsl` has ~2900 lines of name/type logic. Discover and document rules during implementation, especially for: compound names (`asn1_reader` → `Asn1Reader`), abbreviations, reserved Go keywords.
- **Interface casting pattern:** How `vscf_impl_t *` is cast to concrete Go interface types — needs reverse-engineering from generated code.
- **Error message text:** The exact error message strings in `foundation_error.go` — derive from `error_message_getter` in project XML.
- **Buffer length calculation:** How method-specific buffer sizes are derived for `newBuffer()` calls — the GSL uses XML metadata for this.

## Implementation Units

- [ ] **Unit 1: Create project_go_backend.py with name utilities and enum generator**

  **Goal:** Establish the Go backend module with naming utilities and the simplest entity generator (enums).

  **Requirements:** R1, R7

  **Dependencies:** None

  **Files:**
  - Create: `tools/codegen/project_go_backend.py`

  **Approach:**
  - Create Go name utilities: `go_type_name(entity_name)` (PascalCase), `go_method_name(method_name)` (PascalCase for exported), `go_arg_name(arg_name)` (camelCase)
  - Create `generate_go_enum(project_ir, enum) -> str` — produces one `.go` file content
  - Create `generate_go_files(project_ir, license_text) -> list[tuple[str, str]]` — orchestrator that iterates all entities
  - Study `wrappers/go/foundation/alg_id.go`, `asn1_tag.go`, `cipher_state.go` for exact format

  **Patterns to follow:**
  - `tools/codegen/project_cmake_backend.py` — module structure and `generate_*_files()` API
  - `wrappers/go/foundation/alg_id.go` — exact enum output format

  **Test scenarios:**
  - Happy path: generate `alg_id.go` for foundation, diff against legacy — type name, constant names, values match
  - Happy path: generate `status.go` for foundation — error enum with negative values renders correctly
  - Edge case: enum with value=0 first constant (sentinel pattern)

  **Verification:**
  - Generated enum `.go` files for foundation match legacy output

- [ ] **Unit 2: Generate interface wrappers**

  **Goal:** Generate Go interface type declarations from IR interfaces.

  **Requirements:** R1, R4

  **Dependencies:** Unit 1 (uses name utilities)

  **Files:**
  - Modify: `tools/codegen/project_go_backend.py`

  **Approach:**
  - Create `generate_go_interface(project_ir, iface) -> str`
  - Interface embeds `context` type
  - Each method becomes a Go interface method signature
  - Map C argument/return types to Go types
  - Include `Delete()` method
  - Study `wrappers/go/foundation/hash.go`, `random.go`, `cipher.go`

  **Patterns to follow:**
  - `wrappers/go/foundation/hash.go` — interface with value returns
  - `wrappers/go/foundation/random.go` — interface with error returns

  **Test scenarios:**
  - Happy path: generate `hash.go` — method signatures, embedded context, Delete method
  - Happy path: generate `random.go` — methods returning `([]byte, error)` tuple
  - Edge case: interface inheriting from another interface

  **Verification:**
  - Generated interface `.go` files match legacy output signatures

- [ ] **Unit 3: Generate infrastructure files (context.go, helper.go, error.go)**

  **Goal:** Generate the per-project infrastructure files that all other wrappers depend on.

  **Requirements:** R2, R5

  **Dependencies:** Unit 1

  **Files:**
  - Modify: `tools/codegen/project_go_backend.py`

  **Approach:**
  - `context.go` — minimal, just the `context` interface with `Ctx() uintptr`
  - `helper.go` — data marshalling (helperWrapData, helperExtractData, buffer type)
  - `{project}_error.go` — error type, status constants, status handler function
  - CGo header include derives from project umbrella header
  - Error constants derive from enum `status` + `error_message_getter`
  - Study `wrappers/go/foundation/context.go`, `helper.go`, `foundation_error.go`

  **Patterns to follow:**
  - `wrappers/go/foundation/foundation_error.go` — exact error constant format
  - `wrappers/go/foundation/helper.go` — buffer management pattern

  **Test scenarios:**
  - Happy path: foundation `context.go` matches legacy
  - Happy path: foundation `helper.go` matches legacy (same buffer implementation)
  - Happy path: `foundation_error.go` has all status constants with correct codes and messages
  - Happy path: phe `phe_error.go` uses `vsce_` prefix correctly

  **Verification:**
  - Infrastructure files compile as part of the Go package

- [ ] **Unit 4: Generate class/implementation struct wrappers**

  **Goal:** Generate the bulk of Go wrappers — struct types with CGo lifecycle and methods.

  **Requirements:** R1, R3, R4

  **Dependencies:** Units 1-3

  **Files:**
  - Modify: `tools/codegen/project_go_backend.py`

  **Approach:**
  - Create `generate_go_class(project_ir, cls) -> str` and `generate_go_implementation(project_ir, impl) -> str`
  - Struct holds `cCtx *C.{prefix}_{name}_t`
  - Lifecycle: `NewXxx()`, `newXxxWithCtx()`, `newXxxCopy()`, `Delete()`, `delete()`, `Ctx()`
  - Method rendering: marshal args, call C function, KeepAlive, check status, marshal returns
  - Type mapping for arguments and returns (class pointers, interfaces, data, buffers, enums, primitives)
  - Buffer output: derive capacity from method metadata (length getter or constant)
  - Dependencies: `use_*()`, `take_*()`, `release_*()` methods
  - Implementations additionally implement interface methods
  - Study `wrappers/go/foundation/sha256.go` (simple impl), `aes256_gcm.go` (impl with deps), `base64.go` (class)

  **Patterns to follow:**
  - `wrappers/go/foundation/sha256.go` — complete implementation pattern
  - `wrappers/go/foundation/base64.go` — static-method class pattern
  - `wrappers/go/foundation/recipient_cipher.go` — complex class with many methods

  **Test scenarios:**
  - Happy path: `sha256.go` — constructor, Delete, Hash method with buffer management
  - Happy path: `base64.go` — static methods (no cCtx), data in/out
  - Happy path: `aes256_gcm.go` — implementation with interface bindings + dependency setters
  - Edge case: method returning error only (no value return)
  - Edge case: method with multiple buffer outputs
  - Edge case: constructor with arguments (`NewXxxWith...()`)

  **Verification:**
  - Generated struct `.go` files compile
  - `go build ./wrappers/go/foundation/` succeeds
  - Existing tests in `wrappers/go/foundation/*_test.go` pass

- [ ] **Unit 5: Integrate into pipeline and validate parity**

  **Goal:** Wire Go generation into the codegen pipeline and validate against legacy output.

  **Requirements:** R6, R7

  **Dependencies:** Units 1-4

  **Files:**
  - Modify: `tools/codegen/common_bootstrap.py` — add Go wrapper generation
  - Modify: `tools/codegen/new_codegen.sh` — include Go wrappers in verify flow

  **Approach:**
  - In `main()`, after CMake generation, check if project has `go` in wrappers attribute
  - If so, call `generate_go_files()` and write to `wrappers/go/{project}/`
  - Skip `*_test.go` files — never overwrite handwritten tests
  - Verify: diff generated output against legacy, compile, run tests
  - The verify script should restore Go wrapper files after verification

  **Patterns to follow:**
  - CMake integration pattern in `common_bootstrap.py::main()`

  **Test scenarios:**
  - Integration: `--apply` generates Go files to correct paths for foundation
  - Integration: `--apply` generates Go files for phe
  - Integration: test files are NOT overwritten
  - Integration: `go build ./wrappers/go/foundation/` compiles
  - Integration: `go test ./wrappers/go/foundation/` passes
  - Edge case: project without Go wrappers (common, pythia, ratchet) skips generation

  **Verification:**
  - All foundation and phe Go files generated
  - `go build` and `go test` pass for both packages

## System-Wide Impact

- **Interaction graph:** Go wrappers depend on generated C headers (umbrella headers). C generation must complete before Go generation runs.
- **Error propagation:** Wrong type mapping → Go compile errors. Wrong CGo pattern → runtime crashes or memory leaks. Caught by compile + test.
- **State lifecycle risks:** None — Go files are fully regenerated. No merge, no stale state.
- **API surface parity:** Generated Go API must exactly match legacy for ABI compatibility with existing consumers.
- **Unchanged invariants:** Test files, `go.mod`, `go.sum`, `wrappers/go/crypto/` (high-level API), pre-built static libs — all untouched.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| GSL type mapping has edge cases not obvious from reading templates | Start with foundation (most diverse entity types), validate each entity kind before moving to phe |
| Buffer length calculation requires metadata not in current IR | May need to extend IR with buffer length hints from source models; check `go_project_foundation.xml` for the data |
| Interface casting (vscf_impl_t → concrete type) has complex patterns | Study multiple impl files, document the casting pattern before generalizing |
| Go name derivation rules have abbreviation special cases | Build a test set from all existing Go file names vs IR entity names |

## Sources & References

- Legacy GSL templates: `codegen/go.gsl` (2929 lines), `codegen/go_codegen.gsl` (596 lines)
- Resolved Go XML: `codegen/generated/foundation/go_project_foundation.xml` (46K lines)
- IR definitions: `tools/codegen/project_ir.py`
- Go backend pattern: `tools/codegen/project_cmake_backend.py`
- Legacy Go output: `wrappers/go/foundation/` (141 files), `wrappers/go/phe/` (15 files)
- ADRs: `docs/adr/0001-replace-gsl-codegen.md`, `docs/adr/0003-generalize-project-rooted-codegen-beyond-common.md`, `docs/adr/0004-universal-model-driven-codegen.md`
- Roadmap: `docs/codegen-migration/roadmap.md` (Phase 7)
