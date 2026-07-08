---
title: "feat: Add published C++20 SDK wrapper (codegen backend + CMake package)"
type: feat
status: active
date: 2026-07-07
origin: docs/brainstorms/cpp-wrapper-requirements.md
---

# feat: Add published C++20 SDK wrapper

## Overview

Add a first-class, published **C++20 SDK** wrapper for virgil-crypto-c with full API parity to the existing wrappers (foundation, ratchet, phe). Like every other wrapper it is **codegen-generated** — via a new `tools/codegen/project_cpp_backend.py` — from the IR models under `codegen/models/`, so it stays a single source of truth and regenerates without drift. The public API is idiomatic C++20 per the C++ Core Guidelines (RAII, value/move semantics, `std::span`), reports failures via `expected<T, Error>` (so it builds under `-fno-exceptions`), and is distributed as a CMake package with per-library targets (`virgil::foundation-cpp`, `virgil::ratchet-cpp`, `virgil::phe-cpp`) consumable via both `find_package` and `FetchContent`, with extra dependencies pulled through FetchContent.

## Problem Frame

C++ consumers today must call the raw C API (`vscf_*_new`/`_destroy`, `vsc_data`/`vsc_buffer`, status-code checks) — error-prone and un-idiomatic. This adds a maintained C++ binding so C++ developers get RAII lifetimes, `std::span`/`std::vector` data types, and `expected`-based errors, on par with the Java/Go/Swift wrappers. (See origin: `docs/brainstorms/cpp-wrapper-requirements.md`.)

## Requirements Trace

- R1. Idiomatic C++20 API following the Core Guidelines: RAII, value/move semantics, `std::span`, namespaces (`virgil::crypto::foundation`, `::ratchet`, `::phe`).
- R2. Full API parity: every foundation/ratchet/phe class, enum, and interface emitted as an idiomatic C++ equivalent.
- R3. Failures reported via `expected<T, Error>` (not exceptions); `Error` maps the C status enums; builds under `-fno-exceptions`.
- R4. `vsc_data` → `std::span<const uint8_t>` (input); `vsc_buffer` / owned outputs → `std::vector<uint8_t>` / `std::string`; `common` absorbed into the mapping layer, not wrapped.
- R5. Produced by a new codegen backend `tools/codegen/project_cpp_backend.py` from the IR models (no hand-written facade).
- R6. Integrated into `common_bootstrap` so `--project all --apply` regenerates the C++ wrapper with **zero drift** (clean-diff check).
- R7. CMake package: `find_package(VirgilCryptoCpp CONFIG)` exporting per-library targets `virgil::foundation-cpp` / `ratchet-cpp` / `phe-cpp` (no `common` target; `vsc_common` linked transitively), plus FetchContent support.
- R8. `VIRGIL_WRAP_CPP` build option + `configs/cpp-config.cmake` preset, consistent with `VIRGIL_WRAP_*`; link `vsc_foundation`/`vsc_ratchet`/`vsc_phe` + deps.
- R9. Extra deps (GSL, the `expected` implementation) via CMake FetchContent, pinned; no new required system deps.
- R10. Build + test on Linux, macOS (clang), Windows (MSVC), with a CI job.
- R11. Round-trip / cross-wrapper parity tests against the C test vectors.

## Scope Boundaries

- No Conan Center / vcpkg publishing (CMake package + FetchContent only).
- No exceptions-based API surface; no dual throwing/`noexcept` variants.
- No net-new high-level convenience APIs beyond idiomatic 1:1 parity.
- No header-only-only distribution assumption; no C++ standard below C++20.
- No `common` wrapper module.

### Deferred to Separate Tasks

- Prebuilt-binary distribution and integration into `release.yml` (like Go/Apple): later iteration once the source-built SDK is stable. Initial consumers build from source via CMake.
- Conan/vcpkg recipes: future, once the CMake package is proven.

## Context & Research

### Relevant Code and Patterns

- **Codegen dispatch is hard-wired, not auto-discovered.** `tools/codegen/common_bootstrap.py` `main()` reads each project's `wrappers` attr and has one `if "<lang>" in wrappers_set:` block per language that imports `project_<lang>_backend` and writes the returned `(rel_path, content)` tuples. Add a `cpp` block there.
- **Backend contract:** a module-level `generate_<lang>_files(project_ir, license_text="", repo_root=".") -> list[tuple[str, str]]`, plus pure name-utility functions and per-entity generators (imported directly by tests).
- **Closest analog for the generator: `tools/codegen/project_swift_backend.py`.** Its lifetime model maps 1:1 to C++ RAII: default `init()`→`vscf_*_new`, `init(take:)`→adopt ctx, `init(use:)`→`vscf_*_shallow_copy`, `deinit`→`vscf_*_delete`. Type mapping lives in `_swift_type_for_arg` / `_swift_return_type`; buffer-output capacity from `IRCArgument.length_attrs`; status-return → `throws` (C++: → `expected`).
- **IR model:** `tools/codegen/project_ir.py` — `IRProject.{classes,enums,interfaces,implementations}`, `IRClass`, `IRCMethod`, `IRCArgument` (type-mapping heart: `class_name` `"data"`/`"buffer"`/`"self"`, `enum_name`, `interface_name`, `length_attrs`, status returns).
- **Closest analog for the build: `wrappers/java/CMakeLists.txt`** — a compiled native library added via `add_subdirectory`, `project(... LANGUAGES ...)`, per-project subdirs linking the C targets. (Swift is *not* in the CMake graph — it ships xcframeworks — so it is not the build model.)
- **Target-export pattern: `thirdparty/nanopb/CMakeLists.txt` + `cmake/protobuf.cmake`** (recently added) — exports cache vars + `IMPORTED`/ALIAS targets and a resolver, and supports downstream FetchContent/`add_subdirectory`. Mirror this for exporting `virgil::*-cpp` and the package config.
- **Per-project `wrappers=` attrs differ:** foundation `swift,java,python,wasm,go,php`; ratchet `java,swift,wasm,go`; phe `java,python,wasm,go,php`; common `python`. Append `cpp` to foundation, ratchet, phe (not common).
- **Wrapper build options/subdirs:** root `CMakeLists.txt` `VIRGIL_WRAP_*` (~L122-126) and `add_subdirectory("wrappers/<lang>")` guards (~L283-296); presets `configs/<lang>-config.cmake`.
- **Test pattern:** `tools/codegen/test_swift_backend.py` — name-utility unit tests, byte-identical parity tests vs committed files, file-count/structure tests. Run `python3 -m pytest tools/codegen/ -q`.
- **CI pattern:** `.github/workflows/build-go.yml` (Linux/macOS/Windows matrix, `workflow_call` inputs) + `build-macos.yml` (cmake+ctest).

### Institutional Learnings

- `docs/solutions/best-practices/asserts-vs-status-and-error-handling.md` — **Only `vscf_status_t`/`vscf_error_t` (runtime errors) map to the C++ error type. `VSCF_ASSERT*` are always-on and abort** (logic errors / caller bugs); never surface them as recoverable `expected` errors — doing so on attacker input is a DoS. Decisive for R3.
- `docs/solutions/best-practices/vsc-data-and-vsc-buffer-reference.md` + `vsc-buffer-ownership-and-secure-erasure-2026-06-18.md` — `vsc_data` is a non-owning view (→ `std::span`, must not outlive backing store; re-fetch after mutation); `vsc_buffer` is owning/growable (→ `std::vector<uint8_t>`); prefer `new_with_capacity` + `make_secure` + `destroy` for secret material (→ RAII secure erasure). Informs R4.
- `docs/solutions/best-practices/codegen-full-regeneration-and-consistency-check-2026-07-05.md` — all wrappers are committed & generated; keep hand-written tests decoupled from generated symbol names to avoid drift; verify with a clean-diff regenerate. Informs R6, Unit 4/8.
- `docs/solutions/best-practices/codegen-class-context-and-const-length-methods-2026-06-18.md` — IR gotchas the backend inherits: `context="public"` vs stateless `"none"`; const-length buffer-size helpers are `is_const` not `is_static`; **MSVC has no C99 VLAs**. Informs Unit 2, Unit 9.
- `docs/solutions/build-errors/msvc-no-c99-vla-vendored-c-2026-06-18.md` — Windows/MSVC job from day one; the wrapper compiles C with MSVC. Informs R10, Unit 9.
- `docs/solutions/logic-errors/oid-enum-missing-from-codegen-model-2026-04-26.md` — generated regions (`@generated`/`@end`) are overwritten every run; anything the wrapper depends on must live in the model XML, never hand-added.

### External References

- **`expected` → `tl::expected` (TartanLlama, CC0)**: single-header, `std::expected`-shaped (`and_then`/`map`/`or_else`), FetchContent-clean, `-fno-exceptions`-safe **provided the generator never calls `.value()` on an error path** (it aborts under `-fno-exceptions`). Migrating to `std::expected` (C++23) later is a header swap. Fallback: a `std::expected` backport. (Boost.Outcome reserved only if generated-`expected` build time becomes a measured problem.)
- **`span` → `std::span` (C++20)** in public signatures; depend on **Microsoft GSL (MIT)** only for `gsl::not_null` (required delegates/handles), `gsl::finally`, `gsl::narrow_cast` — avoid `gsl::narrow` under `-fno-exceptions`.
- **RAII over C handles**: move-only wrappers by default; map C ref-counting (`_shallow_copy`) to copy semantics only where the C API supports it; rule of five; `not_null` for required interface/delegate params; funnel every fallible C call through a generated status→`expected` helper.
- **CMake distribution**: emit `virgil::<comp>-cpp` ALIAS identically for install & FetchContent; ship `VirgilCryptoCppConfig.cmake` (`configure_package_config_file` + version file) with `find_dependency(tl-expected)` / `find_dependency(Microsoft.GSL)`; use `FetchContent_Declare(... FIND_PACKAGE_ARGS ...)` for dual consumption; prefer **static** per-library over shared to avoid C++ ABI issues.
- **Codegen for C++ (SWIG-style two-layer)**: C shim/`detail` at the bottom, idiomatic proxy on top; strip `vscf_`/`vscr_`/`vsce_` prefixes into namespaces; handle reserved words (`new`/`delete`); keep C includes + `expected` helpers out of public headers; make `-fno-exceptions` safety a template invariant.

## Key Technical Decisions

- **New idiomatic C++ backend, mirroring `project_swift_backend.py`** (OO analog with the matching take/use/shallow_copy/delete lifecycle) — not a facade over a generated 1:1 core. Single source of truth (R5).
- **`tl::expected` for `expected<T, Error>`** (CC0, single-header, `-fno-exceptions`-safe). Per-project `Error` value type (`foundation::Error`, etc.) wrapping that project's status enum + a `message()` accessor, mirroring Swift's `<Project>Error`. Generated status→`expected` helper is a template invariant; `.value()` never emitted on error paths (R3).
- **`std::span<const uint8_t>` in / `std::vector<uint8_t>` out** for data; GSL only for `not_null`/`finally`/`narrow_cast`. Secure-erasing owning buffer for secret material. (Revises the origin doc's "gsl::span" to `std::span` per external research.) (R4)
- **Move-only RAII wrapper** holding the opaque C handle; copy ctor via `_shallow_copy` only where the C class supports it; dtor → `_delete`; rule of five (R1).
- **Two-layer generated output**: public headers (`wrappers/cpp/include/virgil/crypto/<proj>/*.hpp`) expose only the idiomatic class + opaque handle; C includes and `expected`/buffer helpers live in a `detail` header / `.cpp` (R1, keeps `<tl/expected.hpp>` and C headers off the public surface where feasible).
- **Static per-library CMake targets** `foundation-cpp` / `ratchet-cpp` / `phe-cpp` with `virgil::<name>` ALIASes identical in install & FetchContent; `vsc_common` linked transitively (no `common` wrapper) (R7).
- **Deps via `FetchContent_Declare(... FIND_PACKAGE_ARGS ...)`** for `tl::expected` + GSL, pinned by tag/SHA like `thirdparty/` deps; re-`find_dependency` in the installed config (R9).

## Open Questions

### Resolved During Planning

- Which `expected` lib? → `tl::expected` (CC0), with a `std::expected` backport as fallback.
- `gsl::span` vs `std::span`? → `std::span` in public API; GSL for `not_null`/`finally`/`narrow_cast` only.
- Error type shape? → per-project `Error` value type wrapping the C status enum + `message()`.
- Which projects get `cpp`? → foundation, ratchet, phe (not common).
- Static vs header-only? → static per-library (generated `.cpp` bodies); ABI-safe.
- find_package + FetchContent both? → yes, via `FIND_PACKAGE_ARGS` + a Config with `find_dependency`.

### Deferred to Implementation

- Exact naming rules (methods `snake_case` vs `camelCase`; reserved-word handling for `new`/`delete`) — settle in Unit 1 against real IR; the rules become an API contract, so lock them once.
- IR edge cases: interface/delegate ownership transfer, multi-output methods (result struct vs `expected<tuple>`), const-length buffer-capacity helpers, `context="none"` stateless classes — resolve in Unit 2/3 against the real IR.
- Whether the C libs need a specific config when built for the C++ wrapper (cf. the Go `VIRGIL_WRAP_GO=OFF` install-conflict gotcha) — verify in Unit 5.
- Final codegen file counts / parity snapshots for `test_cpp_backend.py` — knowable only after Unit 4 generates the tree.
- Which methods/args carry secret material and should map to secure-erasing buffers — enumerate during Unit 2.

## Output Structure

    wrappers/cpp/
      CMakeLists.txt                      # per-library CXX targets, package export
      cmake/
        VirgilCryptoCppConfig.cmake.in    # find_package config (+ find_dependency)
      include/virgil/crypto/
        foundation/*.hpp                  # generated public headers (RAII, expected)
        ratchet/*.hpp
        phe/*.hpp
        detail/*.hpp                      # generated: C includes, status->expected, buffer helpers
      src/
        foundation/*.cpp                  # generated impl (where non-inline)
        ratchet/*.cpp
        phe/*.cpp
      test/                               # hand-written parity tests (guarded from codegen)
        foundation_test.cpp ...
    configs/cpp-config.cmake
    tools/codegen/project_cpp_backend.py
    tools/codegen/test_cpp_backend.py
    codegen/models/wrapper/wrapper_cpp.xml
    .github/workflows/build-cpp.yml

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification. The implementing agent should treat it as context, not code to reproduce.*

**Two-layer generation (SWIG-style), per project:**

```
IR model (codegen/models/project_foundation/*)
        │  project_cpp_backend.generate_cpp_files()
        ▼
public header  virgil/crypto/foundation/aes256_gcm.hpp     detail  virgil/crypto/foundation/detail/*.hpp
  class Aes256Gcm {                                            - #include "vscf_aes256_gcm.h"
    RAII handle (move-only)                                    - status_to_error(vscf_status_t) -> Error
    expected<vector<uint8_t>, Error> encrypt(span<const u8>)   - make/free vsc_buffer helpers
  };                                                           - vsc_data(span) adapters
```

**IR → idiomatic C++ mapping (directional):**

| IR / C construct | C++ mapping |
|---|---|
| `IRClass` (context=public) | move-only RAII class over the opaque C handle; dtor→`_delete` |
| default ctor / `take` / `use` | default ctor→`_new`; `explicit Cls(T*) noexcept` adopts; copy ctor→`_shallow_copy` (only if supported) |
| `IRCArgument class_name="data"` (in) | `std::span<const uint8_t>` → `vsc_data(ptr,len)` |
| `IRCArgument class_name="buffer"` (out) | allocate `vsc_buffer` (capacity from `length_attrs`) → return `std::vector<uint8_t>` |
| method returns `status` enum | `expected<T, Error>`; `unexpected{Error{status}}` on failure (never `.value()`) |
| `IREnum` | `enum class` (status enum → per-project `Error`) |
| `IRInterface` | abstract base class; required impls passed as `gsl::not_null` |
| `IRImplementation` + impl-tag | `<Project>Implementation` factory/dispatch |
| multi-output method | small generated result struct (or `expected<struct>`) |

**Consumer experience (target):**

```
find_package(VirgilCryptoCpp CONFIG REQUIRED)   # or FetchContent_MakeAvailable(virgil_crypto_cpp)
target_link_libraries(app PRIVATE virgil::foundation-cpp)
// auto c = foundation::Aes256Gcm{}; c.set_key(key); auto ct = c.encrypt(pt); // expected<vector<u8>,Error>
```

## Implementation Units

### Phase A — Codegen backend

- [x] **Unit 1: C++ backend scaffolding, registration, and name/type mapping**

**Goal:** Stand up `project_cpp_backend.py` with the orchestrator + pure name/type utilities, wire it into `common_bootstrap`, register `cpp` on the projects, and emit the smallest vertical slice (enums + per-project `Error` + a base/`detail` header).

**Requirements:** R1, R3 (partial), R5, R6

**Dependencies:** None

**Files:**
- Create: `tools/codegen/project_cpp_backend.py`
- Create: `codegen/models/wrapper/wrapper_cpp.xml`
- Create: `tools/codegen/test_cpp_backend.py`
- Modify: `tools/codegen/common_bootstrap.py` (add `if "cpp" in wrappers_set:` dispatch block near the other language blocks; guard hand-written test files from overwrite)
- Modify: `codegen/models/project_foundation/project_foundation.xml`, `codegen/models/project_ratchet/project_ratchet.xml`, `codegen/models/project_phe/project_phe.xml` (append `cpp` to `wrappers="..."`)

**Approach:**
- `generate_cpp_files(project_ir, license_text="", repo_root=".")` orchestrator mirroring `generate_swift_files`: skip `scope in {private,internal}`, emit enums, a per-project `Error` from the status enum (`_find_status_enum` analog), and a `detail` base header. Hard-code the output dir helper to `wrappers/cpp/...`.
- Pure utilities: `cpp_type_name`, `cpp_method_name`, `cpp_enum_case`, prefix stripping (`vscf`/`vscr`/`vsce` → namespace), reserved-word handling (`new`/`delete`).
- Lock naming rules now (they are an API contract).

**Patterns to follow:** `tools/codegen/project_swift_backend.py` (`generate_swift_files`, `swift_type_name`, `_find_status_enum`); dispatch blocks in `common_bootstrap.py`.

**Test scenarios:**
- Happy path: `cpp_type_name`/`cpp_method_name`/`cpp_enum_case` map representative C names → expected idiomatic C++ (e.g. `vscf_aes256_gcm` → `Aes256Gcm`; status enum → `Error`).
- Edge case: reserved words (`new`, `delete`) and acronym/number boundaries (`aes256`, `sha512`, `rsa`) map correctly and collision-free.
- Edge case: enum with a `status` scope becomes `Error`, not `Status`.
- Happy path: `generate_cpp_files(foundation_ir)` returns non-empty tuples under `wrappers/cpp/`, includes an `Error` header, and excludes private/internal entities.

**Verification:** `python3 -m pytest tools/codegen/test_cpp_backend.py -q` passes; `--project foundation --apply` emits enum + `Error` + detail headers under `wrappers/cpp/`.

- [x] **Unit 2: Class generation — RAII wrappers, data/buffer mapping, status→expected**

**Goal:** Generate idiomatic C++ classes: opaque-handle RAII (ctors take/use, dtor, move, copy-via-shallow_copy where supported), methods mapping `std::span` in / `std::vector<uint8_t>` out with buffer-capacity handling, and status returns funneled through a generated `status→expected<T,Error>` helper.

**Requirements:** R1, R2, R3, R4

**Dependencies:** Unit 1

**Files:**
- Modify: `tools/codegen/project_cpp_backend.py` (class + method-body generators; `detail` status/buffer/data helpers)
- Modify: `tools/codegen/test_cpp_backend.py`

**Approach:**
- `generate_cpp_class`: move-only by default; copy ctor only when the C class exposes `_shallow_copy`; dtor→`_delete`; `explicit Cls(T*) noexcept` adopt-ctor. Rule of five.
- Method bodies: `class_name="data"` arg → `std::span<const uint8_t>` → `vsc_data`; `class_name="buffer"` output → allocate `vsc_buffer` (capacity from `length_attrs`, const-length helper is `is_const`) → copy to `std::vector<uint8_t>`; multi-output → result struct.
- Status return → `expected<T, Error>`; on failure return `unexpected{Error{status}}`; **never emit `.value()` on an error path** (`-fno-exceptions` invariant). Only `vscf_status_t`/`vscf_error_t` become `Error` — asserts are left as-is.
- Dependency setters (`IRDependency`) → `set_x(...)` methods.

**Execution note:** Generate one representative class (e.g. `aes256_gcm`) first and diff it by eye against the C API + the Swift output before generalizing.

**Patterns to follow:** `project_swift_backend.py` `generate_swift_class`, `_swift_method_body`, `_buffer_capacity_expr`, `_emit_dependency_setter`; gotchas in `docs/solutions/best-practices/codegen-class-context-and-const-length-methods-2026-06-18.md`.

**Test scenarios:**
- Happy path: a generated class exposes a default ctor, dtor, and its methods; a status-returning method's signature is `expected<T, Error>`.
- Edge case: a class without `_shallow_copy` is move-only (no copy ctor emitted); one with it emits a copy ctor.
- Edge case: a const-length buffer helper is emitted as `is_const` (not static); buffer output methods size the buffer from `length_attrs`.
- Error path: generated error-branch code returns `unexpected{...}` and contains no `.value()` call (guard against the `-fno-exceptions` foot-gun via a source-substring assertion in the test).
- Happy path: `context="none"` (stateless) classes emit free functions / no `self` handle.

**Verification:** generated `aes256_gcm.hpp/.cpp` compile in a scratch TU against the C libs; pytest class tests pass.

- [x] **Unit 3: Interfaces, implementations, and impl-tag dispatch**

**Goal:** Generate C++ abstract base classes for IR interfaces, concrete implementation wrappers, and the `<Project>Implementation` dispatch, so polymorphic C "interface" objects and delegates work idiomatically.

**Requirements:** R1, R2

**Dependencies:** Unit 2

**Files:**
- Modify: `tools/codegen/project_cpp_backend.py` (interface/implementation/dispatch generators)
- Modify: `tools/codegen/test_cpp_backend.py`

**Approach:**
- `generate_cpp_interface` → abstract base; required interface/delegate params typed as `gsl::not_null`. `generate_cpp_implementation` + `<Project>Implementation` factory mirroring `generate_swift_implementation` / `generate_swift_project_implementation`.
- Model ownership transfer for delegates explicitly (move-in vs borrow), documented in generated comments.

**Patterns to follow:** `project_swift_backend.py` `generate_swift_protocol`, `generate_swift_implementation`, `generate_swift_project_implementation`.

**Test scenarios:**
- Happy path: an IR interface emits an abstract base with pure-virtual methods; an implementation emits a wrapper deriving/holding it.
- Integration: impl-tag dispatch resolves a concrete wrapper from an alg-id/impl tag (mirrors Swift's dispatch test).
- Edge case: a required delegate parameter is `gsl::not_null`.

**Verification:** interface/impl tests pass; a generated interface + one implementation compile together.

- [x] **Unit 4: Full-surface generation, commit, and consistency check**

**Goal:** Regenerate the whole C++ wrapper for foundation/ratchet/phe, commit the generated tree, and lock the no-drift guarantee + codegen snapshot tests.

**Requirements:** R2, R6

**Dependencies:** Unit 3

**Files:**
- Create: `wrappers/cpp/include/...`, `wrappers/cpp/src/...` (generated)
- Modify: `tools/codegen/test_cpp_backend.py` (file-count + parity snapshot tests)

**Approach:**
- Run `python3 -m tools.codegen.common_bootstrap --project all --apply`; commit generated output. Re-run and confirm `git status` is clean (no drift). Add file-count and byte-identical parity tests (as Swift does).
- **Cross-project references (surfaced in Unit 3, resolve here):** foundation compiles clean (133 headers + dispatch verified with `clang++ -std=c++20 -fsyntax-only` against the committed C headers), but phe/ratchet reference **foundation** types (e.g. the `random` dependency has `attrs['project']='foundation'`) and thirdparty C types (`mbedtls_*`, nanopb `ProofOfSuccess`). The include path, C++ namespace qualifier, and — for any foundation *interface* return — the dispatch owner (`foundation::FoundationImplementation`, not phe's) must become project-aware. Thirdparty-typed methods are currently all private (correctly skipped); confirm that holds. This is the main net-new work to make phe/ratchet compile.

**Execution note:** Consistency-first — the acceptance is a clean-diff regenerate.

**Patterns to follow:** `docs/solutions/best-practices/codegen-full-regeneration-and-consistency-check-2026-07-05.md`; parity tests in `test_swift_backend.py`.

**Test scenarios:**
- Happy path: `generate_cpp_files` output is byte-identical to the committed `wrappers/cpp/**` files (parity).
- Happy path: expected file count per project (foundation/ratchet/phe) matches.
- Integration: a full `--project all --apply` run leaves the tree drift-free.

**Verification:** `--project all --apply` then `git status --short` is empty; `pytest tools/codegen/ -q` green (existing pre-existing failures unchanged).

### Phase B — Build & packaging

- [x] **Unit 5: CMake build for the wrapper (per-library CXX targets)**

**Goal:** Build the generated C++ SDK as static per-library targets linking the C libs, gated by `VIRGIL_WRAP_CPP`, with a config preset.

**Requirements:** R8, R10 (partial)

**Dependencies:** Unit 4

**Files:**
- Create: `wrappers/cpp/CMakeLists.txt` (+ `foundation`/`ratchet`/`phe` subdirs or targets)
- Create: `configs/cpp-config.cmake`
- Modify: root `CMakeLists.txt` (`option(VIRGIL_WRAP_CPP ...)`; `add_subdirectory("wrappers/cpp")` guard)

**Approach:**
- `project(virgil_crypto_cpp ... LANGUAGES CXX)`; `foundation-cpp` links `vsc_foundation` (+ transitive `vsc_common`), `ratchet-cpp` → `vsc_ratchet`, `phe-cpp` → `vsc_phe`; `target_compile_features(... cxx_std_20)`; public include dir `wrappers/cpp/include`. Mirror `wrappers/java/CMakeLists.txt`.
- `configs/cpp-config.cmake` mirrors `configs/go-config.cmake` (set `VIRGIL_WRAP_CPP ON`, testing/install layout, `VIRGIL_POST_QUANTUM ON`).
- Verify no build-graph conflict analogous to the Go `VIRGIL_WRAP_GO=OFF` install issue.

**Patterns to follow:** `wrappers/java/CMakeLists.txt`; root `CMakeLists.txt` `VIRGIL_WRAP_*` blocks; `configs/go-config.cmake`.

**Test scenarios:**
- Test expectation: none (build wiring) — covered by Unit 8 tests + Unit 9 CI. Verification is a successful configure+build.

**Verification:** `cmake -Cconfigs/cpp-config.cmake -DVIRGIL_WRAP_CPP=ON -Bbuild -S.` then `cmake --build build` produces `foundation-cpp`/`ratchet-cpp`/`phe-cpp` on macOS/Linux.

**Note (header+cpp split):** conforming to the "static per-library (generated `.cpp` bodies)" decision above, the generators now emit a lean declaration `.hpp` (forward-declaring the C handle, so consumers don't pull the C library headers) plus a definition `.cpp` per class/impl. This unlocked **stack-allocated output buffers** (the `.cpp` includes the internal `private/vsc_buffer_defs.h`, never exposed to consumers) — no per-call heap alloc. All three libraries are STATIC. Units 2–4 had emitted an interim header-only inline form; this revises them to the planned shape. Interfaces/enums/`Error`/dispatch header stay header-only.

- [x] **Unit 6: Third-party deps via FetchContent (tl::expected, GSL)**

**Done:** `tl::expected` is pinned via FetchContent (`v1.1.0`) with `FIND_PACKAGE_ARGS NAMES tl-expected` on CMake ≥ 3.24 (prefers a system copy, fetches as fallback). **GSL is intentionally not pulled** — interface/delegate arguments are passed by reference (`const T&`), which is non-nullable by construction, so `gsl::not_null` is unnecessary; dropping it removes a dependency.


**Goal:** Pull `tl::expected` and Microsoft GSL via CMake FetchContent, pinned, and wire them into the wrapper targets' interface.

**Requirements:** R9

**Dependencies:** Unit 5

**Files:**
- Modify: `wrappers/cpp/CMakeLists.txt` (or a `wrappers/cpp/cmake/deps.cmake`)

**Approach:**
- `FetchContent_Declare(tl-expected ... GIT_TAG <pinned> FIND_PACKAGE_ARGS)` and same for `Microsoft.GSL`; `FetchContent_MakeAvailable`. Link `tl::expected` / `Microsoft.GSL::GSL` to the wrapper targets (PUBLIC where they appear in public headers, else PRIVATE). Pin by tag/SHA like `thirdparty/` deps.

**Patterns to follow:** `thirdparty/nanopb/CMakeLists.txt` (pinned external fetch); external-research CMake guidance (`FIND_PACKAGE_ARGS`).

**Test scenarios:**
- Test expectation: none (dependency wiring) — verified by a clean configure+build with no system GSL/expected installed.

**Verification:** a from-scratch build with no system `tl-expected`/GSL resolves both via FetchContent and links.

- [x] **Unit 7: CMake package export + dual find_package/FetchContent consumption**

**Done:** in-tree `virgil::foundation-cpp`/`ratchet-cpp`/`phe-cpp` ALIASes (for add_subdirectory/FetchContent) + `install(EXPORT ... NAMESPACE virgil::)` (identical names for `find_package`); `VirgilCryptoCppConfig.cmake.in` re-finds the C packages and `tl-expected` via `find_dependency`; `cpp-config.cmake` enables `INSTALL_CMAKE`+`INSTALL_DEPS_CMAKE` (must agree so the C export sets are self-consistent). The package installs cleanly (config + targets + headers + tl-expected). FetchContent/add_subdirectory consumption is verified end-to-end (a scratch consumer links `virgil::foundation-cpp` and runs a base64 round-trip).

**Pre-existing C/thirdparty packaging blockers surfaced (out of C++-wrapper scope):** the installed `find_package` consumption exposed deficiencies in the *C library's own* packaging: (1) the `vsc_*Config.cmake` files reference their deps (`foundation_pb`, `common`, `ed25519`, …) without `find_dependency` — worked around by resolving the transitive C packages in `VirgilCryptoCppConfig.cmake.in`; (2) `thirdparty/ed25519/CMakeLists.txt` had a malformed install-context genex (`$<AND:$<BUILD_INTERFACE:1>,…>`) — **fixed** (wrapped in `$<BUILD_INTERFACE:…>`); (3) the C libraries publicly link **imported thirdparty targets that ship no CMake package config** — `vsc::foundation` → `mbed::crypto`, `falcon`, `mlkem768`, `mldsa65`; `foundation_pb` → `nanopb::protobuf-nanopb` (their `install()` blocks copy only the raw `.a` + headers). So an installed `find_package(VirgilCryptoCpp)` consumer configure-errors when `vsc_foundationTargets.cmake` re-declares `vsc::foundation` with those unresolvable link deps (the `mbed::crypto` `::`-named target hard-errors; `falcon`/`mlkem768`/`mldsa65` degrade to `-lfalcon …` link failures). (3) is a C-library packaging gap (the imported thirdparty deps need exported configs) — it belongs to the C library's install story, not the C++ wrapper, and can't be papered over with more `find_dependency` lines. **FetchContent / add_subdirectory (the primary mode, and what CI exercises) is unaffected** since every imported target exists in the same build; the wrapper's own install/export machinery is correct and will work once the C libraries export their thirdparty deps.


**Goal:** Ship an installable package exporting `virgil::foundation-cpp`/`ratchet-cpp`/`phe-cpp` (same ALIASes for install and FetchContent), with a Config that re-finds deps; prove a downstream consumer.

**Requirements:** R7

**Dependencies:** Unit 6

**Files:**
- Create: `wrappers/cpp/cmake/VirgilCryptoCppConfig.cmake.in`
- Modify: `wrappers/cpp/CMakeLists.txt` (`install(TARGETS ... EXPORT ...)`, `install(EXPORT ... NAMESPACE virgil::)`, `configure_package_config_file`, `write_basic_package_version_file`; `add_library(virgil::foundation-cpp ALIAS foundation-cpp)` etc. in-tree too)

**Approach:**
- Define `virgil::<name>` ALIASes in-tree (so `add_subdirectory`/FetchContent consumers use them) and via the exported namespace (so `find_package` consumers get identical names). Config calls `find_dependency(tl-expected)` + `find_dependency(Microsoft.GSL)`.

**Patterns to follow:** `thirdparty/nanopb/CMakeLists.txt` export block + `cmake/protobuf.cmake` resolver; external-research CMake packaging guidance.

**Test scenarios:**
- Integration: a scratch consumer project that `FetchContent_MakeAvailable`s the wrapper, `target_link_libraries(app PRIVATE virgil::foundation-cpp)`, compiles and runs a trivial call.
- Integration: an installed-tree consumer using `find_package(VirgilCryptoCpp CONFIG REQUIRED)` links the same target.

**Verification:** both consumer modes (FetchContent + installed find_package) build and run the smoke program.

### Phase C — Tests & CI

- [x] **Unit 8: C++ SDK round-trip / parity tests**

**Done:** hand-written tests under `wrappers/cpp/test/` (skipped by the codegen orchestrator), a dependency-free `check.hpp` harness, three ctest cases: `foundation_cpp_test` (AES-256-GCM encrypt→decrypt round-trip; tampered ciphertext → `unexpected{Error::AuthFailed}` with no throw/abort; empty-span round-trip; SHA-256 "abc" known vector; base64 round-trip), `phe_cpp_test` (PheCipher encrypt→decrypt + wrong-key error), `ratchet_cpp_test` (RatchetSession setup + query). Surfaced and fixed a real **empty-input abort**: an empty span has `data()==nullptr` but `vsc_data` asserts non-null, so data args now route through `vsc_data_empty()` when empty (mirrors the Go backend). `setup_defaults()` (not `set_random`/`set_rng`) is used for phe/ratchet since the C API asserts the dependency is unset — setup_defaults still wires the foundation random at runtime. Guarded on `ENABLE_TESTING` (independent of `VIRGIL_C_TESTING`). All three pass locally via `ctest`.


**Goal:** Hand-written C++ tests (guarded from codegen overwrite) proving the wrapper is functionally equivalent to the C API across representative flows.

**Requirements:** R11

**Dependencies:** Unit 5 (build), ideally Unit 7

**Files:**
- Create: `wrappers/cpp/test/foundation_test.cpp` (+ ratchet/phe as applicable)
- Modify: `wrappers/cpp/CMakeLists.txt` (test target + ctest registration)

**Approach:**
- Mirror key C test vectors: e.g. AES-256-GCM encrypt→decrypt round-trip, a hash, signer/verifier, and one ratchet + one phe flow. Assert output bytes equal the C-produced/known vectors. Keep tests decoupled from generated symbol churn where possible (per drift learning). Cover the `expected` error path (a tampered input yields `unexpected{Error}`, not a throw/abort).

**Patterns to follow:** existing C tests under `tests/foundation/`; keep hand-written tests minimal (drift learning).

**Test scenarios:**
- Happy path: AES-256-GCM `encrypt` then `decrypt` round-trips to the original plaintext.
- Error path: decrypt of tampered ciphertext returns `unexpected{Error}` (auth failure) — no exception, no abort.
- Edge case: empty input `std::span`; large buffer output sizing.
- Integration: a ratchet session and a phe flow round-trip end to end.

**Verification:** `ctest` passes on macOS + Linux locally; error-path test confirms `expected` (not abort) under `-fno-exceptions`.

- [x] **Unit 9: CI workflow (Linux / macOS / Windows-MSVC)**

**Done:** `.github/workflows/build-cpp.yml` — a `codegen-tests` job (C++ backend unit + no-drift parity) and a `build` matrix that configures with `cpp-config.cmake`, builds the three libraries **and** the ctest test targets, and runs `ctest -R _cpp_test` on **Linux (GCC + Clang)** and **Windows (MSVC)** — MSVC is first-class given the no-C99-VLA constraint. Linux additionally builds+runs the FetchContent smoke consumer. macOS is omitted per CLAUDE.md (macOS runners are reserved for direct prebuilt dependencies; the wrapper builds the C sources itself). `workflow_call` reuse can be layered on later for release wiring.


**Goal:** Add `build-cpp.yml` building + testing the C++ SDK across the three OSes, including MSVC.

**Requirements:** R10

**Dependencies:** Unit 8

**Files:**
- Create: `.github/workflows/build-cpp.yml`

**Approach:**
- Matrix Linux/macOS/Windows (`ubuntu-latest`/`macos-latest`/`windows-latest`); `setup-python` + venv (codegen/nanopb), install `cmake ninja`; configure `-Cconfigs/cpp-config.cmake -DVIRGIL_WRAP_CPP=ON -DVIRGIL_POST_QUANTUM=ON`, build, run `ctest`. Include a downstream FetchContent smoke-consumer step (from Unit 7). MSVC job is required (no-VLA gotcha); `workflow_call` inputs for future release reuse.

**Patterns to follow:** `.github/workflows/build-go.yml` (matrix + `workflow_call`) and `build-macos.yml` (cmake+ctest); MSVC gotcha in `docs/solutions/best-practices/codegen-class-context-and-const-length-methods-2026-06-18.md`.

**Test scenarios:**
- Test expectation: none (CI config) — its job *is* to run Units 8's tests across OSes. Verification is a green matrix.

**Verification:** `build-cpp.yml` green on Linux, macOS, and Windows/MSVC, including the FetchContent consumer smoke build.

## System-Wide Impact

- **Interaction graph:** New codegen dispatch block in `common_bootstrap.main()`; new `wrappers=` values on 3 project models. Existing backends/wrappers are untouched (additive). Root `CMakeLists.txt` gains one option + one guarded `add_subdirectory`.
- **Error propagation:** C `vscf_status_t`/`vscf_error_t` → per-project `Error` → `expected<T, Error>`; asserts remain aborts and are never surfaced as recoverable.
- **State lifecycle risks:** RAII correctness (double-free/leak) around take/use/shallow_copy/delete; `std::span` inputs must not outlive their backing store; secret buffers must securely erase.
- **API surface parity:** The generator's naming rules become a public API contract — lock them in Unit 1; regeneration must not silently rename symbols (drift learning).
- **Integration coverage:** Cross-layer round-trip (Unit 8) + downstream consumer builds (Unit 7) + tri-platform CI (Unit 9) — the parts unit tests alone won't prove.
- **Unchanged invariants:** The C library, IR models' semantics, and all existing wrappers are unchanged; this is purely additive.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| `-fno-exceptions` foot-gun: generated `.value()` on an error path aborts | Template invariant: route via status→`expected` helper; test asserts generated error branches contain no `.value()` |
| C++ codegen scope underestimated (IR → idiomatic C++ is the hardest part) | Phase A is incremental (enum→class→interface→full); validate one class early (Unit 2 execution note) against Swift output |
| MSVC-only breakage (no VLAs; C compiled with MSVC) | Windows/MSVC CI from day one (Unit 9); no-VLA gotcha noted |
| Generated/hand-written test drift on regeneration | Keep hand-written C++ tests minimal + decoupled from symbol names; parity/consistency tests (Unit 4/8) |
| `tl::expected` build-time inflation over a large generated surface | Confine `<tl/expected.hpp>` to `detail`/`.cpp` where possible; Boost.Outcome is a documented fallback if measured |
| Dep resolution differs between FetchContent and installed consumers | `FIND_PACKAGE_ARGS` + `find_dependency` in Config; both modes smoke-tested (Unit 7/9) |

## Documentation / Operational Notes

- Add a `wrappers/cpp/README.md` with consumption snippets (find_package + FetchContent) — during Unit 7.
- Prebuilt-binary distribution + `release.yml` integration + Conan/vcpkg are explicitly deferred (Scope → Deferred to Separate Tasks).
- CLAUDE.md gates apply: `python3 -m pytest tools/codegen/ -q` for codegen changes; C build + ctest before pushing.

## Sources & References

- **Origin document:** [docs/brainstorms/cpp-wrapper-requirements.md](docs/brainstorms/cpp-wrapper-requirements.md)
- Codegen: `tools/codegen/common_bootstrap.py`, `tools/codegen/project_swift_backend.py`, `tools/codegen/project_ir.py`, `tools/codegen/test_swift_backend.py`
- Build/export: `wrappers/java/CMakeLists.txt`, root `CMakeLists.txt`, `configs/go-config.cmake`, `thirdparty/nanopb/CMakeLists.txt`, `cmake/protobuf.cmake`
- Learnings: `docs/solutions/best-practices/{asserts-vs-status-and-error-handling, vsc-data-and-vsc-buffer-reference, vsc-buffer-ownership-and-secure-erasure-2026-06-18, codegen-full-regeneration-and-consistency-check-2026-07-05, codegen-class-context-and-const-length-methods-2026-06-18}.md`, `docs/solutions/build-errors/msvc-no-c99-vla-vendored-c-2026-06-18.md`
- External: TartanLlama/expected (CC0), microsoft/GSL (MIT), C++ Core Guidelines (R.1/R.20/C.21/C.31-33/F.7), CMake `cmake-packages(7)` + `FetchContent` `FIND_PACKAGE_ARGS`
