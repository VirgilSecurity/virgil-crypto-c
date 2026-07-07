---
date: 2026-07-07
topic: cpp-wrapper
---

# C++ Wrapper (published general-purpose C++ SDK)

## Problem Frame

virgil-crypto-c ships language wrappers for Python, Java/Android, Go, Swift, PHP, and WASM — all **codegen-generated** from the IR models under `codegen/models/` via `tools/codegen/project_*_backend.py`. There is **no C++ wrapper today** (verified: no `project_cpp_backend.py`, no `VIRGIL_WRAP_CPP`, no C++ wrapper under `wrappers/`). C++ consumers must call the raw C API directly (manual `_new`/`_destroy`, `vsc_data`/`vsc_buffer`, status-code checks), which is error-prone and un-idiomatic.

This adds a **published, general-purpose C++ SDK** with full API parity to the other wrappers, so external C++ developers get a first-class, modern-C++ binding.

## Requirements

**API surface & style**
- R1. Provide idiomatic **C++20** bindings following the **C++ Core Guidelines**: RAII (no manual `new`/`delete`/`destroy`), value semantics, `gsl::span` / `gsl::not_null` for buffers and non-null handles, and namespaces (`virgil::crypto::foundation`, `::ratchet`, `::phe`, plus shared/common types).
- R2. **Full API parity** with the other wrappers: every foundation, ratchet, and phe class/enum/interface exposed by codegen has an idiomatic C++ equivalent (1:1 idiomatic mirror, not net-new high-level facades).
- R3. Report failures via an **`expected<T, Error>`** return type (not exceptions), so the SDK is usable under `-fno-exceptions`. The `Error` type maps the C status enums (`vscf_status_t`, `vscr_*`, `vsce_*`).
- R4. Map C data types idiomatically: `vsc_data` (input buffers) as `gsl::span<const uint8_t>` (accepting contiguous ranges), `vsc_buffer` / owned outputs as `std::vector<uint8_t>` (or `std::string` where textual). The `common` library is **absorbed into this mapping layer, not exposed as a wrapped module** (see R7 / Scope).

**Generation (single source of truth)**
- R5. Produce the SDK from a **new codegen backend** `tools/codegen/project_cpp_backend.py` that emits the idiomatic C++20 API directly from the existing IR models. No hand-written facade layer.
- R6. The backend integrates with the existing bootstrap so `python3 -m tools.codegen.common_bootstrap --project all --apply` regenerates the C++ wrapper alongside the others, and re-running produces **no drift** (consistency-check clean).

**Build, packaging & distribution**
- R7. Ship a **CMake package**: an installable `find_package(VirgilCryptoCpp CONFIG)` config exporting **per-library targets** — `virgil::foundation-cpp`, `virgil::ratchet-cpp`, `virgil::phe-cpp` — so consumers link only the modules they use, mirroring the modular C libs. There is **no `common` wrapper target**; the C `vsc_common` lib is linked privately/transitively by these targets. Plus **FetchContent** support (`FetchContent_MakeAvailable`).
- R8. Add a `VIRGIL_WRAP_CPP` build option and a `configs/cpp-config.cmake` preset, consistent with the existing `VIRGIL_WRAP_*` wrappers; link the existing C static libs (`vsc_common`, `vsc_foundation`, `vsc_ratchet`, `vsc_phe`) and their deps.
- R9. Pull the SDK's extra third-party dependencies (**GSL**, the `expected` implementation) via CMake **FetchContent**, SHA/tag-pinned — same pattern as the existing `thirdparty/` deps (mbedtls, nanopb). No new required system dependencies.

**Quality & platforms**
- R10. Build and test on the platforms the C library targets: **Linux, macOS (clang), Windows (MSVC)**, with a CI job mirroring the other wrappers' matrices.
- R11. Ship tests that establish **round-trip / cross-wrapper parity** (e.g. encrypt/decrypt, sign/verify) against the C test vectors, so the C++ layer is proven equivalent to the C API.

## Success Criteria

- A C++ consumer can `find_package(VirgilCryptoCpp CONFIG REQUIRED)` **or** FetchContent it, `target_link_libraries(app PRIVATE virgil::foundation-cpp)` (and/or `virgil::ratchet-cpp` / `virgil::phe-cpp`), and use the module with RAII lifetimes and `expected`-based error handling — no raw C API, no manual `destroy`.
- `common_bootstrap --project all --apply` regenerates the C++ wrapper with zero drift (consistency check clean), same as the other backends.
- Builds and tests pass on Linux, macOS/clang, and Windows/MSVC.
- Round-trip parity tests confirm C++ output interoperates with the C library (and, by extension, the other wrappers).
- GSL + `expected` are fetched via FetchContent and pinned; a consumer needs no manually-installed system deps.

## Scope Boundaries

- **Not** publishing to Conan Center / vcpkg initially (CMake package + FetchContent only; registries can follow later).
- **No** exceptions-based API surface (using `expected` instead); no dual throwing/`noexcept` variants.
- **No** net-new high-level convenience APIs beyond idiomatic 1:1 parity with the generated class surface.
- **No** header-only distribution (the SDK wraps compiled C static libs).
- **No** support for C++ standards below C++20.
- Prebuilt-binary distribution (as Go/Apple do) is out of scope initially — consumers build from source via CMake.

## Key Decisions

- **Published general-purpose SDK, full parity** (not an internal-only thin layer): the wrapper is a first-class citizen like Java/Go/Swift.
- **C++20 + Core Guidelines → idiomatic API**: RAII, value semantics, `gsl::span`/`not_null`.
- **`expected<T, Error>` over exceptions**: `-fno-exceptions`-friendly, explicit — a good fit for a crypto library and embedded consumers.
- **New idiomatic C++ codegen backend** (not a hand-written facade over a generated 1:1 core): single source of truth, regenerable, avoids facade drift as classes are added.
- **CMake package + FetchContent; deps via FetchContent**: no external registry infra; builds directly on the nanopb toolchain-export pattern just landed.
- **Per-library exported targets** (`virgil::foundation-cpp`, `virgil::ratchet-cpp`, `virgil::phe-cpp`): mirrors the modular C libraries so consumers link only what they need, rather than one umbrella target.
- **No `common` wrapper**: `library/common` is only data/buffer/memory primitives, so `vsc_data`/`vsc_buffer` map straight to `gsl::span`/`std::vector<uint8_t>` in the mapping layer; the C `vsc_common` lib is a private/transitive dependency. (Consistent with the Go wrapper, which also has no `common` module.)

## Dependencies / Assumptions

- Reuses the existing C static libs and their FetchContent/thirdparty deps; the C++ layer only adds GSL + an `expected` implementation.
- Assumes the IR models expose enough structure for the backend to derive idiomatic C++ (the other backends demonstrate the IR is sufficient for full-surface generation).
- Versioning aligns with the C library version (single repo release).

## Outstanding Questions

### Resolve Before Planning
- (none — product direction is settled)

### Deferred to Planning
- [Affects R1,R2][Technical] IR → idiomatic-C++ mapping: how C classes (impl/vtable pattern), interfaces, delegates, and ownership map onto RAII C++ classes; how `vsc_data`/`vsc_buffer` map to `gsl::span`/`std::vector<std::byte>`/`std::string`.
- [Affects R3][Needs research] Which `expected` implementation to pin: `tl::expected`, `Boost.Outcome`, or a `std::expected` C++20 backport — evaluate footprint, license (BSD-3 compat), and FetchContent-ability.
- [Affects R3][Technical] `Error` type design: single unified `virgil::crypto::Error`/`Status` vs per-module error types; how to preserve the distinct C status enums.
- [Affects R1][Technical] Naming conventions (mirror C snake_case methods vs C++ conventions) and namespace layout.
- [Affects R5,R6][Technical] Backend design: template strategy, how the new backend plugs into `common_bootstrap`, and the codegen test suite (`test_cpp_backend.py`) mirroring the other backends' tests.
- [Affects R7,R9][Technical] CMake package details: install layout, exported config, and whether the package transitively provides GSL/`expected` to consumers (vendored headers vs FetchContent-at-consume-time).
- [Affects R10][Technical] CI matrix specifics and whether to reuse existing per-wrapper workflows.

## Next Steps

`Resolve Before Planning` is empty → `-> /ce:plan` for structured implementation planning.
