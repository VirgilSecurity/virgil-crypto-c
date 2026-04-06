# Foundation Next-Phase Plan

This note captures the next migration phase after the `common` C backend regularization milestone.

## Goal

Use `foundation` as the next project target, but only after refactoring the current `common`-named project-rooted generator framework into generic shared modules so it remains model-driven and does not reintroduce project- or module-specific hardcodes.

## Top-level source of truth

The next project root is:

- `codegen/models/project_foundation/project_foundation.xml`

As with `common`, the generator should start from the top-level project model, resolve the project graph, lower into a shared IR/output-target model, and only then invoke the C backend.

## Why `foundation` next

`foundation` is large enough to stress the generalized framework:

- many classes
- many interfaces and implementors
- project-specific output surfaces beyond the small `common` proving ground
- a meaningful test of whether naming/path/prefix resolution is truly model-driven

## Inventory snapshot of `project_foundation.xml`

Current top-level inventory from `codegen/models/project_foundation/project_foundation.xml` and its sibling model files:

- **48 classes** — a wide mix of light utility/value objects (`error`, `base64`, `oid`, `pem`, `pem title`) and heavier stateful crypto/session types (`recipient cipher`, `message cipher`, `group session`, `key provider`, `signer`, `verifier`)
- **34 interfaces** — core algorithm contracts for ciphering, hashes, KDFs, randomness, key material, ASN.1, serialization, and padding
- **13 implementors** — large implementation families rooted in `mbedtls`, `virgil`, `ed25519`, `post quantum`, `compound key`, `hybrid key`, and serializer/padding helpers
- **7 enums** — `status`, `asn1 tag`, `alg id`, `oid id`, `recipient cipher decryption state`, `group msg type`, and `cipher state`
- **4 local modules** — `group session typedefs` plus three `mbedtls bridge *` modules, in addition to shared `common` modules (`assert`, `library`, `memory`, `atomic`)

The surface is not a flat list of peer entities. It clusters into a few clear families:

1. **Leaf/value surfaces** — enums, small utility classes, and constant/typedef style modules with shallow dependency depth.
2. **Interface-driven algorithm families** — cipher/hash/KDF/random/key interfaces that define broad backend contracts.
3. **Implementor-heavy crypto backends** — `mbedtls`, `virgil`, post-quantum, hybrid, and compound-key implementations with many cross-references.
4. **Serialization and wire-format surfaces** — ASN.1, PEM, message-info serializers, and algorithm-info serializers.
5. **Session / message workflows** — `recipient cipher`, `message cipher`, signer/verifier flows, and `group session*` types including protobuf-backed artifacts.

## Migration-risk segmentation

### Likely low-risk first slices

The best entry slices are the model areas that are structurally simple, heavily self-contained, and easy to verify in isolation:

- **Enums** (`status`, `asn1 tag`, `alg id`, `oid id`, `group msg type`, `cipher state`) — mostly deterministic constant emission with no ownership graph.
- **Utility/value classes** such as `error`, `base64`, `oid`, and likely `pem title` — shallow dependency surfaces, straightforward signatures, and existing dedicated tests like `test_base64` / `test_pem`.
- **Simple support modules** like `group session typedefs` and the `mbedtls bridge *` helpers — small API surfaces that mostly exercise module output routing.

These slices are useful because they validate the shared loader + IR + output-target path on real `foundation` metadata without forcing the first emitter task to solve deep dependency injection, crypto implementation wiring, or complex handwritten preservation.

### Medium-risk follow-on slices

- **Serialization helpers** (`alg info`, `message info`, ASN.1 reader/writer helpers, `pem`) because they are still bounded but interact with more generated definitions and internal/public header splits.
- **List/container-style classes** like `key recipient info list`, `signer info list`, and `verifier list` that add ownership and generated defs/internal header patterns without yet pulling in the heaviest crypto flows.

### High-risk areas to avoid as the first emitter pass

- **Implementor families** (`virgil`, `mbedtls`, `post quantum`, `compound key`, `hybrid key`) because they encode many concrete implementations, dependency properties, constants, and cross-entity requirements.
- **Stateful crypto workflow classes** such as `recipient cipher`, `message cipher`, `key provider`, `signer`, and `verifier` because they combine interface wiring, buffering, serialization, and crypto defaults.
- **`group session*` types** because they depend on protobuf artifacts, internal headers, typedef modules, and multi-entity workflow semantics rather than a single isolated output.
- **Post-quantum and platform-sensitive code paths** because build behavior also depends on feature flags and third-party libraries (`round5`, `falcon`, mbedTLS threading).

## Preservation and build constraints already visible

The `foundation` inventory already exposes constraints that the first emitter task must preserve:

- **Preservation still matters.** Existing `library/foundation/include/**` and `library/foundation/src/**` files contain generated blocks inside checked-in files rather than being throwaway outputs, so the new emitter must continue updating generated sections without clobbering handwritten content around them.
- **`foundation` is not standalone.** `library/foundation/CMakeLists.txt` requires `vsc::common`, `mbed::crypto`, and the `foundation_pb` sublibrary, so validation must include dependency-aware builds instead of isolated file diffs.
- **Feature flags change the effective surface.** `multi threading` and `post quantum` are first-class project features in `project_foundation.xml`, and the build links optional `round5` / `falcon` libraries behind CMake feature gates.
- **Protobuf-backed artifacts are in scope.** `library/foundation/protobuf/` and the `group session*` model family mean some `foundation` outputs depend on generated nanopb/protobuf assets that should be treated as a distinct higher-risk preservation/build boundary.
- **Internal/public splits are common.** `sources.cmake` references public headers, private headers, internal headers, and `*_defs.c` / `*_internal.c` style outputs, so the shared backend must keep output-target routing model-driven rather than assuming one file pair per entity.
- **Wrappers and downstream consumers exist, but should remain downstream validation only.** `project_foundation.xml` advertises multiple wrappers, and the repo contains wrapper/benchmark/program consumers of `vsc::foundation`; however, the first migration slice should prove the C library/test surfaces first rather than broadening the implementation scope into wrappers.

## Architecture rule carried forward

Do not hardcode project-specific metadata in the backend when it is defined by models.

That includes, where model-defined:

- project names
- prefixes
- namespace/include namespace
- file and output placement
- generated artifact routing

Also, avoid tying backend functionality to specific module names. If behavior is generic, it should be expressed in terms of shared entity kinds, attributes, or IR metadata rather than per-module special cases.

Explicitly: shared functionality must not branch on specific module names when the project metadata, source graph, or IR already expresses the distinction. Module-name checks are only acceptable in thin compatibility adapters or in temporary handwritten builders whose behavior is not yet representable by the shared metadata model.

## Refactor boundaries from the current `common_*` modules

### Shared project graph loading

Responsibilities that should move out of `common_source.py` into a generic shared loader layer:

- XML parsing, code-block protection, text cleanup, and description extraction helpers
- generic source dataclasses for projects, modules, classes, enums, methods, properties, variables, and named references
- project-root loading from an explicit top-level project XML path
- recursive module/dependency graph resolution using `from` metadata and model area names
- generic project/model path derivation from repo-root + project metadata rather than `common` literals

What should remain project-specific is only the convenience entrypoint for locating `project_common.xml`.

### Shared IR and output-target mapping

Responsibilities that should move out of `common_ir.py` into a generic shared IR/output-target layer:

- IR dataclasses for project/entity/output-target structure
- common source-to-IR lowering for modules, classes, enums, methods, variables, constants, and references
- include-namespace / generated-namespace derivation from project metadata
- output-target construction from model-defined prefix, namespace, scope, and work/source roots
- separation of explicit project modules from dependency-resolved modules

The project-specific residue should be limited to compatibility names such as `project_common_to_ir()` while the actual implementation becomes project-agnostic.

### Shared C backend code

Responsibilities that should move out of `common_direct_c.py` into a generic shared C backend layer:

- helpers that navigate IR (`_module_ir`, `_class_ir`, `_type_symbol`, `_include_file`)
- XML construction helpers (`_text`, `_c_module_root_attrs`, `_c_module_root`, comment/type helpers)
- generic argument/return lowering from IR/source attributes into `c_argument` / `c_return`
- renderer registration and direct-XML dispatch wiring based on output-target metadata
- reusable backend-static C rendering rules that are intentionally not model data

The remaining project-specific/backend-edge layer should only contain entity implementations that are still handwritten in Python because the model does not yet express them fully (for example the current `library`, `memory`, `atomic`, `assert`, `data`, `buffer`, and `buffer_defs` direct builders).

## Thin compatibility adapters allowed during migration

These `common`-named adapters can remain temporarily while imports are being moved:

- `project_common_path()` as a convenience wrapper over a generic project-path resolver
- `load_project_common()` and `project_common_to_ir()` as thin pass-through wrappers to shared loader/IR entrypoints
- `common_bootstrap.py` as a project-specific CLI entrypoint that selects the `common` project and shared backend registry
- `inspect_common_source.py`, `inspect_common_ir.py`, and `inspect_common_direct.py` as convenience inspection scripts that continue to target the `common` project while shared internals stabilize

Those adapters should stay intentionally thin: project selection, CLI defaults, and compatibility export names only. They should not keep ownership of shared parsing, IR shaping, output-target computation, or backend-lowering logic.

## Import, script, and documentation changes implied by the refactor

### Python imports / modules

- move internal imports away from `tools.codegen.common_source`, `tools.codegen.common_ir`, and `tools.codegen.common_direct_c` for shared responsibilities
- update `common_bootstrap.py` to import the shared backend registry while remaining the `common`-specific CLI wrapper
- update the inspect scripts to import shared loader/IR/backend entrypoints or compatibility wrappers, whichever keeps command behavior stable during migration

### Verification / scripts

- keep `bash tools/codegen/build_common_with_new_codegen.sh` as the `common` verification gate, but ensure it only depends on the compatibility bootstrap entrypoint rather than owning shared logic
- update any py-compile/documented command snippets that currently name only `common_*` modules so they cover the new shared modules plus the retained `common` adapters

### Documentation updates

- revise ADR implementation guidance and migration notes that currently present `common_source.py`, `common_ir.py`, and `common_direct_c.py` as long-term core architecture
- update `foundation-next-phase-plan.md` and related migration notes so the generic shared modules are the target architecture and `common` becomes the reference adapter/project
- keep task-area context aligned with the new phase ordering: shared refactor first, then `foundation` validation and emitter work

## Concrete refactor plan

1. **Extract the shared loader first.** Move XML parsing, project-root resolution, and dependency-graph loading into generic modules while keeping `project_common_path()` / `load_project_common()` as wrappers.
2. **Extract shared IR/output-target mapping next.** Re-home source-to-IR dataclasses and output-target computation so both `project_common.xml` and `project_foundation.xml` can flow through the same lowering path.
3. **Extract shared C-backend helpers before any new project work.** Move IR navigation, argument/return lowering, XML helpers, and renderer-registration plumbing behind generic backend modules.
4. **Retain only thin `common` adapters.** Keep compatibility wrappers and CLI defaults, but make them delegates to shared internals rather than long-term owners of shared logic.
5. **Prove the shared framework on `foundation` metadata before broad emitters.** Add project-root loading/tests and inventory checks for `project_foundation.xml` once the shared modules exist.
6. **Define `foundation` verification gates.** Establish compile/preservation checks before expanding coverage so backend refactors do not get conflated with project-specific build problems.
7. **Pilot one low-risk `foundation` emitter slice.** Use the shared backend on a small, reviewable `foundation` target before scaling out.

## Recommended execution sequence

1. extract shared loader responsibilities from `common_source.py` into generic codegen modules
2. extract shared IR/output-target responsibilities from `common_ir.py` into generic codegen modules
3. extract shared C backend responsibilities from `common_direct_c.py` into generic codegen modules
4. keep only thin compatibility adapters where they still help migration
5. add `foundation` project-root tests and inventory on top of that shared framework
6. define `foundation` compile/preservation verification gates
7. implement one low-risk `foundation` C emitter slice using the shared backend
8. expand only after the generalized framework proves out

## Recommended verification gates for `foundation`

The first `foundation` emitter work should be gated in layers instead of relying on one broad compile check.

### 1. Shared-framework metadata gate

Before emitting any `foundation` C files, add/keep Python tests that prove the shared project-rooted framework can load and lower `project_foundation.xml` without reintroducing `common` hardcodes.

Recommended command shape:

```bash
python3 -m unittest \
  tests.codegen.test_project_common_source \
  tests.codegen.test_project_common_ir \
  tests.codegen.test_project_c_backend
```

That command is only a placeholder for the current shared-framework suite; the concrete follow-up task should extend it with `foundation`-specific assertions once those tests exist.

### 2. Generator smoke gate for the selected slice

For the first migrated slice, run the shared generator only for the chosen `foundation` targets and inspect the resulting diffs in `library/foundation/**`.

Minimum expectation:

- generated sections update only in the intended files
- no unrelated `library/common/**` changes appear
- output paths, prefixes, and namespaces come from `project_foundation.xml` / shared IR rather than hardcoded literals

### 3. Build gate

Configure and build the C library and tests with `foundation` enabled:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

This validates the main `foundation` library plus its `foundation_pb` dependency wiring through CMake.

### 4. Test gate

Run the `foundation` test subset through CTest:

```bash
cd build && ctest --output-on-failure -R foundation
```

For the first low-risk slice, targeted executions such as `ctest --output-on-failure -R "(base64|pem|key_info|alg_info)"` are acceptable during development, but the step-completion gate for any emitter task should still include the broader `foundation` test set.

### 5. Feature-sensitive spot checks

Because `features.cmake` contains a large dependency graph and optional multi-threading/post-quantum toggles, explicitly verify at least:

- default feature configuration
- one build with `VSCF_POST_QUANTUM=OFF` if the migrated slice intersects post-quantum-adjacent outputs
- one build with multi-threading expectations intact when the slice touches threading-sensitive code paths

## Missing verification infrastructure to add before broad emitter work

Several gates needed for efficient `foundation` migration do not yet exist as dedicated tooling:

1. **No `foundation` equivalent of `tools/codegen/build_common_with_new_codegen.sh`.** There is currently no scripted generate-build-restore loop for `library/foundation`, so the first follow-up should add one before migration broadens beyond a tiny pilot.
2. **No shared-framework tests that explicitly exercise `project_foundation.xml`.** Current Python codegen tests are still `common`-centric; `CG-017` should add loader/IR/backend assertions for `foundation` metadata.
3. **No preservation-focused diff harness for `foundation`.** Because `foundation` files mix generated and handwritten code, the migration needs an automated way to detect writes outside generated blocks.
4. **No narrow slice-selection CLI/documented workflow yet.** A practical emitter task will need a repeatable way to regenerate just the chosen `foundation` entity family rather than broad project output.
5. **Generated build metadata remains legacy-owned.** Files like `library/foundation/features.cmake` and `library/foundation/sources.cmake` are still marked as fully generated by legacy scripts; broad emitter work should avoid silently taking ownership of them without a dedicated plan.

## Verification philosophy

Use tests at each layer:

- project graph loader tests
- IR/output-target tests
- backend resolution tests
- project-specific build/preservation verification

Do not rely on compile success alone as proof that the architecture is correct.

## Recommended first extraction after this planning task

Start with the loader split from `common_source.py`.

Why this first:

- it has the cleanest shared boundary because XML parsing, project-root loading, and dependency graph resolution are already reusable across projects
- `common_ir.py` and `common_direct_c.py` both depend on loader concepts, so extracting loader primitives first reduces rename churn in the later steps
- it gives `foundation` an early proof point (`project_foundation.xml` can load through shared code) without yet committing to backend-specific emitter behavior

The first concrete implementation task should therefore extract generic project-graph loading into shared modules while keeping `project_common_path()` / `load_project_common()` as compatibility wrappers.

## Expected outcome

After this phase, the codegen framework should expose generic shared modules rather than `common`-named core modules, and it should be shared across at least two project roots:

- `project_common.xml`
- `project_foundation.xml`

with `common` serving as the first validated reference slice and `foundation` serving as the first proof that the design is universal rather than project-specific.
