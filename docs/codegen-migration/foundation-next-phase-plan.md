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

Before emitting any `foundation` C files, keep the shared project-rooted tests green and include the dedicated `foundation` metadata coverage added in `CG-017`.

Recommended command:

```bash
python3 -m unittest tests.codegen.test_project_foundation_shared_framework
```

If a batch also touches shared loader / IR / backend internals, run the broader shared-framework suite alongside it:

```bash
python3 -m unittest \
  tests.codegen.test_project_common_source \
  tests.codegen.test_project_common_ir \
  tests.codegen.test_project_c_backend \
  tests.codegen.test_project_foundation_shared_framework
```

### 2. Generator smoke gate for the selected slice

For the first migrated slice, run the shared generator only for the chosen `foundation` targets and inspect the resulting diffs in `library/foundation/**`.

Minimum expectation:

- generated sections update only in the intended files
- no unrelated `library/common/**` changes appear
- output paths, prefixes, and namespaces come from `project_foundation.xml` / shared IR rather than hardcoded literals

### 3. Build + test gate

Use a single helper so future `foundation` batches do not each reinvent the CMake / CTest invocation details:

```bash
bash tools/codegen/verify_foundation_validation_gate.sh
```

This helper should:

- configure a dedicated `build/foundation-gate` tree in `Release`
- build the `foundation` target so `vsc::foundation_pb` stays in the dependency path
- discover the `foundation`-labeled tests via `ctest -N -L foundation` and build those concrete test targets before executing CTest
- run `ctest --output-on-failure -L foundation` so the gate follows the labeled `foundation` test surface instead of relying on name matching

As of 2026-04-07, the documented helper does complete this full sequence successfully in the lane worktree: `bash tools/codegen/verify_foundation_validation_gate.sh` finished with 54/54 `foundation` tests passing in `build/foundation-gate`.

During development, the helper should also support narrower executions:

```bash
bash tools/codegen/verify_foundation_validation_gate.sh --build-only
bash tools/codegen/verify_foundation_validation_gate.sh --post-quantum-off
```

### 4. Feature-sensitive spot checks

Because `features.cmake` contains a large dependency graph and optional multi-threading/post-quantum toggles, explicitly verify at least:

- the default helper run above
- one helper run with `--post-quantum-off` if the migrated slice intersects post-quantum-adjacent outputs
- multi-threading-labeled tests remain included in the `foundation` CTest label set when the slice touches threading-sensitive code paths

## Minimal helper work required for this gate

The smallest reliable infrastructure slice is:

1. add `tools/codegen/verify_foundation_validation_gate.sh` as the documented `foundation` build/test entrypoint
2. label the existing `tests/foundation` CTest registrations with `foundation` so the helper can use `ctest -L foundation` deterministically
3. keep broader preservation diff tooling out of this task; document it as follow-on work once emitter ownership begins

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

## Concise next-phase plan after this inventory task

1. **Validate the shared framework on `project_foundation.xml`.** Add loader/IR/backend tests that prove the generic modules can traverse `foundation` metadata without `common`-specific assumptions.
2. **Add a scripted `foundation` verification loop.** Introduce a `generate -> build -> test -> restore` helper comparable to the existing `common` gate so emitter work has a repeatable safety rail.
3. **Pilot a tiny low-risk C slice.** Limit the first emitter change to enums plus one or two small utility classes/modules so output-target routing and preservation logic can be proven cheaply.
4. **Broaden only after the gates pass.** Move next into serializer/list surfaces, and defer implementor-heavy crypto families plus `group session*` until the shared framework and preservation tooling are stable.

This keeps the sequence aligned with ADR 0003: generalize once, verify on a second project root, then grow coverage without reintroducing project hardcodes.

## Recommended first extraction after this planning task

Start with the loader split from `common_source.py`.

Why this first:

- it has the cleanest shared boundary because XML parsing, project-root loading, and dependency graph resolution are already reusable across projects
- `common_ir.py` and `common_direct_c.py` both depend on loader concepts, so extracting loader primitives first reduces rename churn in the later steps
- it gives `foundation` an early proof point (`project_foundation.xml` can load through shared code) without yet committing to backend-specific emitter behavior

The first concrete implementation task should therefore extract generic project-graph loading into shared modules while keeping `project_common_path()` / `load_project_common()` as compatibility wrappers.

## Recommended first implementation slice after inventory

Start `foundation` emitter work with **enums plus one small utility/value family**:

- primary candidates: `status`, `asn1 tag`, `alg id`, `oid id`, `group msg type`, `cipher state`
- optional companion classes/modules once enum emission is stable: `error`, `base64`, `oid`, `pem title`, or `group session typedefs`

Why this slice first:

- it exercises project-rooted loading on real `foundation` entities
- it verifies prefix/namespace/path routing for `vscf_*` outputs
- it keeps preservation risk low because the files are comparatively small and test coverage already exists for nearby utility behavior
- it avoids the deepest dependency trees (`implementor_*`, key hierarchies, protobuf-backed `group session*`, and post-quantum flows)

Concretely, the first implementation task after this plan should be:

1. prove `project_foundation.xml` loads through the shared framework
2. add the `foundation` generate/build/test harness
3. migrate enum emission and, if capacity remains, one tiny utility surface such as `error` or `base64`

## Validation status after CG-017

The shared project-rooted framework is now explicitly proven on `project_foundation.xml` at the metadata/loading layer.

What is now validated:

- `load_named_project_source("foundation")` can load the top-level project XML, preserve `foundation` metadata (`vscf`, `VSCFoundation`, `virgil crypto foundation`), and resolve the shared core modules (`assert`, `library`, `memory`, `atomic`) even when local `foundation` modules reference them without repeating `from="shared"`.
- shared module-graph traversal now skips non-source generated-module requirements such as `buffer defs`, which appear in `foundation` requires but do not have standalone source XML files.
- shared IR/output-target lowering produces `foundation`-specific include/work roots and `vscf_*` artifact names for modules, classes, and enums without leaking `common` literals into the routed paths.
- the proof point remains metadata-focused only; no `foundation` emitter ownership was broadened in this task.

Remaining pre-emitter gap carried forward:

- the shared C backend helper in `tools/codegen/project_c_backend.py` still resolves output metadata only for modules/classes, so the likely enum-first emitter slice will need enum-target routing support (or a temporary slice-specific adapter) before implementation begins.

## Expected outcome

After this phase, the codegen framework should expose generic shared modules rather than `common`-named core modules, and it should be shared across at least two project roots:

- `project_common.xml`
- `project_foundation.xml`

with `common` serving as the first validated reference slice and `foundation` serving as the first proof that the design is universal rather than project-specific.

## Current recovery note

The first `foundation` validation-gate task (`CG-018`) produced useful partial work but did not complete cleanly under orchestration. That partial work was preserved on:

- `saved/ssiroshtan-CG-018-20260406T092213`

The immediate next work should therefore:

1. salvage and minimize the useful validation-gate changes from the saved branch
2. finish the gate in a clean, executable form
3. only then resume the first low-risk `foundation` C slice
