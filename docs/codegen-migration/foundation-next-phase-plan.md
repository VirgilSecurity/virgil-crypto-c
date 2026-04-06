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

## Verification philosophy

Use tests at each layer:

- project graph loader tests
- IR/output-target tests
- backend resolution tests
- project-specific build/preservation verification

Do not rely on compile success alone as proof that the architecture is correct.

## Expected outcome

After this phase, the codegen framework should expose generic shared modules rather than `common`-named core modules, and it should be shared across at least two project roots:

- `project_common.xml`
- `project_foundation.xml`

with `common` serving as the first validated reference slice and `foundation` serving as the first proof that the design is universal rather than project-specific.
