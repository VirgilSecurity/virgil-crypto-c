# Common Source to IR Mapping

This document records the first direct source-model to IR step for the new generator.

## Current implementation artifacts

- source loader: `tools/codegen/common_source.py` (compatibility wrapper over shared loader code)
- shared IR mapper: `tools/codegen/project_ir.py`
- `common` IR adapter: `tools/codegen/common_ir.py`
- inspectors:
  - `tools/codegen/inspect_common_source.py`
  - `tools/codegen/inspect_common_ir.py`

## Purpose

This step establishes the direct path:

```text
original common model files
  -> tolerant source loader
  -> normalized source objects
  -> shared typed in-memory IR (`project_ir.py`)
  -> thin `common` compatibility adapter where needed
```

This is the architectural direction we want for the final generator.

## Current scope

The current project-rooted IR covers:

- project `common`
- explicit modules referenced by `project_common.xml`
- transitive dependency modules reached through `<require module="...">`
- classes declared in `project_common.xml`
- enums declared in the project model when present
- enough normalized shape to inspect and reason about:
  - project identity (`name`, `namespace`, `framework`, `prefix`)
  - source/work roots and include namespace
  - typed feature/module/class/enum refs
  - module/class/enum source paths and origin metadata
  - requires and C includes as typed refs instead of raw ad hoc dicts
  - callbacks, methods, variables, constructors, struct fields, and enum constants
  - derived C output metadata (`c_symbol`, header/source basenames, include/source paths, generated artifact paths, once guards, visibility)

## Important limitation

The IR mapping is now structurally normalized and carries the project-derived metadata needed for the next C-backend step, but it is still not a full replacement for every legacy semantic rule.

That means it does **not** yet reproduce all code-shape decisions that the legacy GSL pipeline performs.

Examples of deferred work:

- C identifier derivation (`vsc_*` naming)
- C callback/type lowering
- detailed pointer/reference lowering
- declaration/definition placement rules
- cross-entity macro substitution rules like `.(...)`

## Why this step still matters

Even with that limitation, this step is valuable because it:

- proves the new generator can read original `common` source models
- avoids dependence on resolved XML for initial architecture work
- provides a typed place to encode semantic rules incrementally
- gives us a direct bridge toward emitting `common` from original XML

## Useful inspection commands

```bash
python3 tools/codegen/inspect_common_source.py
python3 tools/codegen/inspect_common_source.py --module assert
python3 tools/codegen/inspect_common_source.py --class-name data

python3 tools/codegen/inspect_common_ir.py
python3 tools/codegen/inspect_common_ir.py --module assert
python3 tools/codegen/inspect_common_ir.py --class-name data
```

## Shared IR/output-target layer

The IR/output-target logic is now owned by the generic `tools/codegen/project_ir.py` layer.
That shared module is responsible for:

- reusable IR dataclasses (`IRProject`, `IRModule`, `IRClass`, `IREnum`, `IROutputTarget`, etc.)
- generic lowering from `ProjectSource` / `ModuleSource` / `ClassSource` / `EnumSource`
- output-target derivation from project metadata such as `namespace`, `prefix`, `path`, `work_path`, and entity attrs
- keeping project names, include paths, generated XML names, and prefix-derived symbols model-driven instead of backend-literal-driven

`tools/codegen/common_ir.py` remains only as a thin compatibility layer exporting the old `common`-named entrypoint (`project_common_to_ir()`) while delegating to the shared `project_to_ir()` implementation.

## Current guarantees for backends

Backends can now rely on the IR to provide:

- the resolved `common` project graph, including transitive dependency modules
- explicit project naming metadata instead of only raw project attrs
- per-entity output targeting information derived from project metadata rather than hardcoded per-module literals
- typed containers for methods, variables, struct fields, and enum constants that preserve source descriptions and attrs for later lowering

## Progress update

The project-rooted IR now exists as an explicit stage between the source loader and the direct C backend work.

## Recommended next step

The project-rooted IR stage is now established for the `common` proving-ground slice and re-homed into a shared layer that can be reused by later projects.

The next follow-up work should focus on:

1. tightening parity/comparison tooling for the mixed-mode bootstrap
2. hardening parser/resolver behavior using `common` as the reference project-rooted slice
3. porting remaining support/build emitters that still sit outside the direct C backend path
4. selecting the next migration target beyond `library/common`

Legacy resolved artifacts remain useful here as parity/reference material, but not as the intended runtime source for the regularized `common` C backend.
