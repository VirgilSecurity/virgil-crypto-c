# Common Direct Assert Status

This note records the direct-from-original-model generation slice for `assert` in the `common` project.

## Scope

Current direct generation target:

- `assert` / `vsc_assert`

Source of truth:

- `codegen/models/shared/module_assert.xml`
- project context from `codegen/models/project_common/project_common.xml`

Implementation:

- `tools/codegen/common_direct_c.py`

## What direct lowering covers

For `assert`, the direct path now lowers from original source models into the generated C-module representation used by the bootstrap emitter.

It covers:

- public macros
- callback type
- generated private variable declaration/definition
- public generated methods
- private generated helper method (`vsc_assert_path_basename`)
- include set needed by the generated blocks

## Why `assert` matters

`assert` is a stronger direct-generation target than `data` because it exercises more of the legacy model semantics:

- macro lowering
- callback lowering
- generated source bodies
- public/private method split
- private generated helper functions

## Current status

The mixed-mode `common` generator now lowers these directly from original source models or direct source-driven lowering logic:

- `vsc_library`
- `vsc_assert`
- `vsc_memory`
- `vsc_atomic`
- `vsc_data`

and falls back to legacy resolved XML for the remaining `common` entities.

This mixed mode still builds the `common` CMake target successfully.

## Remaining work

The rest of `common` still needs to be moved off legacy resolved XML.
The next logical targets are:

- `library`
- `memory`
- `atomic`
- then `buffer`

`buffer` should come later because it has a larger surface and more handwritten implementation around generated declarations.
