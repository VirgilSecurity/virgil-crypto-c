# Common Direct Data Status

This note records the first direct-from-original-model generation slice for `common`.

## Scope

Current direct generation target:

- `data` / `vsc_data`

Source of truth:

- `codegen/models/project_common/class_data.xml`
- project context from `codegen/models/project_common/project_common.xml`

Implementation:

- `tools/codegen/common_direct_c.py`

## Current approach

The direct path currently constructs a `c_module`-like in-memory structure for `vsc_data` from original source models, without reading the legacy resolved `c_module_vsc_data.xml` as input.

This is an incremental migration strategy:

- direct generation for selected entities
- fallback to legacy resolved XML for the remaining `common` entities

## Why start with `data`

`data` is a good first direct target because:

- it is small
- it has a public struct
- it has a generated variable in the source file
- it has a synthetic generated `ctx_size` method
- most handwritten implementation remains outside the generated block and is therefore preserved by the existing file-skeleton approach

## Current status

The direct path for `data` is implemented as a first lowering prototype.

It is now wired into the working `common` bootstrap path as a mixed-mode generator:

- `vsc_data` is lowered directly from original source models
- the remaining `common` entities still fall back to legacy resolved XML

This mixed mode still builds the `common` CMake target successfully.

It is not yet the whole `common` generator, but it proves the intended architectural move:

```text
original model -> direct lowering -> emitted C generated block
```

## Next step

After `data`, the next best direct target is:

- `assert`

That will exercise:

- macros
- callbacks
- generated function bodies inside the source generated block
- private generated helpers
