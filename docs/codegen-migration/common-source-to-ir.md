# Common Source to IR Mapping

This document records the first direct source-model to IR step for the new generator.

## Current implementation artifacts

- source loader: `tools/codegen/common_source.py`
- IR mapper: `tools/codegen/common_ir.py`
- inspectors:
  - `tools/codegen/inspect_common_source.py`
  - `tools/codegen/inspect_common_ir.py`

## Purpose

This step establishes the direct path:

```text
original common model files
  -> tolerant source loader
  -> normalized source objects
  -> typed in-memory IR
```

This is the architectural direction we want for the final generator.

## Current scope

The first IR pass currently covers:

- project `common`
- shared modules referenced by `project_common.xml`
- classes declared in `project_common.xml`
- enough shape to inspect and reason about:
  - requires
  - C includes
  - callbacks
  - methods
  - variables
  - macros
  - class properties
  - constructors

## Important limitation

The IR mapping is currently structural, not fully semantic.

That means it does **not** yet reproduce all name-resolution and C-lowering rules that the legacy GSL pipeline performs.

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

## Progress update

The first direct semantic lowering is now implemented for:

- `data` / `vsc_data`

and is wired into the mixed-mode `common` bootstrap path.

## Recommended next step

Implement the next semantic lowering rules for:

1. `assert` module
2. then the remaining `common` entities

Then compare that direct IR against the corresponding legacy resolved artifacts:

- `codegen/generated/common/module_assert.xml`
- `codegen/generated/common/c_module_vsc_assert.xml`
- `codegen/generated/common/module_data.xml`
- `codegen/generated/common/c_module_vsc_data.xml`
