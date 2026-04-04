# Common Entity Mapping: `assert`

This note captures one representative transformation path for the `common` project.

## Source model

Primary source:
- `codegen/models/shared/module_assert.xml`

The source model defines:

- module: `assert`
- dependency on module `library`
- private/system C includes: `stdio.h`, conditional `assert.h`
- callback: `handler`
- variable: `active handler`
- methods:
  - `change handler`
  - `abort`
  - `trigger`
  - `path basename`
- macros:
  - `file path or name`
  - `internal`
  - `opt`
  - `assert`
  - `safe`
  - `static`
  - `ptr`
  - `null`
  - `alloc`

## Legacy resolved module artifact

Resolved module:
- `codegen/generated/common/module_assert.xml`

At this stage, names are normalized and C-facing identities begin to appear, for example:

- `c_prefix = "vsc"`
- callback and method UIDs are assigned
- arguments are normalized to concrete C-oriented forms
- lineage/ownership metadata is attached

## Legacy resolved C-module artifact

Resolved C module:
- `codegen/generated/common/c_module_vsc_assert.xml`

This artifact contains the information closest to final emitted C output:

- final module name: `vsc_assert`
- output targets:
  - header: `../library/common/include/virgil/crypto/common/vsc_assert.h`
  - source: `../library/common/src/vsc_assert.c`
- concrete C includes
- concrete C macros
- callback signature
- variable declaration/definition details
- public and private method signatures and bodies

## Final checked-in files

- `library/common/include/virgil/crypto/common/vsc_assert.h`
- `library/common/src/vsc_assert.c`

These files preserve:

- non-generated prologue/footer text
- generated middle block
- handwritten/manual regions where applicable

## Why `assert` is a good reference path

`assert` is a useful first analysis target because it includes:

- macros
- callback types
- private variable state
- public and private methods
- generated source code blocks
- conditional include behavior in the legacy model

That makes it a strong test case for:

- source model parsing
- name resolution
- generated block emission
- preservation logic

## Immediate implication for the new architecture

The final generator should be able to do this transformation directly:

```text
module_assert.xml
  -> parsed source model
  -> resolved in-memory IR
  -> emitted vsc_assert.h / vsc_assert.c
```

without requiring `module_assert.xml -> c_module_vsc_assert.xml` to be written to disk.

For now, the legacy resolved C-module remains a useful oracle for parity and reverse engineering.
