# Codegen Model Spec for `common` (Pragmatic Migration View)

This document describes the legacy codegen model format as it is used by the `common` library migration work.

It is **not** a full formal specification of the entire historical DSL.
Instead, it documents the subset and conventions that matter for implementing the new C-only generator for `library/common`.

## Sources of truth

There are two kinds of source material for understanding the model language:

1. historical schema/reference docs already in the repo, especially:
   - `docs/project.md`
   - `docs/module.md`
   - `docs/class.md`
2. the actual model files under:
   - `codegen/models/shared/`
   - `codegen/models/project_common/`
   - `codegen/models/project_common/project_common.xml`

For the migration, **actual model files take precedence over historical docs** if they disagree.

## Important constraint: the source format is XML-like, not always strict XML

The model files are intended to look like XML, but they are not always well-formed XML as parsed by a standard XML parser.

Example issue found during implementation:

- `codegen/models/shared/module_atomic.xml` contains raw `&` inside `<code>` blocks
- that makes the file invalid for a normal XML parser without preprocessing

### Practical implication

The new parser for legacy source models must be tolerant.
It should treat certain regions, especially `<code>...</code>`, as DSL text rather than assuming strict XML escaping.

### Recommendation

The parser should support a preprocessing stage that safely protects or normalizes raw code blocks before XML parsing.

## Project-level model for `common`

Primary file:
- `codegen/models/project_common/project_common.xml`

Example responsibilities of the project file:

- defines project metadata
- declares the project prefix (`vsc`)
- references shared modules used by `common`
- references classes defined in `project_common`
- may declare features

### Key attributes used by migration

- `name`
- `brief`
- `namespace`
- `framework`
- `prefix`
- `path`
- `work_path`
- `wrappers`

### Key child elements used by migration

- `<module name="..." from="shared"/>`
- `<class name="..."/>`
- `<feature ...>`

## Module model

For `common`, shared modules live under:
- `codegen/models/shared/module_*.xml`

Examples:
- `module_assert.xml`
- `module_library.xml`
- `module_memory.xml`
- `module_atomic.xml`

### Key module elements relevant for C generation

- `<require ...>`
- `<c_include ...>`
- `<callback ...>`
- `<variable ...>`
- `<method ...>`
- `<macros ...>`
- `<macroses ...>`
- narrative text directly inside the element

### Notes

- module bodies often include free-form descriptive text
- many names are logical names, not yet final C identifiers
- `<code>` blocks may contain macro placeholders such as `.(...)`

## Class model

For `common`, project-local classes live under:
- `codegen/models/project_common/class_*.xml`

Examples:
- `class_data.xml`
- `class_buffer.xml`

### Key class elements relevant for C generation

- `<property ...>`
- `<variable ...>`
- `<method ...>`
- `<constructor ...>`
- narrative text directly inside the element

### Important attributes seen in practice

- class-level:
  - `name`
  - `context`
  - `lifecycle`
  - `is_value_type`
- member-level:
  - `name`
  - `type`
  - `class`
  - `callback`
  - `access`
  - `is_reference`
  - `declaration`
  - `definition`
  - `visibility`
  - `is_const`
  - `nodiscard`

## Common nested elements

### `<argument>`
Used inside callbacks, methods, and constructors.

Important attributes:
- `name`
- `type`
- `class`
- `callback`
- `access`
- `is_reference`

May contain:
- `<string .../>`
- `<array .../>`

### `<return>`
Used inside callbacks and methods.

Important attributes:
- `type`
- `class`
- `access`
- `is_reference`

May contain:
- `<string .../>`
- `<array .../>`

### `<code>`
Contains generation-oriented DSL text.

Important attributes:
- `lang`
- `type`

Observed realities:
- code text can contain raw `&`
- code text can contain backslashes and preprocessor directives
- code text can contain macro substitutions like `.(c_class_assert_method_trigger)`

### `<string>`
Refines string-like semantics for an argument/return/property/value.

Important attributes seen in practice:
- `length`
- `access`

### `<array>`
Refines array-like semantics for an argument/return/property/value.

Important attributes seen in practice:
- `length`
- `access`

### `<value>`
Used inside variables.

Important attributes:
- `value`
- plus type-related metadata in some cases

## Semantic layers in the legacy pipeline

The old generator effectively has multiple layers:

1. **source models**
   - project/module/class XML under `codegen/models/...`
2. **resolved logical models**
   - e.g. `module_*.xml` in `codegen/generated/common`
3. **resolved C-module models**
   - e.g. `c_module_vsc_*.xml`
4. **final emitted C files**
   - headers/sources under `library/common`

The new generator should ultimately do this directly:

```text
source models -> in-memory IR -> final C output
```

without requiring layers 2 and 3 to be written to disk.

## What the new parser must preserve for `common`

At minimum, the new parser/resolver for `common` must preserve:

- project/module/class membership
- descriptive text used in emitted comments
- method/constructor/callback signatures
- pointer/reference semantics from `string`, `array`, and `is_reference`
- visibility/declaration/definition distinctions
- macro/code bodies as literal source content
- dependency relationships such as `require module="library"`

## Recommended parser strategy for `common`

### Step 1 — tolerant source loader
Build a tolerant loader that can parse the `common` source-model subset even when `<code>` blocks contain raw text that is not strict XML-safe.

### Step 2 — normalized source model
Convert project/module/class files into Python source-model objects.

### Step 3 — typed IR
Resolve names and semantics into a generator-oriented IR for C emission.

### Step 4 — direct C emission
Emit `library/common` headers/sources without relying on disk-written resolved XML.

## Scope boundary

This spec is currently scoped to:

- project `common`
- C generation only

It does not yet try to fully specify:

- wrapper generation
- all other projects (`foundation`, `pythia`, `phe`, `ratchet`)
- every DSL feature supported historically by GSL

## Next recommended documentation work

After this pragmatic spec, the next useful docs are:

1. a tolerant parsing note for `<code>` blocks and legacy XML-like quirks
2. a direct source-to-IR mapping for one shared module (`assert`) and one class (`data`)
3. a pointer/reference semantics table for C emission
