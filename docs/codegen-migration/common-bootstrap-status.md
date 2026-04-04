# Common Bootstrap Status

This document records the first executable bootstrap milestone for the new generator effort.

## Goal

Prove that a Python-based generator can regenerate the `common` library surface into a separate output tree without modifying existing source files.

## Current bootstrap approach

Current implementation:

- script: `tools/codegen/common_bootstrap.py`
- input: legacy resolved `codegen/generated/common/c_module_*.xml`
- output: `build/new-codegen-common/library/common/...`
- strategy: preserve existing file prologue/epilogue and regenerate the `@generated` block in headers/sources

This is explicitly a **bootstrap implementation**, not the intended final architecture.

It already follows the required preservation contract for C generation:

- model-driven generated block rewriting
- preservation of existing manual/non-generated file regions

## Why this exists

It proves several important things early:

1. Python can drive the generation flow in this repository.
2. The generated/manual section replacement strategy is workable.
3. The `common` library is a practical first target for migration.
4. The emitter surface can be explored without modifying checked-in code.

## What is currently generated

The bootstrap script currently generates these `common` outputs into `build/new-codegen-common/`:

- headers under `library/common/include/...`
- sources under `library/common/src/...`
- `vsc_platform.h.in`

It currently writes 16 files for the `common` project.

## Current status

### Successes
- the new Python bootstrap produces the `common` C header/source tree in a separate destination
- it preserves the existing non-generated file sections by reusing the checked-in file skeletons
- it demonstrates a generic pass over resolved `c_module` XML rather than a one-off file copier
- it can now be applied onto the real `library/common` files temporarily and the `common` CMake target builds successfully

### Known limitations
- output is not yet parity-clean against the checked-in `common` library
- remaining differences are largely formatting and layout, with some serialization details still needing refinement
- support/build files such as:
  - `features.cmake`
  - `definitions.cmake`
  - `module.modulemap`
  are not part of this bootstrap yet
- this bootstrap still reads legacy resolved XML; the final implementation must move to original XML + in-memory IR

## How to run

Generate into a separate tree:

```bash
python3 tools/codegen/common_bootstrap.py --project common --out build/new-codegen-common
```

Apply directly to the real source tree:

```bash
python3 tools/codegen/common_bootstrap.py --project common --apply
```

Verify diff against current checked-in `common`:

```bash
bash tools/codegen/verify_common_bootstrap.sh
```

Apply to the real tree, build `common`, and automatically restore files afterward:

```bash
bash tools/codegen/build_common_with_new_codegen.sh
```

## Interpretation

This milestone should be treated as:

- **generation success for the `common` library bootstrap path**
- **not yet parity success**
- **not yet the final architecture**

## Next technical steps

1. reduce formatting/signature serialization differences in the bootstrap emitter
2. add a small comparison harness for selected `common` files
3. document one or two representative source-model-to-c-module transformations
4. begin replacing legacy resolved-XML dependence with direct original-XML parsing for the same `common` entities
