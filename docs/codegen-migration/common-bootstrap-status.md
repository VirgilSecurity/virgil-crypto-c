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

The bootstrap script currently generates `common` header/source outputs discovered from resolved `c_module_*.xml` inputs into `build/new-codegen-common/` by rewriting checked-in file skeletons under:

- `library/common/include/...`
- `library/common/src/...`

Its active direct-routing special cases are currently limited to `vsc_library`, `vsc_assert`, `vsc_memory`, `vsc_atomic`, `vsc_data`, `vsc_buffer_defs`, and `vsc_buffer`.

## Current status

### Successes
- the new Python bootstrap produces the `common` C header/source tree in a separate destination
- it preserves the existing non-generated file sections by reusing the checked-in file skeletons
- it demonstrates a generic pass over resolved `c_module` XML rather than a one-off file copier
- it can now be applied onto the real `library/common` files temporarily and the `common` CMake target builds successfully
- it now directly lowers the foundational `common` entities from original source models or direct source-driven lowering logic: `vsc_library`, `vsc_assert`, `vsc_memory`, `vsc_atomic`, `vsc_data`, `vsc_buffer_defs`, and `vsc_buffer`
- the `vsc_buffer` direct path preserves the current generated-block replacement workflow by regenerating only the generated header section and lifecycle/refcount source block while leaving the handwritten source body intact
- the previously open umbrella-header follow-up has now been closed in documentation: `vsc_common_public.h` and `vsc_common_private.h` are treated as stable checked-in support headers whose generated blocks are empty, not as meaningful active direct-routing or resolved-XML fallback surfaces

### Known limitations
- output is not yet parity-clean against the checked-in `common` library
- remaining differences are largely formatting and layout, with some serialization details still needing refinement
- support/build files such as:
  - `features.cmake`
  - `definitions.cmake`
  - `module.modulemap`
  are not part of this bootstrap yet
- this bootstrap still reads legacy resolved XML for any still-unmigrated outputs that may appear in future broader migration work; however, within the current `common` Taskplane slice the foundational entities (`vsc_library`, `vsc_assert`, `vsc_memory`, `vsc_atomic`, `vsc_data`, `vsc_buffer_defs`, and `vsc_buffer`) now come from original models/direct synthesis instead of resolved `c_module` XML

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

1. reduce formatting/signature serialization differences in the bootstrap emitter where they still create review noise
2. add or tighten comparison/parity checks for selected `common` files
3. use the now-complete `common` direct-lowering boundary as the reference slice for the next migration area rather than reopening `common` entity implementation work
4. keep documenting any broader-generator surfaces that still rely on resolved XML so the post-`common` plan stays explicit
