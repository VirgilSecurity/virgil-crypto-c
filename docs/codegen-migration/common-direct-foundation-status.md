# Common Direct Foundation Status

This note records the current direct-from-original-model coverage for the foundational `common` entities.

## Direct-from-source coverage

The mixed-mode `common` generator now lowers these directly from original source models or direct source-driven lowering logic:

- `vsc_library`
- `vsc_assert`
- `vsc_memory`
- `vsc_atomic`
- `vsc_data`
- `vsc_buffer_defs`
- `vsc_buffer`

## Remaining fallback coverage

There is no longer a core `common` entity in this migration slice that still requires legacy resolved XML fallback at runtime.

The two umbrella headers adjacent to this work:

- `vsc_common_public.h`
- `vsc_common_private.h`

remain important support artifacts, but their checked-in `@generated` blocks are empty. For status tracking, they should now be treated as stable checked-in umbrella headers rather than as active fallback coverage.

## Why this matters

This means the new generator now directly owns the foundational building blocks that most of the rest of `common` depends on:

- library/platform-facing C definitions
- assert helpers and macros
- memory helpers
- atomic helpers
- value-type data container

With these direct, the `common` direct-lowering migration surface for core entities is effectively complete.

## Compile status

This mixed-mode generator still successfully builds the `common` CMake target using temporary in-place application plus restoration.

## Recommended next step

Use this completed `common` slice as the baseline for follow-on parser/resolver and parity work, while keeping the umbrella headers documented as static checked-in support artifacts unless a concrete future need for project-composition generation appears.
