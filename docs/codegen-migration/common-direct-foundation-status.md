# Common Direct Foundation Status

This note records the current direct-from-original-model coverage for the foundational `common` entities.

## Direct-from-source coverage

The mixed-mode `common` generator now lowers these directly from original source models or direct source-driven lowering logic:

- `vsc_library`
- `vsc_assert`
- `vsc_memory`
- `vsc_atomic`
- `vsc_data`

## Remaining fallback coverage

The remaining `common` entities still using legacy resolved XML fallback are primarily:

- `vsc_buffer`
- `vsc_buffer_defs`
- umbrella/private aggregation headers such as:
  - `vsc_common_public.h`
  - `vsc_common_private.h`

## Why this matters

This means the new generator now directly owns the foundational building blocks that most of the rest of `common` depends on:

- library/platform-facing C definitions
- assert helpers and macros
- memory helpers
- atomic helpers
- value-type data container

With these direct, the remaining migration surface is more concentrated in the more complex buffer-related API and aggregation headers.

## Compile status

This mixed-mode generator still successfully builds the `common` CMake target using temporary in-place application plus restoration.

## Recommended next step

Move `buffer` and `buffer_defs` off the legacy resolved fallback, then address the remaining aggregation/support headers as needed.
