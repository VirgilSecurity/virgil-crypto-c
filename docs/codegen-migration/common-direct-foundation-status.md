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

Related support headers still not directly owned by a dedicated project-composition emitter are:

- `vsc_common_public.h`
- `vsc_common_private.h`

These umbrella headers are important migration follow-up items, but in the current checked-in files their `@generated` blocks are empty, so they are better treated as deferred support artifacts than as a large active fallback surface.

## Why this matters

This means the new generator now directly owns the foundational building blocks that most of the rest of `common` depends on:

- library/platform-facing C definitions
- assert helpers and macros
- memory helpers
- atomic helpers
- value-type data container

With these direct, the remaining migration surface is no longer the buffer API itself; it is now the much smaller umbrella-header ownership cleanup.

## Compile status

This mixed-mode generator still successfully builds the `common` CMake target using temporary in-place application plus restoration.

## Recommended next step

Decide whether the umbrella headers need a tiny direct emitter or can remain documented static checked-in artifacts, then update the status docs so only real remaining fallback/ownership gaps are described.
