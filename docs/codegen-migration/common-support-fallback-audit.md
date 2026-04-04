# Common Support Fallback Audit

This note audits the remaining non-buffer support and aggregation artifacts around the `common` mixed-mode bootstrap.

## Scope

This audit focuses on support outputs adjacent to the buffer-family migration boundary:

- `vsc_common_public.h`
- `vsc_common_private.h`

It intentionally excludes the primary `vsc_buffer` migration surface, which is now direct and tracked historically in `common-buffer-migration-plan.md`.

## What the active bootstrap actually does

`tools/codegen/common_bootstrap.py` currently special-cases direct lowering for these resolved-module names:

- `c_module_vsc_data.xml`
- `c_module_vsc_assert.xml`
- `c_module_vsc_library.xml`
- `c_module_vsc_atomic.xml`
- `c_module_vsc_memory.xml`
- `c_module_vsc_buffer_defs.xml`
- `c_module_vsc_buffer.xml`

Everything else goes through `ET.parse(xml_path).getroot()` if a resolved `c_module_*.xml` file exists.

The checked-in umbrella headers themselves currently contain empty `@generated` blocks, so their meaningful include lists are effectively static checked-in content today rather than actively generated direct-lowering logic.

## Classification

| Output | Current state | Classification | Rationale |
|---|---|---|---|
| `vsc_common_public.h` | Thin umbrella include list for public `common` headers; checked-in file has an empty generated block. | **Static checked-in support header** | After `vsc_buffer` became direct, the remaining include list is still static checked-in project-composition glue. There is no meaningful generated block left to migrate in the current slice. |
| `vsc_common_private.h` | Thin umbrella include list for private `common` headers; checked-in file has an empty generated block. | **Static checked-in support header** | Its include list is compile-sensitive but structurally trivial, and the checked-in file already represents the intended long-term shape for this slice. |

## Notable non-findings

- No additional non-buffer support/aggregation outputs were found in the active `common_bootstrap.py` routing.
- `vsc_platform.h.in` appears in historical bootstrap status notes, but the current bootstrap implementation does not contain dedicated platform/support emitter logic for it.
- Support/build files such as `features.cmake`, `definitions.cmake`, and `module.modulemap` remain outside this bootstrap and outside this audit's migration boundary.

## Final disposition

Now that both `vsc_buffer_defs` and `vsc_buffer` are direct, the umbrella-header question has a simple answer:

1. `vsc_common_public.h` and `vsc_common_private.h` do not currently need meaningful generated behavior beyond their checked-in include lists
2. their empty `@generated` blocks mean there is no active resolved-XML fallback dependency to close in this task area
3. they should therefore remain documented as stable checked-in support headers unless a future broader project-composition emitter is introduced for a separate reason

The key outcome is to keep these headers from expanding the `common` migration scope while still making their end state explicit.

## Short answer: what happens right after `buffer_defs` and `buffer`

That status sweep is now complete:

- the umbrella headers have been classified as documented static checked-in support headers
- the `common` core entity migration no longer has an active fallback surface inside this Taskplane slice
- remaining work after `common` should focus on parity tooling and the next migration target, not on reopening `common` implementation scope
