# Common Support Fallback Audit

This note audits the remaining non-buffer support and aggregation artifacts around the `common` mixed-mode bootstrap.

## Scope

This audit focuses on support outputs adjacent to the buffer-family migration boundary:

- `vsc_common_public.h`
- `vsc_common_private.h`

It intentionally excludes the primary `vsc_buffer` migration surface, which is tracked separately in `common-buffer-migration-plan.md`.

## What the active bootstrap actually does

`tools/codegen/common_bootstrap.py` currently special-cases direct lowering for these resolved-module names:

- `c_module_vsc_data.xml`
- `c_module_vsc_assert.xml`
- `c_module_vsc_library.xml`
- `c_module_vsc_atomic.xml`
- `c_module_vsc_memory.xml`
- `c_module_vsc_buffer_defs.xml`

Everything else goes through `ET.parse(xml_path).getroot()` if a resolved `c_module_*.xml` file exists.

The checked-in umbrella headers themselves currently contain empty `@generated` blocks, so their meaningful include lists are effectively static checked-in content today rather than actively generated direct-lowering logic.

## Classification

| Output | Current state | Classification | Rationale |
|---|---|---|---|
| `vsc_common_public.h` | Thin umbrella include list for public `common` headers; checked-in file has an empty generated block. | **Deferred direct candidate** | It is project-composition glue, not entity-specific lowering. The only moving piece relevant to this migration is the presence of `vsc_buffer.h`, so it is cleaner to revisit after `vsc_buffer` is direct. |
| `vsc_common_private.h` | Thin umbrella include list for private `common` headers; checked-in file has an empty generated block. | **Deferred direct candidate** | It is compile-sensitive but structurally trivial. Its most meaningful dependency edge is `vsc_buffer_defs.h`, which is already direct, but the final ownership decision is clearer once `vsc_buffer` itself also leaves fallback mode. |

## Notable non-findings

- No additional non-buffer support/aggregation outputs were found in the active `common_bootstrap.py` routing.
- `vsc_platform.h.in` appears in historical bootstrap status notes, but the current bootstrap implementation does not contain dedicated platform/support emitter logic for it.
- Support/build files such as `features.cmake`, `definitions.cmake`, and `module.modulemap` remain outside this bootstrap and outside this audit's migration boundary.

## Immediate post-buffer recommendation

Once both `vsc_buffer_defs` and `vsc_buffer` are direct:

1. re-check whether the umbrella headers still need any generated behavior at all
2. if they do, add a tiny direct/project-composition emitter
3. otherwise, explicitly document them as stable checked-in umbrella headers and remove any stale language that implies meaningful fallback ownership

The key outcome is to keep these headers from expanding the `buffer` migration scope prematurely while still making their end state explicit.

## Short answer: what happens right after `buffer_defs` and `buffer`

Immediately after the two core buffer tasks are direct, the next action should be a very small ownership cleanup:

- verify whether `vsc_common_public.h` and `vsc_common_private.h` need any generated content beyond their static include lists
- choose one end state explicitly:
  - **tiny direct emitter** if project-composition generation is still desired, or
  - **documented static checked-in headers** if the empty generated blocks remain the correct long-term shape
- update status docs so only real active fallback surfaces are described as fallback

In other words: do **not** open another large migration track after `buffer`; close the boundary by making the umbrella-header ownership explicit and keep the remaining work intentionally tiny.
