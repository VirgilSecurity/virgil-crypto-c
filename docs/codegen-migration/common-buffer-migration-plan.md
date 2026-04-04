# Common Buffer Family Migration Plan

This note captures the remaining direct-lowering plan for the `common` buffer family.

## Scope

Targets in this migration slice:

- `vsc_buffer_defs.h`
- `vsc_buffer_defs.c`
- `vsc_buffer.h`
- `vsc_buffer.c`
- follow-up support headers that still reflect buffer-family fallback output

Current direct coverage already removes legacy resolved-XML dependence for the foundational `common` modules:

- `vsc_library`
- `vsc_assert`
- `vsc_memory`
- `vsc_atomic`
- `vsc_data`

That originally left the remaining fallback/ownership cleanup surface concentrated in the thin aggregation headers rather than the core buffer entities; the follow-up sweep in `CG-005` closes that loop by documenting those headers as static checked-in support artifacts.

## Current migration map

| Output | Current source of truth | Current bootstrap behavior | Notes |
|---|---|---|---|
| `vsc_buffer_defs.h` | `codegen/models/project_common/class_buffer.xml` plus two runtime support fields (`self_dealloc_cb`, `refcnt`) that are currently synthesized directly in the Python generator. | **Direct** via `build_direct_buffer_defs_c_module()` in `tools/codegen/common_direct_c.py`. | Thin private support header; compile-sensitive because many downstream libraries include it. The private layout no longer depends on resolved `c_module` XML at runtime. |
| `vsc_buffer_defs.c` | Same effective source as `vsc_buffer_defs.h`. | **Direct** via the same builder, with an intentionally empty generated source block. | Parity risk stays mostly preservation/skeleton-related because the generated body remains empty. |
| `vsc_buffer.h` | `codegen/models/project_common/class_buffer.xml` plus generator-owned lifecycle naming conventions. | **Direct** via `build_direct_buffer_c_module()` in `tools/codegen/common_direct_c.py`. | Public API declarations now come from the original class model instead of resolved `c_module` XML. |
| `vsc_buffer.c` | `codegen/models/project_common/class_buffer.xml` plus preserved handwritten implementation outside `@generated` and the synthesized `self_dealloc_cb` / `refcnt` contract from `vsc_buffer_defs`. | **Direct** for the generated lifecycle/refcount block via the same builder; handwritten methods remain preserved from the checked-in file skeleton. | The direct path keeps generated-block replacement narrow and intentionally does not regenerate the large manual body. |
| `vsc_common_public.h` / `vsc_common_private.h` | Support/aggregation includes derived from project composition. | Not directly owned by a dedicated emitter today; the checked-in files currently carry empty generated blocks. | Thin support artifacts; `CG-005` documents them as stable checked-in umbrella headers rather than as an active buffer-family fallback surface. |

## Recommended execution order

1. **`vsc_buffer_defs` first (`CG-002`)** — complete
   - The private struct definition and paired thin source file now come from direct Python lowering.
   - The implementation stays intentionally narrow and does not widen scope to umbrella headers.
   - This de-risks `vsc_buffer` by making its private type layout explicit in the new direct path before the larger class migration.
2. **`vsc_buffer` second (`CG-004`)** — complete
   - The generated API declarations in `vsc_buffer.h` and the generated lifecycle/refcount block in `vsc_buffer.c` now come from `class_buffer.xml` through direct lowering.
   - Handwritten code outside `@generated` remains preserved exactly by the existing generated-block replacement strategy.
   - Resolved `c_module_vsc_buffer*.xml` is no longer a runtime requirement for this module.
3. **Support-header follow-up after both core tasks (`CG-003` and `CG-005`)** — complete
   - `CG-003` narrowed the remaining question to the two umbrella headers only.
   - `CG-005` closes the boundary by documenting `vsc_common_public.h` and `vsc_common_private.h` as static checked-in umbrella headers for this slice.
   - The result is that no additional core `common` entity migration step remains open in this buffer-family area.

## Verification and commit-safety expectations

Follow-up implementation tasks should use this verification sequence:

```bash
python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py
bash tools/codegen/build_common_with_new_codegen.sh
```

Execution notes:

- `bash tools/codegen/build_common_with_new_codegen.sh` is the main compile gate for this migration slice.
- That script is allowed to apply generated output temporarily into `library/common/**`, build the `common` target, and restore the checked-in generated files afterward.
- Generated changes under `library/common/**` are verification artifacts only and must not be committed.
- After each implementation task, verify that no temporary generated `library/common/**` changes remain staged before commit.

## Key analysis points

- `class_buffer.xml` is the only first-class original source model in this family under `codegen/models/project_common/`.
- In a clean worktree, direct `vsc_buffer` lowering can now run without legacy `codegen/generated/common/c_module_vsc_buffer*.xml`; those resolved XML artifacts remain useful only as reference material or optional fixtures.
- `vsc_buffer_defs` behaves as a support artifact for `buffer`, not as an independently modeled public entity.
- The new direct `vsc_buffer_defs` path reconstructs the private layout from `class_buffer.xml` and injects the runtime support fields (`self_dealloc_cb`, `refcnt`) explicitly in Python rather than reading resolved XML.
- `vsc_buffer.c` is constrained by preservation semantics: only the lifecycle/refcount block is generated, while most operational methods remain outside the generated region and must be preserved exactly.

## Remaining post-buffer follow-up risks

- `class_buffer.xml` does not spell out the runtime support fields used by ownership/refcount handling, so the direct `vsc_buffer` path must continue to respect the synthesized `self_dealloc_cb` / `refcnt` contract introduced by `vsc_buffer_defs`.
- Formatting/comment parity for `vsc_buffer` and `vsc_buffer_defs` is compile-safe but intentionally not byte-for-byte identical to legacy resolved output; follow-up work should avoid coupling to exact legacy whitespace while keeping API/layout parity intact.
- The former ownership question around `vsc_common_public.h` and `vsc_common_private.h` is now resolved for this slice: they are documented as static checked-in umbrella headers unless a future broader project-composition emitter is introduced.
- Temporary bootstrap smoke checks can use a dummy `c_module_vsc_buffer.xml` path name because the direct route is name-based; no committed resolved XML fixture is required.
