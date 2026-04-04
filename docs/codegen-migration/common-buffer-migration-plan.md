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

That leaves the remaining fallback surface concentrated in `vsc_buffer` and thin aggregation headers.

## Current migration map

| Output | Current source of truth | Current bootstrap behavior | Notes |
|---|---|---|---|
| `vsc_buffer_defs.h` | `codegen/models/project_common/class_buffer.xml` plus two runtime support fields (`self_dealloc_cb`, `refcnt`) that are currently synthesized directly in the Python generator. | **Direct** via `build_direct_buffer_defs_c_module()` in `tools/codegen/common_direct_c.py`. | Thin private support header; compile-sensitive because many downstream libraries include it. The private layout no longer depends on resolved `c_module` XML at runtime. |
| `vsc_buffer_defs.c` | Same effective source as `vsc_buffer_defs.h`. | **Direct** via the same builder, with an intentionally empty generated source block. | Parity risk stays mostly preservation/skeleton-related because the generated body remains empty. |
| `vsc_buffer.h` | `codegen/models/project_common/class_buffer.xml` | Falls back through legacy resolved XML path. | Public API surface is almost entirely generated from the class model. |
| `vsc_buffer.c` | `codegen/models/project_common/class_buffer.xml` plus preserved handwritten implementation outside `@generated`. | Falls back through legacy resolved XML path for the generated block only; manual body stays in the checked-in file skeleton. | Largest remaining `common` migration slice because generated and handwritten code meet in one file. |
| `vsc_common_public.h` / `vsc_common_private.h` | Support/aggregation includes derived from project composition. | Not directly owned by a dedicated emitter today; the checked-in files currently carry empty generated blocks. | Thin support artifacts; should be handled after the core buffer family is direct. |

## Recommended execution order

1. **`vsc_buffer_defs` first (`CG-002`)** — complete
   - The private struct definition and paired thin source file now come from direct Python lowering.
   - The implementation stays intentionally narrow and does not widen scope to umbrella headers.
   - This de-risks `vsc_buffer` by making its private type layout explicit in the new direct path before the larger class migration.
2. **`vsc_buffer` second (`CG-004`)**
   - Lower the generated API declarations in `vsc_buffer.h` and the generated lifecycle/refcount block in `vsc_buffer.c` from `class_buffer.xml`.
   - Preserve all handwritten code outside `@generated` exactly as the bootstrap does today.
   - Keep any remaining fallback usage explicit and temporary.
3. **Support-header follow-up after both core tasks (`CG-003` and/or `CG-005`)**
   - Revisit `vsc_common_public.h` and `vsc_common_private.h` once `buffer_defs` and `buffer` are direct.
   - Treat these as thin include aggregators whose end state can be decided with the smaller migration boundary visible.
   - Prefer either a tiny direct/project-composition emitter or an explicit decision to keep them as static checked-in umbrella headers; avoid implying a large resolved-XML dependency if the generated blocks stay empty.

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
- In a clean worktree, the bootstrap still expects legacy `codegen/generated/common/c_module_vsc_buffer*.xml`, but those resolved XML artifacts are gitignored and not committed; follow-up implementation tasks should treat them as reference/runtime artifacts only.
- `vsc_buffer_defs` behaves as a support artifact for `buffer`, not as an independently modeled public entity.
- The new direct `vsc_buffer_defs` path reconstructs the private layout from `class_buffer.xml` and injects the runtime support fields (`self_dealloc_cb`, `refcnt`) explicitly in Python rather than reading resolved XML.
- `vsc_buffer.c` is constrained by preservation semantics: only the lifecycle/refcount block is generated, while most operational methods remain outside the generated region and must be preserved exactly.

## Remaining `vsc_buffer` follow-up risks

- The private `vsc_buffer_t` layout is now direct, but `vsc_buffer.h` and the generated lifecycle section in `vsc_buffer.c` still depend on the fallback path.
- `class_buffer.xml` does not spell out the runtime support fields used by ownership/refcount handling, so the future `vsc_buffer` direct-lowering task must continue to respect the synthesized `self_dealloc_cb` / `refcnt` contract introduced by `vsc_buffer_defs`.
- Formatting/comment parity for `vsc_buffer_defs` is compile-safe but intentionally not byte-for-byte identical to legacy resolved output; `CG-004` should avoid coupling to exact legacy whitespace while keeping API/layout parity intact.
- The main build gate still proves compile safety, but clean worktrees may lack checked-in `codegen/generated/common/c_module_vsc_buffer*.xml`; any explicit bootstrap smoke checks for `vsc_buffer` should use temporary fixtures rather than assuming committed resolved XML exists.
