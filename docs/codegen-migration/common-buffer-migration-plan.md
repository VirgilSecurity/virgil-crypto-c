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

That leaves the remaining fallback surface concentrated in the buffer family and thin aggregation headers.

## Current migration map

| Output | Current source of truth | Current bootstrap behavior | Notes |
|---|---|---|---|
| `vsc_buffer_defs.h` | Buffer-family semantics ultimately come from `codegen/models/project_common/class_buffer.xml`, but the emitted private struct layout is currently available only through legacy resolved `c_module` output. | Falls back through `tools/codegen/common_bootstrap.py` `ET.parse(...)` path because there is no direct builder for `c_module_vsc_buffer_defs.xml`. | Thin private support header; high compile fan-out because many downstream libraries include it. |
| `vsc_buffer_defs.c` | Same effective source as `vsc_buffer_defs.h`. | Falls back through legacy resolved XML path. | Generated block is effectively empty, so parity risk is mostly preservation/skeleton-related. |
| `vsc_buffer.h` | `codegen/models/project_common/class_buffer.xml` | Falls back through legacy resolved XML path. | Public API surface is almost entirely generated from the class model. |
| `vsc_buffer.c` | `codegen/models/project_common/class_buffer.xml` plus preserved handwritten implementation outside `@generated`. | Falls back through legacy resolved XML path for the generated block only; manual body stays in the checked-in file skeleton. | Largest remaining `common` migration slice because generated and handwritten code meet in one file. |
| `vsc_common_public.h` / `vsc_common_private.h` | Support/aggregation includes derived from project composition. | Still emitted via fallback/resolved path. | Thin support artifacts; should be handled after the core buffer family is direct. |

## Recommended execution order

1. **`vsc_buffer_defs` first (`CG-002`)**
   - Directly lower the private struct definition and its paired thin source file.
   - Keep the implementation intentionally narrow: replace the resolved-XML dependency for `vsc_buffer_defs` without widening scope to umbrella headers.
   - This de-risks `vsc_buffer` by making its private type layout explicit in the new direct path before the larger class migration.
2. **`vsc_buffer` second (`CG-004`)**
   - Lower the generated API declarations in `vsc_buffer.h` and the generated lifecycle/refcount block in `vsc_buffer.c` from `class_buffer.xml`.
   - Preserve all handwritten code outside `@generated` exactly as the bootstrap does today.
   - Keep any remaining fallback usage explicit and temporary.
3. **Support-header follow-up after both core tasks (`CG-003` and/or `CG-005`)**
   - Revisit `vsc_common_public.h` and `vsc_common_private.h` once `buffer_defs` and `buffer` are direct.
   - Treat these as thin include aggregators whose end state can be decided with the smaller fallback boundary visible.

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
- `vsc_buffer.c` is constrained by preservation semantics: only the lifecycle/refcount block is generated, while most operational methods remain outside the generated region and must be preserved exactly.
