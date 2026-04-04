# Codegen — Context

**Last Updated:** 2026-04-04
**Status:** Active
**Next Task ID:** CG-006

---

## Ownership

This task area owns the replacement of the legacy iMatix/GSL-based generator with a new maintainable generator.

Current project scope for Taskplane work:

- C generation only
- `library/common` only
- preserve handwritten/manual code outside generated sections
- keep original source models under `codegen/models/**` as the long-term source of truth

---

## Current State

The `common` generator is already in mixed mode.

Direct-from-source or direct source-driven coverage currently includes:

- `vsc_library`
- `vsc_assert`
- `vsc_memory`
- `vsc_atomic`
- `vsc_data`

Legacy resolved-XML fallback still remains primarily around:

- `vsc_buffer`
- `vsc_buffer_defs`
- aggregation/support headers such as `vsc_common_public.h` and `vsc_common_private.h`

The compile gate for this area is:

```bash
bash tools/codegen/build_common_with_new_codegen.sh
```

This script is allowed to apply generated output temporarily into the repo, build `common`, and restore generated C/header files afterward.

---

## Key Files

| Category | Path |
|----------|------|
| Task area | `taskplane-tasks/codegen/` |
| Main bootstrap generator | `tools/codegen/common_bootstrap.py` |
| Direct lowering logic | `tools/codegen/common_direct_c.py` |
| Source model loader | `tools/codegen/common_source.py` |
| IR mapping | `tools/codegen/common_ir.py` |
| Build / verification | `tools/codegen/build_common_with_new_codegen.sh` |
| Migration overview | `docs/codegen-migration/README.md` |
| Roadmap | `docs/codegen-migration/roadmap.md` |
| Foundation status | `docs/codegen-migration/common-direct-foundation-status.md` |

---

## Conventions

- Preserve handwritten code outside generated blocks.
- Do not commit generated changes under `library/common/**`.
- Update migration docs when direct coverage changes.
- Prefer direct lowering from original models over extending resolved-XML dependency.
- Use resolved XML only for parity reference, reverse engineering, or fixtures during migration.

---

## Planned Task Sequence

- `CG-001` — buffer family migration spec and dependency map
- `CG-002` — direct lowering for `vsc_buffer_defs`
- `CG-003` — support-file fallback audit and remaining-common plan
- `CG-004` — direct lowering for `vsc_buffer`
- `CG-005` — final common status/docs sweep after buffer migration

---

## Technical Debt / Future Work

- Reduce remaining dependence on resolved XML after buffer migration.
- Consider whether aggregation headers should become direct outputs or remain thin derived/fallback artifacts.
- Tighten parity/formatting checks after compile-stable direct lowering is complete.
