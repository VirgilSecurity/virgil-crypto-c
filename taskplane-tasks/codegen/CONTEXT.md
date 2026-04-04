# Codegen — Context

**Last Updated:** 2026-04-04
**Status:** Active
**Next Task ID:** CG-011

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

The `common` generator remains mixed mode at the whole-bootstrap level, but the current Taskplane `common` entity slice is now effectively closed and the remaining buffer-family migration batch has completed successfully.

Completed direct-lowered core entities in this slice:

- `vsc_library`
- `vsc_assert`
- `vsc_memory`
- `vsc_atomic`
- `vsc_data`
- `vsc_buffer_defs`
- `vsc_buffer`

There is no longer a core `common` entity in this slice that still requires legacy resolved-XML fallback at runtime.

Related support headers:

- `vsc_common_public.h`
- `vsc_common_private.h`

remain checked-in umbrella headers with empty generated blocks and are now tracked as static support artifacts rather than as active fallback migration work.

Current next-phase focus:

- regularize the architecture around `project_common.xml` as the top-level source of truth
- resolve a full `common` project graph before backend lowering
- build a language-neutral IR first
- derive the C backend from model metadata instead of project-specific hardcodes
- keep the current handwritten-code preservation contract for C

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
| Architecture ADR | `docs/adr/0002-project-rooted-codegen-pipeline.md` |

---

## Conventions

- Preserve handwritten code outside generated blocks.
- Do not commit generated changes under `library/common/**`.
- Update migration docs when direct coverage changes.
- Prefer direct lowering from original models over extending resolved-XML dependency.
- Use resolved XML only for parity reference, reverse engineering, or fixtures during migration.

---

## Planned Task Sequence

Completed:

- `CG-001` — buffer family migration spec and dependency map ✅
- `CG-002` — direct lowering for `vsc_buffer_defs` ✅
- `CG-003` — support-file fallback audit and remaining-common plan ✅
- `CG-004` — direct lowering for `vsc_buffer` ✅
- `CG-005` — final common status/docs sweep after buffer migration ✅

Next architecture phase:

- `CG-006` — tests and fixtures for project-rooted `common` graph loading
- `CG-007` — project-rooted model graph loader for `project_common.xml`
- `CG-008` — normalized IR from the resolved project graph
- `CG-009` — model-driven C resolution from IR without hardcoded project metadata
- `CG-010` — bootstrap integration, preservation validation, and regression docs

---

## Technical Debt / Future Work

- Reduce remaining project-specific hardcodes in `tools/codegen/common_direct_c.py`.
- Make `project_common.xml` and its referenced model graph the explicit entrypoint for `common` generation.
- Tighten automated tests around graph loading, IR construction, and C resolution from model metadata.
- Add parity/tooling checks that make mixed-mode formatting differences easier to review.
- Revisit umbrella-header generation only if a broader project-composition emitter is introduced for reasons beyond the completed `common` migration slice.
