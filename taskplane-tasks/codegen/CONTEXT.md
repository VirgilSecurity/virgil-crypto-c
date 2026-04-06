# Codegen — Context

**Last Updated:** 2026-04-04
**Status:** Active
**Next Task ID:** CG-017

---

## Ownership

This task area owns the replacement of the legacy iMatix/GSL-based generator with a new maintainable generator.

Current project scope for Taskplane work:

- C generation first
- `library/common` is the completed proving-ground slice
- next target is `foundation`
- preserve handwritten/manual code outside generated sections where C outputs are partially generated
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

- treat `common` as the reference implementation for the project-rooted generator framework
- generalize that framework so it can load both `project_common.xml` and `project_foundation.xml`
- keep project names, namespaces, paths, prefixes, and output routing model-driven rather than hardcoded
- define `foundation`-specific verification/preservation gates at the validation layer
- port `foundation` incrementally through the shared C backend

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
| Generalization ADR | `docs/adr/0003-generalize-project-rooted-codegen-beyond-common.md` |
| Next-phase plan | `docs/codegen-migration/foundation-next-phase-plan.md` |

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

Completed architecture phase:

- `CG-006` — tests and fixtures for project-rooted `common` graph loading ✅
- `CG-007` — project-rooted model graph loader for `project_common.xml` ✅
- `CG-008` — normalized IR from the resolved project graph ✅
- `CG-009` — model-driven C resolution from IR without hardcoded project metadata ✅
- `CG-010` — bootstrap integration, preservation validation, and regression docs ✅

Next generalization / foundation phase:

- `CG-011` — foundation project inventory and verification plan
- `CG-012` — shared project-root graph loader for common + foundation
- `CG-013` — shared IR/output-target generalization beyond common assumptions
- `CG-014` — foundation preservation/build gates and tests
- `CG-015` — first low-risk foundation C emitter slice on shared backend
- `CG-016` — foundation bootstrap integration, regression validation, and docs

---

## Technical Debt / Future Work

- Reduce remaining project-specific hardcodes that still assume `common` in shared code paths.
- Generalize project-root graph loading and IR/output-target logic for `foundation`.
- Define and automate `foundation` compile/preservation verification before broad emitter work.
- Add parity/tooling checks that make mixed-mode bootstrap differences easier to review.
- Revisit umbrella/support/build generation only where the broader shared framework requires it.
