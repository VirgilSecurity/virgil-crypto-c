# Codegen — Context

**Last Updated:** 2026-04-08
**Status:** Active
**Next Task ID:** CG-037

> **Note:** CG-034 was merged into CG-033. Task IDs CG-034 is retired.

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

Interface and implementation rendering is now complete. The `project_c_backend.py` module can render:
- Interface dispatch modules (public API) and API struct modules (private)
- Implementation main modules, defs modules (struct definition), and internal modules (vtable init, impl_info)
- Auto-discovery (`discover_renderers`) covers all 5 entity kinds: module, class, enum, interface, implementation

Current next-phase focus:

- treat `common` as the reference implementation for the project-rooted generator framework
- refactor the current `common_*` implementation modules into generic shared codegen modules before broad `foundation` work
- keep project names, namespaces, paths, prefixes, and output routing model-driven rather than hardcoded
- keep backend functionality generic and entity-driven rather than tied to specific module names whenever the model/IR already expresses the needed distinction
- define `foundation`-specific verification/preservation gates only after the shared framework refactor is in place
- port `foundation` incrementally through the shared C backend after that refactor

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
| Test: class dependencies | `tools/codegen/test_class_dependencies.py` |
| Test: interface parsing | `tools/codegen/test_interface_parsing.py` |
| Test: interface rendering | `tools/codegen/test_interface_rendering.py` |
| Test: implementation rendering | `tools/codegen/test_impl_rendering.py` |
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

Next generic-framework refactor phase:

- `CG-011` — generic shared-codegen refactor plan and module split
- `CG-012` — extract shared project graph loader from `common_source.py`
- `CG-013` — extract shared IR/output-targets from `common_ir.py`
- `CG-014` — extract shared C backend from `common_direct_c.py`
- `CG-015` — rename/adapt imports, scripts, tests, and docs for generic modules

Then foundation phase:

- `CG-016` — foundation inventory and verification plan ✅
- `CG-017` — shared framework validation on `project_foundation.xml` ✅
- `CG-018` — foundation preservation/build gates and tests ⚠ partial work preserved on `saved/ssiroshtan-CG-018-20260406T092213`
- `CG-019` — first low-risk foundation C emitter slice and integration ⛔ blocked by `CG-018`

Follow-up recovery phase:

- `CG-020` — finish foundation validation gates from saved work ✅
- `CG-021` — foundation first C slice after validation gates ✅

Universal codegen refactor phase:

- `CG-022` — generic enum renderer in shared C backend
- `CG-023` — generic class renderer in shared C backend
- `CG-024` — generic module renderer in shared C backend
- `CG-025` — auto-discovery of renderable entities from IR
- `CG-026` — eliminate per-project builder files and registry

Lifecycle generation rules phase (ADR 0004 follow-up: replace .cfrag with parametric generation) — **COMPLETE**:

All `.cfrag` files removed. Lifecycle method bodies (init, cleanup, new, delete, destroy, shallow_copy, constructor variants) and dependency management methods (use/take/release) are now generated from class IR by generic rules in `project_c_backend.py`. The `ClassMethodSpec`, `load_support_code`, and `extra_methods` override mechanism have been removed. The `tools/codegen/support/` directory no longer exists.

- `CG-027` — parse class dependencies into source and IR
- `CG-028` — generate lifecycle method bodies from class IR (depends on CG-027)
- `CG-029` — generate dependency management methods: use/take/release (depends on CG-028)
- `CG-030` — verify lifecycle parity and remove cfrag files (depends on CG-029) ✅

Interface and implementor rendering phase:

- `CG-031` — parse interfaces into source and IR ✅
- `CG-032` — parse implementors/implementations into source and IR (depends on CG-031) ✅
- `CG-033` — render interface modules: dispatch + API (depends on CG-031) ✅
- ~~`CG-034`~~ — merged into CG-033
- `CG-035` — render implementation main + defs module (depends on CG-032, CG-033) ✅
- `CG-036` — render implementation internal module + extend auto-discovery (depends on CG-033, CG-035) ✅

---

## Technical Debt / Future Work

- Reduce remaining project-specific hardcodes and `common`-named shared-core assumptions in loader/IR/backend code paths.
- Complete the shared-module refactor before expanding `foundation` emitter coverage.
- Extend the recovered `foundation` validation helper into a full generate-build-restore/preservation harness before broad emitter work.
- Define and automate `foundation` compile/preservation verification before broad emitter work.
- Add parity/tooling checks that make mixed-mode bootstrap differences easier to review.
- Revisit umbrella/support/build generation only where the broader shared framework requires it.
- `_class_dependency_includes` in `project_c_backend.py` fails when rendering foundation classes that reference `common` project classes (e.g. `data`, `buffer`). Cross-project class resolution needs a multi-project-aware lookup. (discovered during CG-029)
