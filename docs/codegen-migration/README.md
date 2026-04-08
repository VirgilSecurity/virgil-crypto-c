# Codegen Migration Working Set

This directory contains the working documents for replacing the legacy iMatix GSL code generation pipeline.

## Documents

- `../codegen-migration-plan.md` — primary migration plan
- `roadmap.md` — milestone-oriented implementation roadmap
- `task-breakdown.md` — implementation backlog and execution checklist
- `initial-task-plan.md` — first implementation stretch
- `tasks-next.md` — immediate execution queue
- `resolved-models-inventory.md` — current state of legacy resolved XML artifacts
- `model-spec-common.md` — pragmatic spec for the `common` source-model subset
- `model-parser-notes.md` — parser constraints and tolerant parsing notes
- `parity-test-plan.md` — strategy for proving generator compatibility
- `risk-register.md` — migration risks and mitigations
- `inventory-template.md` — template for generated output inventory work
- `implementation-notes.md` — architecture and coding notes for the new generator
- `common-bootstrap-status.md` — current executable status of the mixed-mode `common` bootstrap
- `common-direct-foundation-status.md` — current direct-coverage boundary for foundational `common` outputs
- `common-buffer-migration-plan.md` — historical execution map for the completed `common` buffer-family migration
- `common-support-fallback-audit.md` — final disposition of the `common` umbrella/support headers after the buffer migration
- `../adr/0002-project-rooted-codegen-pipeline.md` — project-rooted architecture decision for the `common` generator phase
- `../adr/0003-generalize-project-rooted-codegen-beyond-common.md` — generalization decision for carrying the framework into `foundation`
- `foundation-next-phase-plan.md` — plan for moving the project-rooted generator from `common` into `foundation`

## Summary

Decision:

- replace GSL with a Python-based generator
- keep original XML models as source of truth
- use legacy resolved/intermediate XML for analysis, parity, and fixtures only
- do not make resolved XML a required output of the new generator
- preserve handwritten-code merge semantics first
- port C generation before wrappers
- keep `./codegen.sh` as the stable operator entrypoint during migration
- design internals so incremental generation can be added later

## Current `common` status

For the current Taskplane slice (`library/common` C generation):

1. the bootstrap architecture is now project-rooted: `codegen/models/project_common/project_common.xml` loads into the source graph, lowers into IR/output targets, and dispatches direct C renderers from that project metadata instead of reconstructing file placement from local bootstrap literals
2. the foundational direct-lowering boundary is in place for `vsc_library`, `vsc_assert`, `vsc_memory`, `vsc_atomic`, `vsc_data`, `vsc_buffer_defs`, and `vsc_buffer`
3. legacy resolved `c_module_*.xml` remains allowed only as a fallback/reference path for approved migration and parity roles; it is no longer the intended runtime source for the migrated `common` outputs above
4. the only previously open post-buffer ownership question was the umbrella headers `vsc_common_public.h` and `vsc_common_private.h`
5. those umbrella headers are now best understood as stable checked-in support headers with empty generated blocks, not as meaningful active resolved-XML fallback surfaces
6. the compile gate for this slice remains `bash tools/codegen/build_common_with_new_codegen.sh`

## Shared module naming and compatibility policy

The shared framework is now presented through generic `project_*` module names instead of `common_*` names whenever code is not inherently tied to the `common` project.

Preferred shared modules:

- `tools/codegen/project_source.py` — shared project/model loading and source-graph helpers
- `tools/codegen/project_ir.py` — shared project-to-IR lowering and output-target mapping
- `tools/codegen/project_c_backend.py` — shared C-backend helpers and direct-renderer registration plumbing

Temporary compatibility adapters that remain acceptable during migration:

- `tools/codegen/common_source.py` — `common` convenience wrapper over `project_source.py`
- `tools/codegen/common_ir.py` — `common` compatibility exports over `project_ir.py`
- `tools/codegen/common_direct_c.py` — `common` handwritten/direct-builder adapter over `project_c_backend.py`
- `tools/codegen/common_bootstrap.py` — the current `common`-specific CLI/bootstrap entrypoint

Policy:

- prefer importing shared behavior from the generic `project_*` modules in new or refactored code
- keep `common_*` modules only where they provide project selection, legacy export names, CLI defaults, or handwritten `common` builders
- do not move shared parsing, IR shaping, output-target derivation, or backend helper ownership back into `common_*` modules
- keep the existing `common` validation/build workflow working while these adapters remain in place

## Immediate next actions

1. treat `common` as the reference implementation for the project-rooted generator framework rather than reopening it as a new entity-porting track
2. use the completed `foundation` enum pilot as the reference pattern for cross-project shared-backend work
3. add a broader `foundation` generate/apply/build/restore harness before expanding emitter ownership beyond the pilot slice
4. extend `foundation` coverage incrementally from the enum slice into the next low-risk utility/value family
5. continue treating legacy resolved XML as reference/fixture material instead of a runtime requirement

## After `common`

For this Taskplane slice, the core `common` C backend regularization work is effectively complete.

What remains is smaller cross-cutting migration work rather than another `common` entity port:

- parity and comparison tooling for the mixed-mode bootstrap
- parser/resolver hardening that can reuse the `common` slice as a reference implementation
- support/build file generation that is still outside the direct C backend path
- selection of the next migration target beyond `library/common`

## Remaining follow-up after `common` C backend regularization

The `common` C backend no longer needs another core entity-porting pass for this migration slice.
Remaining follow-up is now concentrated in adjacent migration work:

- tighten parity/comparison tooling so mixed-mode bootstrap diffs are easier to review
- harden parser/resolver behavior using `common` as the reference project-rooted slice
- port support/build emitters that are still outside the direct C backend path
- choose and scope the next post-`common` migration target

## Definition of done for migration

The migration is complete when:

- `./codegen.sh` no longer requires GSL
- the new generator can reproduce required outputs for all supported projects
- handwritten-code preservation behavior is validated by tests
- CI confirms idempotence and no unexpected regeneration diffs
- legacy GSL-based generation is retired
