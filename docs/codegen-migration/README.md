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
- `../adr/0002-project-rooted-codegen-pipeline.md` — project-rooted architecture decision for the next generator phase

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

1. the foundational direct-lowering boundary is in place for `vsc_library`, `vsc_assert`, `vsc_memory`, `vsc_atomic`, `vsc_data`, `vsc_buffer_defs`, and `vsc_buffer`
2. the only previously open post-buffer ownership question was the umbrella headers `vsc_common_public.h` and `vsc_common_private.h`
3. those umbrella headers are now best understood as stable checked-in support headers with empty generated blocks, not as meaningful active resolved-XML fallback surfaces
4. the compile gate for this slice remains `bash tools/codegen/build_common_with_new_codegen.sh`

## Immediate next actions

1. keep using `library/common` as the proving ground for parser/resolver and parity work rather than opening a new `common` implementation track
2. reduce parity/formatting differences in the mixed-mode bootstrap where they still matter for review confidence
3. carry the direct-from-original-model approach into the next target area after `common`
4. continue treating legacy resolved XML as reference/fixture material instead of a runtime requirement

## After `common`

For this Taskplane slice, `common` direct lowering is effectively complete.

What remains is smaller cross-cutting migration work rather than another `common` entity port:

- parity and comparison tooling for the mixed-mode bootstrap
- parser/resolver hardening that can reuse the `common` slice as a reference implementation
- selection of the next migration target beyond `library/common`

## Definition of done for migration

The migration is complete when:

- `./codegen.sh` no longer requires GSL
- the new generator can reproduce required outputs for all supported projects
- handwritten-code preservation behavior is validated by tests
- CI confirms idempotence and no unexpected regeneration diffs
- legacy GSL-based generation is retired
