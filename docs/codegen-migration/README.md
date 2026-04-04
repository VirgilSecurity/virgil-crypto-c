# Codegen Migration Working Set

This directory contains the working documents for replacing the legacy iMatix GSL code generation pipeline.

## Documents

- `../codegen-migration-plan.md` — primary migration plan
- `roadmap.md` — milestone-oriented implementation roadmap
- `task-breakdown.md` — implementation backlog and execution checklist
- `parity-test-plan.md` — strategy for proving generator compatibility
- `risk-register.md` — migration risks and mitigations
- `inventory-template.md` — template for generated output inventory work
- `implementation-notes.md` — architecture and coding notes for the new generator

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

## Immediate next actions

1. snapshot and catalog current resolved XML artifacts, including the known Python gap
2. produce output inventory and golden baseline
3. implement preservation parser/rewriter
4. implement original-XML parser/resolver
5. prove parity on one small generated surface

## Definition of done for migration

The migration is complete when:

- `./codegen.sh` no longer requires GSL
- the new generator can reproduce required outputs for all supported projects
- handwritten-code preservation behavior is validated by tests
- CI confirms idempotence and no unexpected regeneration diffs
- legacy GSL-based generation is retired
