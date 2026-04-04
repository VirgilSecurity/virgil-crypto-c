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
- migrate incrementally
- start from resolved/intermediate XML compatibility where useful
- preserve handwritten-code merge semantics first
- port C generation before wrappers
- keep `./codegen.sh` as the stable operator entrypoint during migration

## Immediate next actions

1. produce output inventory and golden baseline
2. implement preservation parser/rewriter
3. implement resolved-XML loader
4. prove parity on one small generated surface

## Definition of done for migration

The migration is complete when:

- `./codegen.sh` no longer requires GSL
- the new generator can reproduce required outputs for all supported projects
- handwritten-code preservation behavior is validated by tests
- CI confirms idempotence and no unexpected regeneration diffs
- legacy GSL-based generation is retired
