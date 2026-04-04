# ADR 0001: Replace iMatix GSL code generation with a Python-based generator

- Status: Accepted
- Date: 2026-04-04
- Deciders: Project maintainers
- Technical owner: AI-assisted migration effort

## Context

This repository currently relies on a legacy code generation pipeline built on iMatix GSL and invoked through `./codegen.sh`.

The current pipeline:

- requires the external `gsl` executable
- is implemented across a large number of `.gsl` files under `codegen/`
- uses XML models under `codegen/models/`
- emits C code, build support files, and wrappers for multiple languages
- preserves handwritten code in generated files using `@generated`/`@end` section semantics

Key observations from analysis:

- `codegen.sh` is only a thin launcher
- the actual complexity lives in the GSL templates and helper library
- the system acts like a model-driven compiler pipeline, not a simple text templater
- the generator already emits useful intermediate artifacts such as `root.xml`, `meta.xml`, `project.xml`, and `type_resolution_map.xml`
- handwritten-code preservation is a critical compatibility requirement

Problems with the current approach:

- GSL is a stale ecosystem dependency
- the generator implementation is difficult to maintain and debug
- onboarding new contributors into GSL is expensive
- the system has hidden semantics that are not strongly typed or centrally documented

## Decision

We will replace the GSL-based generator with a Python-based generator.

The new generator will:

- keep the existing XML model files under `codegen/models/` as the source of truth
- parse and resolve those original XML models directly
- build a typed in-memory IR rather than writing required intermediate/resolved XML as part of normal generation
- emit final outputs directly
- support optional debug IR dumps for diagnostics when needed
- be designed so incremental generation can be added later

The migration will still be incremental, but resolved/intermediate XML from the legacy generator is now treated primarily as:

- a reverse-engineering aid
- a parity oracle
- a debugging reference

not as the permanent runtime architecture of the new generator.

### Transitional note

Legacy resolved XML currently exists under `codegen/generated/` for all supported language paths except Python, which is known to have issues at the moment. Those artifacts are useful for analysis and test fixture creation, but the new generator should not depend on re-emitting them during normal operation.

## Why Python

Python was selected because it provides:

- strong support for XML processing
- fast iteration for text/code generation tasks
- straightforward testability
- broad contributor familiarity
- good options for typed internal models and templating if needed

## Considered options

### Option A: Keep GSL
Rejected.

This would preserve the current system but would not address maintainability, onboarding, or the stale tool dependency.

### Option B: Rewrite in Python while keeping existing XML inputs
Accepted as the target direction.

This provides a good balance between short-term safety and long-term maintainability.

### Option C: Build a compatibility backend over resolved XML first
Partially accepted as an analysis and validation technique.

Resolved XML remains useful during migration, but it is no longer the preferred permanent runtime seam. The preferred end-state is direct parsing of original XML into a typed in-memory IR.
### Option D: Full redesign of the model format and generator all at once
Rejected for now.

This offers the cleanest end state but carries too much migration risk and scope for the first replacement effort.

### Option E: Freeze most generated outputs and stop evolving codegen
Rejected for now.

This could reduce effort, but it does not solve the maintainability problem if generation still needs to evolve.

## Consequences

### Positive

- removes long-term dependency on GSL
- improves maintainability and contributor accessibility
- enables better typing, testing, and diagnostics
- allows gradual replacement instead of a risky big-bang cutover

### Negative

- migration will require careful parity testing
- handwritten-code preservation must be reimplemented correctly
- wrapper-specific semantics may require additional reverse-engineering
- there will be a temporary period where legacy and new generator concepts coexist

## Non-negotiable compatibility requirements

The replacement must preserve:

- file names
- directory layout
- generated section markers
- handwritten-code preservation semantics
- public/private generation behavior
- wrapper naming/output conventions
- effective type-resolution results and emitted ABI shape

## Implementation notes

The stable user-facing entrypoint should remain `./codegen.sh` during migration.

The recommended internal module layout is documented in `docs/codegen-migration-plan.md` and `docs/codegen-migration/README.md`.

Jinja2 is acceptable for straightforward emitters such as wrapper files and support/build files. More complex C emitters may still be implemented in Python code first, with templating introduced only where it improves maintainability without obscuring logic.

## Follow-up work

1. study and snapshot existing resolved XML artifacts, including current gaps such as Python
2. build a generated-output inventory and golden baseline
3. implement preservation logic for generated/manual sections
4. implement original-XML parser, resolver, and internal IR
5. port low-risk emitters first
6. port C generation before wrappers
7. cut over `codegen.sh`
8. remove GSL after parity is proven
