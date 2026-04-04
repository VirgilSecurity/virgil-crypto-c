# Codegen Migration Plan

## Objective

Replace the stale iMatix GSL-based code generation pipeline with a maintainable modern generator, while preserving current repository behavior, generated outputs, and handwritten-code preservation semantics.

## What was analyzed

The current codegen flow is driven by:

- `./codegen.sh` — thin launcher that checks for `gsl` and runs `gsl codegen/main.xml`
- `codegen/main.xml` — top-level configuration for:
  - external libraries: `mbedtls`, `ed25519`, `nanopb`, `relic`, `round5`, `falcon`
  - projects: `common`, `foundation`, `pythia`, `ratchet`, `phe`
  - wrappers: `swift`, `java`, `wasm`, `python`, `go`, `php`
- `codegen/main.gsl` — orchestration pipeline
- `codegen/*.gsl` — generator logic
- `codegen/models/**/*.xml` — source models
- `codegen/generated/**/*.xml` — intermediate/resolved artifacts

Observed scale:

- ~63 GSL template/helper files
- ~173 model XML files
- ~35 generated intermediate XML files
- ~1189 `@generated` markers across the repo

## Key findings

### 1. `codegen.sh` is not the real complexity
The shell script is simple. The real dependency/problem is the GSL runtime and the large body of generation logic implemented in GSL.

### 2. This is a model-driven compiler pipeline, not just string templates
The generator:

- loads XML models
- resolves cross-project relationships
- resolves types and features
- builds project-specific intermediate models
- emits C code, CMake files, and multiple language wrappers

### 3. The current system already has an implicit IR
The generator writes resolved/intermediate artifacts such as:

- `root.xml`
- `meta.xml`
- `project.xml`
- `type_resolution_map.xml`
- `interfaces.xml`

These are useful for reverse engineering, parity validation, and test fixture creation.

Important current status:

- `codegen/generated/` currently contains resolved XML for all language paths except Python
- Python resolved output is known to have issues for now

The new generator should understand these artifacts, but should not require producing them during normal operation.

### 4. Handwritten code preservation is critical
The current generator preserves non-generated and handwritten portions of generated files using `@generated` / `@end` style regions.

A replacement must preserve:

- manual content before generated sections
- manual content after generated sections
- handwritten function bodies merged back into generated sources where applicable

This is the highest-risk behavior to reimplement incorrectly.

## Recommended strategy

Use a **Python-based incremental rewrite** that keeps the original XML models as the source of truth.

### Primary architecture
The new generator should:

- parse original XML models directly
- resolve them into a typed in-memory IR
- emit final outputs directly
- avoid writing required resolved/intermediate XML during normal generation
- support optional debug IR dumps only when needed

### Role of current resolved XML
Current resolved/intermediate XML should be used to:

- understand legacy semantics
- validate the new resolver
- build test fixtures
- compare new IR/output behavior against the legacy pipeline

but not as the permanent runtime seam of the new architecture.

## Recommended target architecture

```text
tools/codegen/
  cli.py
  loader/
    main_config.py
    model_xml.py
    legacy_resolved_xml.py      # analysis/debug/test fixtures only
  resolve/
    graph.py
    symbol_table.py
    type_resolution.py
    feature_resolution.py
  ir/
    schema.py
    builder.py
  emit/
    c_headers.py
    c_sources.py
    cmake.py
    wrappers/
      python.py
      go.py
      java.py
      swift.py
      php.py
      wasm.py
    templates/
      ...                       # optional Jinja2 templates where helpful
  preserve/
    generated_sections.py
    handwritten_merge.py
  tests/
    golden/
    fixtures/
    test_parity.py
    test_preservation.py
```

## Migration options considered

### Option 1 — Keep XML models, rewrite generator in Python
Pros:

- best cost/benefit
- low migration risk
- contributor-friendly

Cons:

- retains legacy model semantics

### Option 2 — Compatibility backend over current resolved XML
Pros:

- safest incremental migration
- easiest parity path

Cons:

- temporary continued dependence on legacy-generated intermediates

### Option 3 — Full redesign with typed IR and new schema
Pros:

- best long-term maintainability

Cons:

- largest scope and risk

### Option 4 — Freeze most generated outputs, minimize generation scope
Pros:

- cheapest if codegen is mostly historical

Cons:

- does not really solve maintainability if codegen still evolves

### Decision
Recommended path: **keep original XML as source, use legacy resolved XML only for understanding and validation**.

In short:

1. keep current XML model inputs as the long-term source of truth
2. implement a Python generator
3. study current resolved XML to learn legacy semantics and build fixtures
4. build a typed in-memory IR instead of emitting resolved XML by default
5. port C generation before wrappers
6. preserve current `@generated` merge behavior
7. design for future incremental generation
8. later remove GSL once parity is proven

## Implementation plan

### Milestone 0 — Baseline and inventory
Create a complete inventory of generated outputs and classify them.

Tasks:

1. list generated files
2. classify files as:
   - fully generated
   - partially generated with handwritten preservation
3. capture a golden baseline from the current generator
4. record the current invocation contract (`./codegen.sh`)

Deliverables:

- `docs/codegen-migration/inventory.md`
- `docs/codegen-migration/generated-files.txt`
- `docs/codegen-migration/preserved-files.txt`
- reproducible baseline generation notes

### Milestone 1 — Reverse-engineer the effective IR
Document the minimum effective model needed by the new generator.

Tasks:

1. inspect resolved artifacts such as `root.xml`, `meta.xml`, `project.xml`, `type_resolution_map.xml`
2. inspect original XML inputs alongside those artifacts to understand transformation rules
3. note current resolved-output coverage, including the known Python gap
4. define schema for:
   - projects
   - modules
   - classes
   - interfaces
   - implementors
   - enums
   - includes
   - methods
   - wrapper modules
3. write IR notes/schema

Deliverables:

- `docs/codegen-migration/ir.md`
- initial Python dataclasses or Pydantic models

### Milestone 2 — Build preservation layer first
Implement generated/manual section handling before broad emitter work.

Tasks:

1. parse existing generated files
2. extract pre-generated content
3. extract post-generated content
4. preserve handwritten function bodies where current generator does
5. round-trip test these behaviors

Deliverables:

- `tools/codegen/preserve/generated_sections.py`
- `tools/codegen/preserve/handwritten_merge.py`
- tests for preservation behavior

### Milestone 3 — Build original-XML parser and resolver
Parse original XML models and build the new in-memory IR directly.

Tasks:

1. parse original XML sources
2. normalize optional fields and naming
3. implement project/interface/class/module/enum resolution rules
4. compare selected resolver outputs against legacy resolved XML fixtures
5. expose stable APIs for emitters

Deliverables:

- `tools/codegen/loader/model_xml.py`
- `tools/codegen/resolve/*.py`
- `tools/codegen/ir/schema.py`
- parser/resolver tests with sample fixtures

### Milestone 4 — Port low-risk emitters first
Start with simple file families.

Suggested order:

1. enums
2. simple headers
3. simple CMake outputs
4. modulemap/json support files
5. one small wrapper target

Deliverables:

- initial emitter modules
- file-level golden comparison tests

### Milestone 5 — Port C header generation
Implement header emission parity.

Scope:

- aliases
- code snippets
- macros
- enums
- structs
- callbacks
- variable declarations
- method declarations
- include ordering
- prologue/epilogue handling

Deliverables:

- `emit/c_headers.py`
- parity tests for selected projects, especially `common` and `foundation`

### Milestone 6 — Port C source generation
Implement source emission parity.

Scope:

- private declarations
- private enums/structs
- variable definitions
- generated method definitions
- stub vs handwritten method handling

Deliverables:

- `emit/c_sources.py`
- preservation-aware parity tests

### Milestone 7 — Port non-C support generation
Port support outputs used by the build and wrapper layers.

Targets:

- CMake fragments
- modulemap
- JSON support files
- feature-definition outputs where applicable

Deliverables:

- `emit/cmake.py`
- support emitters/tests

### Milestone 8 — Port one wrapper end-to-end
Do not port all wrappers at once.

Recommended first wrapper:

- Python or Go

Avoid starting with:

- Java
- WASM

Deliverables:

- first wrapper emitter module
- wrapper parity tests

### Milestone 9 — Swap the entrypoint
Keep user workflow stable.

Tasks:

1. preserve `./codegen.sh` as entrypoint
2. redirect it to the new generator
3. optionally support a temporary legacy/new switch during transition
4. add CI regeneration checks

Deliverables:

- updated `codegen.sh`
- migration notes in docs

### Milestone 10 — Remove GSL dependency
Only after parity and CI stability are established.

Tasks:

1. stop invoking `gsl`
2. remove GSL requirement from docs
3. archive or remove legacy GSL templates after stabilization

## Suggested execution order by scope

Start with:

1. `common`
2. `foundation`
3. C headers
4. C sources
5. CMake/support outputs
6. one wrapper target

Then extend to:

- `pythia`
- `ratchet`
- `phe`
- remaining wrappers

## Testing strategy

### 1. Golden-file parity tests
For selected projects/files:

- generate with legacy tool
- generate with new tool
- compare outputs

### 2. Structural tests
Validate:

- all expected files exist
- no required outputs disappear
- file names and paths remain stable

### 3. Preservation tests
Given an existing generated file containing manual content:

- rerun generation
- ensure manual content survives

### 4. Idempotence tests
Running the new generator twice should produce no diff.

### 5. Incremental generation tests
Support smaller scopes during development:

- one project
- one wrapper
- one module

## Non-negotiable compatibility requirements

Must preserve:

- file names
- directory layout
- generated section markers
- public/private output split
- type-resolution results
- wrapper naming conventions
- handwritten-code preservation semantics

Nice to preserve:

- close formatting compatibility
- existing prologue/comment style
- current invocation shape (`./codegen.sh`)

## Risks and mitigations

### Risk 1 — Semantic drift
Generated code may compile but differ subtly from legacy behavior.

Mitigation:

- golden tests
- normalized comparisons where needed
- compile/test generated outputs in CI

### Risk 2 — Handwritten code loss
Most serious risk.

Mitigation:

- build preservation layer early
- explicit tests for generated/manual merge behavior
- no destructive cutover without reviewable diffs

### Risk 3 — Wrapper under-specification
Some wrapper behavior may depend on undocumented GSL conventions.

Mitigation:

- port wrappers after C core
- document wrapper-specific rules as discovered
- start with only one wrapper target

### Risk 4 — Scope explosion
Porting all outputs at once will likely stall the migration.

Mitigation:

- stagger milestones
- define minimum viable replacement around C + one high-value wrapper

## Suggested first three tasks when resuming work

1. snapshot and study current resolved XML artifacts, including documenting the Python gap
2. implement preservation parser/rewriter for `@generated` files
3. implement original-XML parser/resolver and validate one simple enum/header path against legacy artifacts

## Suggested short roadmap

### Week 1
- inventory
- baseline snapshots
- preservation prototype
- resolved XML schema notes

### Week 2
- resolved XML loader
- first parity tests
- enums/simple headers

### Week 3
- broader header generation
- first source generation
- idempotence tests

### Week 4
- CMake/support outputs
- first wrapper target
- CI integration for the new generator

### Week 5+
- remaining wrappers
- swap entrypoint
- remove GSL

## Final recommendation

Proceed with an incremental Python rewrite:

- keep original XML as source of truth
- use current resolved XML only for analysis, validation, and fixtures
- implement a typed in-memory IR
- implement handwritten-code preservation first
- port C generation before wrappers
- use Jinja2 selectively where it helps, especially for wrappers/support files
- preserve `./codegen.sh` as the stable user-facing entrypoint
- design for future incremental generation
- remove GSL only after parity is proven
