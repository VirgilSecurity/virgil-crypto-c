# Codegen Migration Task Breakdown

This backlog is written as an execution checklist for the implementation effort.

## Epic A — Baseline and inventory

- [ ] A1. Enumerate all generated outputs produced by the current system
- [ ] A2. Classify outputs as fully generated vs partially generated
- [ ] A3. Record all locations containing `@generated` markers
- [ ] A4. Produce a golden baseline regeneration procedure
- [ ] A5. Capture a clean diff after legacy regeneration
- [ ] A6. Document current invocation contract for `./codegen.sh`

## Epic B — Legacy semantics analysis and IR design

- [ ] B1. Inspect `root.xml`, `meta.xml`, `project.xml`, `type_resolution_map.xml`, `interfaces.xml`
- [ ] B2. Inspect original XML inputs side-by-side with resolved XML to infer transformation rules
- [ ] B3. Document current resolved XML coverage, noting that all language paths are available except Python, which currently has issues
- [ ] B4. Define the minimum internal IR required by emitters
- [ ] B5. Decide whether to use dataclasses or Pydantic models for the first pass
- [ ] B6. Document naming and path normalization rules
- [ ] B7. Document public/private entity distinctions relevant to emitters

## Epic C — Preservation layer

- [ ] C1. Implement generated section boundary parser
- [ ] C2. Implement extraction of content before generated blocks
- [ ] C3. Implement extraction of content after generated blocks
- [ ] C4. Implement handwritten function-body extraction for source files
- [ ] C5. Implement merge/rewrite logic preserving manual content
- [ ] C6. Add unit tests for header preservation scenarios
- [ ] C7. Add unit tests for source/body preservation scenarios
- [ ] C8. Add idempotence tests for preservation logic

## Epic D — Original-XML parser, resolver, and internal APIs

- [ ] D1. Implement parser for `codegen/main.xml`
- [ ] D2. Implement parser for original project/model/wrapper XML files
- [ ] D3. Implement symbol/type/feature resolution into a typed in-memory IR
- [ ] D4. Implement loading/resolution of C modules, enums, methods, includes, structs, variables
- [ ] D5. Implement loading/resolution of wrapper project/module artifacts
- [ ] D6. Add optional loader for legacy resolved XML fixtures used only for comparison/debugging
- [ ] D7. Expose stable Python APIs for emitters
- [ ] D8. Add fixture-based parser/resolver tests

## Epic E — First emitters

- [ ] E1. Implement enum emitter
- [ ] E2. Implement simple header emitter path
- [ ] E3. Implement one support/build file emitter
- [ ] E4. Add golden-file tests for first emitters
- [ ] E5. Add normalization helpers for whitespace-insensitive comparisons where justified

## Epic F — C header emitter parity

- [ ] F1. Emit aliases
- [ ] F2. Emit code snippets in correct order
- [ ] F3. Emit macros/macros groups
- [ ] F4. Emit enums
- [ ] F5. Emit struct declarations/definitions as needed
- [ ] F6. Emit callback declarations
- [ ] F7. Emit variable declarations
- [ ] F8. Emit method declarations
- [ ] F9. Preserve include ordering and conditional include behavior
- [ ] F10. Preserve prologue/epilogue behavior
- [ ] F11. Add parity tests for representative modules in `common`
- [ ] F12. Add parity tests for representative modules in `foundation`

## Epic G — C source emitter parity

- [ ] G1. Emit private aliases/snippets/macros
- [ ] G2. Emit private enums and structs
- [ ] G3. Emit variable definitions
- [ ] G4. Emit generated method definitions
- [ ] G5. Support stub vs handwritten implementation handling
- [ ] G6. Add source parity tests for representative modules
- [ ] G7. Add compile validation for regenerated C outputs

## Epic H — Build/support generation

- [ ] H1. Port CMake file generation
- [ ] H2. Port modulemap generation
- [ ] H3. Port other support/json outputs required by wrappers or packaging
- [ ] H4. Add parity tests for support files

## Epic I — Wrapper migration

### First wrapper
- [ ] I1. Select first wrapper target (recommended: Go first, since Python legacy resolved output currently has known issues)
- [ ] I2. Implement wrapper project/module loader needs
- [ ] I3. Implement wrapper project emitter
- [ ] I4. Implement wrapper source emitter
- [ ] I5. Add parity tests for first wrapper target

### Remaining wrappers
- [ ] I6. Prioritize remaining wrapper targets by maintenance value
- [ ] I7. Port second wrapper target
- [ ] I8. Port remaining wrapper targets iteratively
- [ ] I9. Add per-wrapper validation strategy

## Epic J — CLI and entrypoint

- [ ] J1. Create new generator CLI skeleton under `tools/codegen/`
- [ ] J2. Support scoped generation for one project/module during development
- [ ] J3. Keep `./codegen.sh` as stable user-facing entrypoint
- [ ] J4. Add a temporary legacy/new switch if needed during transition
- [ ] J5. Update developer documentation for the new flow

## Epic K — CI and cutover

- [ ] K1. Add CI job for regeneration cleanliness
- [ ] K2. Add CI job for parity tests
- [ ] K3. Add CI job for idempotence checks
- [ ] K4. Make new generator the default
- [ ] K5. Remove GSL requirement from docs
- [ ] K6. Retire or archive legacy generator assets after stabilization

## Suggested execution order

1. Epic A
2. Epic B
3. Epic C
4. Epic D
5. Epic E
6. Epic F
7. Epic G
8. Epic H
9. Epic I
10. Epic J
11. Epic K

## Definition of ready for implementation

A task should not start until:

- its inputs are identified
- expected outputs are known
- a parity or validation strategy exists
- handwritten preservation impact is understood, if applicable

## Definition of done for a migration task

A task is done when:

- implementation exists
- tests exist where appropriate
- output compatibility is validated
- docs are updated if behavior or process changed
