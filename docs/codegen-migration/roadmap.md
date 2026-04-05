# Codegen Migration Roadmap

## Phase 0 — Baseline

### Goal
Establish a trustworthy reference point for migration.

### Deliverables
- generated output inventory
- list of preserved/manual-merge files
- golden baseline generation procedure
- documented current generator contract

### Exit criteria
- we know what must be reproduced
- we know which outputs are high-risk because of handwritten code

## Phase 1 — Legacy semantics analysis

### Goal
Use existing resolved/intermediate XML artifacts to understand the legacy resolver and define the new in-memory IR.

### Deliverables
- schema notes for resolved XML
- mapping notes from original XML to effective resolved entities
- documented gaps such as the current Python issue
- first internal IR representation

### Exit criteria
- the team understands enough legacy semantics to implement the new resolver directly from original XML

## Phase 2 — Original-XML parser and resolver

### Goal
Build the new parser and resolver directly on top of original XML models.

### Deliverables
- parser for main/model XML
- symbol/type/feature resolution logic
- validation against selected legacy resolved XML artifacts

### Exit criteria
- the new generator can build enough in-memory IR from original XML to drive at least one emitter

## Phase 3 — Preservation layer

### Goal
Reimplement generated/manual section preservation safely.

### Deliverables
- generated section parser
- handwritten body extraction/merge utility
- round-trip unit tests

### Exit criteria
- no manual content loss in tested scenarios

## Phase 4 — First emitters

### Goal
Generate a small, low-risk subset of outputs using the new pipeline.

### Suggested scope
- enums
- simple headers
- simple support/build files

### Exit criteria
- file-level parity for a small selected surface

## Phase 5 — C generation parity

### Goal
Port core C header and source generation.

### Deliverables
- C header emitter
- C source emitter
- parity tests on `common` and `foundation`

### Exit criteria
- selected C outputs match legacy generation closely enough for compile/test validation

### Current checkpoint

The `common` proving-ground slice has now crossed the architecture regularization milestone:

- the executable bootstrap path is project-rooted (`project_common.xml` → source graph → IR/output targets → C backend)
- direct lowering covers the core `library/common` C entities needed for the compile gate
- legacy resolved XML is now a fallback/reference input for parity and unmigrated surfaces, not the preferred runtime source for the migrated `common` outputs
- the remaining work after this checkpoint is primarily parity/tooling cleanup, support/build emission, and choosing the next migration target

## Phase 6 — Support/build generation

### Goal
Port non-C files used by the build and packaging pipeline.

### Deliverables
- CMake emitter(s)
- modulemap/support emitters
- parity tests

### Exit criteria
- support/build files can be regenerated without relying on GSL emitters

## Phase 7 — Wrapper migration

### Goal
Port wrapper generation one target at a time.

### Recommended order
1. Python or Go
2. next highest-value wrapper
3. remaining wrappers

### Exit criteria
- each wrapper target has file-level parity and validation gates

## Phase 8 — Cutover

### Goal
Make the new generator the default path.

### Deliverables
- `./codegen.sh` invokes the new generator
- CI validates clean regeneration
- migration notes updated

### Exit criteria
- day-to-day generation no longer depends on GSL

## Phase 9 — Legacy retirement

### Goal
Remove the GSL dependency and retire legacy generator assets when safe.

### Deliverables
- docs updated to remove GSL requirement
- legacy code archived or removed

### Exit criteria
- all supported generation flows work without GSL
