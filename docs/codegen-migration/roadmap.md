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

## Phase 1 — Compatibility seam

### Goal
Use existing resolved/intermediate XML artifacts as a seam for the first implementation passes.

### Deliverables
- schema notes for resolved XML
- Python loader for resolved XML
- first internal IR representation

### Exit criteria
- the new generator can load enough resolved data to drive at least one emitter

## Phase 2 — Preservation layer

### Goal
Reimplement generated/manual section preservation safely.

### Deliverables
- generated section parser
- handwritten body extraction/merge utility
- round-trip unit tests

### Exit criteria
- no manual content loss in tested scenarios

## Phase 3 — First emitters

### Goal
Generate a small, low-risk subset of outputs using the new pipeline.

### Suggested scope
- enums
- simple headers
- simple support/build files

### Exit criteria
- file-level parity for a small selected surface

## Phase 4 — C generation parity

### Goal
Port core C header and source generation.

### Deliverables
- C header emitter
- C source emitter
- parity tests on `common` and `foundation`

### Exit criteria
- selected C outputs match legacy generation closely enough for compile/test validation

## Phase 5 — Support/build generation

### Goal
Port non-C files used by the build and packaging pipeline.

### Deliverables
- CMake emitter(s)
- modulemap/support emitters
- parity tests

### Exit criteria
- support/build files can be regenerated without relying on GSL emitters

## Phase 6 — Wrapper migration

### Goal
Port wrapper generation one target at a time.

### Recommended order
1. Python or Go
2. next highest-value wrapper
3. remaining wrappers

### Exit criteria
- each wrapper target has file-level parity and validation gates

## Phase 7 — Cutover

### Goal
Make the new generator the default path.

### Deliverables
- `./codegen.sh` invokes the new generator
- CI validates clean regeneration
- migration notes updated

### Exit criteria
- day-to-day generation no longer depends on GSL

## Phase 8 — Legacy retirement

### Goal
Remove the GSL dependency and retire legacy generator assets when safe.

### Deliverables
- docs updated to remove GSL requirement
- legacy code archived or removed

### Exit criteria
- all supported generation flows work without GSL
