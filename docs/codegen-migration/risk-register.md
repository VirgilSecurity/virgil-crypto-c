# Codegen Migration Risk Register

## R1 — Handwritten code loss

### Description
The legacy generator preserves manual code around generated sections and may also preserve handwritten function bodies in source files.

### Impact
Critical

### Likelihood
High

### Mitigation
- implement preservation layer early
- test preservation behavior before broad emitter work
- require diff review for cutover

## R2 — Semantic drift in generated C outputs

### Description
The new generator may produce code that looks similar but changes ABI, ordering, or behavior subtly.

### Impact
Critical

### Likelihood
Medium

### Mitigation
- golden-file tests
- structural tests
- compile/build validation
- phase migration from low-risk outputs to core C outputs

## R3 — Hidden GSL semantics not captured in docs

### Description
Important behaviors are embedded in helper functions and resolution logic spread across many GSL files.

### Impact
High

### Likelihood
High

### Mitigation
- use resolved XML as an early migration seam
- document discovered rules as implementation notes
- delay full front-end replacement until emitters are understood

## R4 — Wrapper-specific behavior is under-specified

### Description
Some wrapper targets may rely on conventions or metadata not obvious from top-level templates.

### Impact
High

### Likelihood
Medium

### Mitigation
- migrate wrappers after C core
- choose one wrapper target first
- document wrapper-specific rules as discovered

## R5 — Scope explosion

### Description
Attempting to replace all generators and wrappers at once may stall the effort.

### Impact
High

### Likelihood
High

### Mitigation
- phased roadmap
- prioritize C generation first
- define minimum viable replacement
- treat wrappers as incremental follow-on work

## R6 — Tooling churn during transition

### Description
A temporary coexistence period between legacy and new generator paths may confuse contributors.

### Impact
Medium

### Likelihood
Medium

### Mitigation
- keep `./codegen.sh` as stable entrypoint
- document temporary switches clearly if introduced
- add CI checks to enforce expected path

## R7 — Incomplete output inventory

### Description
Unknown generated outputs may be missed and later break downstream workflows.

### Impact
High

### Likelihood
Medium

### Mitigation
- produce inventory first
- use repo-wide marker/path analysis
- compare clean regeneration diffs
