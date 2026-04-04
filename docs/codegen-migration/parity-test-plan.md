# Codegen Parity Test Plan

## Purpose

The new generator must be proven compatible with the current generator before cutover. This document describes how compatibility should be measured.

## Test categories

### 1. Golden-file parity tests
For a selected set of outputs:

1. generate artifacts using the legacy generator
2. generate artifacts using the new generator
3. compare outputs

Use strict byte-for-byte comparison where possible.

Allow normalized comparison only where formatting differences are known to be harmless and unavoidable.

### 2. Structural parity tests
Verify that:

- expected files exist
- no expected file is missing
- path layout is preserved
- file naming conventions are preserved

### 3. Preservation tests
For files containing generated/manual boundaries:

- start from a file containing manual content
- rerun generation
- assert that manual content is preserved
- assert that generated region updates correctly

### 4. Idempotence tests
Run the new generator twice on the same input and confirm there is no diff after the second run.

### 5. Compile/build validation
Regenerated outputs must still participate correctly in the build.

At minimum:

- compile validation for regenerated C outputs
- any wrapper-specific validation available for migrated wrappers

## Scope prioritization

### Highest priority
- C headers in `common` and `foundation`
- C sources in `common` and `foundation`
- files with handwritten-code preservation

### Medium priority
- CMake/support outputs
- first wrapper target

### Later priority
- remaining wrapper targets
- less commonly changed outputs

## Comparison strategy

### Strict comparison preferred
Use exact file comparison when possible because subtle changes in generated code can matter.

### Normalized comparison allowed sparingly
If required, normalize only clearly irrelevant formatting such as:

- trailing whitespace
- line-ending style

Do not normalize away changes in:

- include ordering
- declaration ordering
- macro layout when it may affect behavior or readability contracts
- preserved/manual content boundaries

## Fixture strategy

Maintain fixtures for:

- representative original XML inputs
- representative legacy resolved XML artifacts used as semantic reference material
- representative existing generated files with handwritten content
- representative expected emitted files

## Failure handling

When parity fails:

1. identify whether the difference is semantic or formatting-only
2. decide whether the new output or the expectation should change
3. document intentional deviations before accepting them

## Known current caveat

Legacy resolved XML is currently available for all language paths except Python, which has known issues. Early parity work should therefore prioritize C outputs and a non-Python wrapper target such as Go.

## Exit gate for cutover

The new generator can become the default only when:

- selected core outputs pass parity tests
- preservation tests pass
- idempotence tests pass
- compile/build validation passes for migrated surfaces
