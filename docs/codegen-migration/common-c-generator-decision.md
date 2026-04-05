# Decision: `common` C generator works from model + existing C files

## Decision

For the `common` C generator, the new codegen path must treat generation as:

```text
model + existing C/header file skeleton -> rewritten generated block + preserved manual code
```

and not as fully replacing each file from scratch.

## Why

The existing repository uses partially-generated C files.

In practice:

- API/type/declaration sections are largely generated
- some helper functions may also be generated
- complex function bodies and handwritten implementation outside the generated block must be preserved

This is different from wrapper generation, where files are largely or entirely generated from models.

## Consequences

### For C generation

The generator must:

- read the existing checked-in target file
- preserve non-generated regions
- rewrite only the generated region
- tolerate handwritten code outside generated sections

### For wrapper generation

Wrapper generation may still be treated as fully-generated output.

## Current implementation status

The current `tools/codegen/common_bootstrap.py` follows this preservation model for `common` by:

- reading the existing target file
- splitting around the `@generated` block
- regenerating the block
- writing the rest of the file back unchanged

The bootstrap entrypoint should also resolve direct-rendered XML inputs from the IR-derived renderer map instead of assuming project-specific generated XML basenames in its file scan. Legacy `c_module_*.xml` discovery remains as fallback behavior for non-direct inputs.

## Long-term implication

This preservation contract is a first-class architectural requirement for the C generator and should remain explicit in future refactors.
