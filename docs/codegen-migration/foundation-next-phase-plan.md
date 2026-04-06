# Foundation Next-Phase Plan

This note captures the next migration phase after the `common` C backend regularization milestone.

## Goal

Use `foundation` as the next project target, but only after refactoring the current `common`-named project-rooted generator framework into generic shared modules so it remains model-driven and does not reintroduce project- or module-specific hardcodes.

## Top-level source of truth

The next project root is:

- `codegen/models/project_foundation/project_foundation.xml`

As with `common`, the generator should start from the top-level project model, resolve the project graph, lower into a shared IR/output-target model, and only then invoke the C backend.

## Why `foundation` next

`foundation` is large enough to stress the generalized framework:

- many classes
- many interfaces and implementors
- project-specific output surfaces beyond the small `common` proving ground
- a meaningful test of whether naming/path/prefix resolution is truly model-driven

## Architecture rule carried forward

Do not hardcode project-specific metadata in the backend when it is defined by models.

That includes, where model-defined:

- project names
- prefixes
- namespace/include namespace
- file and output placement
- generated artifact routing

Also, avoid tying backend functionality to specific module names. If behavior is generic, it should be expressed in terms of shared entity kinds, attributes, or IR metadata rather than per-module special cases.

## Recommended execution sequence

1. extract shared loader responsibilities from `common_source.py` into generic codegen modules
2. extract shared IR/output-target responsibilities from `common_ir.py` into generic codegen modules
3. extract shared C backend responsibilities from `common_direct_c.py` into generic codegen modules
4. keep only thin compatibility adapters where they still help migration
5. add `foundation` project-root tests and inventory on top of that shared framework
6. define `foundation` compile/preservation verification gates
7. implement one low-risk `foundation` C emitter slice using the shared backend
8. expand only after the generalized framework proves out

## Verification philosophy

Use tests at each layer:

- project graph loader tests
- IR/output-target tests
- backend resolution tests
- project-specific build/preservation verification

Do not rely on compile success alone as proof that the architecture is correct.

## Expected outcome

After this phase, the codegen framework should expose generic shared modules rather than `common`-named core modules, and it should be shared across at least two project roots:

- `project_common.xml`
- `project_foundation.xml`

with `common` serving as the first validated reference slice and `foundation` serving as the first proof that the design is universal rather than project-specific.
