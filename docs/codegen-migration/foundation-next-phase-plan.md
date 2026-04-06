# Foundation Next-Phase Plan

This note captures the next migration phase after the `common` C backend regularization milestone.

## Goal

Use `foundation` as the next project target while generalizing the project-rooted generator framework so it remains model-driven and does not reintroduce project-specific hardcodes.

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

## Recommended execution sequence

1. add `foundation` project-root tests and inventory
2. generalize the project graph loader to support both `common` and `foundation`
3. generalize the IR/output-target model beyond `common` assumptions
4. define `foundation` compile/preservation verification gates
5. implement one low-risk `foundation` C emitter slice using the shared backend
6. expand only after the generalized framework proves out

## Verification philosophy

Use tests at each layer:

- project graph loader tests
- IR/output-target tests
- backend resolution tests
- project-specific build/preservation verification

Do not rely on compile success alone as proof that the architecture is correct.

## Expected outcome

After this phase, the codegen framework should be shared across at least two project roots:

- `project_common.xml`
- `project_foundation.xml`

with `common` serving as the first validated reference slice and `foundation` serving as the first proof that the design is universal rather than project-specific.
