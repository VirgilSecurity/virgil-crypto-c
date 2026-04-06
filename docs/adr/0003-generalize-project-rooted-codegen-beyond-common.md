# ADR 0003: Generalize the Project-Rooted Codegen Framework Beyond `common`

- Status: Accepted
- Date: 2026-04-05

## Context

The `common` C proving-ground slice is now regularized around a project-rooted architecture:

```text
project model -> resolved project graph -> language-neutral IR -> C backend -> emitted generated sections
```

That architecture was validated against `project_common.xml`, with tests and build verification for `library/common`.

The next target should be `foundation`, but the work should not become a second project-specific implementation track. The generator framework must instead become more universal so the same project-rooted pipeline can load `project_foundation.xml`, derive model-defined metadata, and drive C generation without hardcoded project names, namespaces, paths, or prefixes.

## Decision

The next migration phase will first refactor the currently `common`-named project-rooted framework into generic shared codegen modules, and only then target `foundation` on top of that shared framework rather than adding new `foundation`-specific hardcoded paths.

### Scope

- Keep C generation first.
- Use `codegen/models/project_foundation/project_foundation.xml` as the next top-level project root.
- Generalize the loader, IR, and output-target machinery so they work for both `common` and `foundation` from model-defined metadata.
- Preserve the rule that project-specific naming/path/prefix information must come from models, not backend literals.

### Framework requirements

The universalized framework must:

- accept a top-level project model as the root entrypoint
- resolve referenced classes, interfaces, implementors, enums, modules, and dependencies from that project graph
- derive output metadata from project/model facts
- allow project-specific compile gates and preservation rules without re-hardcoding per-project naming logic
- keep legacy resolved XML as parity/reference material only, not as the intended runtime source for migrated outputs
- keep backend functionality entity- and metadata-driven rather than tied to specific module names

In other words, project selection may differ (`common`, `foundation`, later others), but the backend logic should not fork into module-name-specific functionality when the same behavior can be derived from the model graph and shared IR.

### Pre-foundation framework refactor

Before broad `foundation` work, the current `common_*` implementation modules should be refactored so shared responsibilities live in generic codegen modules rather than project-specific file names.

That means separating and generalizing:

1. project graph loading
2. shared IR/output-target logic
3. shared C backend/lowering logic
4. bootstrap integration points that should be project-agnostic

Thin compatibility adapters may remain temporarily if they help migration, but the core architecture should no longer present itself as `common`-specific where the behavior is shared.

### Foundation-next strategy

After the shared-framework refactor, `foundation` should proceed with:

1. project/root graph loading and tests on the shared loader
2. generalized IR/output-target support proven across more than one project root
3. explicit `foundation` verification gates and preservation inventory
4. a low-risk C emitter pilot before broader foundation coverage

## Consequences

### Positive

- `common` becomes a reusable architecture reference rather than a one-off migration island.
- `foundation` work directly tests whether the framework is truly model-driven.
- future project targets can reuse the same project-rooted machinery.

### Trade-offs

- some code currently shaped around `common` naming/output assumptions will need another cleanup/refactor pass before `foundation` work can sit on a truly shared base
- we should expect discovery work around `foundation`-specific preservation and build surfaces before broad emitter work begins

## Implementation guidance

1. Do not fork the architecture into separate `common_*` and `foundation_*` pipelines if the difference is only project metadata.
2. Do not introduce functionality branches keyed off specific module names when the same rule can be expressed against shared entity kinds, model attributes, or IR metadata.
3. Add tests that prove shared loader/IR/output-target behavior across at least `common` and `foundation`.
4. Introduce project-specific verification commands only at the orchestration/build-validation layer, not in core naming/output resolution.
5. Keep generated/manual preservation semantics explicit for C outputs that are not fully generated.

## Non-goals

- wrapper migration in this phase
- full `foundation` parity in one step
- reintroducing project-specific hardcoded naming/path logic as a shortcut
