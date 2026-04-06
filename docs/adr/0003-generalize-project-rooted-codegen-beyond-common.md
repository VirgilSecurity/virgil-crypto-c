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

The next migration phase will target `foundation` by generalizing the current project-rooted framework rather than adding new `foundation`-specific hardcoded paths.

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

### Foundation-first strategy

`foundation` should start with:

1. project/root graph loading and tests
2. generalized IR/output-target support for non-`common` entities
3. explicit `foundation` verification gates and preservation inventory
4. a low-risk C emitter pilot before broader foundation coverage

## Consequences

### Positive

- `common` becomes a reusable architecture reference rather than a one-off migration island.
- `foundation` work directly tests whether the framework is truly model-driven.
- future project targets can reuse the same project-rooted machinery.

### Trade-offs

- some code currently shaped around `common` naming/output assumptions will need another cleanup pass
- we should expect discovery work around `foundation`-specific preservation and build surfaces before broad emitter work begins

## Implementation guidance

1. Do not fork the architecture into separate `common_*` and `foundation_*` pipelines if the difference is only project metadata.
2. Add tests that prove shared loader/IR/output-target behavior across at least `common` and `foundation`.
3. Introduce project-specific verification commands only at the orchestration/build-validation layer, not in core naming/output resolution.
4. Keep generated/manual preservation semantics explicit for C outputs that are not fully generated.

## Non-goals

- wrapper migration in this phase
- full `foundation` parity in one step
- reintroducing project-specific hardcoded naming/path logic as a shortcut
