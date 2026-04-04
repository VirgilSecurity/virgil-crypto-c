# ADR 0002: Project-Rooted Codegen Pipeline for `common`

- Status: Accepted
- Date: 2026-04-04

## Context

The current `common` migration proved that we can replace the legacy GSL/iMatix generator incrementally, preserve handwritten C outside generated blocks, and validate the result by rebuilding `library/common`.

However, the current direct-lowering layer still contains module-specific hardcoded naming, file layout, and code-shape decisions that should ultimately come from the source models.

For `common`, the top-level project model (`codegen/models/project_common/project_common.xml`) is the correct root of truth. It declares the project scope and references the subelements that define classes, modules, enums, and generation metadata. The new generator should therefore start from the project model, resolve the model graph, and only then derive language-specific outputs.

## Decision

The new generator architecture for `common` will be project-rooted and model-driven.

### Root of truth

- `project_common.xml` is the top-level entrypoint for the `common` project.
- The generator must parse the project model first, then recursively resolve referenced model files and subelements.
- Project-specific metadata such as namespaces, paths, prefixes, naming conventions, and output grouping must come from the model graph, not Python hardcodes.

### Internal pipeline

The generator pipeline will be:

```text
project model
  -> resolved project graph
  -> language-neutral IR
  -> C resolution layer
  -> emitted C/header generated sections
```

Wrapper backends may later resolve from the same IR in parallel, but C is the first required backend.

### Language-neutral IR

Before generating C, the generator must build a normalized in-memory IR that captures:

- project identity and generation settings
- modules, classes, enums, constants, and callbacks
- type references and method signatures
- output targets and generation roles
- naming metadata needed by language backends

This IR should express model-derived facts, not baked-in `common` assumptions.

### C backend

The C backend must:

- derive C-facing names, file targets, includes, and declarations from the IR
- preserve the current handwritten-code contract for `library/common`
- regenerate only generated sections when applying to checked-in C/header files
- avoid hardcoded project-specific prefixes, namespaces, and file paths when these are model-defined

### Allowed hardcoding

The backend may still contain reusable C-generation machinery and static runtime support templates when they are not model data. But project-specific metadata must not be hardcoded.

## Consequences

### Positive

- `common` becomes the training base for the final architecture rather than a one-off migration shim.
- The generator becomes extensible to other backends because they can share the same IR.
- Naming/path/prefix behavior becomes auditable against the source models.
- We reduce the risk of silently encoding legacy template behavior in Python literals.

### Trade-offs

- We need a stronger project-graph loader and a more explicit IR than the current mixed-mode implementation.
- Some currently hardcoded direct-lowering logic will need to be refactored or replaced.
- Migration velocity may temporarily slow while the architecture is regularized.

## Implementation guidance

1. Start from `project_common.xml`, not per-module entrypoints.
2. Resolve the full model graph for `common` before backend-specific lowering.
3. Move project-specific naming and output-layout logic out of hardcoded direct builders.
4. Keep the compile gate:
   - `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`
   - `bash tools/codegen/build_common_with_new_codegen.sh`
5. Add focused tests for:
   - project graph loading
   - IR construction
   - C resolution from model-derived metadata
   - preservation/build verification behavior

## Non-goals for this ADR

- wrapper backend implementation
- replacing handwritten-code preservation semantics
- requiring resolved XML as a new mandatory output artifact
