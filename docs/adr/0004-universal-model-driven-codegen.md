# ADR 0004: Universal Model-Driven Codegen

- Status: Accepted
- Date: 2026-04-07

## Context

The current framework has shared generic modules (`project_source.py`, `project_ir.py`, `project_c_backend.py`) but still requires per-project Python files (`common_direct_c.py`, `foundation_direct_c.py`) that manually list entities and contain handwritten rendering logic. Adding a new project means writing a new `*_direct_c.py` file with hardcoded entity lists and custom builders.

## Decision

Eliminate per-project builder files. The shared C backend must render any entity from any project based on its IR entity kind and model attributes alone.

### Rules

1. No per-project `*_direct_c.py` files. One shared C backend handles all projects.
2. Entity discovery is automatic from the IR — no hardcoded entity lists.
3. Rendering is dispatched by entity kind (enum, class, module, interface, implementor) using generic rules derived from model/IR attributes.
4. Project selection is just: which `project_*.xml` to load. Everything else follows from the model.
5. Project-specific runtime C code (e.g. `common` allocator wiring, platform shims) that is not expressible in models should live as checked-in static support code, not as generated-by-Python builders.

### What changes

- `common_direct_c.py` → hardcoded builders become either generic IR-driven renderers or static checked-in C support code
- `foundation_direct_c.py` → eliminated; enum rendering becomes a generic capability
- `project_direct_registry.py` → eliminated; the shared backend discovers entities from IR
- `common_bootstrap.py` → becomes a thin project-selection CLI, not the owner of rendering logic

### What stays

- `project_source.py` — shared loader
- `project_ir.py` — shared IR
- `project_c_backend.py` — shared C backend (expanded to handle all entity kinds generically)
- Handwritten C preservation contract for partially-generated files
- Per-project build/test verification scripts at the validation layer only

### Important downstream constraint: wrappers

The resolved C modules, enums, and classes produced by the C backend are not terminal outputs — they will also serve as input for wrapper generation (Go, Java, Swift, PHP, Python, WASM).

This means the C backend's resolved output must be:
- structurally complete enough for wrapper backends to consume
- stable in shape so wrapper backends can rely on the resolved C representation
- not lossy — model information needed by wrappers (e.g. method signatures, type metadata, enum constants, class relationships) must survive C resolution even if the C emitter doesn't use every detail

The generic renderers should therefore preserve model/IR richness in their resolved output rather than stripping it down to only what C emission needs.

## Consequences

- Adding a new project requires zero new Python files
- The C backend becomes testable against any project's IR
- Rendering correctness is auditable against the model
- Some current hardcoded `common` builders will need to be reclassified as either generic renderers or static support code
- Resolved C output serves double duty: C file emission + wrapper backend input
- Wrapper backends can be added later against the same resolved representation without re-resolving from source models
