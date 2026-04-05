# Codegen Migration Implementation Notes

## Proposed implementation principles

1. Preserve behavior before improving architecture.
2. Prefer explicit, typed internal representations.
3. Keep emitters small and testable.
4. Separate loading, transformation, emission, and preservation concerns.
5. Keep `./codegen.sh` stable while internals change.

## Recommended internal layering

### Loader layer
Responsible primarily for reading original XML model files.

A legacy resolved-XML reader may exist, but only for:

- analysis
- parity/debugging
- fixture support

### IR layer
Responsible for a normalized internal representation suitable for emitters.

For the `common` project-rooted path, this now includes explicit project naming/output metadata and per-entity output targets so C backends do not need to reconstruct file placement from ad hoc Python literals.

### Emitter layer
Responsible only for turning IR into file content.

For the `common` C backend, project-specific facts should now come from `project_common_to_ir()` / `IROutputTarget` rather than local Python literals. This includes:

- C symbol stems and typedef names
- include/source basenames and checked-in output paths
- generated XML basenames used for bootstrap dispatch
- once guards and visibility metadata
- project prefix-derived callback/type spellings

Acceptable remaining hardcodes in `common_direct_c.py` are backend-static implementation details that are not modeled today, such as reusable C runtime snippets, macro bodies, and fixed support behavior (`memset`, allocator wiring, atomic/compiler branches, assertion helper bodies).

### Preservation layer
Responsible only for merging generated content into files that may contain manual content.

For `common`, keep preservation helpers separate from direct rendering so tests can verify that handwritten prefix/suffix content survives generated-block rewrites unchanged.

## Early implementation preference

For the first pass, prefer:

- explicit Python code emitters over heavy templating for complex C generation
- Jinja2 selectively for wrappers and support/build files where it keeps structure clear
- dataclasses first, unless validation needs justify Pydantic immediately
- test fixtures kept small and representative

## Incremental-generation goal

The new architecture should make incremental generation possible later. That means:

- stable internal entity IDs
- explicit dependency mapping from source XML to IR nodes to output files
- backend-facing output metadata derived once in the IR layer instead of re-derived independently in emitters
- deterministic emitters
- minimal hidden filesystem coupling

## Future refactor opportunity

Optional debug IR dumps may be introduced later for diagnostics, but the normal generation path should not require emitting resolved XML artifacts.

## Guardrails

- do not silently accept semantic output differences without documentation
- do not cut over before preservation tests exist
- do not port all wrappers simultaneously
- do not reintroduce project-specific path/name reconstruction in emitters when the IR already exposes the output metadata
