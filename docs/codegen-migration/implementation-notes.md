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

### Emitter layer
Responsible only for turning IR into file content.

### Preservation layer
Responsible only for merging generated content into files that may contain manual content.

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
- deterministic emitters
- minimal hidden filesystem coupling

## Future refactor opportunity

Optional debug IR dumps may be introduced later for diagnostics, but the normal generation path should not require emitting resolved XML artifacts.

## Guardrails

- do not silently accept semantic output differences without documentation
- do not cut over before preservation tests exist
- do not port all wrappers simultaneously
