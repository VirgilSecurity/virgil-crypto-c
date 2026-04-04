# Codegen Migration Implementation Notes

## Proposed implementation principles

1. Preserve behavior before improving architecture.
2. Prefer explicit, typed internal representations.
3. Keep emitters small and testable.
4. Separate loading, transformation, emission, and preservation concerns.
5. Keep `./codegen.sh` stable while internals change.

## Recommended internal layering

### Loader layer
Responsible for reading either:

- current resolved/intermediate XML artifacts, or later
- original XML model files

### IR layer
Responsible for a normalized internal representation suitable for emitters.

### Emitter layer
Responsible only for turning IR into file content.

### Preservation layer
Responsible only for merging generated content into files that may contain manual content.

## Early implementation preference

For the first pass, prefer:

- explicit Python code emitters over heavy templating
- dataclasses first, unless validation needs justify Pydantic immediately
- test fixtures kept small and representative

## Future refactor opportunity

Once parity is achieved, the front-end can be replaced so the new system loads original models directly and no longer depends on legacy-generated resolved XML.

## Guardrails

- do not silently accept semantic output differences without documentation
- do not cut over before preservation tests exist
- do not port all wrappers simultaneously
