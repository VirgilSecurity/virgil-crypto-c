# Prototype codegen bootstrap

This is the first implementation slice of the new generator.

Current scope:

- reads legacy resolved `c_module_*.xml` for the `common` project
- regenerates the generated blocks of existing common C headers/sources
- writes output to a separate destination tree by default

This is a bootstrap step, not the final architecture.

It exists to:

- validate preservation and emission mechanics
- prove that the common library can be regenerated under a new Python implementation
- provide a concrete target while the direct original-XML parser/resolver is being built

The long-term architecture remains:

- original XML as source of truth
- typed in-memory IR
- direct final output emission
- optional debug/fixture support for legacy resolved XML
