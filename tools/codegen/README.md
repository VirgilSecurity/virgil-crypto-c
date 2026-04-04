# Prototype codegen bootstrap

This is the first implementation slice of the new generator.

Current scope:

- reads legacy resolved `c_module_*.xml` for the `common` project
- regenerates the generated blocks of existing common C headers/sources
- writes output to a separate destination tree by default
- includes a first source-model loader for original XML in `project_common` / `shared`

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

Useful commands:

```bash
python3 tools/codegen/common_bootstrap.py --project common --out build/new-codegen-common
bash tools/codegen/verify_common_bootstrap.sh
python3 tools/codegen/inspect_common_source.py
python3 tools/codegen/inspect_common_source.py --module assert
python3 tools/codegen/inspect_common_source.py --class-name data
```
