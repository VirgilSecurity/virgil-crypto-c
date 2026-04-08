# Prototype codegen bootstrap

This is the first implementation slice of the new generator.

Current scope:

- reads legacy resolved `c_module_*.xml` for the `common` project
- regenerates the generated blocks of existing common C headers/sources
- writes output to a separate destination tree by default
- uses generic shared modules for source loading (`project_source.py`), IR lowering (`project_ir.py`), and C-backend helpers (`project_c_backend.py`) while keeping `common_*` entrypoints as compatibility adapters

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
python3 tools/codegen/common_bootstrap.py --project common --apply
bash tools/codegen/verify_common_bootstrap.sh
bash tools/codegen/build_common_with_new_codegen.sh
python3 tools/codegen/inspect_common_source.py
python3 tools/codegen/inspect_common_source.py --module assert
python3 tools/codegen/inspect_common_source.py --class-name data
python3 tools/codegen/inspect_common_ir.py
python3 tools/codegen/inspect_common_ir.py --module assert
python3 tools/codegen/inspect_common_ir.py --class-name data
```

For new shared-core integrations, prefer importing `load_named_project_source()` from `tools.codegen.project_source`, `project_to_ir()` from `tools.codegen.project_ir`, and shared backend helpers from `tools.codegen.project_c_backend`. The bootstrap entry point `common_bootstrap.py` contains both the rendering pipeline and common-specific custom overrides (e.g. buffer runtime methods). Adding a new project requires zero new Python files — just register the project name in `common_bootstrap._SUPPORTED_PROJECTS`.
