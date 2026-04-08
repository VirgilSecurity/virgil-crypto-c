from __future__ import annotations

from pathlib import Path
import unittest

from tools.codegen.project_c_backend import direct_xml_name
from tools.codegen.project_direct_registry import direct_c_renderers_for_project, supported_projects
from tools.codegen.project_ir import project_to_ir
from tools.codegen.project_source import load_named_project_source


REPO_ROOT = Path(__file__).resolve().parents[2]


class ProjectDirectRegistryTest(unittest.TestCase):
    def test_supported_projects_lists_shared_bootstrap_projects(self) -> None:
        self.assertEqual(("common", "foundation"), supported_projects())

    def test_direct_c_renderers_for_project_rejects_unknown_project(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported project 'unknown'"):
            direct_c_renderers_for_project("unknown", REPO_ROOT)

    def test_direct_c_renderers_for_project_loads_generic_foundation_enum_renderers(self) -> None:
        renderers = direct_c_renderers_for_project("foundation", REPO_ROOT)

        self.assertIn("c_module_vscf_alg_id.xml", renderers)
        self.assertIn("c_module_vscf_cipher_state.xml", renderers)

    def test_foundation_registry_keys_follow_model_derived_ir_outputs(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        ir = project_to_ir(project)
        renderers = direct_c_renderers_for_project("foundation", REPO_ROOT)
        expected = {direct_xml_name(enum.output) for enum in ir.enums}

        self.assertEqual(expected, set(renderers))


if __name__ == "__main__":
    unittest.main()
