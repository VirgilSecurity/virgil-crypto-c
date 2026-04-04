from __future__ import annotations

from pathlib import Path
import unittest

from tests.codegen.project_common_fixtures import PROJECT_COMMON_EXPECTATIONS
from tools.codegen.common_source import load_project_common, load_project_source


REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECT_COMMON_XML = REPO_ROOT / "codegen/models/project_common/project_common.xml"


class ProjectCommonSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.project_from_entrypoint = load_project_source(PROJECT_COMMON_XML)
        cls.project_from_repo_root = load_project_common(REPO_ROOT)

    def test_project_common_loader_starts_from_project_xml_entrypoint(self) -> None:
        self.assertEqual(str(PROJECT_COMMON_XML), self.project_from_entrypoint.path)
        self.assertEqual(self.project_from_entrypoint.to_dict(), self.project_from_repo_root.to_dict())

    def test_project_common_loader_exposes_project_metadata(self) -> None:
        expected = PROJECT_COMMON_EXPECTATIONS["project"]
        project = self.project_from_entrypoint

        self.assertEqual(expected["name"], project.name)
        self.assertEqual(expected["version"], project.version)
        self.assertEqual(expected["namespace"], project.attrs["namespace"])
        self.assertEqual(expected["framework"], project.attrs["framework"])
        self.assertEqual(expected["prefix"], project.attrs["prefix"])
        self.assertEqual(expected["path"], project.attrs["path"])
        self.assertEqual(expected["work_path"], project.attrs["work_path"])
        self.assertEqual(expected["wrappers"], project.attrs["wrappers"])
        self.assertEqual(expected["features"], [
            {"name": feature.name, "default": feature.attrs.get("default")}
            for feature in project.feature_refs
        ])
        self.assertEqual(PROJECT_COMMON_EXPECTATIONS["enum_names"], [enum_ref["name"] for enum_ref in project.enum_refs])

    def test_project_common_loader_resolves_referenced_modules(self) -> None:
        project = self.project_from_entrypoint
        expected_names = PROJECT_COMMON_EXPECTATIONS["module_names"]

        self.assertEqual(expected_names, [module_ref["name"] for module_ref in project.module_refs])
        self.assertEqual(expected_names, [module.name for module in project.modules])

        for module_name, facts in PROJECT_COMMON_EXPECTATIONS["module_facts"].items():
            module = next(module for module in project.modules if module.name == module_name)
            if "requires" in facts:
                self.assertEqual(facts["requires"], [ref.attrs["module"] for ref in module.requires])
            if "callbacks" in facts:
                self.assertEqual(facts["callbacks"], [callback.name for callback in module.callbacks])
            if "methods" in facts:
                self.assertEqual(facts["methods"], [method.name for method in module.methods])
            if "macros" in facts:
                self.assertEqual(facts["macros"], [macro.name for macro in module.macroses])
            if "code_snippets" in facts:
                rendered_code = "\n".join(
                    block["text"]
                    for block in (
                        module.code_blocks
                        + [block for method in module.methods + module.macroses + module.macro_groups for block in method.code_blocks]
                    )
                )
                for snippet in facts["code_snippets"]:
                    self.assertIn(snippet, rendered_code)

    def test_project_common_loader_resolves_referenced_classes(self) -> None:
        project = self.project_from_entrypoint
        expected_names = PROJECT_COMMON_EXPECTATIONS["class_names"]

        self.assertEqual(expected_names, [class_ref["name"] for class_ref in project.class_refs])
        self.assertEqual(expected_names, [cls.name for cls in project.classes])

        for class_name, facts in PROJECT_COMMON_EXPECTATIONS["class_facts"].items():
            cls = next(loaded_class for loaded_class in project.classes if loaded_class.name == class_name)
            self.assertEqual(facts["properties"], [prop.name for prop in cls.properties])
            self.assertEqual(facts["constructors"], [ctor.name for ctor in cls.constructors])
            self.assertEqual(facts["methods"], [method.name for method in cls.methods[: len(facts["methods"])]])


if __name__ == "__main__":
    unittest.main()
