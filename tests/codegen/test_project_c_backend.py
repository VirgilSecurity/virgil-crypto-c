from __future__ import annotations

from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

from tools.codegen.common_direct_c import (
    build_direct_buffer_defs_c_module,
    build_direct_data_c_module,
    direct_c_renderers,
)
from tools.codegen.project_source import load_named_project_source
from tools.codegen.project_c_backend import (
    DirectRendererSpec,
    argument_from_source,
    class_ir,
    class_type_symbol,
    derived_module_output_from_class,
    direct_renderer_map,
    direct_xml_name,
    return_from_source,
)
from tools.codegen.project_ir import project_to_ir


REPO_ROOT = Path(__file__).resolve().parents[2]


class ProjectCBackendTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.project = load_named_project_source("common", REPO_ROOT)
        cls.ir = project_to_ir(cls.project)

    def test_shared_lowering_helpers_use_ir_class_symbols(self) -> None:
        root = ET.Element("c_method")

        self_arg = argument_from_source(root, {"class": "self"}, name="self", project_ir=self.ir, owner_class="data")
        data_return = return_from_source(root, {"class": "self"}, project_ir=self.ir, owner_class="buffer")

        self.assertEqual(class_type_symbol(self.ir, "data"), self_arg.attrib["type"])
        self.assertEqual("class", self_arg.attrib["type_is"])
        self.assertEqual(class_type_symbol(self.ir, "buffer"), data_return.attrib["type"])
        self.assertEqual("class", data_return.attrib["type_is"])

    def test_shared_renderer_registry_matches_common_adapter_outputs(self) -> None:
        buffer_defs_output = derived_module_output_from_class(
            class_ir(self.ir, "buffer").output,
            entity_name="buffer_defs",
            stem_suffix="defs",
            generated_source_stem="buffer_defs",
            header_visibility="private",
        )
        shared_renderers = direct_renderer_map(
            self.ir,
            [
                DirectRendererSpec(entity_kind="class", entity_name="data", renderer=build_direct_data_c_module),
                DirectRendererSpec(
                    entity_kind="class",
                    entity_name="buffer",
                    renderer=build_direct_buffer_defs_c_module,
                    output_resolver=lambda _project_ir: buffer_defs_output,
                ),
            ],
        )
        adapter_renderers = direct_c_renderers(REPO_ROOT)

        self.assertIs(shared_renderers[direct_xml_name(class_ir(self.ir, "data").output)], adapter_renderers[direct_xml_name(class_ir(self.ir, "data").output)])
        self.assertIs(shared_renderers[direct_xml_name(buffer_defs_output)], adapter_renderers[direct_xml_name(buffer_defs_output)])


if __name__ == "__main__":
    unittest.main()
