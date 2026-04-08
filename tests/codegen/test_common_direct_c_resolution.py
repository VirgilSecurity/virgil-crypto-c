from __future__ import annotations

from pathlib import Path
import unittest

from tools.codegen.common_direct_c import (
    build_direct_assert_c_module,
    build_direct_atomic_c_module,
    build_direct_buffer_c_module,
    build_direct_buffer_defs_c_module,
    build_direct_data_c_module,
    build_direct_library_c_module,
    build_direct_memory_c_module,
    direct_c_renderers,
)
from tools.codegen.project_source import load_named_project_source
from tools.codegen.project_c_backend import (
    c_module_root_attrs,
    class_ir,
    derived_module_output_from_class,
    direct_xml_name,
    module_ir,
)
from tools.codegen.project_ir import IROutputTarget, project_to_ir


REPO_ROOT = Path(__file__).resolve().parents[2]


class CommonDirectCResolutionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.project = load_named_project_source("common", REPO_ROOT)
        cls.ir = project_to_ir(cls.project)

    def test_c_module_root_attrs_follow_output_metadata(self) -> None:
        output = IROutputTarget(
            entity_kind="module",
            entity_name="demo",
            c_artifact_kind="module",
            c_symbol="alt_demo",
            stem="alt_demo",
            include_file="alt_demo.h",
            source_file="alt_demo.c",
            header_path="../alt/include/demo/alt_demo.h",
            source_path="../alt/src/alt_demo.c",
            generated_header_path="generated/demo/c_module_alt_demo.xml",
            generated_source_path="generated/demo/module_demo.xml",
            once_guard="alt_demo_h_included",
            header_visibility="private",
            source_visibility="public",
        )

        attrs = c_module_root_attrs(output, entity_id="demo", scope="private", class_name="")

        self.assertEqual("alt_demo", attrs["name"])
        self.assertEqual("alt_demo.h", attrs["c_include_file"])
        self.assertEqual("alt_demo.c", attrs["c_source_file"])
        self.assertEqual("../alt/include/demo/alt_demo.h", attrs["header_file"])
        self.assertEqual("../alt/src/alt_demo.c", attrs["source_file"])
        self.assertEqual("alt_demo_h_included", attrs["once_guard"])
        self.assertEqual("private", attrs["scope"])

    def test_direct_builders_take_root_output_metadata_from_ir(self) -> None:
        cases = [
            (build_direct_library_c_module(REPO_ROOT), module_ir(self.ir, "library").output),
            (build_direct_memory_c_module(REPO_ROOT), module_ir(self.ir, "memory").output),
            (build_direct_atomic_c_module(REPO_ROOT), module_ir(self.ir, "atomic").output),
            (build_direct_assert_c_module(REPO_ROOT), module_ir(self.ir, "assert").output),
            (build_direct_data_c_module(REPO_ROOT), class_ir(self.ir, "data").output),
            (build_direct_buffer_c_module(REPO_ROOT), class_ir(self.ir, "buffer").output),
        ]

        for root, output in cases:
            assert output is not None
            self.assertEqual(output.c_symbol, root.attrib["name"])
            self.assertEqual(output.include_file, root.attrib["c_include_file"])
            self.assertEqual(output.source_file, root.attrib["c_source_file"])
            self.assertEqual(output.header_path, root.attrib["header_file"])
            self.assertEqual(output.source_path, root.attrib["source_file"])
            self.assertEqual(output.once_guard, root.attrib["once_guard"])

    def test_direct_builders_use_ir_include_names_for_cross_module_dependencies(self) -> None:
        memory_root = build_direct_memory_c_module(REPO_ROOT)
        assert_root = build_direct_assert_c_module(REPO_ROOT)
        data_root = build_direct_data_c_module(REPO_ROOT)
        buffer_defs_root = build_direct_buffer_defs_c_module(REPO_ROOT)

        memory_includes = {include.attrib["file"] for include in memory_root.findall("c_include")}
        assert_includes = {include.attrib["file"] for include in assert_root.findall("c_include")}
        data_includes = {include.attrib["file"] for include in data_root.findall("c_include")}
        buffer_defs_includes = {include.attrib["file"] for include in buffer_defs_root.findall("c_include")}

        self.assertIn(module_ir(self.ir, "library").output.include_file, memory_includes)
        self.assertIn(module_ir(self.ir, "assert").output.include_file, memory_includes)
        self.assertIn(module_ir(self.ir, "library").output.include_file, assert_includes)
        self.assertIn(module_ir(self.ir, "memory").output.include_file, data_includes)
        self.assertIn(module_ir(self.ir, "assert").output.include_file, data_includes)
        self.assertIn(module_ir(self.ir, "atomic").output.include_file, buffer_defs_includes)
        self.assertEqual(f"{class_ir(self.ir, 'buffer').output.c_symbol}_t", buffer_defs_root.find("c_struct").attrib["name"])

    def test_buffer_runtime_support_is_loaded_from_checked_in_fragments(self) -> None:
        buffer_root = build_direct_buffer_c_module(REPO_ROOT)
        method_by_name = {method.attrib["name"]: method for method in buffer_root.findall("c_method")}

        self.assertEqual("external", method_by_name["vsc_buffer_is_empty"].attrib["definition"])
        self.assertIsNone(method_by_name["vsc_buffer_is_empty"].find("c_code"))
        self.assertIn("self->self_dealloc_cb = vsc_dealloc;", method_by_name["vsc_buffer_new"].find("c_code").text)
        self.assertIn("VSC_ATOMIC_COMPARE_EXCHANGE_WEAK", method_by_name["vsc_buffer_delete"].find("c_code").text)

    def test_data_methods_are_declared_from_ir_without_python_stub_bodies(self) -> None:
        data_root = build_direct_data_c_module(REPO_ROOT)
        method_by_name = {method.attrib["name"]: method for method in data_root.findall("c_method")}

        self.assertEqual("external", method_by_name["vsc_data"].attrib["definition"])
        self.assertIsNone(method_by_name["vsc_data"].find("c_code"))
        self.assertEqual("external", method_by_name["vsc_data_is_valid"].attrib["definition"])
        self.assertIsNone(method_by_name["vsc_data_is_valid"].find("c_code"))

    def test_bootstrap_renderer_dispatch_uses_ir_generated_xml_names(self) -> None:
        renderers = direct_c_renderers(REPO_ROOT)
        buffer_defs_output = derived_module_output_from_class(
            class_ir(self.ir, "buffer").output,
            entity_name="buffer_defs",
            stem_suffix="defs",
            generated_source_stem="buffer_defs",
            header_visibility="private",
        )
        expected_names = {
            direct_xml_name(module_ir(self.ir, "library").output),
            direct_xml_name(module_ir(self.ir, "assert").output),
            direct_xml_name(module_ir(self.ir, "memory").output),
            direct_xml_name(module_ir(self.ir, "atomic").output),
            direct_xml_name(class_ir(self.ir, "data").output),
            direct_xml_name(class_ir(self.ir, "buffer").output),
            direct_xml_name(buffer_defs_output),
        }

        self.assertEqual(expected_names, set(renderers))
        self.assertIs(renderers[direct_xml_name(module_ir(self.ir, "library").output)], build_direct_library_c_module)
        self.assertIs(renderers[direct_xml_name(module_ir(self.ir, "assert").output)], build_direct_assert_c_module)
        self.assertIs(renderers[direct_xml_name(module_ir(self.ir, "memory").output)], build_direct_memory_c_module)
        self.assertIs(renderers[direct_xml_name(module_ir(self.ir, "atomic").output)], build_direct_atomic_c_module)
        self.assertIs(renderers[direct_xml_name(class_ir(self.ir, "data").output)], build_direct_data_c_module)
        self.assertIs(renderers[direct_xml_name(class_ir(self.ir, "buffer").output)], build_direct_buffer_c_module)
        self.assertIs(renderers[direct_xml_name(buffer_defs_output)], build_direct_buffer_defs_c_module)


if __name__ == "__main__":
    unittest.main()
