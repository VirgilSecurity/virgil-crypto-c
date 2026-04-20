from __future__ import annotations

from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

from tools.codegen.common_direct_c import (
    build_direct_assert_c_module,
    build_direct_atomic_c_module,
    build_direct_buffer_defs_c_module,
    build_direct_data_c_module,
    build_direct_library_c_module,
    build_direct_memory_c_module,
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
    enum_ir,
    module_ir,
    render_class_c_module,
    render_enum_c_module,
    render_module_c_module,
    return_from_source,
)
from tools.codegen.project_ir import IRConstant, IREnum, IROutputTarget, IRProject, project_to_ir


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

    def test_render_enum_c_module_derives_common_names_from_ir_output(self) -> None:
        project_ir = IRProject(name="common", prefix="vsc")
        demo_enum = IREnum(
            name="demo mode",
            attrs={"scope": "public"},
            description="Common demo enum.",
            constants=[
                IRConstant(name="fast path", attrs={"value": "7"}, description="Fast path constant."),
                IRConstant(name="slow path", attrs={}),
            ],
            output=IROutputTarget(
                entity_kind="enum",
                entity_name="demo mode",
                c_artifact_kind="module",
                c_symbol="vsc_demo_mode",
                stem="vsc_demo_mode",
                include_file="vsc_demo_mode.h",
                source_file="vsc_demo_mode.c",
                header_path="library/common/include/vsc_demo_mode.h",
                source_path="library/common/src/vsc_demo_mode.c",
                generated_header_path="generated/common/c_module_vsc_demo_mode.xml",
                generated_source_path="generated/common/enum_demo_mode.xml",
                once_guard="vsc_demo_mode_h_included",
            ),
        )

        root = render_enum_c_module(project_ir, demo_enum)

        self.assertEqual("vsc_demo_mode", root.attrib["name"])
        self.assertEqual("library/common/include/vsc_demo_mode.h", root.attrib["header_file"])
        enum_elem = root.find("c_enum")
        self.assertIsNotNone(enum_elem)
        self.assertEqual("vsc_demo_mode_t", enum_elem.attrib["name"])
        constants = enum_elem.findall("c_constant")
        self.assertEqual("vsc_demo_mode_FAST_PATH", constants[0].attrib["name"])
        self.assertEqual("7", constants[0].attrib["value"])
        self.assertEqual("vsc_demo_mode_SLOW_PATH", constants[1].attrib["name"])

    def test_render_class_c_module_derives_data_shape_from_ir(self) -> None:
        root = render_class_c_module(self.ir, class_ir(self.ir, "data"))

        self.assertEqual("vsc_data", root.attrib["name"])
        self.assertEqual(
            [include.attrib["file"] for include in root.findall("c_include") if include.attrib["scope"] == "public"],
            ["vsc_library.h", "vsc_data.h"],
        )
        struct = root.find("c_struct")
        self.assertIsNotNone(struct)
        self.assertEqual("public", struct.attrib["definition"])
        fields = struct.findall("c_property")
        self.assertEqual([field.attrib["name"] for field in fields], ["bytes", "len"])
        self.assertEqual("given", fields[0].attrib["array"])
        self.assertEqual("1", fields[0].attrib["is_const_type"])

    def test_render_module_c_module_matches_common_adapter_outputs_for_shared_modules(self) -> None:
        cases = [
            ("library", build_direct_library_c_module),
            ("memory", build_direct_memory_c_module),
            ("assert", build_direct_assert_c_module),
            ("atomic", build_direct_atomic_c_module),
        ]

        for module_name, adapter in cases:
            with self.subTest(module=module_name):
                generic = render_module_c_module(self.ir, module_ir(self.ir, module_name))
                via_adapter = adapter(REPO_ROOT)
                self.assertEqual(ET.tostring(via_adapter), ET.tostring(generic))

    def test_render_module_c_module_derives_aliases_constants_and_macro_group_members_from_ir(self) -> None:
        root = render_module_c_module(self.ir, module_ir(self.ir, "library"))

        alias = root.find("c_alias")
        self.assertIsNotNone(alias)
        self.assertEqual("byte", alias.attrib["name"])
        self.assertEqual("uint8_t", alias.attrib["type"])

        enum_elem = root.find("c_enum")
        self.assertIsNotNone(enum_elem)
        constant = enum_elem.find("c_constant")
        self.assertIsNotNone(constant)
        self.assertEqual("VSC_POINTER_SIZE", constant.attrib["name"])
        self.assertEqual("sizeof (void *)", constant.attrib["value"])

        macro_groups = root.findall("c_macroses")
        self.assertTrue(macro_groups)
        self.assertEqual(
            [macro.attrib["name"] for macro in macro_groups[0].findall("c_macros")],
            ["VSC_PUBLIC", "VSC_PRIVATE", "VSC_SHARED_LIBRARY", "VSC_INTERNAL_BUILD"],
        )

    def test_render_enum_c_module_preserves_foundation_enum_metadata_from_ir(self) -> None:
        foundation_ir = project_to_ir(load_named_project_source("foundation", REPO_ROOT))
        root = render_enum_c_module(foundation_ir, enum_ir(foundation_ir, "recipient cipher decryption state"))

        self.assertEqual("private", root.attrib["scope"])
        self.assertEqual(
            "../library/foundation/include/virgil/crypto/foundation/private/vscf_recipient_cipher_decryption_state.h",
            root.attrib["header_file"],
        )
        self.assertEqual("vscf_recipient_cipher_decryption_state.h", root.attrib["c_include_file"])
        enum_elem = root.find("c_enum")
        self.assertIsNotNone(enum_elem)
        self.assertEqual("vscf_recipient_cipher_decryption_state_t", enum_elem.attrib["typedef_name"])
        constants = enum_elem.findall("c_constant")
        self.assertEqual("vscf_recipient_cipher_decryption_state_WAITING_MESSAGE_INFO", constants[0].attrib["name"])
        self.assertEqual("0", constants[0].attrib["value"])


if __name__ == "__main__":
    unittest.main()
