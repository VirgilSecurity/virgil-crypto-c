from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from tools.codegen.common_bootstrap import c_decl, direct_c_renderers, iter_project_xml_paths, merge_generated_section, render_callback, render_enum, render_method_signature, render_one


REPO_ROOT = Path(__file__).resolve().parents[2]


class CommonBootstrapTest(unittest.TestCase):
    def test_direct_c_renderers_uses_shared_project_registry_for_foundation(self) -> None:
        renderers = direct_c_renderers(REPO_ROOT, project="foundation")

        self.assertIn("c_module_vscf_status.xml", renderers)
        self.assertIn("c_module_vscf_recipient_cipher_decryption_state.xml", renderers)

    def test_merge_generated_section_preserves_handwritten_prefix_and_suffix(self) -> None:
        existing = """// handwritten prefix\n//  @generated\nold generated\n//  @end\n// handwritten suffix\n"""
        generated = "//  @generated\nnew generated\n//  @end\n"

        merged = merge_generated_section(existing, generated)

        self.assertEqual(
            "// handwritten prefix\n//  @generated\nnew generated\n//  @end\n// handwritten suffix\n",
            merged,
        )

    def test_iter_project_xml_paths_includes_direct_renderer_names_without_disk_xml(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            project_dir = Path(tmp_dir)
            direct_only = project_dir / "custom_model_named.xml"
            legacy_named = project_dir / "c_module_legacy.xml"
            legacy_named.write_text("<c_module />")

            with patch("tools.codegen.common_bootstrap.direct_c_renderers", return_value={direct_only.name: object()}):
                xml_paths = iter_project_xml_paths(project_dir, REPO_ROOT)

        self.assertEqual([direct_only], xml_paths)

    def test_render_enum_supports_named_typedef_and_implicit_values(self) -> None:
        enum = ET.Element("c_enum", name="demo_enum_t", typedef_name="demo_enum_t")
        ET.SubElement(enum, "c_constant", name="DEMO_FIRST", value="7")
        ET.SubElement(enum, "c_constant", name="DEMO_SECOND")

        rendered = render_enum(enum)

        self.assertEqual(
            "enum demo_enum_t {\n"
            "    DEMO_FIRST = 7,\n"
            "    DEMO_SECOND\n"
            "};\n"
            "typedef enum demo_enum_t demo_enum_t;",
            rendered,
        )

    def test_iter_project_xml_paths_includes_legacy_fallbacks_only_when_requested(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            project_dir = Path(tmp_dir)
            direct_only = project_dir / "custom_model_named.xml"
            legacy_named = project_dir / "c_module_legacy.xml"
            unresolved = project_dir / "c_module_skip_unresolved.xml"
            legacy_named.write_text("<c_module />")
            unresolved.write_text("<c_module />")

            with patch("tools.codegen.common_bootstrap.direct_c_renderers", return_value={direct_only.name: object()}):
                xml_paths = iter_project_xml_paths(project_dir, REPO_ROOT, include_legacy_fallback=True)

        self.assertEqual(sorted([direct_only, legacy_named]), xml_paths)

    def test_render_one_preserves_handwritten_content_when_rewriting_generated_blocks(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            repo_root = Path(tmp_dir).resolve()
            codegen_root = repo_root / "codegen"
            out_root = repo_root / "out"
            target = repo_root / "library/common/include/demo.h"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                "// handwritten prefix\n"
                "//  @generated\nold generated\n//  @end\n"
                "// handwritten suffix\n"
            )

            xml_path = codegen_root / "generated/common/custom.xml"
            xml_path.parent.mkdir(parents=True, exist_ok=True)

            root = ET.Element(
                "c_module",
                {
                    "header_file": "../library/common/include/demo.h",
                    "source_file": "",
                },
            )
            ET.SubElement(root, "c_code", definition="public").text = "#define DEMO 1"

            with patch("tools.codegen.common_bootstrap.direct_c_renderers", return_value={xml_path.name: lambda _repo_root: root}):
                written = render_one(xml_path, repo_root, codegen_root, out_root)

            self.assertEqual([out_root / "library/common/include/demo.h"], written)
            self.assertEqual(
                "// handwritten prefix\n"
                "//  @generated\n"
                "// --------------------------------------------------------------------------\n"
                "// clang-format off\n"
                "//  Generated section start.\n"
                "// --------------------------------------------------------------------------\n"
                "\n"
                "#define DEMO 1\n"
                "// --------------------------------------------------------------------------\n"
                "//  Generated section end.\n"
                "// clang-format on\n"
                "// --------------------------------------------------------------------------\n"
                "//  @end\n"
                "// handwritten suffix\n",
                written[0].read_text(),
            )


class CDeclarationRenderingTests(unittest.TestCase):
    """Tests for c_decl and render_method_signature fixed-array argument handling."""

    def _make_method(self, arg_attribs: list[dict]) -> ET.Element:
        method = ET.Element("c_method", name="test_fn", visibility="public", declaration="public")
        ET.SubElement(method, "c_return", type="void", accessed_by="value")
        for attribs in arg_attribs:
            ET.SubElement(method, "c_argument", **attribs)
        return method

    def test_c_decl_fixed_array_renders_bracketed_size(self) -> None:
        result = c_decl("char", "str", "value", None, False, True, "primitive", array_length="64")
        self.assertEqual("char str[64]", result)

    def test_c_decl_dynamic_array_renders_as_pointer(self) -> None:
        result = c_decl("char", "str", "value", None, False, True, "primitive", array_length=None)
        self.assertEqual("char *str", result)

    def test_render_method_signature_fixed_array_arg_renders_bracketed_size(self) -> None:
        method = self._make_method([
            {"type": "char", "name": "str", "accessed_by": "value", "type_is": "primitive", "array": "64"},
        ])
        sig = render_method_signature(method, for_definition=False)
        self.assertIn("char str[64]", sig)

    def test_render_method_signature_dynamic_array_arg_renders_as_pointer(self) -> None:
        method = self._make_method([
            {"type": "char", "name": "buf", "accessed_by": "value", "type_is": "primitive", "array": "given"},
        ])
        sig = render_method_signature(method, for_definition=False)
        self.assertIn("char *buf", sig)
        self.assertNotIn("[", sig)

    def test_render_method_signature_derived_array_arg_renders_as_pointer(self) -> None:
        method = self._make_method([
            {"type": "char", "name": "buf", "accessed_by": "value", "type_is": "primitive", "array": "derived"},
        ])
        sig = render_method_signature(method, for_definition=False)
        self.assertIn("char *buf", sig)
        self.assertNotIn("[", sig)

    def test_render_callback_fixed_array_arg_renders_bracketed_size(self) -> None:
        cb = ET.Element("c_callback", name="my_fn_t")
        ET.SubElement(cb, "c_return", type="void", accessed_by="value")
        ET.SubElement(cb, "c_argument", type="char", name="str", accessed_by="value", type_is="primitive", array="64")
        rendered = render_callback(cb)
        self.assertIn("char str[64]", rendered)

    def test_render_callback_dynamic_array_arg_renders_as_pointer(self) -> None:
        cb = ET.Element("c_callback", name="my_fn_t")
        ET.SubElement(cb, "c_return", type="void", accessed_by="value")
        ET.SubElement(cb, "c_argument", type="char", name="buf", accessed_by="value", type_is="primitive", array="given")
        rendered = render_callback(cb)
        self.assertIn("char *buf", rendered)
        self.assertNotIn("[", rendered)


if __name__ == "__main__":
    unittest.main()
