from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from tools.codegen.common_bootstrap import iter_project_xml_paths, render_one
from tools.codegen.foundation_direct_c import direct_c_renderers


REPO_ROOT = Path(__file__).resolve().parents[2]


class FoundationDirectCTest(unittest.TestCase):
    def test_foundation_direct_renderer_registry_exposes_enum_slice(self) -> None:
        renderers = direct_c_renderers(REPO_ROOT)

        self.assertEqual(
            {
                "c_module_vscf_status.xml",
                "c_module_vscf_asn1_tag.xml",
                "c_module_vscf_alg_id.xml",
                "c_module_vscf_oid_id.xml",
                "c_module_vscf_recipient_cipher_decryption_state.xml",
                "c_module_vscf_group_msg_type.xml",
                "c_module_vscf_cipher_state.xml",
            },
            set(renderers.keys()),
        )

    def test_foundation_render_one_writes_enum_header_into_out_tree(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            repo_root = REPO_ROOT
            codegen_root = repo_root / "codegen"
            out_root = Path(tmp_dir).resolve()
            xml_path = codegen_root / "generated/foundation/c_module_vscf_alg_id.xml"

            written = render_one(xml_path, repo_root, codegen_root, out_root, project="foundation")

            self.assertEqual(
                [
                    out_root / "library/foundation/include/virgil/crypto/foundation/vscf_alg_id.h",
                    out_root / "library/foundation/src/vscf_alg_id.c",
                ],
                written,
            )
            generated = written[0].read_text()
            generated_source = written[1].read_text()
            self.assertIn("enum vscf_alg_id_t {", generated)
            self.assertIn("typedef enum vscf_alg_id_t vscf_alg_id_t;", generated)
            self.assertIn("vscf_alg_id_SHA224,", generated)
            self.assertNotIn("library/common", generated)
            self.assertTrue(generated.startswith("//  @license\n"))
            self.assertIn("//  Generated section start.", generated_source)
            self.assertIn("//  Generated section end.", generated_source)

    def test_iter_project_xml_paths_uses_foundation_project_registry(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            project_dir = Path(tmp_dir)
            xml_paths = iter_project_xml_paths(project_dir, REPO_ROOT, project="foundation")

        self.assertEqual(
            [
                project_dir / "c_module_vscf_alg_id.xml",
                project_dir / "c_module_vscf_asn1_tag.xml",
                project_dir / "c_module_vscf_cipher_state.xml",
                project_dir / "c_module_vscf_group_msg_type.xml",
                project_dir / "c_module_vscf_oid_id.xml",
                project_dir / "c_module_vscf_recipient_cipher_decryption_state.xml",
                project_dir / "c_module_vscf_status.xml",
            ],
            xml_paths,
        )


if __name__ == "__main__":
    unittest.main()
