from __future__ import annotations

import io
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from tools.codegen.common_bootstrap import iter_project_xml_paths, main, render_one
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

    def test_shared_bootstrap_cli_generates_only_foundation_enum_slice_into_out_tree(self) -> None:
        expected = {
            "library/foundation/include/virgil/crypto/foundation/private/vscf_recipient_cipher_decryption_state.h",
            "library/foundation/include/virgil/crypto/foundation/vscf_alg_id.h",
            "library/foundation/include/virgil/crypto/foundation/vscf_asn1_tag.h",
            "library/foundation/include/virgil/crypto/foundation/vscf_cipher_state.h",
            "library/foundation/include/virgil/crypto/foundation/vscf_group_msg_type.h",
            "library/foundation/include/virgil/crypto/foundation/vscf_oid_id.h",
            "library/foundation/include/virgil/crypto/foundation/vscf_status.h",
            "library/foundation/src/vscf_alg_id.c",
            "library/foundation/src/vscf_asn1_tag.c",
            "library/foundation/src/vscf_cipher_state.c",
            "library/foundation/src/vscf_group_msg_type.c",
            "library/foundation/src/vscf_oid_id.c",
            "library/foundation/src/vscf_recipient_cipher_decryption_state.c",
            "library/foundation/src/vscf_status.c",
        }

        build_root = REPO_ROOT / "build"
        build_root.mkdir(exist_ok=True)

        with TemporaryDirectory(dir=build_root) as tmp_dir:
            out_dir = Path(tmp_dir).resolve() / "foundation-enums"
            stdout = io.StringIO()
            argv = [
                "common_bootstrap.py",
                "--repo-root",
                str(REPO_ROOT),
                "--project",
                "foundation",
                "--out",
                str(out_dir),
            ]

            with patch("sys.argv", argv), patch("sys.stdout", stdout):
                exit_code = main()

            self.assertEqual(0, exit_code)
            generated_files = {
                str(path.relative_to(out_dir)).replace("\\", "/")
                for path in out_dir.rglob("*")
                if path.is_file()
            }

        self.assertEqual(expected, generated_files)
        self.assertIn("generated 14 files into", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
