from __future__ import annotations

from pathlib import Path
import unittest

from tools.codegen.project_ir import project_to_ir
from tools.codegen.project_source import load_named_project_source, project_model_path


REPO_ROOT = Path(__file__).resolve().parents[2]


class ProjectFoundationSharedFrameworkTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.project = load_named_project_source("foundation", REPO_ROOT)
        cls.ir = project_to_ir(cls.project)

    def test_foundation_loader_resolves_project_root_and_shared_module_dependencies(self) -> None:
        project = self.project

        self.assertEqual(project_model_path("foundation", REPO_ROOT), Path(project.path))
        self.assertEqual("foundation", project.name)
        self.assertEqual("virgil crypto foundation", project.namespace)
        self.assertEqual("VSCFoundation", project.framework)
        self.assertEqual("vscf", project.prefix)
        self.assertEqual(str(REPO_ROOT / "library/foundation"), project.source_root)
        self.assertEqual(str(REPO_ROOT / "codegen/generated/foundation"), project.work_root)
        self.assertEqual(["multi threading", "post quantum"], [feature.name for feature in project.feature_refs])
        self.assertEqual(
            [
                "assert",
                "library",
                "memory",
                "atomic",
                "group session typedefs",
                "mbedtls bridge random",
                "mbedtls bridge entropy",
                "mbedtls bridge entropy poll",
            ],
            [module.name for module in project.modules],
        )
        self.assertEqual(["platform"], [module.name for module in project.dependency_modules])

        bridge_random = project.module_named("mbedtls bridge random", resolved=True)
        self.assertEqual(["library", "assert"], [ref.name for ref in bridge_random.requires[:2]])
        self.assertEqual(
            ["assert", "library", "platform", "memory", "atomic"],
            [module.name for module in project.resolved_modules[:5]],
        )
        self.assertEqual(
            ["shared", "shared", "shared", "shared"],
            [project.module_named(name, resolved=True).from_area for name in ["assert", "library", "memory", "atomic"]],
        )

    def test_foundation_ir_output_targets_stay_model_driven_and_project_specific(self) -> None:
        ir = self.ir

        self.assertEqual("virgil/crypto/foundation", ir.include_namespace)
        self.assertEqual("generated/foundation", ir.generated_namespace)
        self.assertEqual(["status", "asn1 tag", "alg id", "oid id", "recipient cipher decryption state", "group msg type", "cipher state"], [ref.name for ref in ir.enum_refs])

        group_typedefs = next(module for module in ir.modules if module.name == "group session typedefs")
        error_class = next(cls for cls in ir.classes if cls.name == "error")
        status_enum = next(enum for enum in ir.enums if enum.name == "status")
        recipient_state_enum = next(enum for enum in ir.enums if enum.name == "recipient cipher decryption state")

        self.assertEqual("vscf_group_session_typedefs", group_typedefs.output.c_symbol)
        self.assertEqual("../library/foundation/include/virgil/crypto/foundation/vscf_group_session_typedefs.h", group_typedefs.output.header_path)
        self.assertEqual("generated/foundation/module_group_session_typedefs.xml", group_typedefs.output.generated_source_path)

        self.assertEqual("vscf_error", error_class.output.c_symbol)
        self.assertEqual("../library/foundation/include/virgil/crypto/foundation/vscf_error.h", error_class.output.header_path)
        self.assertEqual("generated/foundation/class_error.xml", error_class.output.generated_source_path)

        self.assertEqual("vscf_status", status_enum.output.c_symbol)
        self.assertEqual("../library/foundation/include/virgil/crypto/foundation/vscf_status.h", status_enum.output.header_path)
        self.assertEqual("generated/foundation/enum_status.xml", status_enum.output.generated_source_path)

        self.assertEqual("vscf_recipient_cipher_decryption_state", recipient_state_enum.output.c_symbol)
        self.assertEqual(
            "../library/foundation/include/virgil/crypto/foundation/private/vscf_recipient_cipher_decryption_state.h",
            recipient_state_enum.output.header_path,
        )
        self.assertEqual("generated/foundation/enum_recipient_cipher_decryption_state.xml", recipient_state_enum.output.generated_source_path)
        self.assertEqual("private", recipient_state_enum.output.header_visibility)

        for output in [group_typedefs.output, error_class.output, status_enum.output, recipient_state_enum.output]:
            assert output is not None
            self.assertTrue(output.c_symbol.startswith("vscf_"))
            self.assertIn("foundation", output.header_path)
            self.assertIn("foundation", output.generated_source_path)
            self.assertNotIn("common", output.header_path)
            self.assertNotIn("common", output.generated_source_path)

    def test_foundation_metadata_differs_from_common_without_backend_hardcodes(self) -> None:
        common_ir = project_to_ir(load_named_project_source("common", REPO_ROOT))
        foundation_ir = self.ir

        self.assertEqual("vsc", common_ir.prefix)
        self.assertEqual("vscf", foundation_ir.prefix)
        self.assertEqual("virgil/crypto/common", common_ir.include_namespace)
        self.assertEqual("virgil/crypto/foundation", foundation_ir.include_namespace)
        self.assertEqual("generated/common", common_ir.generated_namespace)
        self.assertEqual("generated/foundation", foundation_ir.generated_namespace)

        common_error_output = next(cls for cls in foundation_ir.classes if cls.name == "error").output
        common_buffer_output = next(cls for cls in common_ir.classes if cls.name == "buffer").output
        assert common_error_output is not None
        assert common_buffer_output is not None
        self.assertTrue(common_error_output.header_path.startswith("../library/foundation/"))
        self.assertTrue(common_buffer_output.header_path.startswith("../library/common/"))
        self.assertNotEqual(common_error_output.header_path.split("/include/")[0], common_buffer_output.header_path.split("/include/")[0])


if __name__ == "__main__":
    unittest.main()
