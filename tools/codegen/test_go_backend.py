"""Tests for the Go wrapper backend (tools/codegen/project_go_backend.py).

Unit 1 scope: name utilities + enum generator + orchestrator parity with
the legacy GSL output.
"""
from __future__ import annotations

import pathlib
import unittest

from tools.codegen.project_go_backend import (
    generate_go_enum,
    generate_go_files,
    go_arg_name,
    go_constant_name,
    go_method_name,
    go_type_name,
)
from tools.codegen.project_ir import project_to_ir
from tools.codegen.project_source import load_named_project_source


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


class NameUtilityTests(unittest.TestCase):
    def test_go_type_name_single_word(self) -> None:
        self.assertEqual(go_type_name("hash"), "Hash")

    def test_go_type_name_two_words(self) -> None:
        self.assertEqual(go_type_name("alg id"), "AlgId")

    def test_go_type_name_preserves_digits(self) -> None:
        self.assertEqual(go_type_name("aes256 gcm"), "Aes256Gcm")

    def test_go_type_name_underscores(self) -> None:
        # Model names sometimes arrive with underscores rather than spaces.
        self.assertEqual(go_type_name("asn1_reader"), "Asn1Reader")

    def test_go_method_name_is_pascal(self) -> None:
        self.assertEqual(go_method_name("encrypt data"), "EncryptData")

    def test_go_arg_name_is_camel(self) -> None:
        self.assertEqual(go_arg_name("plain text"), "plainText")

    def test_go_arg_name_single_word_lowercases(self) -> None:
        self.assertEqual(go_arg_name("Data"), "data")

    def test_go_constant_name_prefixes_type(self) -> None:
        self.assertEqual(go_constant_name("alg id", "aes256 gcm"), "AlgIdAes256Gcm")


class FoundationEnumParityTests(unittest.TestCase):
    """Generated enums must match the legacy GSL output byte-for-byte."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = project_to_ir(load_named_project_source("foundation", str(REPO_ROOT)))
        cls.files = dict(generate_go_files(cls.ir))

    def _legacy(self, name: str) -> str:
        return (REPO_ROOT / "wrappers" / "go" / "foundation" / name).read_text()

    def _generated(self, name: str) -> str:
        return self.files[f"wrappers/go/foundation/{name}"]

    def test_alg_id_matches_legacy(self) -> None:
        # Sequential integer values, no descriptions on constants.
        self.assertEqual(self._generated("alg_id.go"), self._legacy("alg_id.go"))

    def test_asn1_tag_matches_legacy(self) -> None:
        # Hex literal values must be preserved verbatim.
        self.assertEqual(self._generated("asn1_tag.go"), self._legacy("asn1_tag.go"))

    def test_cipher_state_has_per_constant_doc_blocks(self) -> None:
        # Every constant carries a doc comment inside the const() block.
        self.assertEqual(self._generated("cipher_state.go"), self._legacy("cipher_state.go"))

    def test_group_msg_type_matches_legacy(self) -> None:
        # First constant has explicit value=1 (no sentinel zero entry).
        self.assertEqual(self._generated("group_msg_type.go"), self._legacy("group_msg_type.go"))

    def test_oid_id_matches_legacy(self) -> None:
        self.assertEqual(self._generated("oid_id.go"), self._legacy("oid_id.go"))

    def test_status_enum_is_not_emitted_as_standalone_file(self) -> None:
        # ``status`` is consumed by {project}_error.go (Unit 3), not a .go file.
        self.assertNotIn("wrappers/go/foundation/status.go", self.files)

    def test_impl_tag_enum_is_not_emitted_as_standalone_file(self) -> None:
        # ``impl/tag`` powers the interface dispatch switch, never a standalone enum.
        self.assertTrue(
            all("tag.go" not in path or "asn1_tag.go" in path for path in self.files)
        )

    def test_private_scope_enum_is_not_emitted(self) -> None:
        # ``recipient cipher decryption state`` is scope="private".
        self.assertNotIn(
            "wrappers/go/foundation/recipient_cipher_decryption_state.go",
            self.files,
        )


class EnumGenerationEdgeCaseTests(unittest.TestCase):
    """Value-handling edge cases on the pure generator."""

    def _make_enum(self, name: str, constants: list[tuple[str, str | None]],
                   description: str = "", attrs: dict[str, str] | None = None):
        from tools.codegen.project_ir import IRCConstant, IREnum
        return IREnum(
            name=name,
            description=description,
            attrs=attrs or {},
            constants=[
                IRCConstant(
                    name=cname,
                    attrs=({"value": cval} if cval is not None else {}),
                )
                for cname, cval in constants
            ],
        )

    def _make_project(self, name: str = "foundation"):
        from tools.codegen.project_ir import IRProject
        return IRProject(name=name)

    def test_sequential_default_values(self) -> None:
        enum = self._make_enum("demo", [("a", None), ("b", None), ("c", None)])
        out = generate_go_enum(self._make_project(), enum)
        self.assertIn("DemoA Demo = 0", out)
        self.assertIn("DemoB Demo = 1", out)
        self.assertIn("DemoC Demo = 2", out)

    def test_explicit_value_resets_sequence(self) -> None:
        # After an explicit value, the next implicit constant continues from
        # the next integer (matching C enum semantics).
        enum = self._make_enum("demo", [("a", "5"), ("b", None), ("c", None)])
        out = generate_go_enum(self._make_project(), enum)
        self.assertIn("DemoA Demo = 5", out)
        self.assertIn("DemoB Demo = 6", out)
        self.assertIn("DemoC Demo = 7", out)

    def test_hex_value_preserved_verbatim(self) -> None:
        enum = self._make_enum("demo", [("a", "0x01"), ("b", "0x0C")])
        out = generate_go_enum(self._make_project(), enum)
        self.assertIn("DemoA Demo = 0x01", out)
        self.assertIn("DemoB Demo = 0x0C", out)

    def test_negative_values_supported(self) -> None:
        # The ``status`` enum uses negative values — the generator must not
        # break on them even though we don't emit a standalone file for it.
        enum = self._make_enum("demo", [("ok", "0"), ("bad", "-1")])
        out = generate_go_enum(self._make_project(), enum)
        self.assertIn("DemoOk Demo = 0", out)
        self.assertIn("DemoBad Demo = -1", out)

    def test_output_ends_with_newline(self) -> None:
        enum = self._make_enum("demo", [("a", None)])
        self.assertTrue(generate_go_enum(self._make_project(), enum).endswith("\n"))


if __name__ == "__main__":
    unittest.main()
