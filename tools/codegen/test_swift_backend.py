"""Tests for the Swift wrapper backend (tools/codegen/project_swift_backend.py).

Unit 1 scope: name utilities + enum generator + orchestrator parity with
the legacy GSL output.
"""
from __future__ import annotations

import pathlib
import unittest

from tools.codegen.project_swift_backend import (
    generate_swift_enum,
    generate_swift_files,
    swift_case_name,
    swift_method_name,
    swift_type_name,
)
from tools.codegen.project_ir import project_to_ir
from tools.codegen.project_source import load_named_project_source


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


class NameUtilityTests(unittest.TestCase):
    def test_type_name_single_word(self) -> None:
        self.assertEqual(swift_type_name("hash"), "Hash")

    def test_type_name_two_words(self) -> None:
        self.assertEqual(swift_type_name("alg id"), "AlgId")

    def test_type_name_preserves_digits(self) -> None:
        self.assertEqual(swift_type_name("aes256 gcm"), "Aes256Gcm")

    def test_type_name_underscores(self) -> None:
        self.assertEqual(swift_type_name("asn1_reader"), "Asn1Reader")

    def test_type_name_compound(self) -> None:
        self.assertEqual(swift_type_name("group msg type"), "GroupMsgType")

    def test_case_name_single_word(self) -> None:
        self.assertEqual(swift_case_name("sha256"), "sha256")

    def test_case_name_two_words(self) -> None:
        self.assertEqual(swift_case_name("aes256 gcm"), "aes256Gcm")

    def test_case_name_complex(self) -> None:
        self.assertEqual(swift_case_name("round5 nd 1cca 5d"), "round5Nd1cca5d")

    def test_case_name_none(self) -> None:
        self.assertEqual(swift_case_name("none"), "none")

    def test_case_name_camel_multi(self) -> None:
        self.assertEqual(swift_case_name("compound key"), "compoundKey")

    def test_method_name_single(self) -> None:
        self.assertEqual(swift_method_name("hash"), "hash")

    def test_method_name_multi(self) -> None:
        self.assertEqual(swift_method_name("alg id"), "algId")


# ---------------------------------------------------------------------------
# Foundation enum parity tests
# ---------------------------------------------------------------------------

def _load_foundation_ir():
    src = load_named_project_source("foundation", str(REPO_ROOT))
    return project_to_ir(src)


def _legacy_content(rel_path: str) -> str:
    return (REPO_ROOT / rel_path).read_text()


class FoundationEnumParityTests(unittest.TestCase):
    """Generated Swift enum files must be byte-identical to legacy output."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_foundation_ir()
        cls.files = dict(generate_swift_files(cls.ir))

    def _assert_parity(self, rel_path: str) -> None:
        legacy = _legacy_content(rel_path)
        generated = self.files.get(rel_path)
        self.assertIsNotNone(generated, f"Expected file {rel_path} was not generated")
        self.assertEqual(generated, legacy, f"Generated {rel_path} differs from legacy")

    def test_alg_id_parity(self) -> None:
        self._assert_parity(
            "wrappers/swift/VirgilCrypto/VirgilCryptoFoundation/AlgId.swift"
        )

    def test_asn1_tag_parity(self) -> None:
        self._assert_parity(
            "wrappers/swift/VirgilCrypto/VirgilCryptoFoundation/Asn1Tag.swift"
        )

    def test_cipher_state_parity(self) -> None:
        self._assert_parity(
            "wrappers/swift/VirgilCrypto/VirgilCryptoFoundation/CipherState.swift"
        )

    def test_group_msg_type_parity(self) -> None:
        self._assert_parity(
            "wrappers/swift/VirgilCrypto/VirgilCryptoFoundation/GroupMsgType.swift"
        )

    def test_oid_id_parity(self) -> None:
        self._assert_parity(
            "wrappers/swift/VirgilCrypto/VirgilCryptoFoundation/OidId.swift"
        )


class FoundationEnumFileCountTests(unittest.TestCase):
    """Orchestrator produces the correct number of enum files."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_foundation_ir()
        cls.files = generate_swift_files(cls.ir)

    def test_foundation_enum_count(self) -> None:
        # Foundation has 5 public non-infrastructure enums
        self.assertEqual(len(self.files), 5)

    def test_status_enum_not_emitted(self) -> None:
        paths = [p for p, _ in self.files]
        for p in paths:
            self.assertNotIn("Status", p.split("/")[-1])

    def test_impl_tag_not_emitted(self) -> None:
        paths = [p for p, _ in self.files]
        for p in paths:
            self.assertNotIn("ImplTag", p.split("/")[-1])
            self.assertNotIn("impl", p.split("/")[-1].lower().replace("implementation", ""))


# ---------------------------------------------------------------------------
# Ratchet enum parity tests
# ---------------------------------------------------------------------------

class RatchetEnumParityTests(unittest.TestCase):
    """Ratchet project enum files match legacy."""

    @classmethod
    def setUpClass(cls) -> None:
        src = load_named_project_source("ratchet", str(REPO_ROOT))
        cls.ir = project_to_ir(src)
        cls.files = dict(generate_swift_files(cls.ir))

    def test_msg_type_parity(self) -> None:
        rel = "wrappers/swift/VirgilCrypto/VirgilCryptoRatchet/MsgType.swift"
        legacy = _legacy_content(rel)
        self.assertEqual(self.files.get(rel), legacy)

    def test_group_msg_type_parity(self) -> None:
        rel = "wrappers/swift/VirgilCrypto/VirgilCryptoRatchet/GroupMsgType.swift"
        legacy = _legacy_content(rel)
        self.assertEqual(self.files.get(rel), legacy)

    def test_ratchet_enum_count(self) -> None:
        self.assertEqual(len(self.files), 2)


# ---------------------------------------------------------------------------
# Pythia — no public enums
# ---------------------------------------------------------------------------

class PythiaEnumTests(unittest.TestCase):
    """Pythia has no public enums — should generate 0 enum files."""

    @classmethod
    def setUpClass(cls) -> None:
        src = load_named_project_source("pythia", str(REPO_ROOT))
        cls.ir = project_to_ir(src)
        cls.files = generate_swift_files(cls.ir)

    def test_no_enum_files(self) -> None:
        self.assertEqual(len(self.files), 0)


if __name__ == "__main__":
    unittest.main()
