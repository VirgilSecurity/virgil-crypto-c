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


# The committed Swift files carry the license header, so parity checks must generate
# with the same license text the release pipeline uses (read from the repo LICENSE).
_LICENSE = (REPO_ROOT / "LICENSE").read_text()


class FoundationEnumParityTests(unittest.TestCase):
    """Generated Swift enum files must be byte-identical to legacy output."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_foundation_ir()
        cls.files = dict(generate_swift_files(cls.ir, license_text=_LICENSE, repo_root=str(REPO_ROOT)))

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


class FoundationFileCountTests(unittest.TestCase):
    """Orchestrator produces the correct number of files."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_foundation_ir()
        cls.files = generate_swift_files(cls.ir, license_text=_LICENSE, repo_root=str(REPO_ROOT))

    def test_foundation_total_file_count(self) -> None:
        # Foundation has 131 Swift files total (enums + protocols + classes + infrastructure);
        # +1 vs the prior baseline for the new ChunkedAlgInfo.swift.
        self.assertEqual(len(self.files), 132)

    def test_foundation_enum_count(self) -> None:
        # 5 public non-infrastructure enum files
        enum_files = [p for p, _ in self.files if p.endswith((".swift",))
                     and any(p.endswith(f"/{n}.swift") for n in
                             ["AlgId", "Asn1Tag", "CipherState", "GroupMsgType", "OidId"])]
        self.assertEqual(len(enum_files), 5)

    def test_status_enum_not_standalone(self) -> None:
        # Status enum becomes FoundationError.swift, not Status.swift
        paths = [p for p, _ in self.files]
        self.assertFalse(any(p.endswith("/Status.swift") for p in paths))

    def test_impl_tag_not_standalone(self) -> None:
        paths = [p for p, _ in self.files]
        self.assertFalse(any("ImplTag" in p.split("/")[-1] for p in paths))


# ---------------------------------------------------------------------------
# Ratchet enum parity tests
# ---------------------------------------------------------------------------

class RatchetEnumParityTests(unittest.TestCase):
    """Ratchet project enum files match legacy."""

    @classmethod
    def setUpClass(cls) -> None:
        src = load_named_project_source("ratchet", str(REPO_ROOT))
        cls.ir = project_to_ir(src)
        cls.files = dict(generate_swift_files(cls.ir, license_text=_LICENSE, repo_root=str(REPO_ROOT)))

    def test_msg_type_parity(self) -> None:
        rel = "wrappers/swift/VirgilCrypto/VirgilCryptoRatchet/MsgType.swift"
        legacy = _legacy_content(rel)
        self.assertEqual(self.files.get(rel), legacy)

    def test_group_msg_type_parity(self) -> None:
        rel = "wrappers/swift/VirgilCrypto/VirgilCryptoRatchet/GroupMsgType.swift"
        legacy = _legacy_content(rel)
        self.assertEqual(self.files.get(rel), legacy)

    def test_ratchet_total_file_count(self) -> None:
        # Ratchet has 8 Swift files total
        self.assertEqual(len(self.files), 8)


if __name__ == "__main__":
    unittest.main()
