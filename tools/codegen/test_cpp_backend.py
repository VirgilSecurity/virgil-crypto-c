"""Tests for the C++ wrapper backend (tools/codegen/project_cpp_backend.py).

Unit 1 scope: name/type utilities, enum generation, the ``Error`` type, and the
orchestrator's entity selection (Error + enums; infrastructure/private excluded).
"""
from __future__ import annotations

import pathlib
import unittest

from tools.codegen.project_cpp_backend import (
    cpp_enum_case,
    cpp_method_name,
    cpp_type_name,
    generate_cpp_error,
    generate_cpp_files,
)
from tools.codegen.project_ir import project_to_ir
from tools.codegen.project_source import load_named_project_source


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


class NameUtilityTests(unittest.TestCase):
    def test_type_name_single_word(self) -> None:
        self.assertEqual(cpp_type_name("hash"), "Hash")

    def test_type_name_two_words(self) -> None:
        self.assertEqual(cpp_type_name("alg id"), "AlgId")

    def test_type_name_preserves_digits(self) -> None:
        self.assertEqual(cpp_type_name("aes256 gcm"), "Aes256Gcm")

    def test_type_name_underscores(self) -> None:
        self.assertEqual(cpp_type_name("asn1_reader"), "Asn1Reader")

    def test_enum_case_pascal(self) -> None:
        self.assertEqual(cpp_enum_case("bad arguments"), "BadArguments")

    def test_enum_case_none(self) -> None:
        self.assertEqual(cpp_enum_case("none"), "None")

    def test_enum_case_digits(self) -> None:
        self.assertEqual(cpp_enum_case("aes256 gcm"), "Aes256Gcm")

    def test_method_name_multi(self) -> None:
        self.assertEqual(cpp_method_name("encrypt data"), "encrypt_data")

    def test_method_name_single(self) -> None:
        self.assertEqual(cpp_method_name("hash"), "hash")

    def test_method_name_reserved_word_gets_trailing_underscore(self) -> None:
        self.assertEqual(cpp_method_name("delete"), "delete_")
        self.assertEqual(cpp_method_name("new"), "new_")


def _load_ir(name: str):
    return project_to_ir(load_named_project_source(name, str(REPO_ROOT)))


class GenerationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_ir("foundation")
        cls.files = dict(generate_cpp_files(cls.ir, repo_root=str(REPO_ROOT)))

    def test_emits_non_empty(self) -> None:
        self.assertTrue(self.files)

    def test_all_paths_under_wrapper_dir(self) -> None:
        for path in self.files:
            self.assertTrue(
                path.startswith("wrappers/cpp/include/virgil/crypto/foundation/"),
                path,
            )

    def test_emits_error_header_not_status(self) -> None:
        paths = set(self.files)
        self.assertIn("wrappers/cpp/include/virgil/crypto/foundation/error.hpp", paths)
        # The status enum becomes Error, not a plain status.hpp; impl/tag is skipped too.
        self.assertNotIn("wrappers/cpp/include/virgil/crypto/foundation/status.hpp", paths)
        self.assertNotIn("wrappers/cpp/include/virgil/crypto/foundation/impl_tag.hpp", paths)

    def test_error_header_shape(self) -> None:
        content = self.files["wrappers/cpp/include/virgil/crypto/foundation/error.hpp"]
        self.assertIn("#pragma once", content)
        self.assertIn("namespace virgil::crypto::foundation {", content)
        self.assertIn("enum class Error : int {", content)
        # success is not an error case
        self.assertNotIn("Success", content)

    def test_error_cases_strip_redundant_error_prefix_and_keep_c_values(self) -> None:
        content = self.files["wrappers/cpp/include/virgil/crypto/foundation/error.hpp"]
        # Error::BadArguments, not Error::ErrorBadArguments; values match the C enum.
        self.assertIn("BadArguments = -1,", content)
        self.assertNotIn("ErrorBadArguments", content)
        self.assertIn("AuthFailed = -201,", content)

    def test_generate_cpp_error_directly(self) -> None:
        content = generate_cpp_error(self.ir)
        self.assertIn("enum class Error : int {", content)

    def test_enum_header_shape(self) -> None:
        alg_id = "wrappers/cpp/include/virgil/crypto/foundation/alg_id.hpp"
        self.assertIn(alg_id, self.files)
        content = self.files[alg_id]
        self.assertIn("enum class AlgId : int {", content)
        self.assertIn("#pragma once", content)


if __name__ == "__main__":
    unittest.main()
