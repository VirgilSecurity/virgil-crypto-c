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


class ClassGenerationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_ir("foundation")
        cls.files = dict(generate_cpp_files(cls.ir, repo_root=str(REPO_ROOT)))
        cls.kp = cls.files["wrappers/cpp/include/virgil/crypto/foundation/key_provider.hpp"]

    def test_raii_lifecycle_rule_of_five(self) -> None:
        c = self.kp
        self.assertIn("KeyProvider() : c_ctx_(vscf_key_provider_new())", c)
        self.assertIn("explicit KeyProvider(vscf_key_provider_t* c_ctx) noexcept", c)
        self.assertIn("KeyProvider(const KeyProvider& other)", c)  # copy via shallow_copy
        self.assertIn("vscf_key_provider_shallow_copy(other.c_ctx_)", c)
        self.assertIn("KeyProvider(KeyProvider&& other) noexcept", c)  # move
        self.assertIn("~KeyProvider() { vscf_key_provider_delete(c_ctx_); }", c)
        self.assertIn("vscf_key_provider_t* c_ctx() const noexcept", c)
        self.assertIn("private:", c)

    def test_status_methods_return_expected(self) -> None:
        self.assertIn("tl::expected<void, Error> setup_defaults()", self.kp)
        self.assertIn("tl::expected<PrivateKey, Error> generate_private_key(AlgId alg_id)", self.kp)

    def test_error_branch_uses_unexpected(self) -> None:
        self.assertIn("return tl::unexpected(static_cast<Error>(status));", self.kp)

    def test_enum_arg_cast_to_c_enum(self) -> None:
        self.assertIn("static_cast<vscf_alg_id_t>(alg_id)", self.kp)

    def test_dependency_setter(self) -> None:
        self.assertIn("void set_random(const Random& random)", self.kp)
        self.assertIn("vscf_key_provider_release_random(c_ctx_);", self.kp)
        self.assertIn("vscf_key_provider_use_random(c_ctx_, random.c_ctx());", self.kp)

    def test_no_value_call_anywhere(self) -> None:
        # -fno-exceptions invariant: never call expected::value() on an error path.
        for path, content in self.files.items():
            self.assertNotIn(".value()", content, path)

    def test_buffer_output_maps_to_vector(self) -> None:
        # At least one generated class must exercise the buffer->vector pattern.
        joined = "\n".join(self.files.values())
        self.assertIn("vsc_buffer_use(", joined)
        self.assertIn(".resize(vsc_buffer_len(", joined)
        self.assertIn("vsc_buffer_delete(", joined)

    def test_static_class_has_no_handle(self) -> None:
        # A context="none" class (e.g. base64) is emitted with static methods and
        # no C handle member.
        # Pick a context=none class that is actually emitted (public scope).
        content = None
        for c in self.ir.classes:
            if c.attrs.get("context") != "none":
                continue
            if c.attrs.get("scope") in {"private", "internal"}:
                continue
            path = f"wrappers/cpp/include/virgil/crypto/foundation/{c.name.replace(' ', '_').lower()}.hpp"
            if path in self.files:
                content = self.files[path]
                break
        self.assertIsNotNone(content, "expected at least one emitted static (context=none) class")
        self.assertNotIn("c_ctx_", content)
        self.assertIn("static ", content)


if __name__ == "__main__":
    unittest.main()
