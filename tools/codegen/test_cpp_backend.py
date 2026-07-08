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
    _cpp_return_expr,
    _cpp_method_body,
    _uses_output_buffer,
    _interface_ref_split,
)
from tools.codegen.project_ir import (
    project_to_ir, IRCArgument, IRCMethod, IRInterface,
)
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
                path.startswith("wrappers/cpp/include/virgil/crypto/foundation/")
                or path.startswith("wrappers/cpp/src/foundation/"),
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
        # header holds declarations; source holds the bodies (header+cpp split).
        cls.kp = cls.files["wrappers/cpp/include/virgil/crypto/foundation/key_provider.hpp"]
        cls.kp_cpp = cls.files["wrappers/cpp/src/foundation/key_provider.cpp"]

    def test_raii_lifecycle_rule_of_five(self) -> None:
        # Declarations in the header (C handle forward-declared, not included).
        h = self.kp
        self.assertIn("struct vscf_key_provider_t;", h)
        self.assertIn("KeyProvider();", h)
        self.assertIn("explicit KeyProvider(vscf_key_provider_t* c_ctx) noexcept;", h)
        self.assertIn("KeyProvider(const KeyProvider& other);", h)
        self.assertIn("KeyProvider(KeyProvider&& other) noexcept;", h)
        self.assertIn("~KeyProvider();", h)
        self.assertIn("vscf_key_provider_t* c_ctx() const noexcept;", h)
        self.assertIn("private:", h)
        # Definitions in the source.
        s = self.kp_cpp
        self.assertIn("KeyProvider::KeyProvider() : c_ctx_(vscf_key_provider_new()) {}", s)
        self.assertIn("vscf_key_provider_shallow_copy(other.c_ctx_)", s)
        self.assertIn("KeyProvider::~KeyProvider() { vscf_key_provider_delete(c_ctx_); }", s)

    def test_status_methods_return_expected(self) -> None:
        # Signatures in the header; the wrap-body in the source.
        self.assertIn("tl::expected<void, Error> setup_defaults();", self.kp)
        self.assertIn(
            "tl::expected<std::unique_ptr<PrivateKey>, Error> generate_private_key(AlgId alg_id)",
            self.kp,
        )
        self.assertIn("return FoundationImplementation::wrap_private_key(proxy_result);", self.kp_cpp)

    def test_error_branch_uses_unexpected(self) -> None:
        self.assertIn("return tl::unexpected(static_cast<Error>(status));", self.kp_cpp)

    def test_enum_arg_cast_to_c_enum(self) -> None:
        self.assertIn("static_cast<vscf_alg_id_t>(alg_id)", self.kp_cpp)

    def test_dependency_setter(self) -> None:
        self.assertIn("void set_random(const Random& random);", self.kp)   # decl
        self.assertIn("vscf_key_provider_release_random(c_ctx_);", self.kp_cpp)
        # Interface args are passed via impl() (the polymorphic handle), not c_ctx().
        self.assertIn("vscf_key_provider_use_random(c_ctx_, random.impl());", self.kp_cpp)

    def test_header_does_not_include_c_library(self) -> None:
        # The lean public header forward-declares the C handle instead of pulling
        # the C library header (the whole point of the header+cpp split).
        self.assertNotIn("vscf_key_provider.h", self.kp)
        self.assertIn("vscf_key_provider.h", self.kp_cpp)

    def test_no_value_call_anywhere(self) -> None:
        # -fno-exceptions invariant: never call expected::value() on an error path.
        for path, content in self.files.items():
            self.assertNotIn(".value()", content, path)

    def test_buffer_output_uses_stack_buffer(self) -> None:
        # Output buffers are stack-allocated (init/use/cleanup), not heap (new/delete).
        joined = "\n".join(v for k, v in self.files.items() if k.endswith(".cpp"))
        self.assertIn("vsc_buffer_t ", joined)       # value, not pointer
        self.assertIn("vsc_buffer_init(&", joined)
        self.assertIn("vsc_buffer_use(&", joined)
        self.assertIn(".resize(vsc_buffer_len(&", joined)
        self.assertIn("vsc_buffer_cleanup(&", joined)

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


class InterfaceAndImplementationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_ir("foundation")
        cls.files = dict(generate_cpp_files(cls.ir, repo_root=str(REPO_ROOT)))

    def _f(self, name: str) -> str:
        return self.files[f"wrappers/cpp/include/virgil/crypto/foundation/{name}"]

    def _c(self, name: str) -> str:
        return self.files[f"wrappers/cpp/src/foundation/{name}"]

    def test_context_base(self) -> None:
        c = self._f("context.hpp")
        self.assertIn("class Context {", c)
        self.assertIn("virtual vscf_impl_t* impl() const noexcept = 0;", c)
        self.assertIn("virtual ~Context() = default;", c)

    def test_interface_is_abstract_base(self) -> None:
        c = self._f("hash.hpp")
        self.assertIn("class Hash : virtual public Context {", c)
        self.assertIn("virtual std::vector<uint8_t> hash(std::span<const uint8_t> data) = 0;", c)
        self.assertIn("virtual void start() = 0;", c)

    def test_interface_inheritance_chain(self) -> None:
        # cipher_info-style inheritance is expressed as virtual public bases.
        c = self._f("auth_encrypt.hpp")  # auth encrypt : cipher info (per IR inherits)
        self.assertRegex(c, r"class AuthEncrypt : virtual public Context(, virtual public \w+)+ \{")

    def test_implementation_inherits_and_overrides(self) -> None:
        h = self._f("sha256.hpp")
        s = self._c("sha256.cpp")
        self.assertIn("class Sha256 : virtual public Alg, virtual public Hash {", h)
        self.assertIn("vscf_impl_t* impl() const noexcept override;", h)  # decl
        self.assertIn("vscf_impl_t* Sha256::impl() const noexcept { return vscf_sha256_impl(c_ctx_); }", s)
        self.assertIn("std::vector<uint8_t> hash(std::span<const uint8_t> data) override;", h)  # decl
        self.assertIn("vscf_sha256_hash(", s)  # calls its own C func, not vscf_hash_*

    def test_interface_return_wrapped_as_unique_ptr(self) -> None:
        self.assertIn("std::unique_ptr<AlgInfo> produce_alg_info() const override;", self._f("sha256.hpp"))
        self.assertIn("return FoundationImplementation::wrap_alg_info(proxy_result);", self._c("sha256.cpp"))

    def test_interface_arg_uses_impl(self) -> None:
        self.assertIn("restore_alg_info(const AlgInfo& alg_info)", self._f("sha256.hpp"))
        self.assertIn("vscf_sha256_restore_alg_info(c_ctx_, alg_info.impl());", self._c("sha256.cpp"))

    def test_dispatch_header_declares_wrap(self) -> None:
        c = self._f("foundation_implementation.hpp")
        self.assertIn("class FoundationImplementation {", c)
        self.assertIn("static std::unique_ptr<Hash> wrap_hash(vscf_impl_t* impl);", c)

    def test_dispatch_source_switches_on_tag(self) -> None:
        c = self.files["wrappers/cpp/src/foundation/foundation_implementation.cpp"]
        self.assertIn("std::unique_ptr<Hash> FoundationImplementation::wrap_hash(vscf_impl_t* impl) {", c)
        self.assertIn("switch (vscf_impl_tag(impl)) {", c)
        self.assertIn("case vscf_impl_tag_SHA256:", c)
        self.assertIn("return std::make_unique<Sha256>(reinterpret_cast<vscf_sha256_t*>(impl));", c)

    def test_no_value_call_in_interfaces_and_impls(self) -> None:
        for path, content in self.files.items():
            self.assertNotIn(".value()", content, path)


class OwnershipAndConventionTests(unittest.TestCase):
    """Regression tests for the C API ownership/const/naming conventions the wrapper
    must honour to compile against the real C headers."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_ir("foundation")
        cls.files = dict(generate_cpp_files(cls.ir, repo_root=str(REPO_ROOT)))

    def _f(self, name: str) -> str:
        return self.files[f"wrappers/cpp/include/virgil/crypto/foundation/{name}"]

    def _c(self, name: str) -> str:
        return self.files[f"wrappers/cpp/src/foundation/{name}"]

    def test_borrowed_interface_return_is_shallow_copied(self) -> None:
        # access="readonly" -> C returns `const vscf_impl_t*` (borrowed); the RAII
        # wrapper must shallow-copy so it does not double-free the callee's object.
        self.assertIn(
            "wrap_alg_info(vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result)))",
            self._c("raw_public_key.cpp"),
        )

    def test_owned_interface_return_is_adopted_directly(self) -> None:
        # access="disown" -> owned; adopt the returned impl without copying.
        c = self._c("sha256.cpp")
        self.assertIn("wrap_alg_info(proxy_result);", c)
        self.assertNotIn("wrap_alg_info(vscf_impl_shallow_copy", c)

    def test_borrowed_class_return_is_shallow_copied(self) -> None:
        self.assertIn(
            "RawPublicKey(vscf_raw_public_key_shallow_copy("
            "const_cast<vscf_raw_public_key_t*>(proxy_result)))",
            self._c("raw_private_key.cpp"),
        )

    def test_disown_object_argument_transfers_via_shallow_copied_ref(self) -> None:
        # C sig: set_public_key(self, vscf_raw_public_key_t **). Hand it a copy so the
        # caller keeps ownership; the callee adopts + nulls the temp.
        c = self._c("raw_private_key.cpp")
        self.assertIn(
            "vscf_raw_public_key_t* raw_public_key_ref = "
            "vscf_raw_public_key_shallow_copy(raw_public_key.c_ctx());",
            c,
        )
        self.assertIn("vscf_raw_private_key_set_public_key(c_ctx_, &raw_public_key_ref);", c)

    def test_class_typed_dependency_uses_c_ctx_not_impl(self) -> None:
        # use_ecies takes vscf_ecies_t* (Ecies is a plain class, no impl()); use_random
        # takes vscf_impl_t* (Random is an interface).
        c = self._c("curve25519.cpp")
        self.assertIn("vscf_curve25519_use_ecies(c_ctx_, ecies.c_ctx());", c)
        self.assertIn("vscf_curve25519_use_random(c_ctx_, random.impl());", c)

    def test_private_implementation_method_is_not_wrapped(self) -> None:
        # deserialize_simple_alg_info et al. have no declaration="public" and live only
        # in the .c — wrapping them would call undeclared C functions.
        c = self._f("alg_info_der_deserializer.hpp")
        self.assertNotIn("deserialize_simple", c)
        self.assertIn("deserialize", c)  # the public method survives

    def test_enum_header_includes_its_c_header(self) -> None:
        c = self._f("oid_id.hpp")
        self.assertIn("#include <virgil/crypto/foundation/vscf_oid_id.h>", c)

    def test_constants_are_screaming_snake_case(self) -> None:
        # A constant and a method may share a base name in C (vscf_ml_dsa_SIGNATURE_LEN
        # vs vscf_ml_dsa_signature_len); distinct case keeps them from colliding in C++.
        c = self._f("ml_dsa.hpp")
        self.assertIn("static constexpr std::size_t SIGNATURE_LEN = 3309;", c)
        self.assertIn("std::size_t signature_len(", c)

    def test_string_argument_is_string_view_passed_as_c_str(self) -> None:
        # Parameter (decl) is a non-owning std::string_view; the body materialises a
        # std::string for the null-terminated C const char*.
        self.assertIn("std::string_view title", self._f("pem.hpp"))
        self.assertIn("vscf_pem_wrapped_len(std::string(title).c_str(), data_len);", self._c("pem.cpp"))

    def test_status_returning_dependency_setter_returns_expected(self) -> None:
        # vscf_ctr_drbg_use_entropy_source returns vscf_status_t (VSCF_NODISCARD);
        # its setter must surface the failure, not drop it.
        self.assertIn("tl::expected<void, Error> set_entropy_source(const EntropySource& entropy_source);",
                      self._f("ctr_drbg.hpp"))
        self.assertIn("const vscf_status_t status = vscf_ctr_drbg_use_entropy_source(", self._c("ctr_drbg.cpp"))
        # a plain (void-returning) use_ setter stays void
        self.assertIn("void set_hash(const Hash& hash);", self._f("hkdf.hpp"))

    def test_is_const_methods_are_const_qualified(self) -> None:
        # Class method, interface override, and interface pure-virtual decl all pick
        # up C++ `const` from the IR is_const flag (declarations); static methods never.
        rpk = self._f("raw_private_key.hpp")
        self.assertIn("RawPublicKey get_public_key() const;", rpk)     # class method decl
        self.assertIn("AlgId alg_id() const override;", rpk)           # interface override decl
        self.assertIn("virtual AlgId alg_id() const = 0;", self._f("key.hpp"))  # interface decl
        # a mutating method stays non-const
        self.assertNotIn("setup_defaults() const", self._f("key_provider.hpp"))

    def test_interface_forward_declares_referenced_class(self) -> None:
        # Interfaces forward-declare referenced class/interface types instead of
        # including their headers, breaking the include cycle
        # (interface -> concrete class -> foundation_implementation.hpp -> interface).
        c = self._f("key_alg.hpp")
        self.assertIn("class RawPublicKey;", c)
        self.assertNotIn("#include <virgil/crypto/foundation/raw_public_key.hpp>", c)

    def test_interface_does_not_include_dispatch_header(self) -> None:
        for name in ("hash.hpp", "alg.hpp", "key_alg.hpp"):
            c = self._f(name)
            self.assertNotIn("foundation_implementation.hpp", c, name)


class CrossProjectTests(unittest.TestCase):
    """phe/ratchet reference foundation types (random, private/public key) across
    projects; the include path and type name must resolve to the foundation
    namespace, not the local one."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.phe = dict(generate_cpp_files(_load_ir("phe"), repo_root=str(REPO_ROOT)))
        cls.ratchet = dict(generate_cpp_files(_load_ir("ratchet"), repo_root=str(REPO_ROOT)))

    def test_phe_dependency_on_foundation_uses_foundation_namespace(self) -> None:
        c = self.phe["wrappers/cpp/include/virgil/crypto/phe/phe_cipher.hpp"]
        self.assertIn("#include <virgil/crypto/foundation/random.hpp>", c)
        self.assertIn("void set_random(const virgil::crypto::foundation::Random& random)", c)

    def test_ratchet_arg_on_foundation_uses_foundation_namespace(self) -> None:
        c = self.ratchet["wrappers/cpp/include/virgil/crypto/ratchet/ratchet_session.hpp"]
        self.assertIn("#include <virgil/crypto/foundation/private_key.hpp>", c)
        self.assertIn("#include <virgil/crypto/foundation/public_key.hpp>", c)
        self.assertIn("virgil::crypto::foundation::PrivateKey", c)
        self.assertIn("virgil::crypto::foundation::PublicKey", c)

    def test_buffer_return_copies_out_and_frees(self) -> None:
        # vscr_ratchet_session_serialize returns an owned vsc_buffer_t*.
        self.assertIn("std::vector<uint8_t> serialize()",
                      self.ratchet["wrappers/cpp/include/virgil/crypto/ratchet/ratchet_session.hpp"])
        s = self.ratchet["wrappers/cpp/src/ratchet/ratchet_session.cpp"]
        self.assertIn("vsc_buffer_bytes(proxy_result)", s)
        self.assertIn("vsc_buffer_delete(proxy_result);", s)

    def test_length_owner_class_header_included(self) -> None:
        # phe_client buffers size against PheCommon::PHE_*_LENGTH constants; the
        # capacity expression (and so the include) lives in the .cpp body.
        s = self.phe["wrappers/cpp/src/phe/phe_client.cpp"]
        self.assertIn("#include <virgil/crypto/phe/phe_common.hpp>", s)
        self.assertIn("PheCommon::PHE_PRIVATE_KEY_LENGTH", s)


class GeneratedTreeParityTests(unittest.TestCase):
    """The committed wrappers/cpp tree must be byte-identical to a fresh
    regeneration (no drift), and the per-project file counts must be stable."""

    # Update deliberately if the surface changes; a mismatch flags accidental drift.
    EXPECTED_FILE_COUNTS = {"foundation": 223, "phe": 15, "ratchet": 9}

    @classmethod
    def setUpClass(cls) -> None:
        cls.license = (REPO_ROOT / "LICENSE").read_text()

    def _generate(self, project: str):
        return dict(generate_cpp_files(
            _load_ir(project), license_text=self.license, repo_root=str(REPO_ROOT),
        ))

    def test_generated_tree_is_byte_identical_to_committed(self) -> None:
        for project in ("foundation", "phe", "ratchet"):
            for rel, content in self._generate(project).items():
                path = REPO_ROOT / rel
                self.assertTrue(path.exists(), f"missing committed file: {rel}")
                self.assertEqual(path.read_text(), content, f"drift in {rel}")

    def test_per_project_file_counts(self) -> None:
        for project, expected in self.EXPECTED_FILE_COUNTS.items():
            self.assertEqual(len(self._generate(project)), expected, project)


class HardeningTests(unittest.TestCase):
    """Latent-gap hardening from code review — behaviours not exercised by the current
    IR but that must be correct if the models grow these shapes."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.phe = project_to_ir(load_named_project_source("phe", str(REPO_ROOT)))
        cls.foundation = project_to_ir(load_named_project_source("foundation", str(REPO_ROOT)))

    def test_cross_project_interface_return_uses_owning_project(self) -> None:
        # A phe method returning a foundation interface must dispatch/shallow-copy via
        # foundation (vscf_/FoundationImplementation), never the local phe project.
        borrowed = IRCArgument(name="pk", interface_name="private key",
                               project="foundation", access="readonly")
        expr = _cpp_return_expr(self.phe, borrowed, "proxy_result")
        self.assertIn("virgil::crypto::foundation::FoundationImplementation::wrap_private_key", expr)
        self.assertIn("vscf_impl_shallow_copy(const_cast<vscf_impl_t*>(proxy_result))", expr)
        self.assertNotIn("vsce_impl", expr)  # not the local (phe) prefix

        owned = IRCArgument(name="pk", interface_name="private key",
                            project="foundation", access="disown")
        self.assertEqual(
            _cpp_return_expr(self.phe, owned, "proxy_result"),
            "virgil::crypto::foundation::FoundationImplementation::wrap_private_key(proxy_result)",
        )

    def test_cross_project_class_return_uses_owning_project(self) -> None:
        borrowed = IRCArgument(name="k", class_name="raw private key",
                               project="foundation", access="readonly")
        expr = _cpp_return_expr(self.phe, borrowed, "proxy_result")
        self.assertIn("virgil::crypto::foundation::RawPrivateKey(", expr)
        self.assertIn("vscf_raw_private_key_shallow_copy(const_cast<vscf_raw_private_key_t*>(proxy_result))", expr)

    def test_borrowed_buffer_return_not_deleted(self) -> None:
        # An owned (disown) vsc_buffer_t* return is freed; a borrowed one must not be.
        def body(access):
            m = IRCMethod(name="serialize",
                          returns=[IRCArgument(name="out", class_name="buffer", access=access)])
            return "\n".join(_cpp_method_body(self.foundation, "ratchet session", m))
        self.assertIn("vsc_buffer_delete(proxy_result);", body("disown"))
        self.assertNotIn("vsc_buffer_delete(proxy_result);", body("readonly"))

    def test_uses_output_buffer_detects_buffer_return(self) -> None:
        m = IRCMethod(name="serialize",
                      returns=[IRCArgument(name="out", class_name="buffer", access="disown")])
        self.assertTrue(_uses_output_buffer([m]))

    def test_interface_result_struct_member_class_is_included(self) -> None:
        # A multi-value interface return whose member is a by-value local class must be
        # #included (complete type needed for the result struct), not forward-declared.
        m = IRCMethod(name="split", declaration="public", returns=[
            IRCArgument(name="a", class_name="raw private key", access="disown"),
            IRCArgument(name="b", class_name="raw public key", access="disown"),
        ])
        iface = IRInterface(name="splitter", methods=[m])
        includes, fwd = _interface_ref_split(self.foundation, iface)
        self.assertIn("virgil/crypto/foundation/raw_private_key.hpp", includes)
        self.assertNotIn("RawPrivateKey", fwd)

    def test_dispatch_deletes_impl_on_unknown_tag(self) -> None:
        files = dict(generate_cpp_files(self.foundation, repo_root=str(REPO_ROOT)))
        c = files["wrappers/cpp/src/foundation/foundation_implementation.cpp"]
        self.assertIn("default:", c)
        self.assertIn("vscf_impl_delete(impl);", c)


if __name__ == "__main__":
    unittest.main()
