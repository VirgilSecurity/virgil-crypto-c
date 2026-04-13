"""Tests for the Go wrapper backend (tools/codegen/project_go_backend.py).

Unit 1 scope: name utilities + enum generator + orchestrator parity with
the legacy GSL output.
"""
from __future__ import annotations

import pathlib
import unittest

from tools.codegen.project_go_backend import (
    generate_go_class_scaffold,
    generate_go_enum,
    generate_go_files,
    generate_go_implementation,
    generate_go_implementation_scaffold,
    generate_go_instance_class,
    generate_go_project_implementation,
    generate_go_static_class,
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


class FoundationInterfaceParityTests(unittest.TestCase):
    """Every foundation interface file must round-trip byte-for-byte."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = project_to_ir(load_named_project_source("foundation", str(REPO_ROOT)))
        cls.files = dict(generate_go_files(cls.ir))

    def _assert_match(self, name: str) -> None:
        gen = self.files[f"wrappers/go/foundation/{name}"]
        legacy = (REPO_ROOT / "wrappers" / "go" / "foundation" / name).read_text()
        self.assertEqual(gen, legacy, f"{name} drift")

    def test_hash_matches_legacy(self) -> None:
        # Constants → getter methods, buffer-class output returns []byte.
        self._assert_match("hash.go")

    def test_random_matches_legacy(self) -> None:
        # Methods with status return → trailing error.
        self._assert_match("random.go")

    def test_cipher_matches_legacy(self) -> None:
        # Inherit is ignored; private-visibility methods filtered.
        self._assert_match("cipher.go")

    def test_auth_encrypt_has_multi_buffer_returns(self) -> None:
        # Two buffer outputs + status return -> ([]byte, []byte, error).
        self._assert_match("auth_encrypt.go")

    def test_key_alg_has_boolean_getters_and_class_returns(self) -> None:
        # Covers boolean-typed constants and (*ClassType, error) returns.
        self._assert_match("key_alg.go")

    def test_asn1_writer_imports_unsafe_for_byte_reference(self) -> None:
        # type="byte" is_reference="1" return -> unsafe.Pointer import.
        self._assert_match("asn1_writer.go")

    def test_all_foundation_interfaces_match_byte_for_byte(self) -> None:
        drift = []
        for iface in self.ir.interfaces:
            if iface.attrs.get("scope") == "private":
                continue
            stem = iface.name.replace(" ", "_").lower()
            gen_path = f"wrappers/go/foundation/{stem}.go"
            legacy_path = REPO_ROOT / "wrappers" / "go" / "foundation" / f"{stem}.go"
            if not legacy_path.exists():
                continue
            if self.files[gen_path] != legacy_path.read_text():
                drift.append(stem)
        self.assertEqual(drift, [], f"interface drift: {drift}")


class InfrastructureFileParityTests(unittest.TestCase):
    """context.go, helper.go, and {project}_error.go must round-trip."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.files_by_project = {
            proj: dict(
                generate_go_files(
                    project_to_ir(load_named_project_source(proj, str(REPO_ROOT)))
                )
            )
            for proj in ("foundation", "phe")
        }

    def _assert_match(self, project: str, name: str) -> None:
        path = f"wrappers/go/{project}/{name}"
        gen = self.files_by_project[project][path]
        legacy = (REPO_ROOT / path).read_text()
        self.assertEqual(gen, legacy, f"{path} drift")

    def test_foundation_context_matches_legacy(self) -> None:
        self._assert_match("foundation", "context.go")

    def test_phe_context_matches_legacy(self) -> None:
        # Same template, different prefix + include path.
        self._assert_match("phe", "context.go")

    def test_foundation_helper_matches_legacy(self) -> None:
        # buffer.newBuffer references FoundationError — error type must be
        # substituted per project.
        self._assert_match("foundation", "helper.go")

    def test_phe_helper_uses_phe_error(self) -> None:
        self._assert_match("phe", "helper.go")

    def test_foundation_error_matches_legacy(self) -> None:
        # Covers: status-enum-driven constants, switch dispatch with
        # uppercase C symbol mapping, multi-line descriptions flattened
        # in switch messages but preserved in const doc blocks.
        self._assert_match("foundation", "foundation_error.go")

    def test_phe_error_preserves_acronyms(self) -> None:
        # phe has 'error RNG failed' -> PheErrorErrorRNGFailed (uppercase
        # acronym retention).
        self._assert_match("phe", "phe_error.go")


class NameUtilityAcronymTests(unittest.TestCase):
    def test_uppercase_acronym_preserved(self) -> None:
        self.assertEqual(go_type_name("error RNG failed"), "ErrorRNGFailed")

    def test_mixed_case_preserved(self) -> None:
        self.assertEqual(go_type_name("error Protobuf decode failed"), "ErrorProtobufDecodeFailed")


class ClassScaffoldTests(unittest.TestCase):
    """Scaffolding emits the struct+lifecycle shape every class shares.

    These tests pin down the structural invariants. Byte-for-byte parity
    against the full legacy file is NOT expected — method bodies,
    dependency wiring, and interface bindings are out of scope for Unit 4.1.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = project_to_ir(load_named_project_source("foundation", str(REPO_ROOT)))

    def _class_ir(self, name: str):
        for c in self.ir.classes:
            if c.name == name:
                return c
        raise AssertionError(f"class {name!r} not in IR")

    def _impl_ir(self, name: str):
        for i in self.ir.implementations:
            if i.name == name:
                return i
        raise AssertionError(f"impl {name!r} not in IR")

    def test_static_class_has_empty_struct_and_no_lifecycle(self) -> None:
        out = generate_go_class_scaffold(self.ir, self._class_ir("base64"))
        self.assertIn("type Base64 struct {", out)
        # No cCtx on static classes.
        self.assertNotIn("cCtx", out)
        # No lifecycle symbols.
        self.assertNotIn("NewBase64(", out)
        self.assertNotIn("SetFinalizer", out)
        # No runtime import (no lifecycle uses it).
        self.assertNotIn('import "runtime"', out)

    def test_regular_class_struct_has_ccx_field(self) -> None:
        out = generate_go_class_scaffold(self.ir, self._class_ir("key provider"))
        self.assertIn("type KeyProvider struct {", out)
        self.assertIn("cCtx *C.vscf_key_provider_t", out)

    def test_regular_class_emits_full_lifecycle(self) -> None:
        out = generate_go_class_scaffold(self.ir, self._class_ir("key provider"))
        for needed in (
            "func NewKeyProvider()",
            "func newKeyProviderWithCtx(",
            "func newKeyProviderCopy(",
            "func (obj *KeyProvider) Delete()",
            "func (obj *KeyProvider) delete()",
            "func (obj *KeyProvider) Ctx() uintptr",
            "C.vscf_key_provider_new()",
            "C.vscf_key_provider_delete(obj.cCtx)",
            "C.vscf_key_provider_shallow_copy(ctx)",
            "runtime.SetFinalizer(obj, (*KeyProvider).Delete)",
        ):
            self.assertIn(needed, out, f"missing: {needed!r}")

    def test_implementation_scaffold_matches_class_shape(self) -> None:
        # sha256 is an implementation, not a class.
        out = generate_go_implementation_scaffold(self.ir, self._impl_ir("sha256"))
        self.assertIn("type Sha256 struct {", out)
        self.assertIn("cCtx *C.vscf_sha256_t", out)
        self.assertIn("func NewSha256()", out)
        self.assertIn("C.vscf_sha256_new()", out)
        self.assertIn("C.vscf_sha256_shallow_copy(ctx)", out)
        self.assertIn("C.vscf_sha256_delete(obj.cCtx)", out)

    def test_scaffold_classes_appear_in_orchestrator_output(self) -> None:
        # Unit 4.7 wires every class/impl + dispatch file into the
        # orchestrator. The orchestrator must produce one file per
        # public class/impl plus the project-wide dispatch file.
        files = dict(generate_go_files(self.ir))
        self.assertIn("wrappers/go/foundation/base64.go", files)
        self.assertIn("wrappers/go/foundation/sha256.go", files)
        self.assertIn("wrappers/go/foundation/key_provider.go", files)
        self.assertIn(
            "wrappers/go/foundation/foundation_implementation.go", files,
        )


class StaticClassGenerationTests(unittest.TestCase):
    """Method-body generation for context="none" classes.

    These classes are package-level helpers with no cCtx — the simplest
    shape in the wrapper. Parity is measured modulo GSL tracer comments
    (``/*pr4*/``, ``/* r7 */``, …) which are decoration only.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = project_to_ir(load_named_project_source("foundation", str(REPO_ROOT)))

    def _strip_tracers(self, text: str) -> str:
        # Remove the GSL tracer comments but preserve neighbouring
        # whitespace — the surrounding spacing IS part of the legacy
        # layout we want to match.
        import re as _re

        text = _re.sub(r"/\*[a-zA-Z0-9_. ]+?\*/", "", text)
        # Legacy GSL leaves isolated whitespace behind after a tracer,
        # e.g. ``algId) /*pa7*/)`` → ``algId) )``;
        # ``getData() /* r7 */,`` → ``getData() ,``;
        # ``(ctx *C.xxx_t /*ct2*/)`` → ``(ctx *C.xxx_t )``.
        # Collapse those specific patterns so they don't cause spurious
        # drift diffs.
        text = _re.sub(r"\) \)", "))", text)
        text = _re.sub(r"\) ,", "),", text)
        text = _re.sub(r"([A-Za-z0-9_]) \)", r"\1)", text)
        # Tidy trailing spaces per line so rstripping differences don't
        # cause spurious diffs.
        text = "\n".join(line.rstrip() for line in text.splitlines()) + "\n"
        return text

    def _static_class(self, name: str):
        for c in self.ir.classes:
            if c.name == name:
                return c
        raise AssertionError(f"class {name!r} not found")

    def _assert_modulo_tracers(self, name: str, filename: str) -> None:
        cls = self._static_class(name)
        gen = generate_go_static_class(self.ir, cls)
        legacy = (REPO_ROOT / "wrappers" / "go" / "foundation" / filename).read_text()
        self.assertEqual(
            self._strip_tracers(gen),
            self._strip_tracers(legacy),
            f"{filename} drift (modulo tracers)",
        )

    def test_base64_matches_legacy_modulo_tracers(self) -> None:
        # Covers: primitive size args, data+buffer round-trip, buffer
        # capacity resolved via <length method=…><proxy cast=data_length/>,
        # status->error dispatch (decode).
        self._assert_modulo_tracers("base64", "base64.go")

    def test_oid_matches_legacy_modulo_tracers(self) -> None:
        # Covers: enum args cast to C.vscf_<enum>_t, <return class=data/>
        # rendered via helperExtractData, boolean return.
        self._assert_modulo_tracers("oid", "oid.go")

    def test_pem_matches_legacy_modulo_tracers(self) -> None:
        # Covers: string args with C.CString + defer C.free + unsafe import,
        # buffer capacity via proxy call that references the Go string.
        self._assert_modulo_tracers("pem", "pem.go")

    def test_non_static_class_raises(self) -> None:
        # Guard: instance classes (context=public) must go through the
        # instance generator, not this static path.
        instance_cls = next(
            c for c in self.ir.classes if c.attrs.get("context") != "none"
        )
        with self.assertRaises(ValueError):
            generate_go_static_class(self.ir, instance_cls)

    def test_static_classes_appear_in_orchestrator_output(self) -> None:
        # Unit 4.7 wires the static-class path into generate_go_files.
        files = dict(generate_go_files(self.ir))
        for stem in ("base64", "oid", "pem"):
            self.assertIn(f"wrappers/go/foundation/{stem}.go", files)


class BufferLengthMetadataTests(unittest.TestCase):
    """The source parser must capture <length>/<proxy> metadata on buffer args."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = project_to_ir(load_named_project_source("foundation", str(REPO_ROOT)))

    def test_length_method_and_proxy_captured(self) -> None:
        cls = next(c for c in self.ir.classes if c.name == "base64")
        encode = next(m for m in cls.methods if m.name == "encode")
        out_arg = next(a for a in encode.arguments if a.class_name == "buffer")
        self.assertEqual(out_arg.length_attrs.get("method"), "encoded len")
        self.assertEqual(out_arg.length_attrs.get("proxy_0_argument"), "data")
        self.assertEqual(out_arg.length_attrs.get("proxy_0_to"), "data len")
        self.assertEqual(out_arg.length_attrs.get("proxy_0_cast"), "data_length")

    def test_non_buffer_args_have_empty_length_attrs(self) -> None:
        cls = next(c for c in self.ir.classes if c.name == "base64")
        encoded_len = next(m for m in cls.methods if m.name == "encoded len")
        for arg in encoded_len.arguments:
            self.assertEqual(arg.length_attrs, {})


class InstanceClassGenerationTests(unittest.TestCase):
    """Method-body generation for context!="none" classes.

    Covers the receiver pattern (``func (obj *T) Method``), cCtx
    threading, KeepAlive emission, dependency setters, public class
    constants, and named constructors. Parity is measured modulo GSL
    tracer comments.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = project_to_ir(load_named_project_source("foundation", str(REPO_ROOT)))

    def _strip_tracers(self, text: str) -> str:
        import re as _re

        text = _re.sub(r"/\*[a-zA-Z0-9_. ]+?\*/", "", text)
        text = _re.sub(r"\) \)", "))", text)
        text = _re.sub(r"\) ,", "),", text)
        text = _re.sub(r"([A-Za-z0-9_]) \)", r"\1)", text)
        return "\n".join(line.rstrip() for line in text.splitlines()) + "\n"

    def _instance(self, name: str):
        for c in self.ir.classes:
            if c.name == name:
                return c
        raise AssertionError(f"class {name!r} not found")

    def _assert_modulo_tracers(self, name: str, filename: str) -> None:
        cls = self._instance(name)
        gen = generate_go_instance_class(self.ir, cls)
        legacy = (REPO_ROOT / "wrappers" / "go" / "foundation" / filename).read_text()
        self.assertEqual(
            self._strip_tracers(gen),
            self._strip_tracers(legacy),
            f"{filename} drift",
        )

    def test_padding_params_matches_legacy_modulo_tracers(self) -> None:
        # Covers: public const block, named constructor, instance methods.
        self._assert_modulo_tracers("padding params", "padding_params.go")

    def test_message_info_returns_class_and_interface_correctly(self) -> None:
        # Covers: class returns -> newXxxCopy(); interface returns ->
        # FoundationImplementationWrapXxxCopy() with implicit error pair.
        self._assert_modulo_tracers("message info", "message_info.go")

    def test_key_recipient_info_list_resolves_self_returns(self) -> None:
        # Covers: class="self" resolution to the enclosing class type.
        self._assert_modulo_tracers(
            "key recipient info list", "key_recipient_info_list.go"
        )

    def test_static_call_path_rejects_instance_class(self) -> None:
        instance = next(
            c for c in self.ir.classes if c.attrs.get("context") != "none"
        )
        with self.assertRaises(ValueError):
            generate_go_static_class(self.ir, instance)

    def test_instance_call_path_rejects_static_class(self) -> None:
        static = next(
            c for c in self.ir.classes if c.attrs.get("context") == "none"
        )
        with self.assertRaises(ValueError):
            generate_go_instance_class(self.ir, static)

    def test_instance_classes_appear_in_orchestrator_output(self) -> None:
        # Unit 4.7 wires the instance-class path into generate_go_files.
        files = dict(generate_go_files(self.ir))
        for stem in ("padding_params", "message_info", "key_recipient_info_list"):
            self.assertIn(f"wrappers/go/foundation/{stem}.go", files)

    def test_dependency_setters_emit_release_then_use(self) -> None:
        cls = self._instance("signer")
        gen = generate_go_instance_class(self.ir, cls)
        # Both deps from class_signer.xml must surface as setter methods
        # mapped through release_/use_ on the C side.
        self.assertIn("func (obj *Signer) SetHash(hash Hash)", gen)
        self.assertIn("C.vscf_signer_release_hash(obj.cCtx)", gen)
        self.assertIn(
            "C.vscf_signer_use_hash(obj.cCtx, "
            "(*C.vscf_impl_t)(unsafe.Pointer(hash.Ctx())))",
            gen,
        )
        self.assertIn("func (obj *Signer) SetRandom(random Random)", gen)


class InstanceClassSyntaxSurveyTests(unittest.TestCase):
    """Every generated instance class must be syntactically valid Go.

    A regression here means the generator produced something gofmt
    can't parse — the worst kind of breakage because it would surface
    only when the file is integrated into the orchestrator output.
    """

    def test_all_instance_classes_pass_gofmt(self) -> None:
        import shutil
        import subprocess
        import tempfile

        if shutil.which("gofmt") is None:
            self.skipTest("gofmt not on PATH")
        ir = project_to_ir(load_named_project_source("foundation", str(REPO_ROOT)))
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            for cls in ir.classes:
                if cls.attrs.get("context") == "none":
                    continue
                path = tmp_path / f"{cls.name.replace(' ', '_')}.go"
                path.write_text(generate_go_instance_class(ir, cls))
                proc = subprocess.run(
                    ["gofmt", "-e", str(path)],
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(
                    proc.returncode, 0,
                    f"gofmt rejected {cls.name!r}: {proc.stderr.decode()}",
                )


class ImplementationGenerationTests(unittest.TestCase):
    """Method-body generation for IRImplementation entities.

    Implementations share the struct/method shape of instance classes
    plus interface-binding expansion (an impl's public Go API comes
    primarily from the interfaces it implements). They also have a
    distinct file layout: deps and impl-specific methods come BEFORE
    the lifecycle block, then binding-expanded methods come after.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = project_to_ir(load_named_project_source("foundation", str(REPO_ROOT)))

    def _strip_tracers(self, text: str) -> str:
        import re as _re

        text = _re.sub(r"/\*[a-zA-Z0-9_. ]+?\*/", "", text)
        text = _re.sub(r"\) \)", "))", text)
        text = _re.sub(r"\) ,", "),", text)
        text = _re.sub(r"([A-Za-z0-9_]) \)", r"\1)", text)
        return "\n".join(line.rstrip() for line in text.splitlines()) + "\n"

    def _impl(self, name: str):
        for i in self.ir.implementations:
            if i.name == name:
                return i
        raise AssertionError(f"impl {name!r} not found")

    def _assert_modulo_tracers(self, name: str, filename: str) -> None:
        gen = generate_go_implementation(self.ir, self._impl(name))
        legacy = (REPO_ROOT / "wrappers" / "go" / "foundation" / filename).read_text()
        self.assertEqual(
            self._strip_tracers(gen),
            self._strip_tracers(legacy),
            f"{filename} drift",
        )

    def test_sha256_expands_alg_and_hash_bindings(self) -> None:
        # Covers: per-binding constant-as-getter expansion, interface
        # methods proxied through C, ``access="disown"`` -> Wrap (no Copy).
        self._assert_modulo_tracers("sha256", "sha256.go")

    def test_sha384_matches_legacy(self) -> None:
        self._assert_modulo_tracers("sha384", "sha384.go")

    def test_aes256_gcm_handles_buffer_blank_lines(self) -> None:
        # Covers: multi-buffer blank-line ordering, dependency-free impl.
        self._assert_modulo_tracers("aes256 gcm", "aes256_gcm.go")

    def test_implementation_specific_method_filtered_unless_public(self) -> None:
        # asn1rd has impl-specific methods (mbedtls_has_error, read_tag_data)
        # that lack ``declaration="public"`` and should NOT surface on the
        # Go side — the C layer keeps them but the wrapper hides them.
        gen = generate_go_implementation(self.ir, self._impl("asn1rd"))
        self.assertNotIn("MbedtlsHasError", gen)
        self.assertNotIn("ReadTagData", gen)

    def test_impl_specific_method_with_declaration_public_emits(self) -> None:
        # rsa.setup_defaults has ``declaration="public"`` -> wrapped.
        gen = generate_go_implementation(self.ir, self._impl("rsa"))
        self.assertIn("func (obj *Rsa) SetupDefaults() error", gen)

    def test_implementation_layout_orders_deps_before_lifecycle(self) -> None:
        # On impls, dependency setters precede the Ctx/NewT lifecycle —
        # opposite ordering from instance classes.
        gen = generate_go_implementation(self.ir, self._impl("hmac"))
        set_pos = gen.index("func (obj *Hmac) SetHash(")
        ctx_pos = gen.index("func (obj *Hmac) Ctx() uintptr")
        self.assertLess(
            set_pos, ctx_pos,
            "SetHash must appear before Ctx() in implementations",
        )


class ImplementationSyntaxSurveyTests(unittest.TestCase):
    """Every generated implementation must parse via gofmt.

    A regression here means we've produced something that won't compile,
    even before CGo headers come into play.
    """

    def test_all_implementations_pass_gofmt(self) -> None:
        import shutil
        import subprocess
        import tempfile

        if shutil.which("gofmt") is None:
            self.skipTest("gofmt not on PATH")
        ir = project_to_ir(load_named_project_source("foundation", str(REPO_ROOT)))
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            for impl in ir.implementations:
                path = tmp_path / f"{impl.name.replace(' ', '_')}.go"
                path.write_text(generate_go_implementation(ir, impl))
                proc = subprocess.run(
                    ["gofmt", "-e", str(path)],
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(
                    proc.returncode, 0,
                    f"gofmt rejected {impl.name!r}: {proc.stderr.decode()}",
                )


class ProjectImplementationDispatchTests(unittest.TestCase):
    """{project}_implementation.go must regenerate to legacy modulo tracers.

    This file is the runtime glue that makes every per-method
    ``FoundationImplementationWrap*`` call link — without it, all of
    Unit 4.3/4.4's interface returns would reference undefined
    symbols.
    """

    def _strip_tracers(self, text: str) -> str:
        import re as _re

        text = _re.sub(r"/\*[a-zA-Z0-9_. ]+?\*/", "", text)
        text = _re.sub(r"\) \)", "))", text)
        text = _re.sub(r"\) ,", "),", text)
        text = _re.sub(r"([A-Za-z0-9_]) \)", r"\1)", text)
        return "\n".join(line.rstrip() for line in text.splitlines()) + "\n"

    def _assert_project_matches(self, project: str, filename: str) -> None:
        ir = project_to_ir(load_named_project_source(project, str(REPO_ROOT)))
        gen = generate_go_project_implementation(ir)
        legacy = (REPO_ROOT / "wrappers" / "go" / project / filename).read_text()
        self.assertEqual(
            self._strip_tracers(gen),
            self._strip_tracers(legacy),
            f"{project}/{filename} drift",
        )

    def test_foundation_dispatch_matches_legacy(self) -> None:
        # 33 interface dispatch pairs (Wrap + WrapCopy) routing 53
        # implementations through C.vscf_impl_tag(ctx).
        self._assert_project_matches("foundation", "foundation_implementation.go")

    def test_phe_dispatch_matches_legacy(self) -> None:
        # phe has no interface bindings — output is just the empty
        # FoundationImplementation-style struct stub.
        self._assert_project_matches("phe", "phe_implementation.go")

    def test_dispatch_orders_interfaces_by_impl_discovery(self) -> None:
        # The legacy GSL output lists interfaces in the order their
        # FIRST binding implementation appears, NOT XML declaration
        # order. Verify Alg/Hash/Encrypt show up in that sequence.
        ir = project_to_ir(load_named_project_source("foundation", str(REPO_ROOT)))
        gen = generate_go_project_implementation(ir)
        alg_pos = gen.index("FoundationImplementationWrapAlg(")
        hash_pos = gen.index("FoundationImplementationWrapHash(")
        encrypt_pos = gen.index("FoundationImplementationWrapEncrypt(")
        self.assertLess(alg_pos, hash_pos)
        self.assertLess(hash_pos, encrypt_pos)


class FullOrchestratorCoverageTests(unittest.TestCase):
    """End-to-end: generate_go_files now covers the entire wrapper set."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.foundation_files = dict(generate_go_files(
            project_to_ir(load_named_project_source("foundation", str(REPO_ROOT)))
        ))
        cls.phe_files = dict(generate_go_files(
            project_to_ir(load_named_project_source("phe", str(REPO_ROOT)))
        ))

    def test_foundation_emits_dispatch_and_infrastructure(self) -> None:
        self.assertIn(
            "wrappers/go/foundation/foundation_implementation.go",
            self.foundation_files,
        )
        self.assertIn(
            "wrappers/go/foundation/foundation_error.go", self.foundation_files,
        )
        self.assertIn("wrappers/go/foundation/context.go", self.foundation_files)
        self.assertIn("wrappers/go/foundation/helper.go", self.foundation_files)

    def test_foundation_emits_every_public_entity(self) -> None:
        ir = project_to_ir(load_named_project_source("foundation", str(REPO_ROOT)))
        expected = set()
        for enum in ir.enums:
            if enum.name in {"status", "impl/tag"}:
                continue
            if enum.attrs.get("scope") == "private":
                continue
            expected.add(f"wrappers/go/foundation/{enum.name.replace(' ', '_')}.go")
        for iface in ir.interfaces:
            if iface.attrs.get("scope") == "private":
                continue
            expected.add(f"wrappers/go/foundation/{iface.name.replace(' ', '_')}.go")
        for cls in ir.classes:
            if cls.attrs.get("scope") in {"private", "internal"}:
                continue
            if cls.name == "error":
                continue
            expected.add(f"wrappers/go/foundation/{cls.name.replace(' ', '_')}.go")
        for impl in ir.implementations:
            if impl.attrs.get("scope") in {"private", "internal"}:
                continue
            expected.add(f"wrappers/go/foundation/{impl.name.replace(' ', '_')}.go")
        missing = expected - set(self.foundation_files)
        self.assertFalse(missing, f"orchestrator missing {sorted(missing)[:5]}")

    def test_no_test_files_emitted(self) -> None:
        # Test files (*_test.go) are handwritten and must NEVER be
        # overwritten by the generator.
        for path in self.foundation_files:
            self.assertFalse(
                path.endswith("_test.go"),
                f"orchestrator must not emit test file: {path}",
            )

    def test_no_handwritten_crypto_layer_emitted(self) -> None:
        # The high-level wrappers/go/crypto/ tree is owned by humans.
        for path in self.foundation_files:
            self.assertFalse(
                path.startswith("wrappers/go/crypto/"),
                f"orchestrator must not touch wrappers/go/crypto/: {path}",
            )

    def test_phe_emits_minimal_set(self) -> None:
        # phe ships infra + a handful of class files + dispatch stub.
        self.assertIn("wrappers/go/phe/context.go", self.phe_files)
        self.assertIn("wrappers/go/phe/helper.go", self.phe_files)
        self.assertIn("wrappers/go/phe/phe_error.go", self.phe_files)
        self.assertIn("wrappers/go/phe/phe_implementation.go", self.phe_files)


if __name__ == "__main__":
    unittest.main()
