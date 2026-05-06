"""Tests for CG-032 — Parse implementors and implementations into Source and IR."""

from __future__ import annotations

import unittest
from pathlib import Path

from tools.codegen.project_ir import project_to_ir, IRImplementation
from tools.codegen.project_source import load_named_project_source, load_implementor_source


REPO_ROOT = Path(__file__).resolve().parents[2]


class TestImplementorSourceParsing(unittest.TestCase):
    """Test that ImplementorSource is correctly parsed from XML models."""

    def test_foundation_has_13_implementors(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        self.assertEqual(len(project.implementors), 13)
        self.assertEqual(len(project.implementor_refs), 13)

    def test_common_has_zero_implementors(self) -> None:
        project = load_named_project_source("common", REPO_ROOT)
        self.assertEqual(len(project.implementors), 0)
        self.assertEqual(len(project.implementor_refs), 0)

    def test_mbedtls_has_expected_implementations(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        mbedtls = project.implementor_named("mbedtls")
        impl_names = [impl.name for impl in mbedtls.implementations]
        expected = ["sha224", "sha256", "sha384", "sha512", "aes256 gcm", "aes256 cbc", "asn1rd", "asn1wr"]
        self.assertEqual(impl_names, expected)

    def test_mbedtls_attrs(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        mbedtls = project.implementor_named("mbedtls")
        self.assertEqual(mbedtls.attrs.get("is_default"), "1")

    def test_sha256_interface_bindings(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        mbedtls = project.implementor_named("mbedtls")
        sha256 = next(impl for impl in mbedtls.implementations if impl.name == "sha256")
        binding_names = [b.name for b in sha256.interface_bindings]
        self.assertEqual(binding_names, ["alg", "hash"])
        hash_binding = next(b for b in sha256.interface_bindings if b.name == "hash")
        constants = {c.name: c.value for c in hash_binding.constants}
        self.assertEqual(constants, {"digest len": "32", "block len": "64"})

    def test_sha256_property(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        mbedtls = project.implementor_named("mbedtls")
        sha256 = next(impl for impl in mbedtls.implementations if impl.name == "sha256")
        self.assertEqual(len(sha256.properties), 1)
        prop = sha256.properties[0]
        self.assertEqual(prop.name, "hash ctx")
        self.assertEqual(prop.attrs.get("library"), "mbedtls")
        self.assertEqual(prop.attrs.get("class"), "mbedtls_sha256_context")

    def test_aes256_gcm_multiple_interface_bindings(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        mbedtls = project.implementor_named("mbedtls")
        aes = next(impl for impl in mbedtls.implementations if impl.name == "aes256 gcm")
        binding_names = [b.name for b in aes.interface_bindings]
        expected = ["alg", "encrypt", "decrypt", "cipher info", "cipher",
                    "cipher auth info", "auth encrypt", "auth decrypt", "cipher auth"]
        self.assertEqual(binding_names, expected)

    def test_aes256_gcm_has_method(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        mbedtls = project.implementor_named("mbedtls")
        aes = next(impl for impl in mbedtls.implementations if impl.name == "aes256 gcm")
        method_names = [m.name for m in aes.methods]
        self.assertIn("update internal", method_names)

    def test_implementation_requirements(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        mbedtls = project.implementor_named("mbedtls")
        sha256 = next(impl for impl in mbedtls.implementations if impl.name == "sha256")
        req_kinds = [r.kind for r in sha256.requirements]
        self.assertIn("library", req_kinds)
        self.assertIn("header", req_kinds)
        self.assertIn("interface", req_kinds)
        self.assertIn("impl", req_kinds)
        lib_req = next(r for r in sha256.requirements if r.kind == "library")
        self.assertEqual(lib_req.name, "mbedtls")
        self.assertEqual(lib_req.attrs.get("feature"), "SHA256 C")

    def test_total_53_implementations(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        total = sum(len(imp.implementations) for imp in project.implementors)
        self.assertEqual(total, 53)

    def test_ed25519_has_dependencies(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        ed25519 = project.implementor_named("ed25519 pk")
        impl = next(i for i in ed25519.implementations if i.name == "ed25519")
        dep_names = [d.name for d in impl.dependencies]
        self.assertIn("random", dep_names)
        self.assertIn("ecies", dep_names)


class TestIRImplementationParsing(unittest.TestCase):
    """Test that IRImplementation is correctly built from source."""

    def test_ir_has_53_implementations(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        ir = project_to_ir(project)
        self.assertEqual(len(ir.implementations), 53)

    def test_ir_implementation_output_target(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        ir = project_to_ir(project)
        sha256 = next(i for i in ir.implementations if i.name == "sha256")
        self.assertIsNotNone(sha256.output)
        self.assertEqual(sha256.output.entity_kind, "implementation")
        self.assertEqual(sha256.output.entity_name, "sha256")
        self.assertEqual(sha256.output.stem, "vscf_sha256")

    def test_ir_implementation_interface_bindings(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        ir = project_to_ir(project)
        sha256 = next(i for i in ir.implementations if i.name == "sha256")
        binding_names = [b.name for b in sha256.interface_bindings]
        self.assertEqual(binding_names, ["alg", "hash"])
        hash_binding = next(b for b in sha256.interface_bindings if b.name == "hash")
        self.assertEqual(len(hash_binding.constants), 2)
        digest = next(c for c in hash_binding.constants if c.name == "digest len")
        self.assertEqual(digest.value, "32")

    def test_ir_implementation_properties(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        ir = project_to_ir(project)
        sha256 = next(i for i in ir.implementations if i.name == "sha256")
        self.assertEqual(len(sha256.properties), 1)
        self.assertEqual(sha256.properties[0].name, "hash ctx")

    def test_ir_implementation_implementor_name(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        ir = project_to_ir(project)
        sha256 = next(i for i in ir.implementations if i.name == "sha256")
        self.assertEqual(sha256.implementor_name, "mbedtls")

    def test_ir_implementation_requirements(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        ir = project_to_ir(project)
        sha256 = next(i for i in ir.implementations if i.name == "sha256")
        self.assertEqual(len(sha256.requirements), 4)
        lib = next(r for r in sha256.requirements if r.kind == "library")
        self.assertEqual(lib.name, "mbedtls")

    def test_common_ir_has_zero_implementations(self) -> None:
        project = load_named_project_source("common", REPO_ROOT)
        ir = project_to_ir(project)
        self.assertEqual(len(ir.implementations), 0)


if __name__ == "__main__":
    unittest.main()
