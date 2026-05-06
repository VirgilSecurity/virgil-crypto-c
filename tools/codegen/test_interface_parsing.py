"""Tests for CG-031 — Parse interfaces into Source and IR."""

from __future__ import annotations

import unittest
from pathlib import Path

from tools.codegen.project_ir import project_to_ir, IRInterface
from tools.codegen.project_source import load_named_project_source, load_interface_source, InterfaceSource


REPO_ROOT = Path(__file__).resolve().parents[2]


class TestInterfaceSourceParsing(unittest.TestCase):
    """Test that InterfaceSource is correctly parsed from XML models."""

    def test_foundation_has_expected_interface_count(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        self.assertGreaterEqual(len(project.interfaces), 33)
        self.assertEqual(len(project.interface_refs), len(project.interfaces))

    def test_common_has_zero_interfaces(self) -> None:
        project = load_named_project_source("common", REPO_ROOT)
        self.assertEqual(len(project.interfaces), 0)
        self.assertEqual(len(project.interface_refs), 0)

    def test_hash_methods_and_constants(self) -> None:
        iface = load_interface_source(REPO_ROOT / "codegen/models/project_foundation/interface_hash.xml")
        self.assertEqual(iface.name, "hash")
        method_names = [m.name for m in iface.methods]
        self.assertIn("hash", method_names)
        self.assertIn("start", method_names)
        self.assertIn("update", method_names)
        self.assertIn("finish", method_names)
        constant_names = [c.name for c in iface.constants]
        self.assertIn("digest len", constant_names)
        self.assertIn("block len", constant_names)

    def test_cipher_inheritance(self) -> None:
        iface = load_interface_source(REPO_ROOT / "codegen/models/project_foundation/interface_cipher.xml")
        self.assertEqual(iface.name, "cipher")
        self.assertIn("encrypt", iface.inherits)
        self.assertIn("decrypt", iface.inherits)
        self.assertIn("cipher info", iface.inherits)

    def test_random_methods(self) -> None:
        iface = load_interface_source(REPO_ROOT / "codegen/models/project_foundation/interface_random.xml")
        self.assertEqual(iface.name, "random")
        method_names = [m.name for m in iface.methods]
        self.assertIn("random", method_names)
        self.assertIn("reseed", method_names)

    def test_hash_method_arguments(self) -> None:
        iface = load_interface_source(REPO_ROOT / "codegen/models/project_foundation/interface_hash.xml")
        hash_method = next(m for m in iface.methods if m.name == "hash")
        arg_names = [a.name for a in hash_method.arguments]
        self.assertIn("data", arg_names)
        self.assertIn("digest", arg_names)
        # hash is static
        self.assertEqual(hash_method.attrs.get("is_static"), "1")

    def test_random_method_returns(self) -> None:
        iface = load_interface_source(REPO_ROOT / "codegen/models/project_foundation/interface_random.xml")
        random_method = next(m for m in iface.methods if m.name == "random")
        self.assertTrue(len(random_method.returns) > 0)
        self.assertEqual(random_method.returns[0].get("enum"), "status")

    def test_interface_description(self) -> None:
        iface = load_interface_source(REPO_ROOT / "codegen/models/project_foundation/interface_hash.xml")
        self.assertIn("hashing", iface.description.lower())


class TestIRInterfaceParsing(unittest.TestCase):
    """Test that IRInterface is correctly built from InterfaceSource."""

    def test_ir_has_interfaces(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        ir = project_to_ir(project)
        self.assertGreaterEqual(len(ir.interfaces), 33)

    def test_ir_interface_output_target(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        ir = project_to_ir(project)
        ir_hash = next(i for i in ir.interfaces if i.name == "hash")
        self.assertIsNotNone(ir_hash.output)
        self.assertEqual(ir_hash.output.entity_kind, "interface")
        self.assertEqual(ir_hash.output.entity_name, "hash")
        self.assertIn("vscf_hash", ir_hash.output.stem)

    def test_ir_interface_methods(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        ir = project_to_ir(project)
        ir_hash = next(i for i in ir.interfaces if i.name == "hash")
        method_names = [m.name for m in ir_hash.methods]
        self.assertIn("hash", method_names)
        self.assertIn("start", method_names)

    def test_ir_interface_constants(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        ir = project_to_ir(project)
        ir_hash = next(i for i in ir.interfaces if i.name == "hash")
        constant_names = [c.name for c in ir_hash.constants]
        self.assertIn("digest len", constant_names)

    def test_ir_interface_inherits(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        ir = project_to_ir(project)
        ir_cipher = next(i for i in ir.interfaces if i.name == "cipher")
        self.assertIn("encrypt", ir_cipher.inherits)
        self.assertIn("decrypt", ir_cipher.inherits)

    def test_ir_interface_refs(self) -> None:
        project = load_named_project_source("foundation", REPO_ROOT)
        ir = project_to_ir(project)
        self.assertGreaterEqual(len(ir.interface_refs), 33)
        ref_names = [r.name for r in ir.interface_refs]
        self.assertIn("hash", ref_names)

    def test_common_ir_has_zero_interfaces(self) -> None:
        project = load_named_project_source("common", REPO_ROOT)
        ir = project_to_ir(project)
        self.assertEqual(len(ir.interfaces), 0)


if __name__ == "__main__":
    unittest.main()
