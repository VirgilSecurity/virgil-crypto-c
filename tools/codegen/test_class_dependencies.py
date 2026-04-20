"""Tests for CG-027 — Parse class dependencies into Source and IR."""

from __future__ import annotations

import unittest
from pathlib import Path

from tools.codegen.project_ir import project_to_ir, IRDependency
from tools.codegen.project_source import load_named_project_source, load_class_source, DependencySource


REPO_ROOT = Path(__file__).resolve().parents[2]


class TestDependencySourceParsing(unittest.TestCase):
    """Test that DependencySource is correctly parsed from XML models."""

    def test_ecies_has_expected_dependencies(self) -> None:
        ecies = load_class_source(REPO_ROOT / "codegen/models/project_foundation/class_ecies.xml")
        dep_names = [d.name for d in ecies.dependencies]
        self.assertEqual(len(ecies.dependencies), 5)
        self.assertIn("random", dep_names)
        self.assertIn("cipher", dep_names)
        self.assertIn("mac", dep_names)
        self.assertIn("kdf", dep_names)
        self.assertIn("ephemeral key", dep_names)

    def test_buffer_has_zero_dependencies(self) -> None:
        buffer = load_class_source(REPO_ROOT / "codegen/models/project_common/class_buffer.xml")
        self.assertEqual(len(buffer.dependencies), 0)

    def test_dependency_attrs_include_interface(self) -> None:
        ecies = load_class_source(REPO_ROOT / "codegen/models/project_foundation/class_ecies.xml")
        random_dep = next(d for d in ecies.dependencies if d.name == "random")
        self.assertEqual(random_dep.attrs["interface"], "random")

    def test_dependency_with_description(self) -> None:
        ecies = load_class_source(REPO_ROOT / "codegen/models/project_foundation/class_ecies.xml")
        ek_dep = next(d for d in ecies.dependencies if d.name == "ephemeral key")
        self.assertIn("ephemeral key", ek_dep.description.lower())

    def test_dependency_with_has_observers(self) -> None:
        """Find a class model that has has_observers attribute and verify it's parsed."""
        # group_session has a dependency with has_observers="1"
        group_session = load_class_source(
            REPO_ROOT / "codegen/models/project_foundation/class_group_session.xml"
        )
        observer_deps = [d for d in group_session.dependencies if d.attrs.get("has_observers") == "1"]
        self.assertGreater(len(observer_deps), 0, "should find at least one dependency with has_observers")

    def test_dependency_is_dataclass_instance(self) -> None:
        ecies = load_class_source(REPO_ROOT / "codegen/models/project_foundation/class_ecies.xml")
        for dep in ecies.dependencies:
            self.assertIsInstance(dep, DependencySource)


class TestDependencyIR(unittest.TestCase):
    """Test that IRDependency is correctly built from DependencySource."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.foundation_ir = project_to_ir(load_named_project_source("foundation", REPO_ROOT))
        cls.common_ir = project_to_ir(load_named_project_source("common", REPO_ROOT))

    def _class_ir(self, ir, name):
        return next(c for c in ir.classes if c.name == name)

    def test_ecies_ir_has_five_dependencies(self) -> None:
        ecies = self._class_ir(self.foundation_ir, "ecies")
        self.assertEqual(len(ecies.dependencies), 5)

    def test_ecies_ir_dependency_type_kind_is_interface(self) -> None:
        ecies = self._class_ir(self.foundation_ir, "ecies")
        for dep in ecies.dependencies:
            self.assertEqual(dep.type_kind, "interface")

    def test_ecies_ir_random_dependency_fields(self) -> None:
        ecies = self._class_ir(self.foundation_ir, "ecies")
        random_dep = next(d for d in ecies.dependencies if d.name == "random")
        self.assertEqual(random_dep.type_name, "random")
        self.assertFalse(random_dep.has_observers)
        self.assertFalse(random_dep.is_observers_return_status)

    def test_buffer_ir_has_zero_dependencies(self) -> None:
        buffer = self._class_ir(self.common_ir, "buffer")
        self.assertEqual(len(buffer.dependencies), 0)

    def test_has_observers_mapped_correctly(self) -> None:
        group_session = self._class_ir(self.foundation_ir, "group session")
        observer_deps = [d for d in group_session.dependencies if d.has_observers]
        self.assertGreater(len(observer_deps), 0, "should find at least one IR dependency with has_observers=True")

    def test_class_type_kind_dependency(self) -> None:
        """Find a dependency with class attribute (not interface) and verify type_kind."""
        # recipient_cipher has a dependency on 'padding params' with class attribute
        recipient_cipher = self._class_ir(self.foundation_ir, "recipient cipher")
        class_deps = [d for d in recipient_cipher.dependencies if d.type_kind == "class"]
        self.assertGreater(len(class_deps), 0, "should find at least one class-type dependency")
        self.assertEqual(class_deps[0].type_name, "padding params")

    def test_ir_dependency_is_dataclass_instance(self) -> None:
        ecies = self._class_ir(self.foundation_ir, "ecies")
        for dep in ecies.dependencies:
            self.assertIsInstance(dep, IRDependency)


if __name__ == "__main__":
    unittest.main()
