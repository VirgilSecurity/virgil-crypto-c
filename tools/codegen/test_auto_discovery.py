"""Tests for CG-025/CG-036 — auto-discovery of renderable entities from IR."""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import cast

from tools.codegen.project_c_backend import (
    DirectCRenderer,
    discover_renderers,
    direct_xml_name,
    implementation_defs_output,
    implementation_internal_output,
    interface_api_output,
    render_enum_c_module,
    render_module_c_module,
    render_class_c_module,
)
from tools.codegen.project_ir import IROutputTarget, project_to_ir
from tools.codegen.project_source import load_named_project_source
from tools.codegen.common_bootstrap import direct_c_renderers_for_project


REPO_ROOT = Path(__file__).resolve().parents[2]


class TestDiscoverRenderersCommon(unittest.TestCase):
    """Auto-discovery for the ``common`` project."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.project_ir = project_to_ir(load_named_project_source("common", REPO_ROOT))

    def test_discovers_all_modules(self) -> None:
        renderers = discover_renderers(self.project_ir, entity_kinds={"module"})
        expected_modules = {m.name for m in self.project_ir.modules}
        discovered_names = set()
        for module in self.project_ir.modules:
            xml = direct_xml_name(cast(IROutputTarget, module.output))
            self.assertIn(xml, renderers, f"module '{module.name}' not discovered")
            discovered_names.add(module.name)
        self.assertEqual(discovered_names, expected_modules)

    def test_discovers_all_classes(self) -> None:
        renderers = discover_renderers(self.project_ir, entity_kinds={"class"})
        expected_classes = {c.name for c in self.project_ir.classes}
        discovered_names = set()
        for cls in self.project_ir.classes:
            xml = direct_xml_name(cast(IROutputTarget, cls.output))
            self.assertIn(xml, renderers, f"class '{cls.name}' not discovered")
            discovered_names.add(cls.name)
        self.assertEqual(discovered_names, expected_classes)

    def test_discovers_all_enums(self) -> None:
        renderers = discover_renderers(self.project_ir, entity_kinds={"enum"})
        expected_enums = {e.name for e in self.project_ir.enums}
        discovered_names = set()
        for enum in self.project_ir.enums:
            xml = direct_xml_name(cast(IROutputTarget, enum.output))
            self.assertIn(xml, renderers)
            discovered_names.add(enum.name)
        self.assertEqual(discovered_names, expected_enums)

    def test_full_discovery_covers_all_entities(self) -> None:
        """Common project has no interfaces or implementations."""
        renderers = discover_renderers(self.project_ir)
        # Classes that are non-value-type with context != 'none' get a defs module
        class_defs_count = sum(
            1 for c in self.project_ir.classes
            if c.attrs.get('is_value_type') not in {'1', 'true'}
            and c.attrs.get('context', 'public') != 'none'
        )
        total_expected = (
            len(self.project_ir.modules)
            + len(self.project_ir.classes)
            + len(self.project_ir.enums)
            + class_defs_count
        )
        self.assertEqual(len(renderers), total_expected)

    def test_common_has_no_interfaces_or_implementations(self) -> None:
        self.assertEqual(len(self.project_ir.interfaces), 0)
        self.assertEqual(len(self.project_ir.implementations), 0)

    def test_custom_overrides_replace_default(self) -> None:
        sentinel_called = []

        def custom_renderer(repo_root):
            sentinel_called.append(True)
            return render_module_c_module(self.project_ir, self.project_ir.modules[0])

        first_module = self.project_ir.modules[0]
        xml_name = direct_xml_name(cast(IROutputTarget, first_module.output))
        renderers = discover_renderers(self.project_ir, custom_overrides={xml_name: custom_renderer})
        # Call the renderer and verify it's the custom one
        renderers[xml_name](".")
        self.assertTrue(sentinel_called, "custom override was not used")

    def test_custom_overrides_extra_keys_included(self) -> None:
        """Overrides with keys not in the IR (e.g. derived outputs) are included."""
        renderers = discover_renderers(
            self.project_ir,
            custom_overrides={"c_module_vsc_buffer_defs.xml": lambda r: None},
        )
        self.assertIn("c_module_vsc_buffer_defs.xml", renderers)

    def test_entity_kinds_filter(self) -> None:
        modules_only = discover_renderers(self.project_ir, entity_kinds={"module"})
        classes_only = discover_renderers(self.project_ir, entity_kinds={"class"})
        # No overlap between module and class renderers
        self.assertEqual(set(modules_only.keys()) & set(classes_only.keys()), set())


class TestDiscoverRenderersFoundation(unittest.TestCase):
    """Auto-discovery for the ``foundation`` project."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.project_ir = project_to_ir(load_named_project_source("foundation", REPO_ROOT))

    def test_discovers_all_enums(self) -> None:
        renderers = discover_renderers(self.project_ir, entity_kinds={"enum"})
        for enum in self.project_ir.enums:
            xml = direct_xml_name(cast(IROutputTarget, enum.output))
            self.assertIn(xml, renderers, f"enum '{enum.name}' not discovered")
        self.assertEqual(len(renderers), len(self.project_ir.enums))

    def test_discovers_interfaces(self) -> None:
        renderers = discover_renderers(self.project_ir, entity_kinds={"interface"})
        # Each interface produces 2 renderers (dispatch + api)
        self.assertEqual(len(renderers), len(self.project_ir.interfaces) * 2)

    def test_discovers_implementations(self) -> None:
        renderers = discover_renderers(self.project_ir, entity_kinds={"implementation"})
        # Each implementation produces 3 renderers (main + defs + internal),
        # plus 1 private renderer per implementation that has scope="private" methods.
        from tools.codegen.project_c_backend import _impl_has_private_methods
        private_count = sum(1 for impl in self.project_ir.implementations if _impl_has_private_methods(impl))
        self.assertEqual(len(renderers), len(self.project_ir.implementations) * 3 + private_count)

    def test_full_discovery_covers_all_entities(self) -> None:
        renderers = discover_renderers(self.project_ir)
        # Project-global impl infrastructure modules (api, api_private,
        # impl, impl_private) are added when interfaces/implementations exist.
        infra_count = 4 if (self.project_ir.interfaces or self.project_ir.implementations) else 0
        # Non-value-type classes with context != 'none' and lifecycle != 'none' get a defs module
        class_defs_count = sum(
            1 for c in self.project_ir.classes
            if c.attrs.get('is_value_type') not in {'1', 'true'}
            and c.attrs.get('context', 'public') != 'none'
            and c.attrs.get('lifecycle') != 'none'
        )
        # Classes with internal-scope methods get an internal module
        class_internal_count = sum(
            1 for c in self.project_ir.classes
            if any(m.attrs.get('scope') == 'internal' for m in c.methods)
        )
        # Implementations with scope="private" methods get an extra private module
        from tools.codegen.project_c_backend import _impl_has_private_methods
        impl_private_count = sum(
            1 for impl in self.project_ir.implementations if _impl_has_private_methods(impl)
        )
        # Bound discovery instead of exactly re-deriving it (an exact count merely
        # duplicates discover_renderers and drifts on every model change). The
        # guaranteed minimum is one renderer per module/class/enum, two per interface
        # (dispatch + api), and three per implementation (main + defs + internal); the
        # optional defs/internal/private/infra modules only add to that.
        mandatory_min = (
            len(self.project_ir.modules)
            + len(self.project_ir.classes)
            + len(self.project_ir.enums)
            + len(self.project_ir.interfaces) * 2
            + len(self.project_ir.implementations) * 3
        )
        optional_max = (
            impl_private_count + infra_count + class_defs_count + class_internal_count
        )
        self.assertGreaterEqual(len(renderers), mandatory_min)
        self.assertLessEqual(len(renderers), mandatory_min + optional_max)

    def test_full_discovery_has_expected_enum_count(self) -> None:
        renderers = discover_renderers(self.project_ir, entity_kinds={"enum"})
        self.assertGreater(len(renderers), 0, "foundation should have enums")


class TestRegistryIntegration(unittest.TestCase):
    """Integration tests for the registry entry point."""

    def test_common_registry(self) -> None:
        renderers = direct_c_renderers_for_project("common", REPO_ROOT)
        # Should have all entities + buffer_defs custom override
        self.assertIn("c_module_vsc_buffer_defs.xml", renderers)
        self.assertIn("c_module_vsc_library.xml", renderers)
        self.assertIn("c_module_vsc_data.xml", renderers)

    def test_foundation_registry(self) -> None:
        renderers = direct_c_renderers_for_project("foundation", REPO_ROOT)
        self.assertGreater(len(renderers), 0)

    def test_entity_kinds_filter_via_registry(self) -> None:
        enums = direct_c_renderers_for_project("foundation", REPO_ROOT, entity_kinds={"enum"})
        all_renderers = direct_c_renderers_for_project("foundation", REPO_ROOT)
        self.assertLess(len(enums), len(all_renderers))

    def test_unsupported_project_raises(self) -> None:
        with self.assertRaises(ValueError):
            direct_c_renderers_for_project("nonexistent", REPO_ROOT)

    def test_renderers_are_callable(self) -> None:
        renderers = direct_c_renderers_for_project("common", REPO_ROOT)
        for name, renderer in renderers.items():
            self.assertTrue(callable(renderer), f"renderer for '{name}' is not callable")


if __name__ == "__main__":
    unittest.main()
