"""Tests for CG-037 — Fix cross-project and external type resolution."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

from tools.codegen.project_c_backend import (
    render_class_c_module,
    render_module_c_module,
    class_ir,
    module_ir,
)
from tools.codegen.project_ir import IRProject, project_to_ir
from tools.codegen.project_source import load_named_project_source


REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_foundation_ir() -> IRProject:
    pir = project_to_ir(load_named_project_source("foundation", REPO_ROOT))
    pir_common = project_to_ir(load_named_project_source("common", REPO_ROOT))
    pir.fallback_projects = [pir_common]
    return pir


class TestBrainkeyClientRendering(unittest.TestCase):
    """Bug 1: External library types (mbedtls_ecp_group) should not do IR lookup."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.pir = _load_foundation_ir()
        cls.cls_obj = class_ir(cls.pir, "brainkey client")
        cls.root = render_class_c_module(cls.pir, cls.cls_obj)

    def test_renders_without_error(self) -> None:
        """Rendering should succeed (previously raised KeyError for mbedtls_ecp_group)."""
        self.assertIsNotNone(self.root)

    def test_external_type_in_arguments(self) -> None:
        """External library types should appear as raw C types in arguments."""
        args = self.root.findall(".//c_argument")
        type_names = {a.get("type") for a in args}
        # mbedtls_ecp_group should appear as a raw type name
        self.assertTrue(
            any("mbedtls_ecp" in t for t in type_names if t),
            f"Expected mbedtls_ecp_group in argument types, got: {type_names}",
        )


class TestMessageCipherRendering(unittest.TestCase):
    """Bug 2: const-qualified class names should have const stripped before lookup."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.pir = _load_foundation_ir()
        cls.cls_obj = class_ir(cls.pir, "message cipher")
        cls.root = render_class_c_module(cls.pir, cls.cls_obj)

    def test_renders_without_error(self) -> None:
        """Rendering should succeed (previously raised KeyError for 'const vscf_..._t')."""
        self.assertIsNotNone(self.root)

    def test_const_qualified_type_resolved(self) -> None:
        """const-qualified library class should resolve to the type name without 'const' prefix."""
        args = self.root.findall(".//c_argument")
        for arg in args:
            type_name = arg.get("type", "")
            self.assertFalse(
                type_name.startswith("const "),
                f"Argument type should not start with 'const ': {type_name}",
            )


class TestMbedtlsBridgeRandomRendering(unittest.TestCase):
    """Bug 3: Module requires should dispatch by kind (module/class/interface/header)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.pir = _load_foundation_ir()
        cls.mod = module_ir(cls.pir, "mbedtls bridge random")
        cls.root = render_module_c_module(cls.pir, cls.mod)

    def test_renders_without_error(self) -> None:
        """Rendering should succeed (previously raised KeyError for 'impl' as module)."""
        self.assertIsNotNone(self.root)

    def test_includes_present(self) -> None:
        """Module should have c_include elements."""
        includes = self.root.findall(".//c_include")
        self.assertGreater(len(includes), 0, "Expected at least one c_include")


class TestFoundationZeroSkips(unittest.TestCase):
    """Integration test: foundation codegen should produce 0 skipped modules."""

    def test_foundation_no_skips(self) -> None:
        result = subprocess.run(
            ["bash", "tools/codegen/new_codegen.sh", "foundation"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=300,
        )
        output = result.stdout + result.stderr
        self.assertNotIn(
            "skipped",
            output.lower(),
            f"Foundation codegen should have 0 skips. Output:\n{output[-500:]}",
        )


class TestCommonRegression(unittest.TestCase):
    """Regression test: common codegen should still work correctly."""

    def test_common_no_skips(self) -> None:
        result = subprocess.run(
            ["bash", "tools/codegen/new_codegen.sh", "common"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=300,
        )
        output = result.stdout + result.stderr
        self.assertNotIn(
            "skipped",
            output.lower(),
            f"Common codegen should have 0 skips. Output:\n{output[-500:]}",
        )


if __name__ == "__main__":
    unittest.main()
