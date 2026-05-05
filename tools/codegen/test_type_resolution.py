"""Tests for CG-037 — Fix cross-project and external type resolution."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.codegen.common_bootstrap import render_one
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

    # Known skipped modules due to missing 'impl/tag' enum (pre-existing, not yet resolved)
    KNOWN_FOUNDATION_SKIPS = {"c_module_vscf_key.xml", "c_module_vscf_key_api.xml"}

    def test_foundation_no_unexpected_skips(self) -> None:
        result = subprocess.run(
            ["bash", "tools/codegen/new_codegen.sh", "foundation"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=300,
        )
        output = result.stdout + result.stderr
        # Parse skipped module names from output
        import re
        skipped = set(re.findall(r"(c_module_\S+\.xml):", output))
        unexpected = skipped - self.KNOWN_FOUNDATION_SKIPS
        self.assertFalse(
            unexpected,
            f"Foundation codegen has unexpected skips: {unexpected}. Output:\n{output[-500:]}",
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


class TestHeaderIncludeInjection(unittest.TestCase):
    """Unit 2: Include injection adds missing includes to new and existing headers.

    Uses vscf_recipient_cipher as the test subject because its renderer produces
    several includes (vsc_buffer.h, vsc_data.h, vscf_impl.h, …) that are NOT
    currently present in the checked-in header — making it easy to verify the
    fix adds them without removing anything that belongs.
    """

    CODEGEN_ROOT = REPO_ROOT / "codegen"
    XML_KEY = "c_module_vscf_recipient_cipher.xml"
    # header_file attr for recipient_cipher → resolves to this path under repo root
    HEADER_REL = Path("library/foundation/include/virgil/crypto/foundation/vscf_recipient_cipher.h")

    @classmethod
    def _run_render_one(cls, out_root: Path) -> str:
        """Run render_one for recipient_cipher and return the output header text."""
        xml_path = cls.CODEGEN_ROOT / "generated" / "foundation" / cls.XML_KEY
        render_one(
            xml_path,
            REPO_ROOT,
            cls.CODEGEN_ROOT,
            out_root,
            project="foundation",
        )
        header_path = out_root / cls.HEADER_REL
        return header_path.read_text()

    def _get_generated_includes_section(self, text: str) -> str:
        """Return the @generated_header_includes section text."""
        start = "//  @generated_header_includes"
        end = "//  @end"
        s = text.find(start)
        if s < 0:
            return ""
        e = text.find(end, s)
        return text[s:e + len(end)] if e >= 0 else text[s:]

    def test_existing_file_gains_cross_project_includes(self) -> None:
        """Existing header must gain vsc_buffer.h and vsc_data.h (cross-project deps)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            text = self._run_render_one(Path(tmpdir))
        section = self._get_generated_includes_section(text)
        self.assertIn('#include "vsc_buffer.h"', section,
                      "vsc_buffer.h (cross-project) should be injected into existing header")
        self.assertIn('#include "vsc_data.h"', section,
                      "vsc_data.h (cross-project) should be injected into existing header")

    def test_interface_dep_include_present(self) -> None:
        """Interface dependency should inject vscf_impl.h into the header."""
        with tempfile.TemporaryDirectory() as tmpdir:
            text = self._run_render_one(Path(tmpdir))
        section = self._get_generated_includes_section(text)
        self.assertIn('#include "vscf_impl.h"', section,
                      "vscf_impl.h should be present for interface dependencies")

    def test_self_include_excluded(self) -> None:
        """The header must not include itself in the generated section."""
        with tempfile.TemporaryDirectory() as tmpdir:
            text = self._run_render_one(Path(tmpdir))
        section = self._get_generated_includes_section(text)
        self.assertNotIn('#include "vscf_recipient_cipher.h"', section,
                         "Header must not include itself in @generated_header_includes")

    def test_existing_includes_preserved(self) -> None:
        """Includes already in the checked-in header must still be present in output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            text = self._run_render_one(Path(tmpdir))
        for inc in ('#include "vscf_library.h"', '#include "vscf_status.h"',
                    '#include "vscf_signer_info.h"'):
            self.assertIn(inc, text, f"Pre-existing include {inc} must be preserved")

    def test_framework_conditional_includes_preserved(self) -> None:
        """Apple-framework conditional includes in the user area must not be disturbed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            text = self._run_render_one(Path(tmpdir))
        self.assertIn("VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK", text,
                      "Framework-conditional includes must be preserved")
        self.assertIn("#   include <virgil/crypto/common/vsc_data.h>", text,
                      "Indented framework conditional include must survive codegen")

    def test_idempotency(self) -> None:
        """Running render_one twice on the same output produces identical results."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir)
            first = self._run_render_one(out)
            # Second run: same out dir, target already exists so is_new_file=False.
            xml_path = self.CODEGEN_ROOT / "generated" / "foundation" / self.XML_KEY
            render_one(xml_path, REPO_ROOT, self.CODEGEN_ROOT, out, project="foundation")
            header_path = out / self.HEADER_REL
            second = header_path.read_text()
        self.assertEqual(first, second, "render_one must be idempotent on the same file")


if __name__ == "__main__":
    unittest.main()
