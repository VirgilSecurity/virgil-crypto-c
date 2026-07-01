"""Tests for the PHP wrapper backend (tools/codegen/project_php_backend.py)."""
from __future__ import annotations

import pathlib
import unittest

from tools.codegen.project_php_backend import generate_php_files
from tools.codegen.project_ir import project_to_ir
from tools.codegen.project_source import load_named_project_source


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _load_ir(project_name: str):
    src = load_named_project_source(project_name, str(REPO_ROOT))
    return project_to_ir(src)


class FoundationFileCountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_ir("foundation")
        cls.files = generate_php_files(cls.ir, repo_root=str(REPO_ROOT))
        cls.paths = [p for p, _ in cls.files]

    def test_php_file_count(self) -> None:
        php = [p for p in self.paths if p.endswith(".php")]
        self.assertEqual(len(php), 131)

    def test_c_extension_files(self) -> None:
        c_files = [p for p in self.paths if p.endswith(".c") or p.endswith(".h")]
        self.assertEqual(len(c_files), 2)

    def test_total_file_count(self) -> None:
        # 122 PHP + 2 C ext + 1 extension_status = 125
        # (CMakeLists.txt not in resolved XML — generated separately)
        self.assertGreaterEqual(len(self.files), 124)


class PheFileCountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_ir("phe")
        cls.files = generate_php_files(cls.ir, repo_root=str(REPO_ROOT))

    def test_total_file_count(self) -> None:
        self.assertEqual(len(self.files), 10)


class StructuralTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_ir("foundation")
        cls.files = dict(generate_php_files(cls.ir, repo_root=str(REPO_ROOT)))

    def test_php_class_has_namespace(self) -> None:
        content = self.files.get(
            "wrappers/php/VirgilCryptoWrapper/src/Foundation/Sha256.php", ""
        )
        self.assertIn("namespace Virgil\\CryptoWrapper\\Foundation", content)

    def test_php_class_has_constructor(self) -> None:
        content = self.files.get(
            "wrappers/php/VirgilCryptoWrapper/src/Foundation/Sha256.php", ""
        )
        self.assertIn("__construct", content)
        self.assertIn("vscf_sha256_new_php", content)

    def test_php_class_implements_interfaces(self) -> None:
        content = self.files.get(
            "wrappers/php/VirgilCryptoWrapper/src/Foundation/Sha256.php", ""
        )
        self.assertIn("implements Alg, Hash", content)

    def test_c_extension_has_php_includes(self) -> None:
        c_file = None
        for path, content in self.files.items():
            if path.endswith(".c"):
                c_file = content
                break
        self.assertIsNotNone(c_file)
        self.assertIn("#include <php.h>", c_file)

    def test_c_extension_has_error_handler(self) -> None:
        """The extension_status module generates the C error handler code."""
        c_files = [content for path, content in self.files.items() if path.endswith(".c")]
        self.assertTrue(any("VSCF_HANDLE_STATUS" in c for c in c_files) or
                       any("vscf_handle_throw_exception" in c for c in c_files))


if __name__ == "__main__":
    unittest.main()
