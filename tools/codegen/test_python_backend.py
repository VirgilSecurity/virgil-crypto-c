"""Tests for the Python wrapper backend (tools/codegen/project_python_backend.py)."""
from __future__ import annotations

import pathlib
import unittest

from tools.codegen.project_python_backend import generate_python_files
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
        cls.files = generate_python_files(cls.ir, repo_root=str(REPO_ROOT))
        cls.paths = [p for p, _ in cls.files]

    def test_total_file_count(self) -> None:
        # 111 bridge + 131 high-level = 242
        self.assertEqual(len(self.files), 242)

    def test_bridge_file_count(self) -> None:
        bridge = [p for p in self.paths if "_c_bridge" in p]
        self.assertEqual(len(bridge), 111)

    def test_highlevel_file_count(self) -> None:
        hl = [p for p in self.paths if "_c_bridge" not in p]
        self.assertEqual(len(hl), 131)


class PheFileCountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_ir("phe")
        cls.files = generate_python_files(cls.ir, repo_root=str(REPO_ROOT))

    def test_total_file_count(self) -> None:
        self.assertEqual(len(self.files), 26)


class CommonFileCountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_ir("common")
        cls.files = generate_python_files(cls.ir, repo_root=str(REPO_ROOT))

    def test_total_file_count(self) -> None:
        # common: 5 bridge + 1 high-level (__init__.py) = 6
        self.assertEqual(len(self.files), 6)


class StructuralTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_ir("foundation")
        cls.files = dict(generate_python_files(cls.ir, repo_root=str(REPO_ROOT)))

    def test_bridge_has_ctypes(self) -> None:
        content = self.files.get(
            "wrappers/python/virgil_crypto_lib/foundation/_c_bridge/_vscf_sha256.py", ""
        )
        self.assertIn("Structure", content)
        self.assertIn("vscf_sha256_t", content)

    def test_highlevel_has_class(self) -> None:
        content = self.files.get(
            "wrappers/python/virgil_crypto_lib/foundation/sha256.py", ""
        )
        self.assertIn("class Sha256", content)

    def test_bridge_init_has_imports(self) -> None:
        content = self.files.get(
            "wrappers/python/virgil_crypto_lib/foundation/_c_bridge/__init__.py", ""
        )
        self.assertIn("VscfSha256", content)

    def test_highlevel_init_has_imports(self) -> None:
        content = self.files.get(
            "wrappers/python/virgil_crypto_lib/foundation/__init__.py", ""
        )
        self.assertIn("Sha256", content)

    def test_sha256_has_method_bodies(self) -> None:
        """Generated sha256.py should have real method implementations."""
        content = self.files.get(
            "wrappers/python/virgil_crypto_lib/foundation/sha256.py", ""
        )
        self.assertIn("class Sha256", content)
        self.assertIn("def hash(", content)
        self.assertIn("VscfSha256", content)


if __name__ == "__main__":
    unittest.main()
