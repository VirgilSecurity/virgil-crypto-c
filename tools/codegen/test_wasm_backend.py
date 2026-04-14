"""Tests for the WASM wrapper backend (tools/codegen/project_wasm_backend.py)."""
from __future__ import annotations

import pathlib
import unittest

from tools.codegen.project_wasm_backend import generate_wasm_files
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
        cls.files = generate_wasm_files(cls.ir, repo_root=str(REPO_ROOT))
        cls.paths = [p for p, _ in cls.files]

    def test_total_file_count(self) -> None:
        # 93 JS files + 1 CMakeLists.txt = 94
        self.assertEqual(len(self.files), 94)

    def test_js_file_count(self) -> None:
        js = [p for p in self.paths if p.endswith(".js")]
        self.assertEqual(len(js), 93)

    def test_cmake_file_generated(self) -> None:
        cmake = [p for p in self.paths if p.endswith("CMakeLists.txt")]
        self.assertEqual(len(cmake), 1)

    def test_has_index_js(self) -> None:
        self.assertTrue(any(p.endswith("index.js") for p in self.paths))

    def test_has_precondition_js(self) -> None:
        self.assertTrue(any(p.endswith("precondition.js") for p in self.paths))

    def test_has_error_class(self) -> None:
        self.assertTrue(any(p.endswith("FoundationError.js") for p in self.paths))

    def test_has_interface_dispatch(self) -> None:
        self.assertTrue(any(p.endswith("FoundationInterface.js") for p in self.paths))

    def test_has_enum_files(self) -> None:
        self.assertTrue(any(p.endswith("AlgId.js") for p in self.paths))
        self.assertTrue(any(p.endswith("Asn1Tag.js") for p in self.paths))

    def test_has_class_files(self) -> None:
        self.assertTrue(any(p.endswith("Sha256.js") or p.endswith("sha256.js") for p in self.paths))
        self.assertTrue(any(p.endswith("Base64.js") for p in self.paths))


class PheFileCountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_ir("phe")
        cls.files = generate_wasm_files(cls.ir, repo_root=str(REPO_ROOT))

    def test_total_file_count(self) -> None:
        # 10 JS + 1 CMake = 11
        self.assertEqual(len(self.files), 11)


class PythiaFileCountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_ir("pythia")
        cls.files = generate_wasm_files(cls.ir, repo_root=str(REPO_ROOT))

    def test_total_file_count(self) -> None:
        # 4 JS + 1 CMake = 5
        self.assertEqual(len(self.files), 5)


class RatchetFileCountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_ir("ratchet")
        cls.files = generate_wasm_files(cls.ir, repo_root=str(REPO_ROOT))

    def test_total_file_count(self) -> None:
        # 8 JS + 1 CMake = 9
        self.assertEqual(len(self.files), 9)


class StructuralTests(unittest.TestCase):
    """Verify generated JS files contain expected structural elements."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_ir("foundation")
        cls.files = dict(generate_wasm_files(cls.ir, repo_root=str(REPO_ROOT)))

    def test_enum_has_object_freeze(self) -> None:
        content = self.files.get("wrappers/wasm/foundation/src/AlgId.js", "")
        self.assertIn("Object.freeze", content)
        self.assertIn("NONE:", content)
        self.assertIn("SHA256:", content)

    def test_class_has_constructor(self) -> None:
        # sha256.js or Sha256.js
        for key, content in self.files.items():
            if "sha256" in key.lower() and key.endswith(".js"):
                self.assertIn("constructor", content)
                self.assertIn("delete()", content)
                self.assertIn("module.exports", content)
                return
        self.fail("No sha256 JS file found")

    def test_index_has_require(self) -> None:
        content = self.files.get("wrappers/wasm/foundation/src/index.js", "")
        self.assertIn("require(", content)
        self.assertIn("module.exports", content)

    def test_cmake_has_emscripten(self) -> None:
        content = self.files.get("wrappers/wasm/foundation/CMakeLists.txt", "")
        self.assertIn("WASM=1", content)
        self.assertIn("MODULARIZE=1", content)
        self.assertIn("FoundationModule", content)


if __name__ == "__main__":
    unittest.main()
