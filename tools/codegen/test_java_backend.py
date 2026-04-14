"""Tests for the Java wrapper backend (tools/codegen/project_java_backend.py)."""
from __future__ import annotations

import pathlib
import unittest

from tools.codegen.project_java_backend import generate_java_files
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
        cls.files = generate_java_files(cls.ir, repo_root=str(REPO_ROOT))
        cls.paths = [p for p, _ in cls.files]

    def test_total_file_count(self) -> None:
        self.assertEqual(len(self.files), 135)

    def test_java_file_count(self) -> None:
        java = [p for p in self.paths if p.endswith(".java")]
        self.assertEqual(len(java), 133)

    def test_jni_c_file(self) -> None:
        c_files = [p for p in self.paths if p.endswith(".c")]
        self.assertEqual(len(c_files), 1)
        self.assertTrue(c_files[0].endswith("FoundationJNI.c"))

    def test_jni_h_file(self) -> None:
        h_files = [p for p in self.paths if p.endswith(".h")]
        self.assertEqual(len(h_files), 1)
        self.assertTrue(h_files[0].endswith("FoundationJNI.h"))


class PheFileCountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_ir("phe")
        cls.files = generate_java_files(cls.ir, repo_root=str(REPO_ROOT))

    def test_total_file_count(self) -> None:
        self.assertEqual(len(self.files), 21)


class PythiaFileCountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_ir("pythia")
        cls.files = generate_java_files(cls.ir, repo_root=str(REPO_ROOT))

    def test_total_file_count(self) -> None:
        self.assertEqual(len(self.files), 10)


class RatchetFileCountTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_ir("ratchet")
        cls.files = generate_java_files(cls.ir, repo_root=str(REPO_ROOT))

    def test_total_file_count(self) -> None:
        self.assertEqual(len(self.files), 10)


class StructuralTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ir = _load_ir("foundation")
        cls.files = dict(generate_java_files(cls.ir, repo_root=str(REPO_ROOT)))

    def test_java_has_package(self) -> None:
        sha = [c for p, c in self.files.items() if "Sha256.java" in p]
        self.assertTrue(sha)
        self.assertIn("package com.virgilsecurity.crypto.foundation", sha[0])

    def test_java_has_class(self) -> None:
        sha = [c for p, c in self.files.items() if "Sha256.java" in p]
        self.assertTrue(sha)
        self.assertIn("class Sha256", sha[0])

    def test_jni_c_has_jni_calls(self) -> None:
        c_files = [c for p, c in self.files.items() if p.endswith(".c")]
        self.assertTrue(c_files)
        # JNI C code has JNI API calls
        self.assertIn("FindClass", c_files[0])

    def test_jni_c_has_method_code(self) -> None:
        c_files = [c for p, c in self.files.items() if p.endswith(".c")]
        self.assertTrue(c_files)
        self.assertIn("FindClass", c_files[0])


if __name__ == "__main__":
    unittest.main()
