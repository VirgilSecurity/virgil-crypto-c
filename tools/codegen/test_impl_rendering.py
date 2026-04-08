"""Tests for CG-035 — render implementation main + defs modules."""

from __future__ import annotations

import unittest
from pathlib import Path

from tools.codegen.project_c_backend import (
    implementation_ir,
    implementation_defs_output,
    render_implementation_c_module,
    render_implementation_defs_c_module,
)
from tools.codegen.project_ir import IROutputTarget, IRProject, project_to_ir
from tools.codegen.project_source import load_named_project_source


REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_foundation_ir() -> tuple[IRProject, list[IRProject]]:
    pir = project_to_ir(load_named_project_source("foundation", REPO_ROOT))
    pir_common = project_to_ir(load_named_project_source("common", REPO_ROOT))
    return pir, [pir_common]


class TestSha256MainModule(unittest.TestCase):
    """Test render_implementation_c_module for 'sha256'."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.pir, cls.fallbacks = _load_foundation_ir()
        cls.impl = implementation_ir(cls.pir, "sha256")
        cls.root = render_implementation_c_module(cls.pir, cls.impl, fallback_projects=cls.fallbacks)

    def test_lifecycle_methods_present(self) -> None:
        methods = self.root.findall(".//c_method")
        names = {m.get("name") for m in methods}
        for lifecycle in ("init", "cleanup", "new", "delete", "destroy", "shallow_copy"):
            self.assertIn(f"vscf_sha256_{lifecycle}", names, f"Missing lifecycle method: {lifecycle}")

    def test_interface_method_implementations(self) -> None:
        """sha256 implements hash (hash, start, update, finish) and alg (alg_id, produce_alg_info, restore_alg_info)."""
        methods = self.root.findall(".//c_method")
        names = {m.get("name") for m in methods}
        expected_interface_methods = {
            "vscf_sha256_hash",
            "vscf_sha256_start",
            "vscf_sha256_update",
            "vscf_sha256_finish",
            "vscf_sha256_alg_id",
            "vscf_sha256_produce_alg_info",
            "vscf_sha256_restore_alg_info",
        }
        for m_name in expected_interface_methods:
            self.assertIn(m_name, names, f"Missing interface method: {m_name}")

    def test_impl_cast_methods(self) -> None:
        methods = self.root.findall(".//c_method")
        names = {m.get("name") for m in methods}
        self.assertIn("vscf_sha256_impl_size", names)
        self.assertIn("vscf_sha256_impl", names)
        self.assertIn("vscf_sha256_impl_const", names)

    def test_includes_match_reference(self) -> None:
        includes = self.root.findall(".//c_include")
        include_files = {inc.get("file") for inc in includes}
        # Key includes from the reference XML
        self.assertIn("vscf_library.h", include_files)
        self.assertIn("vscf_assert.h", include_files)
        self.assertIn("vscf_memory.h", include_files)
        self.assertIn("mbedtls/sha256.h", include_files)
        self.assertIn("vscf_alg_info.h", include_files)
        self.assertIn("vscf_simple_alg_info.h", include_files)
        self.assertIn("vscf_sha256_defs.h", include_files)
        self.assertIn("vscf_sha256_internal.h", include_files)

    def test_interface_binding_constants(self) -> None:
        constants = self.root.findall(".//c_constant")
        const_map = {c.get("name"): c.get("value") for c in constants}
        self.assertEqual(const_map.get("vscf_sha256_DIGEST_LEN"), "32")
        self.assertEqual(const_map.get("vscf_sha256_BLOCK_LEN"), "64")

    def test_init_body_has_info_assignment(self) -> None:
        """Implementation init() sets self->info = &info unlike class init()."""
        methods = self.root.findall(".//c_method")
        init_m = next(m for m in methods if m.get("name") == "vscf_sha256_init")
        code = init_m.find("c_code")
        self.assertIn("self->info = &info;", code.text)

    def test_shallow_copy_proxies_to_impl(self) -> None:
        """Implementation shallow_copy proxies to vscf_impl_shallow_copy."""
        methods = self.root.findall(".//c_method")
        sc = next(m for m in methods if m.get("name") == "vscf_sha256_shallow_copy")
        code = sc.find("c_code")
        self.assertIn("vscf_impl_shallow_copy", code.text)

    def test_delete_uses_dealloc(self) -> None:
        """Implementation delete uses vscf_dealloc directly (not self_dealloc_cb)."""
        methods = self.root.findall(".//c_method")
        del_m = next(m for m in methods if m.get("name") == "vscf_sha256_delete")
        code = del_m.find("c_code")
        self.assertIn("vscf_dealloc(self)", code.text)
        self.assertNotIn("self_dealloc_cb", code.text)

    def test_alg_id_return_type(self) -> None:
        methods = self.root.findall(".//c_method")
        alg_id = next(m for m in methods if m.get("name") == "vscf_sha256_alg_id")
        ret = alg_id.find("c_return")
        self.assertEqual(ret.get("type"), "vscf_alg_id_t")

    def test_restore_alg_info_has_nodiscard(self) -> None:
        methods = self.root.findall(".//c_method")
        m = next(m for m in methods if m.get("name") == "vscf_sha256_restore_alg_info")
        attrs = m.findall("c_attribute")
        attr_values = [a.get("value") for a in attrs]
        self.assertIn("VSCF_NODISCARD", attr_values)

    def test_scope_is_public(self) -> None:
        self.assertEqual(self.root.get("scope"), "public")

    def test_total_method_count(self) -> None:
        """sha256 should have 18 methods: 3 cast + 6 lifecycle + 2 ctx + 7 interface."""
        methods = self.root.findall(".//c_method")
        self.assertEqual(len(methods), 18)


class TestSha256DefsModule(unittest.TestCase):
    """Test render_implementation_defs_c_module for 'sha256'."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.pir, cls.fallbacks = _load_foundation_ir()
        cls.impl = implementation_ir(cls.pir, "sha256")
        cls.root = render_implementation_defs_c_module(cls.pir, cls.impl, fallback_projects=cls.fallbacks)

    def test_struct_has_base_fields(self) -> None:
        struct = self.root.find(".//c_struct")
        self.assertIsNotNone(struct)
        props = struct.findall("c_property")
        # First two are info and refcnt
        self.assertEqual(props[0].get("name"), "info")
        self.assertEqual(props[0].get("type"), "vscf_impl_info_t")
        self.assertEqual(props[1].get("name"), "refcnt")
        self.assertIn("size_t", props[1].get("type"))

    def test_struct_has_hash_ctx(self) -> None:
        struct = self.root.find(".//c_struct")
        props = struct.findall("c_property")
        hash_ctx = props[2]
        self.assertEqual(hash_ctx.get("name"), "hash_ctx")
        self.assertEqual(hash_ctx.get("type"), "mbedtls_sha256_context")
        self.assertEqual(hash_ctx.get("type_is"), "class")
        self.assertEqual(hash_ctx.get("accessed_by"), "value")

    def test_library_include(self) -> None:
        includes = self.root.findall(".//c_include")
        include_files = {inc.get("file"): inc for inc in includes}
        self.assertIn("mbedtls/sha256.h", include_files)
        mbedtls_inc = include_files["mbedtls/sha256.h"]
        self.assertEqual(mbedtls_inc.get("is_system"), "1")

    def test_scope_is_private(self) -> None:
        self.assertEqual(self.root.get("scope"), "private")

    def test_standard_includes(self) -> None:
        includes = self.root.findall(".//c_include")
        include_files = {inc.get("file") for inc in includes}
        self.assertIn("vscf_library.h", include_files)
        self.assertIn("vscf_impl_private.h", include_files)
        self.assertIn("vscf_sha256.h", include_files)
        self.assertIn("vscf_atomic.h", include_files)


class TestAes256GcmDefsModule(unittest.TestCase):
    """Test render_implementation_defs_c_module for 'aes256 gcm'."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.pir, cls.fallbacks = _load_foundation_ir()
        cls.impl = implementation_ir(cls.pir, "aes256 gcm")
        cls.root = render_implementation_defs_c_module(cls.pir, cls.impl, fallback_projects=cls.fallbacks)

    def test_struct_has_multiple_properties(self) -> None:
        struct = self.root.find(".//c_struct")
        props = struct.findall("c_property")
        # info + refcnt + 9 properties = 11
        self.assertEqual(len(props), 11)

    def test_property_types(self) -> None:
        struct = self.root.find(".//c_struct")
        props = struct.findall("c_property")
        prop_map = {p.get("name"): p for p in props}

        # cipher_ctx: external library class
        cipher_ctx = prop_map["cipher_ctx"]
        self.assertEqual(cipher_ctx.get("type"), "mbedtls_cipher_context_t")
        self.assertEqual(cipher_ctx.get("type_is"), "class")
        self.assertEqual(cipher_ctx.get("accessed_by"), "value")

        # key: byte with fixed array
        key = prop_map["key"]
        self.assertEqual(key.get("type"), "byte")
        self.assertEqual(key.get("array"), "fixed")
        self.assertEqual(key.get("length"), "vscf_aes256_gcm_KEY_LEN")

        # nonce: byte with fixed array
        nonce = prop_map["nonce"]
        self.assertEqual(nonce.get("array"), "fixed")
        self.assertEqual(nonce.get("length"), "vscf_aes256_gcm_NONCE_LEN")

        # auth_data: project class pointer
        auth_data = prop_map["auth_data"]
        self.assertEqual(auth_data.get("type"), "vsc_buffer_t")
        self.assertEqual(auth_data.get("type_is"), "class")
        self.assertEqual(auth_data.get("accessed_by"), "pointer")

        # state: enum as primitive
        state = prop_map["state"]
        self.assertEqual(state.get("type"), "vscf_cipher_state_t")
        self.assertEqual(state.get("type_is"), "primitive")

        # cached_data_len: primitive size
        cdl = prop_map["cached_data_len"]
        self.assertEqual(cdl.get("type"), "size_t")
        self.assertEqual(cdl.get("type_is"), "primitive")

    def test_library_include(self) -> None:
        includes = self.root.findall(".//c_include")
        include_files = {inc.get("file") for inc in includes}
        self.assertIn("mbedtls/cipher.h", include_files)


if __name__ == "__main__":
    unittest.main()
