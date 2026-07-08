"""Tests for CG-035/CG-036 — render implementation main, defs, and internal modules."""

from __future__ import annotations

import unittest
from pathlib import Path

from tools.codegen.project_c_backend import (
    implementation_ir,
    implementation_defs_output,
    render_implementation_c_module,
    render_implementation_defs_c_module,
    render_implementation_internal_c_module,
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
        """sha256 has 18 methods: 3 cast + 6 lifecycle + 2 ctx + 7 interface."""
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
        # info + refcnt + 10 properties = 12
        self.assertEqual(len(props), 12)

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


class TestSha256InternalModule(unittest.TestCase):
    """Test render_implementation_internal_c_module for 'sha256'."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.pir, cls.fallbacks = _load_foundation_ir()
        cls.impl = implementation_ir(cls.pir, "sha256")
        cls.root = render_implementation_internal_c_module(cls.pir, cls.impl, fallback_projects=cls.fallbacks)

    def test_api_table_variables_present(self) -> None:
        """sha256 implements alg and hash — should have alg_api and hash_api variables."""
        variables = self.root.findall("c_variable")
        var_names = {v.get("name") for v in variables}
        self.assertIn("alg_api", var_names)
        self.assertIn("hash_api", var_names)

    def test_impl_info_variable_present(self) -> None:
        variables = self.root.findall("c_variable")
        info = next((v for v in variables if v.get("name") == "info"), None)
        self.assertIsNotNone(info)
        self.assertEqual(info.get("type"), "vscf_impl_info_t")
        self.assertEqual(info.get("is_const_type"), "1")

    def test_includes_match_reference(self) -> None:
        includes = self.root.findall("c_include")
        include_files = {inc.get("file") for inc in includes}
        expected = {
            "vscf_sha256_internal.h",
            "vscf_library.h",
            "vscf_memory.h",
            "vscf_assert.h",
            "vscf_sha256.h",
            "vscf_sha256_defs.h",
            "vscf_alg.h",
            "vscf_alg_api.h",
            "vscf_hash.h",
            "vscf_hash_api.h",
        }
        self.assertEqual(include_files, expected)

    def test_init_cleanup_methods_present(self) -> None:
        methods = self.root.findall("c_method")
        names = {m.get("name") for m in methods}
        self.assertIn("vscf_sha256_init", names)
        self.assertIn("vscf_sha256_cleanup", names)
        self.assertIn("vscf_sha256_init_ctx", names)
        self.assertIn("vscf_sha256_cleanup_ctx", names)

    def test_hash_api_table_function_pointers(self) -> None:
        """The hash_api variable should contain function pointer values for sha256's methods."""
        variables = self.root.findall("c_variable")
        hash_api = next(v for v in variables if v.get("name") == "hash_api")
        values = hash_api.findall("c_value")
        value_names = [v.get("value") for v in values]
        # Should contain all hash method implementations
        self.assertIn("vscf_sha256_hash", value_names)
        self.assertIn("vscf_sha256_start", value_names)
        self.assertIn("vscf_sha256_update", value_names)
        self.assertIn("vscf_sha256_finish", value_names)
        # And the constants
        self.assertIn("vscf_sha256_DIGEST_LEN", value_names)
        self.assertIn("vscf_sha256_BLOCK_LEN", value_names)

    def test_scope_is_internal(self) -> None:
        self.assertEqual(self.root.get("scope"), "internal")

    def test_find_api_method_present(self) -> None:
        methods = self.root.findall("c_method")
        find_api = next((m for m in methods if m.get("name") == "vscf_sha256_find_api"), None)
        self.assertIsNotNone(find_api)
        self.assertEqual(find_api.get("declaration"), "private")
        self.assertEqual(find_api.get("definition"), "private")
        modifiers = [m.get("value") for m in find_api.findall("c_modifier")]
        self.assertIn("static", modifiers)

    def test_find_api_code_has_switch_cases(self) -> None:
        methods = self.root.findall("c_method")
        find_api = next(m for m in methods if m.get("name") == "vscf_sha256_find_api")
        code = find_api.find("c_code")
        self.assertIn("vscf_api_tag_ALG", code.text)
        self.assertIn("vscf_api_tag_HASH", code.text)
        self.assertIn("&alg_api", code.text)
        self.assertIn("&hash_api", code.text)

    def test_lifecycle_methods_definition_private(self) -> None:
        """In the internal module, lifecycle methods have definition=private."""
        methods = self.root.findall("c_method")
        for name in ("vscf_sha256_init", "vscf_sha256_cleanup", "vscf_sha256_new",
                     "vscf_sha256_delete", "vscf_sha256_destroy", "vscf_sha256_shallow_copy"):
            m = next(m for m in methods if m.get("name") == name)
            self.assertEqual(m.get("definition"), "private", f"{name} should have definition=private")
            self.assertEqual(m.get("declaration"), "external", f"{name} should have declaration=external")

    def test_impl_info_values(self) -> None:
        variables = self.root.findall("c_variable")
        info = next(v for v in variables if v.get("name") == "info")
        values = info.findall("c_value")
        value_names = [v.get("value") for v in values]
        self.assertEqual(value_names[0], "vscf_impl_tag_SHA256")
        self.assertEqual(value_names[1], "vscf_sha256_find_api")
        self.assertEqual(value_names[2], "vscf_sha256_cleanup")
        self.assertEqual(value_names[3], "vscf_sha256_delete")


if __name__ == "__main__":
    unittest.main()
