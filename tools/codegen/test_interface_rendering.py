"""Tests for CG-033 — render interface modules (dispatch + API)."""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import cast

from tools.codegen.project_c_backend import (
    render_interface_api_c_module,
    render_interface_c_module,
    interface_ir,
    interface_api_output,
)
from tools.codegen.project_ir import IROutputTarget, IRProject, project_to_ir
from tools.codegen.project_source import load_named_project_source


REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_foundation_ir() -> tuple[IRProject, list[IRProject]]:
    pir = project_to_ir(load_named_project_source("foundation", REPO_ROOT))
    pir_common = project_to_ir(load_named_project_source("common", REPO_ROOT))
    return pir, [pir_common]


class TestHashApiModule(unittest.TestCase):
    """Test render_interface_api_c_module for the 'hash' interface."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.pir, cls.fallbacks = _load_foundation_ir()
        cls.iface = interface_ir(cls.pir, "hash")
        cls.root = render_interface_api_c_module(cls.pir, cls.iface, fallback_projects=cls.fallbacks)

    def test_has_4_callbacks(self) -> None:
        callbacks = self.root.findall(".//c_callback")
        self.assertEqual(len(callbacks), 4)
        names = {cb.get("name") for cb in callbacks}
        self.assertEqual(names, {
            "vscf_hash_api_hash_fn",
            "vscf_hash_api_start_fn",
            "vscf_hash_api_update_fn",
            "vscf_hash_api_finish_fn",
        })

    def test_struct_has_correct_fields(self) -> None:
        struct = self.root.find(".//c_struct")
        self.assertIsNotNone(struct)
        props = struct.findall("c_property")
        self.assertEqual(len(props), 8)
        field_names = [p.get("name") for p in props]
        # Order: api_tag, impl_tag, 4 callbacks, 2 constants
        self.assertEqual(field_names, [
            "api_tag", "impl_tag",
            "hash_cb", "start_cb", "update_cb", "finish_cb",
            "digest_len", "block_len",
        ])

    def test_api_tag_field_type(self) -> None:
        struct = self.root.find(".//c_struct")
        api_tag = struct.findall("c_property")[0]
        self.assertEqual(api_tag.get("type"), "vscf_api_tag_t")

    def test_impl_tag_field_type(self) -> None:
        struct = self.root.find(".//c_struct")
        impl_tag = struct.findall("c_property")[1]
        self.assertEqual(impl_tag.get("type"), "vscf_impl_tag_t")

    def test_constant_field_types(self) -> None:
        struct = self.root.find(".//c_struct")
        props = struct.findall("c_property")
        digest_len = props[6]
        block_len = props[7]
        self.assertEqual(digest_len.get("type"), "size_t")
        self.assertEqual(block_len.get("type"), "size_t")

    def test_scope_is_private(self) -> None:
        self.assertEqual(self.root.get("scope"), "private")

    def test_includes_library_api_impl(self) -> None:
        includes = self.root.findall(".//c_include")
        include_files = {inc.get("file") for inc in includes}
        self.assertIn("vscf_library.h", include_files)
        self.assertIn("vscf_api.h", include_files)
        self.assertIn("vscf_impl.h", include_files)


class TestHashDispatchModule(unittest.TestCase):
    """Test render_interface_c_module for the 'hash' interface."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.pir, cls.fallbacks = _load_foundation_ir()
        cls.iface = interface_ir(cls.pir, "hash")
        cls.root = render_interface_c_module(cls.pir, cls.iface, fallback_projects=cls.fallbacks)

    def test_has_9_methods(self) -> None:
        methods = self.root.findall(".//c_method")
        self.assertEqual(len(methods), 9)

    def test_method_names(self) -> None:
        methods = self.root.findall(".//c_method")
        names = {m.get("name") for m in methods}
        expected = {
            "vscf_hash",           # static dispatch (deduplicated: method name == iface name)
            "vscf_hash_start",     # stateful dispatch
            "vscf_hash_update",    # stateful dispatch
            "vscf_hash_finish",    # stateful dispatch
            "vscf_hash_digest_len",  # constant getter
            "vscf_hash_block_len",   # constant getter
            "vscf_hash_api",         # utility
            "vscf_hash_is_implemented",  # utility
            "vscf_hash_api_tag",     # utility
        }
        self.assertEqual(names, expected)

    def test_dispatch_methods_have_code(self) -> None:
        methods = self.root.findall(".//c_method")
        for m in methods:
            code = m.find("c_code")
            self.assertIsNotNone(code, f"Method {m.get('name')} has no c_code element")
            self.assertTrue(code.text, f"Method {m.get('name')} has empty c_code")

    def test_stateful_method_body_has_vtable_lookup(self) -> None:
        """Non-static methods should do vtable lookup via _api() call."""
        methods = self.root.findall(".//c_method")
        start = next(m for m in methods if m.get("name") == "vscf_hash_start")
        code_text = start.find("c_code").text
        self.assertIn("vscf_hash_api(impl)", code_text)
        self.assertIn("hash_api->start_cb", code_text)

    def test_static_method_body_no_vtable_lookup(self) -> None:
        """Static methods take api struct directly, no vtable lookup."""
        methods = self.root.findall(".//c_method")
        hash_m = next(m for m in methods if m.get("name") == "vscf_hash")
        code_text = hash_m.find("c_code").text
        self.assertNotIn("vscf_hash_api(impl)", code_text)
        self.assertIn("hash_api->hash_cb", code_text)

    def test_scope_is_public(self) -> None:
        self.assertEqual(self.root.get("scope"), "public")

    def test_includes_correct(self) -> None:
        includes = self.root.findall(".//c_include")
        include_files = {inc.get("file") for inc in includes}
        self.assertIn("vscf_library.h", include_files)
        self.assertIn("vscf_impl.h", include_files)
        self.assertIn("vscf_assert.h", include_files)
        self.assertIn("vscf_hash_api.h", include_files)


class TestCipherDispatchModule(unittest.TestCase):
    """Test render_interface_c_module for the 'cipher' interface (has inheritance)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.pir, cls.fallbacks = _load_foundation_ir()
        cls.iface = interface_ir(cls.pir, "cipher")
        cls.root = render_interface_c_module(cls.pir, cls.iface, fallback_projects=cls.fallbacks)

    def test_has_inherited_api_getters(self) -> None:
        """Cipher inherits encrypt, decrypt, cipher_info — should have API getters."""
        methods = self.root.findall(".//c_method")
        names = {m.get("name") for m in methods}
        self.assertIn("vscf_cipher_encrypt_api", names)
        self.assertIn("vscf_cipher_decrypt_api", names)
        self.assertIn("vscf_cipher_cipher_info_api", names)

    def test_total_method_count(self) -> None:
        """10 own dispatch + 0 constants + _api + 3 inherited getters + is_implemented + api_tag = 16."""
        methods = self.root.findall(".//c_method")
        self.assertEqual(len(methods), 16)

    def test_includes_inherited_interfaces(self) -> None:
        includes = self.root.findall(".//c_include")
        include_files = {inc.get("file") for inc in includes}
        self.assertIn("vscf_encrypt.h", include_files)
        self.assertIn("vscf_decrypt.h", include_files)
        self.assertIn("vscf_cipher_info.h", include_files)


class TestCipherApiModule(unittest.TestCase):
    """Test render_interface_api_c_module for 'cipher' (has inheritance)."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.pir, cls.fallbacks = _load_foundation_ir()
        cls.iface = interface_ir(cls.pir, "cipher")
        cls.root = render_interface_api_c_module(cls.pir, cls.iface, fallback_projects=cls.fallbacks)

    def test_struct_has_inherited_api_pointers(self) -> None:
        struct = self.root.find(".//c_struct")
        props = struct.findall("c_property")
        field_names = [p.get("name") for p in props]
        # After api_tag and impl_tag, inherited API pointers come first
        self.assertIn("encrypt_api", field_names)
        self.assertIn("decrypt_api", field_names)
        self.assertIn("cipher_info_api", field_names)
        # Inherited pointers should come before method callbacks
        encrypt_idx = field_names.index("encrypt_api")
        first_cb_idx = field_names.index("set_nonce_cb")
        self.assertLess(encrypt_idx, first_cb_idx)

    def test_includes_inherited_interfaces(self) -> None:
        includes = self.root.findall(".//c_include")
        include_files = {inc.get("file") for inc in includes}
        self.assertIn("vscf_encrypt.h", include_files)
        self.assertIn("vscf_decrypt.h", include_files)
        self.assertIn("vscf_cipher_info.h", include_files)


if __name__ == "__main__":
    unittest.main()
