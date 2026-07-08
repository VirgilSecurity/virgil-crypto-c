"""Tests for external library cmake codegen (features.cmake generation).

Covers:
- XML parsing via load_external_library_source
- IR conversion via external_library_to_ir
- CMake generation via generate_external_library_features_cmake
- End-to-end round-trip against the real library_*.xml models
"""

from __future__ import annotations

import textwrap
import unittest
from pathlib import Path

from tools.codegen.project_source import ExternalLibrarySource, ProjectFeatureSource, load_external_library_source
from tools.codegen.project_ir import IRExternalLibrary, IRFeature, IRFeatureRequire, external_library_to_ir
from tools.codegen.project_cmake_backend import (
    generate_external_library_cmake_files,
    generate_external_library_features_cmake,
    _render_cmake_default,
    _emit_require_check,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
EXTERNAL_MODELS = REPO_ROOT / "codegen" / "models" / "external"


# ---------------------------------------------------------------------------
# Unit: _render_cmake_default
# ---------------------------------------------------------------------------

class TestRenderCmakeDefault(unittest.TestCase):

    def test_off_lowercase(self) -> None:
        self.assertEqual(_render_cmake_default("off"), "OFF")

    def test_off_uppercase(self) -> None:
        self.assertEqual(_render_cmake_default("OFF"), "OFF")

    def test_on_lowercase(self) -> None:
        self.assertEqual(_render_cmake_default("on"), "ON")

    def test_variable_reference_verbatim(self) -> None:
        self.assertEqual(_render_cmake_default("${VIRGIL_POST_QUANTUM}"), "${VIRGIL_POST_QUANTUM}")

    def test_unknown_value_defaults_to_on(self) -> None:
        self.assertEqual(_render_cmake_default("yes"), "ON")


# ---------------------------------------------------------------------------
# Unit: _emit_require_check
# ---------------------------------------------------------------------------

class TestEmitRequireCheck(unittest.TestCase):

    def _emit(self, flag: str, alternatives: list[str], prefix: str) -> str:
        lines: list[str] = []
        req = IRFeatureRequire(alternatives=alternatives)
        _emit_require_check(lines, flag, req, prefix)
        return "\n".join(lines)

    def test_single_dep_hard_dependency(self) -> None:
        out = self._emit("MYLIB_FEATURE_A", ["feature b"], "mylib")
        self.assertIn("if(MYLIB_FEATURE_A AND NOT MYLIB_FEATURE_B)", out)
        self.assertIn("message(FATAL_ERROR)", out)

    def test_or_group_at_least_one(self) -> None:
        out = self._emit("MYLIB_CTR_DRBG_C", ["timing c", "havege c", "platform entropy"], "mylib")
        self.assertIn("if(MYLIB_CTR_DRBG_C AND NOT (MYLIB_TIMING_C OR MYLIB_HAVEGE_C OR MYLIB_PLATFORM_ENTROPY))", out)
        self.assertIn("message(FATAL_ERROR)", out)

    def test_empty_alternatives_emits_nothing(self) -> None:
        lines: list[str] = []
        _emit_require_check(lines, "MYLIB_X", IRFeatureRequire(alternatives=[]), "mylib")
        self.assertEqual(lines, [])


# ---------------------------------------------------------------------------
# Unit: generate_external_library_features_cmake (synthetic IR)
# ---------------------------------------------------------------------------

class TestGenerateFeaturesSimple(unittest.TestCase):
    """Verify generation from a hand-built IR without touching any XML files."""

    def _make_simple_lib(self) -> IRExternalLibrary:
        return IRExternalLibrary(
            name="testlib",
            prefix="TL",
            path="../thirdparty/testlib",
            features=[
                IRFeature(name="fast mode", attrs={"name": "fast mode", "default": "off"},
                          description="Enable fast mode."),
            ],
        )

    def test_library_option_present(self) -> None:
        lib = self._make_simple_lib()
        out = generate_external_library_features_cmake(lib)
        self.assertIn('option(TL_LIBRARY "Enable build of the \'testlib\' library" ON)', out)

    def test_feature_option_present(self) -> None:
        lib = self._make_simple_lib()
        out = generate_external_library_features_cmake(lib)
        self.assertIn('option(TL_FAST_MODE "Enable fast mode." OFF)', out)

    def test_mark_as_advanced_lists_all_flags(self) -> None:
        lib = self._make_simple_lib()
        out = generate_external_library_features_cmake(lib)
        self.assertIn("mark_as_advanced(", out)
        self.assertIn("TL_LIBRARY", out)
        self.assertIn("TL_FAST_MODE", out)

    def test_include_guard_present(self) -> None:
        out = generate_external_library_features_cmake(self._make_simple_lib())
        self.assertIn("include_guard()", out)

    def test_trailing_newline(self) -> None:
        out = generate_external_library_features_cmake(self._make_simple_lib())
        self.assertTrue(out.endswith("\n"))

    def test_no_dep_checks_when_none_declared(self) -> None:
        lib = self._make_simple_lib()
        out = generate_external_library_features_cmake(lib)
        self.assertNotIn("FATAL_ERROR", out)

    def test_variable_default_propagated_verbatim(self) -> None:
        lib = IRExternalLibrary(
            name="mylib",
            prefix="ML",
            path="../thirdparty/mylib",
            features=[
                IRFeature(name="library", attrs={"name": "library", "default": "${SOME_VAR}"}),
            ],
        )
        out = generate_external_library_features_cmake(lib)
        self.assertIn("ML_LIBRARY", out)
        self.assertIn("${SOME_VAR}", out)
        self.assertNotIn('"${SOME_VAR}"', out)

    def test_hard_dependency_check(self) -> None:
        lib = IRExternalLibrary(
            name="mylib",
            prefix="ML",
            path="../thirdparty/mylib",
            features=[
                IRFeature(
                    name="feature a",
                    attrs={"name": "feature a"},
                    requires=[IRFeatureRequire(alternatives=["feature b"])],
                ),
                IRFeature(name="feature b", attrs={"name": "feature b"}),
            ],
        )
        out = generate_external_library_features_cmake(lib)
        self.assertIn("if(ML_FEATURE_A AND NOT ML_FEATURE_B)", out)

    def test_or_group_dependency_check(self) -> None:
        lib = IRExternalLibrary(
            name="mylib",
            prefix="ML",
            path="../thirdparty/mylib",
            features=[
                IRFeature(
                    name="ctr drbg c",
                    attrs={"name": "ctr drbg c"},
                    requires=[IRFeatureRequire(alternatives=["timing c", "havege c"])],
                ),
                IRFeature(name="timing c", attrs={"name": "timing c"}),
                IRFeature(name="havege c", attrs={"name": "havege c"}),
            ],
        )
        out = generate_external_library_features_cmake(lib)
        self.assertIn("if(ML_CTR_DRBG_C AND NOT (ML_TIMING_C OR ML_HAVEGE_C))", out)

    def test_mutex_checks_for_library_requires(self) -> None:
        lib = IRExternalLibrary(
            name="mylib",
            prefix="ML",
            path="../thirdparty/mylib",
            features=[
                IRFeature(name="impl a", attrs={"name": "impl a"}),
                IRFeature(name="impl b", attrs={"name": "impl b"}),
            ],
            library_requires=[IRFeatureRequire(alternatives=["impl a", "impl b"])],
        )
        out = generate_external_library_features_cmake(lib)
        self.assertIn("if(ML_IMPL_A AND ML_IMPL_B)", out)
        self.assertIn("if(NOT (ML_IMPL_A OR ML_IMPL_B))", out)


# ---------------------------------------------------------------------------
# Unit: generate_external_library_cmake_files (path mapping)
# ---------------------------------------------------------------------------

class TestGenerateCmakeFilesPathMapping(unittest.TestCase):

    def _lib(self, path: str) -> IRExternalLibrary:
        return IRExternalLibrary(name="x", prefix="X", path=path)

    def test_strips_leading_dotdot(self) -> None:
        files = generate_external_library_cmake_files(self._lib("../thirdparty/x"))
        self.assertEqual(files[0][0], "thirdparty/x/features.cmake")

    def test_adds_trailing_slash_when_missing(self) -> None:
        files = generate_external_library_cmake_files(self._lib("../thirdparty/x"))
        self.assertTrue(files[0][0].endswith("features.cmake"))

    def test_path_already_with_slash(self) -> None:
        files = generate_external_library_cmake_files(self._lib("../thirdparty/x/"))
        self.assertEqual(files[0][0], "thirdparty/x/features.cmake")


# ---------------------------------------------------------------------------
# Integration: load_external_library_source (real XML files)
# ---------------------------------------------------------------------------

class TestLoadExternalLibraryFalcon(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = load_external_library_source(EXTERNAL_MODELS / "library_falcon.xml")

    def test_name(self) -> None:
        self.assertEqual(self.source.name, "falcon")

    def test_path(self) -> None:
        self.assertIn("thirdparty/falcon", self.source.path)

    def test_library_feature_has_variable_default(self) -> None:
        lib_feat = next(f for f in self.source.features if f.name == "library")
        self.assertEqual(lib_feat.attrs.get("default"), "${VIRGIL_POST_QUANTUM}")

    def test_non_library_features_present(self) -> None:
        names = {f.name for f in self.source.features}
        self.assertIn("ENABLE TESTING", names)
        self.assertIn("BUILD SPEEDTEST", names)

    def test_enable_testing_default_off(self) -> None:
        feat = next(f for f in self.source.features if f.name == "ENABLE TESTING")
        self.assertEqual(feat.attrs.get("default"), "off")


class TestLoadExternalLibraryEd25519(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = load_external_library_source(EXTERNAL_MODELS / "library_ed25519.xml")

    def test_name(self) -> None:
        self.assertEqual(self.source.name, "ed25519")

    def test_three_features(self) -> None:
        self.assertEqual(len(self.source.features), 3)

    def test_library_requires_has_one_group(self) -> None:
        self.assertEqual(len(self.source.library_requires), 1)

    def test_library_requires_group_has_three_alternatives(self) -> None:
        self.assertEqual(len(self.source.library_requires[0]), 3)

    def test_ref10_default_on(self) -> None:
        ref10 = next(f for f in self.source.features if f.name == "REF10")
        self.assertNotEqual(ref10.attrs.get("default", "on"), "off")


class TestLoadExternalLibraryMbedtls(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = load_external_library_source(EXTERNAL_MODELS / "library_mbedtls.xml")

    def test_ecp_c_has_two_requires(self) -> None:
        ecp = next(f for f in self.source.features if f.name == "ECP C")
        self.assertEqual(len(ecp.requires), 2)

    def test_ecp_c_hard_dep_on_bignum(self) -> None:
        ecp = next(f for f in self.source.features if f.name == "ECP C")
        hard_deps = [r for r in ecp.requires if len(r) == 1]
        self.assertTrue(any("BIGNUM C" in r for r in hard_deps))

    def test_ctr_drbg_c_or_group_has_two_alternatives(self) -> None:
        # mbedTLS 3.x removed HAVEGE, so CTR_DRBG's entropy OR-group is now
        # {TIMING_C, PLATFORM_ENTROPY} (was 3 with HAVEGE_C pre-3.0).
        ctr = next(f for f in self.source.features if f.name == "CTR_DRBG C")
        or_groups = [r for r in ctr.requires if len(r) > 1]
        self.assertTrue(any(len(r) == 2 for r in or_groups))
        self.assertFalse(any("HAVEGE C" in r for r in or_groups))

    def test_sha256_alt_default_off(self) -> None:
        feat = next(f for f in self.source.features if f.name == "SHA256 ALT")
        self.assertEqual(feat.attrs.get("default"), "off")


# ---------------------------------------------------------------------------
# Integration: external_library_to_ir (falcon and ed25519)
# ---------------------------------------------------------------------------

class TestExternalLibraryToIrFalcon(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        source = load_external_library_source(EXTERNAL_MODELS / "library_falcon.xml")
        cls.ir = external_library_to_ir(source)

    def test_prefix_falls_back_to_name(self) -> None:
        self.assertEqual(self.ir.prefix, "falcon")

    def test_features_are_ir_feature_instances(self) -> None:
        for feat in self.ir.features:
            self.assertIsInstance(feat, IRFeature)

    def test_library_feature_default_carried(self) -> None:
        lib_feat = next(f for f in self.ir.features if f.name == "library")
        self.assertEqual(lib_feat.attrs.get("default"), "${VIRGIL_POST_QUANTUM}")


class TestExternalLibraryToIrEd25519(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        source = load_external_library_source(EXTERNAL_MODELS / "library_ed25519.xml")
        cls.ir = external_library_to_ir(source)

    def test_library_requires_are_ir_feature_require(self) -> None:
        for req in self.ir.library_requires:
            self.assertIsInstance(req, IRFeatureRequire)

    def test_three_alternatives_in_library_require(self) -> None:
        self.assertEqual(len(self.ir.library_requires[0].alternatives), 3)


# ---------------------------------------------------------------------------
# Integration: full generation round-trip (real XML → cmake content)
# ---------------------------------------------------------------------------

class TestRoundTripFalcon(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        source = load_external_library_source(EXTERNAL_MODELS / "library_falcon.xml")
        ir = external_library_to_ir(source)
        cls.cmake = generate_external_library_features_cmake(ir)

    def test_library_option_uses_variable_default(self) -> None:
        self.assertIn("${VIRGIL_POST_QUANTUM}", self.cmake)

    def test_enable_testing_is_off(self) -> None:
        self.assertIn("FALCON_ENABLE_TESTING", self.cmake)
        self.assertIn("OFF", self.cmake)

    def test_no_fatal_error_in_falcon(self) -> None:
        self.assertNotIn("FATAL_ERROR", self.cmake)

    def test_output_path_is_correct(self) -> None:
        source = load_external_library_source(EXTERNAL_MODELS / "library_falcon.xml")
        ir = external_library_to_ir(source)
        files = generate_external_library_cmake_files(ir)
        self.assertEqual(files[0][0], "thirdparty/falcon/features.cmake")


class TestRoundTripEd25519(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        source = load_external_library_source(EXTERNAL_MODELS / "library_ed25519.xml")
        ir = external_library_to_ir(source)
        cls.cmake = generate_external_library_features_cmake(ir)

    def test_pairwise_mutex_check(self) -> None:
        self.assertIn("if(ED25519_REF10 AND ED25519_AMD64_RADIX_64_24K)", self.cmake)
        self.assertIn("if(ED25519_REF10 AND ED25519_AMD64_RADIX_51_30K)", self.cmake)
        self.assertIn("if(ED25519_AMD64_RADIX_64_24K AND ED25519_AMD64_RADIX_51_30K)", self.cmake)

    def test_mandatory_one_of_check(self) -> None:
        self.assertIn(
            "if(NOT (ED25519_REF10 OR ED25519_AMD64_RADIX_64_24K OR ED25519_AMD64_RADIX_51_30K))",
            self.cmake,
        )

    def test_ref10_default_is_on(self) -> None:
        import re
        match = re.search(r'option\(ED25519_REF10 "[^"]*" (\w+)\)', self.cmake)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "ON")


class TestRoundTripMbedtls(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        source = load_external_library_source(EXTERNAL_MODELS / "library_mbedtls.xml")
        ir = external_library_to_ir(source)
        cls.cmake = generate_external_library_features_cmake(ir)

    def test_ecp_c_hard_dep_bignum(self) -> None:
        self.assertIn("if(MBEDTLS_ECP_C AND NOT MBEDTLS_BIGNUM_C)", self.cmake)

    def test_ctr_drbg_or_group(self) -> None:
        # mbedTLS 3.x dropped HAVEGE from the CTR_DRBG entropy OR-group.
        self.assertIn(
            "if(MBEDTLS_CTR_DRBG_C AND NOT (MBEDTLS_TIMING_C OR MBEDTLS_PLATFORM_ENTROPY))",
            self.cmake,
        )

    def test_entropy_c_or_group_sha(self) -> None:
        self.assertIn(
            "if(MBEDTLS_ENTROPY_C AND NOT (MBEDTLS_SHA256_C OR MBEDTLS_SHA512_C))",
            self.cmake,
        )

    def test_sha256_alt_off_by_default(self) -> None:
        import re
        match = re.search(r'option\(MBEDTLS_SHA256_ALT "[^"]*" (\w+)\)', self.cmake)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "OFF")


if __name__ == "__main__":
    unittest.main()
