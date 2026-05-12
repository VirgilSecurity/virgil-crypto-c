---
module: codegen
tags: [codegen, tests, mbedtls, swift, wasm, php, python, cmake]
problem_type: stale-test-assertions
---

# Pre-existing stale codegen test assertions (as of 2026-05-12)

25 codegen tests fail. None are related to Java/Go fixes introduced in rc.8/rc.9.
They fall into three root-cause groups.

## Group 1 — mbedTLS 3.6.5 LTS upgrade removed HAVEGE_C

**Failing tests** (2):
- `test_cmake_external_backend.py::TestLoadExternalLibraryMbedtls::test_ctr_drbg_c_or_group_has_three_alternatives`
- `test_cmake_external_backend.py::TestRoundTripMbedtls::test_ctr_drbg_or_group`

**Root cause**: mbedTLS 3.x removed the `HAVEGE` entropy source (`MBEDTLS_HAVEGE_C`).
The generated CMake `if(MBEDTLS_CTR_DRBG_C AND NOT (...))` now has 2 alternatives
(`MBEDTLS_TIMING_C OR MBEDTLS_PLATFORM_ENTROPY`) instead of 3. Tests assert 3.

**Fix**: Update the assertions to expect the 2-alternative form:
```
if(MBEDTLS_CTR_DRBG_C AND NOT (MBEDTLS_TIMING_C OR MBEDTLS_PLATFORM_ENTROPY))
```

**Failing tests** (8) — same root cause, different symptom:
- `test_swift_backend.py::FoundationEnumParityTests::test_alg_id_parity`
- `test_swift_backend.py::FoundationEnumParityTests::test_asn1_tag_parity`
- `test_swift_backend.py::FoundationEnumParityTests::test_cipher_state_parity`
- `test_swift_backend.py::FoundationEnumParityTests::test_group_msg_type_parity`
- `test_swift_backend.py::FoundationEnumParityTests::test_oid_id_parity`
- `test_swift_backend.py::RatchetEnumParityTests::test_group_msg_type_parity`
- `test_swift_backend.py::RatchetEnumParityTests::test_msg_type_parity`
- `test_swift_backend.py::FoundationFileCountTests::test_foundation_total_file_count`

The Swift parity tests compare generated output against legacy committed `.swift` files in
`wrappers/swift/`. The legacy files were not regenerated after the mbedTLS upgrade (and
possibly after Pythia removal). The generated output has no copyright header while the legacy
files do, signalling they are from a different generation run.

**Fix**: Run `python3 -m tools.codegen.common_bootstrap --project foundation --apply` and
`--project ratchet --apply`, then re-commit the updated Swift wrapper files. Update the
file-count assertion to match.

## Group 2 — Stale count assertions across backends

All of these are simple off-by-N count assertions that were not updated after code changes
(Pythia removal, mbedTLS upgrade, or other IR additions).

| Test file | Assertion | Expected | Actual | Delta |
|---|---|---|---|---|
| `test_implementor_parsing.py` | total implementations | 53 | 54 | +1 |
| `test_implementor_parsing.py` | IR implementations | 53 | 54 | +1 |
| `test_impl_infra_rendering.py` | impl tag enum constants | 53 | 54 | +1 |
| `test_impl_rendering.py` | Sha256 method count | 20 | 18 | -2 |
| `test_impl_rendering.py` | Aes256Gcm struct properties | 11 | 12 | +1 |
| `test_php_backend.py` | foundation PHP file count | 122 | 123 | +1 |
| `test_python_backend.py` | foundation bridge file count | 108 | 103 | -5 |
| `test_python_backend.py` | foundation highlevel file count | 122 | 123 | +1 |
| `test_python_backend.py` | foundation total file count | 230 | 226 | -4 |
| `test_wasm_backend.py` | foundation JS file count | N/A | off | varies |
| `test_wasm_backend.py` | foundation total file count | N/A | off | varies |
| `test_wasm_backend.py` | phe total file count | N/A | off | varies |
| `test_wasm_backend.py` | ratchet total file count | N/A | off | varies |

**Fix**: Run the full regeneration and update each assertion to match actual output. These
are snapshot tests — the fix is mechanical (run codegen, `grep` actual count, update the
number). No logic change required.

## Group 3 — Missing module import in auto-discovery tests

**Failing tests** (2):
- `test_auto_discovery.py::TestDiscoverRenderersFoundation::test_discovers_implementations`
- `test_auto_discovery.py::TestDiscoverRenderersFoundation::test_full_discovery_covers_all_entities`

**Root cause**: `test_auto_discovery.py` does `from project_c_backend import _impl_has_private_methods`
at test time. There is no `project_c_backend` module at the `tools/codegen` package level;
the function lives inside a nested path. This is a test import bug, not a codegen bug.

**Fix**: Either expose `_impl_has_private_methods` from the correct module path, or change
the test to call it via the actual module where it's defined.

## How to identify new regressions vs these pre-existing failures

Run:
```bash
python3 -m pytest tools/codegen/ -q 2>&1 | tail -5
```

The baseline is `25 failed, 339 passed`. Any count above 25 failed indicates a new regression.
The 25 known failures are listed by name above; cross-reference before investigating.
