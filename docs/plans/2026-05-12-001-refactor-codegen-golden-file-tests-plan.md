---
title: "refactor: Replace codegen count-snapshot tests with golden-file tests"
type: refactor
status: active
date: 2026-05-12
---

# refactor: Replace codegen count-snapshot tests with golden-file tests

## Overview

The codegen test suite currently uses two brittle patterns that provide low defect-detection value at high maintenance cost: count snapshots (`assertEqual(len(files), 137)`) and full-project parity checks against the checked-in `wrappers/` tree. Neither pattern detected any of the four codegen bugs found and fixed during the 0.19.0 RC cycle. This plan replaces them with focused golden-file tests driven by minimal programmatic IR fixtures — one test per codegen feature, verified by comparing generated output against a committed golden string.

## Problem Frame

Count-snapshot tests encode the current state of the IR model rather than any invariant. Every legitimate API addition, removal, or rename breaks them mechanically, and the fix is always the same: run codegen, read the new number, update the assertion. They carry zero signal about whether the generated code is correct.

The four bugs found during 0.19.0-rc.8 / rc.9 / rc.10:
1. JNI dep setters missing for `<class>` entities (only `<impl>` was covered)
2. Go import paths used legacy `virgil/<project>` instead of canonical module path
3. `<return class="buffer" access="disown">` generated raw `*C.vsc_buffer_t` instead of `[]byte`
4. Impl entity constant getters (`getKeyMaterialLenMin`, `getSeedLen`, etc.) silently omitted

All four were live in production codegen, all four were invisible to the test suite. The count assertions ran green the entire time.

The fix: replace count assertions with small, behavior-targeted tests that construct a minimal `IRProject` programmatically, call the generator, and compare a specific slice of the output against a committed golden string.

## Requirements Trace

- R1. Each codegen feature has a dedicated test with a minimal programmatic IR fixture
- R2. Generated output is compared against a committed golden file, not an integer count
- R3. A `--update-golden` flag regenerates golden files from current output without manual editing
- R4. Count-snapshot assertions are deleted from existing test files once golden coverage replaces them
- R5. The four bugs from the 0.19.0 RC cycle are covered as permanent regression guards
- R6. Fixing the remaining 25 pre-existing test failures reduces the baseline to ≤2 unexplained failures

## Scope Boundaries

- Only Java and Go backends are covered in this plan. PHP, Python, Swift, and WASM golden tests follow the same pattern but are a separate future task.
- The existing structural tests (`test_java_has_package`, `test_jni_c_has_jni_calls`) are not deleted — they test real invariants and are orthogonal to count snapshots.
- C backend tests (`test_impl_rendering.py`, `test_impl_infra_rendering.py`, `test_interface_rendering.py`) are out of scope; their stale counts are separate.

### Deferred to Separate Tasks

- PHP, Python, Swift, WASM golden tests: same pattern, separate PR
- C backend stale count fixes: separate PR

## Context & Research

### Relevant Code and Patterns

- `tools/codegen/test_cmake_external_backend.py::TestGenerateFeaturesSimple` — already does this correctly: builds `IRExternalLibrary` inline, calls the generator, asserts on string output. The model to follow.
- `tools/codegen/test_go_backend.py` — contains ad-hoc legacy parity tests that compare generated Go against checked-in `wrappers/go/` files. These are de-facto golden tests; the new infrastructure formalises the same idea with compact synthetic fixtures.
- `tools/codegen/project_ir.py` — all IR types are `@dataclass` instances with keyword arguments and `field(default_factory=list)` defaults. Constructing a minimal `IRProject` with one class and one method requires no XML loading.
- Generator contracts: all six backends return `list[tuple[str, str]]` — `(repo_relative_path, file_content)`. `dict(generate_java_files(ir))` gives path-keyed lookup.
- `tools/codegen/project_go_backend.py:_GO_MODULE_ROOT` — the canonical import path constant added in the rc.9 fix; golden test must verify this value is used.

### Institutional Learnings

- `docs/solutions/best-practices/codegen-test-stale-assertions-2026-05-12.md` — documents all 25 pre-existing failures, their root causes, and the baseline (`25 failed, 339 passed`). The cmake and auto-discovery failures in that doc are fixed in Unit 5 of this plan.

## Key Technical Decisions

- **Programmatic IR fixtures, not XML loading**: Each test constructs a minimal `IRProject` containing only the entities needed to exercise one feature. Tests are independent of the real foundation/phe/ratchet models — adding a new API never breaks a test for constant getters. Pattern: `test_cmake_external_backend.py::TestGenerateFeaturesSimple`.

- **Golden files as committed text under `tools/codegen/testdata/golden/`**: Small files storing only the relevant generated snippet (a single `.java` class, one `.go` method body). Updated via `pytest --update-golden`. No third-party plugin needed — implemented as a pytest `conftest.py` helper using stdlib only.

- **New test files, not modifications to existing ones**: `test_java_golden.py` and `test_go_golden.py` are new. Existing test files are only touched to delete count assertions once golden coverage is confirmed green. This allows landing infrastructure first, coverage second, cleanup third without a single large risky PR.

- **Deletion is the last step**: Count-snapshot tests are deleted only after the corresponding golden test is committed and green. Never delete first.

- **Missing golden → auto-create on first run, not a hard failure**: On the first run with `--update-golden`, the file is written. On subsequent runs without the flag, a missing golden fails with an actionable message: `Golden file not found. Run pytest --update-golden to create it.`

## Open Questions

### Resolved During Planning

- **Do we need a pytest plugin (syrupy, pytest-regressions)?** No — pytest 9.0.3's `addoption` and stdlib file I/O cover everything needed. Adding a plugin dependency for this is unnecessary complexity.
- **Should goldens store the full generated file or a snippet?** A snippet is better for fixtures with one entity. The full file is appropriate when the test exercises a complete class. Either is valid; the rule is: store the minimum that proves the feature.
- **Where do golden files live?** `tools/codegen/testdata/golden/<backend>/<feature>.golden`. Committed to git. The path is relative to the repo root.

### Deferred to Implementation

- Exact golden file contents (written on first `--update-golden` run, then committed)
- Whether any existing `test_go_backend.py` legacy parity tests should be migrated to the new infrastructure or left as-is (left for the implementer to assess when touching that file)

## Output Structure

```
tools/codegen/
├── conftest.py                                    (new)
├── testdata/
│   └── golden/
│       ├── java/
│       │   ├── impl_constant_getter.golden        (new)
│       │   ├── class_dep_setter_jni_c.golden      (new)
│       │   └── impl_dep_setter_jni_c.golden       (new)
│       └── go/
│           ├── foreign_import_canonical.golden    (new)
│           └── disown_buffer_return.golden        (new)
├── test_java_golden.py                            (new)
└── test_go_golden.py                              (new)
```

Existing files modified (count assertions deleted):
```
tools/codegen/
├── test_java_backend.py       (delete test_total_file_count, test_java_file_count)
├── test_cmake_external_backend.py   (update HAVEGE_C assertions)
└── test_auto_discovery.py     (fix project_c_backend import)
```

## Implementation Units

- [ ] **Unit 1: Golden file infrastructure**

**Goal:** `conftest.py` with `assert_golden()` helper and `--update-golden` pytest flag; create `testdata/golden/` directory scaffold.

**Requirements:** R2, R3

**Dependencies:** None

**Files:**
- Create: `tools/codegen/conftest.py`
- Create: `tools/codegen/testdata/golden/java/.gitkeep`
- Create: `tools/codegen/testdata/golden/go/.gitkeep`

**Approach:**
- Register `--update-golden` via `pytest_addoption(parser)` in `conftest.py`
- Expose a `update_golden` pytest fixture (session-scoped, reads `config.getoption`)
- `assert_golden(content, golden_path, update)`: if `update=True`, write `content` to `golden_path` and return; if `update=False` and file missing, `pytest.fail` with actionable message; otherwise `assert content == golden_path.read_text()` with a diff in the failure message
- `golden_path` is always resolved relative to `tools/codegen/testdata/golden/`; accept a short relative string like `"java/impl_constant_getter.golden"` and resolve against a base dir constant
- No changes to existing test files in this unit

**Patterns to follow:**
- `pytest_addoption` / `pytest.ini_options` pattern (pytest 9 docs)
- `tools/codegen/test_cmake_external_backend.py` for how tests in this suite are structured (unittest.TestCase + setUpClass)

**Test scenarios:**
- Happy path: call `assert_golden("content", path, update=False)` with a golden file containing `"content"` → passes silently
- Mismatch: call with content `"a"` vs golden `"b"` → `AssertionError` with a message mentioning the golden file path
- Update mode: call with `update=True`, golden file does not exist → file is created with correct content, test passes
- Update mode: call with `update=True`, golden file exists with different content → file is overwritten, test passes
- Missing golden without update flag → `pytest.fail` message contains `--update-golden`

**Verification:**
- `python3 -m pytest tools/codegen/conftest.py --collect-only` reports the fixture without error
- A minimal inline test exercising `assert_golden` passes with and without `--update-golden`
- No existing tests break after adding `conftest.py`

---

- [ ] **Unit 2: Java backend golden tests**

**Goal:** `test_java_golden.py` with focused golden tests for impl constant getters and dep setter JNI C generation — the two Java bugs from the 0.19.0 RC cycle.

**Requirements:** R1, R2, R5

**Dependencies:** Unit 1

**Files:**
- Create: `tools/codegen/test_java_golden.py`
- Create: `tools/codegen/testdata/golden/java/impl_constant_getter.golden`
- Create: `tools/codegen/testdata/golden/java/class_dep_setter_jni_c.golden`
- Create: `tools/codegen/testdata/golden/java/impl_dep_setter_jni_c.golden`

**Approach:**
- Each test class in `test_java_golden.py` follows the `unittest.TestCase` + `setUpClass` pattern already used throughout the suite
- Build a minimal `IRProject` with one or two entities — only what the feature needs. Example for constant getter test: an `IRImplementation` named `"key material rng"` with two `IRCConstant` entries; no methods, no dependencies, no interface bindings
- Call `generate_java_files(ir)`, convert to dict, extract the relevant `.java` file content
- Call `assert_golden(content, "java/impl_constant_getter.golden", update_golden)` where `update_golden` comes from the `update_golden` fixture
- Since these use `unittest.TestCase`, access the fixture via `request` or use a module-level helper; prefer a module-level `GOLDEN_UPDATE` sentinel read from `sys.argv` or environment, or restructure as plain pytest functions (not TestCase) to use fixtures directly — implementer's choice, but must work with `python3 -m pytest tools/codegen/ -q`

**Patterns to follow:**
- `tools/codegen/test_cmake_external_backend.py::TestGenerateFeaturesSimple` — minimal IR construction, direct assertion
- IR construction: `IRProject(name="foundation", implementations=[IRImplementation(name="key material rng", constants=[IRCConstant(...), ...])])`

**Test scenarios:**
- Happy path — impl constant getter: `IRImplementation` with `constants=[IRCConstant(name="key material len min", attrs={"value": "32", "definition": "public"})]` → generated `.java` contains `public int getKeyMaterialLenMin()` returning `32`
- Happy path — impl constant getter matches golden: above test stores/compares against golden file
- Edge case — no constants: `IRImplementation` with empty `constants` → generated `.java` contains no `getXxx()` getter methods
- Happy path — class dep setter in JNI C: `IRClass` with one `IRDependency` → generated `FoundationJNI.c` contains the dep setter function definition for that dependency; matches golden
- Happy path — impl dep setter in JNI C: `IRImplementation` with one `IRDependency` → same; matches golden
- Regression guard: the golden for `impl_constant_getter` must contain `getKeyMaterialLenMin` and `getKeyMaterialLenMax`; if the codegen regresses, the golden comparison fails

**Verification:**
- `python3 -m pytest tools/codegen/test_java_golden.py -v` — all tests pass
- Running with `--update-golden` writes the golden files; running again without it passes

---

- [ ] **Unit 3: Go backend golden tests**

**Goal:** `test_go_golden.py` with focused golden tests for canonical import paths and disown buffer return generation — the two Go bugs from the 0.19.0 RC cycle.

**Requirements:** R1, R2, R5

**Dependencies:** Unit 1

**Files:**
- Create: `tools/codegen/test_go_golden.py`
- Create: `tools/codegen/testdata/golden/go/foreign_import_canonical.golden`
- Create: `tools/codegen/testdata/golden/go/disown_buffer_return.golden`

**Approach:**
- Build a minimal `IRProject` with `fallback_projects` set to reference a foreign project, and an `IRClass` with one method that has a cross-project argument — enough to trigger `_foreign_import_lines`
- For the disown buffer return test: an `IRImplementation` with one method whose `returns` list contains `IRCArgument(name="result", kind="class", class_name="buffer", access="disown")`
- Call `generate_go_files(ir)`, extract the relevant `.go` file, call `assert_golden`
- The canonical import golden file must contain `"github.com/VirgilSecurity/virgil-crypto-c/wrappers/go/foundation"` — if `_GO_MODULE_ROOT` ever regresses to `"virgil/foundation"`, the test fails
- The disown buffer golden must contain both `C.GoBytes` and `defer C.vsc_buffer_delete` — if either is dropped, the test fails

**Patterns to follow:**
- `tools/codegen/test_go_backend.py::TestGoBackendEnum` for how IR is constructed for Go backend tests
- `_GO_MODULE_ROOT = "github.com/VirgilSecurity/virgil-crypto-c/wrappers/go"` in `project_go_backend.py`

**Test scenarios:**
- Happy path — canonical import: generated `.go` for a class with a cross-project dependency imports with full `github.com/VirgilSecurity/...` path; matches golden
- Regression guard: golden content contains the full module root string; test fails if backend reverts to `"virgil/<project>"`
- Happy path — disown buffer return: method with `<return class="buffer" access="disown">` → generated method body contains `C.GoBytes(unsafe.Pointer(C.vsc_buffer_bytes(proxyResult)), ...)` and `defer C.vsc_buffer_delete(proxyResult)`; matches golden
- Regression guard: golden content contains both `GoBytes` and `defer`; test fails if either is dropped
- Edge case — non-disown buffer: method returning buffer without `access="disown"` → no `defer C.vsc_buffer_delete` in output

**Verification:**
- `python3 -m pytest tools/codegen/test_go_golden.py -v` — all tests pass
- Golden files contain the specific strings documented in the test scenarios above

---

- [ ] **Unit 4: Delete Java and Go count-snapshot assertions**

**Goal:** Remove stale count-snapshot assertions from `test_java_backend.py`; confirm the corresponding golden tests now cover the behavioral intent.

**Requirements:** R4

**Dependencies:** Units 2 and 3 green

**Files:**
- Modify: `tools/codegen/test_java_backend.py`

**Approach:**
- Delete `FoundationFileCountTests::test_total_file_count`, `FoundationFileCountTests::test_java_file_count`, `PheFileCountTests::test_total_file_count`, `RatchetFileCountTests::test_total_file_count`
- Keep: `test_jni_c_file`, `test_jni_h_file` (these verify file names, not counts — a real invariant)
- Keep: all `StructuralTests` (`test_java_has_package`, `test_java_has_class`, `test_jni_c_has_jni_calls`, `test_jni_c_has_method_code`)
- Do not touch `test_php_backend.py`, `test_python_backend.py`, `test_swift_backend.py`, or `test_wasm_backend.py` in this unit — their count stubs are out of scope per Scope Boundaries

**Test expectation: none** — this unit only deletes tests; the remaining tests in the file continue to pass, and the golden tests from Units 2–3 provide the replacement coverage.

**Verification:**
- `python3 -m pytest tools/codegen/test_java_backend.py -v` — remaining tests pass; count assertion tests are gone
- `python3 -m pytest tools/codegen/ -q` — total pass count drops by the number of deleted assertions, zero new failures

---

- [ ] **Unit 5: Fix pre-existing cmake and auto-discovery test failures**

**Goal:** Repair the 4 pre-existing test failures in `test_cmake_external_backend.py` and `test_auto_discovery.py` that have concrete root causes and straightforward fixes.

**Requirements:** R6

**Dependencies:** None (independent of Units 1–4)

**Files:**
- Modify: `tools/codegen/test_cmake_external_backend.py`
- Modify: `tools/codegen/test_auto_discovery.py`

**Approach:**
- `test_cmake_external_backend.py` (2 failures): The tests assert that the `CTR_DRBG` OR-group has 3 alternatives (`TIMING_C OR HAVEGE_C OR PLATFORM_ENTROPY`). `HAVEGE_C` was removed in the mbedTLS 3.6.5 LTS upgrade — the generated cmake now has 2 alternatives. Update both assertions to the 2-alternative form: `MBEDTLS_CTR_DRBG_C AND NOT (MBEDTLS_TIMING_C OR MBEDTLS_PLATFORM_ENTROPY)`.
- `test_auto_discovery.py` (2 failures): Tests do `from project_c_backend import _impl_has_private_methods` — `project_c_backend` is not a module at the `tools/codegen` package level. Find the actual module where `_impl_has_private_methods` is defined and fix the import to use the correct path.

**Test scenarios:**
- cmake: `test_ctr_drbg_or_group` passes with the 2-alternative OR string
- cmake: `test_ctr_drbg_c_or_group_has_three_alternatives` — this test by name asserts 3 alternatives; either rename and fix the assertion to `has_two_alternatives`, or delete it if the 2-alternative form is fully covered by the string test
- auto-discovery: both discovery tests pass without `ModuleNotFoundError`

**Verification:**
- `python3 -m pytest tools/codegen/test_cmake_external_backend.py tools/codegen/test_auto_discovery.py -v` — all tests pass
- `python3 -m pytest tools/codegen/ -q` — pre-existing failure count drops by 4

## System-Wide Impact

- **Interaction graph:** Only `tools/codegen/` test files and the new `testdata/golden/` directory. No production codegen code changes — this is test infrastructure only.
- **Error propagation:** A golden mismatch surfaces as a pytest assertion failure with the golden file path in the message. The `--update-golden` flag is the recovery path.
- **State lifecycle risks:** Golden files are committed to git. A developer who changes a template without updating goldens will see test failures on their branch — that is the intended behavior.
- **API surface parity:** The new tests exercise the same `generate_java_files()` / `generate_go_files()` public API already tested. No new API surface.
- **Integration coverage:** The golden tests use the full generator pipeline (IR → backend → output string), so they exercise the same path as production codegen. They are integration tests of the codegen layer, not unit tests of individual helper functions.
- **Unchanged invariants:** The existing structural tests (`test_java_has_package`, `test_jni_c_has_jni_calls`) are unchanged and continue to provide coverage for correctness that is orthogonal to the count snapshots.

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| unittest.TestCase tests can't use pytest fixtures directly | Use module-level helper or restructure golden tests as plain `def test_*` functions (pytest supports both) |
| Golden files become stale if template changes intentionally | That is the intended signal — update with `--update-golden` and commit the diff. The change is visible in PR review. |
| Constructing a valid minimal IRProject is complex for some features | Start with the simplest possible IR and add fields only until the generator produces the feature under test. `TestGenerateFeaturesSimple` in `test_cmake_external_backend.py` demonstrates this is tractable. |
| Unit 5 cmake rename test (`has_three_alternatives`) — rename vs delete | Rename is cleaner; delete is acceptable if the string test fully covers the assertion. Implementer decides. |

## Sources & References

- Related solution doc: `docs/solutions/best-practices/codegen-test-stale-assertions-2026-05-12.md`
- Existing golden-style pattern: `tools/codegen/test_cmake_external_backend.py::TestGenerateFeaturesSimple`
- IR type definitions: `tools/codegen/project_ir.py`
- Go backend canonical import constant: `tools/codegen/project_go_backend.py` (`_GO_MODULE_ROOT`)
- Java backend impl constants fix: `tools/codegen/project_java_backend.py` (`_generate_impl_file`, `_generate_class_entity_file`)
