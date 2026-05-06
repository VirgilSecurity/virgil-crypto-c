---
title: Generating thirdparty/*/features.cmake from external library XML models
date: 2026-04-26
category: docs/solutions/best-practices
module: codegen
problem_type: best_practice
component: tooling
severity: medium
applies_when:
  - Adding a new external thirdparty library that needs cmake feature flags
  - Modifying feature declarations in codegen/models/external/library_*.xml
  - Extending the codegen cmake backend
resolution_type: code_fix
tags:
  - codegen
  - cmake
  - external-library
  - thirdparty
  - features-cmake
  - code-generation
---

# Generating thirdparty/*/features.cmake from external library XML models

## Context

`thirdparty/*/features.cmake` files were handwritten by hand. The codegen system already
parsed `codegen/models/external/library_*.xml` files but consumed only the
`<error_message_getter>` element — all structural metadata (`path`, `prefix`, `<feature>`,
`<require>`) was silently ignored. This created two maintenance problems:

1. New `<feature>` additions to `library_*.xml` had to be manually mirrored to `features.cmake`.
2. Handwritten files drifted: e.g., mbedtls's CTR_DRBG check used `AND NOT A AND NOT B`
   (meaning both must be absent) instead of the correct `AND NOT (A OR B)` (at least one present).

The fix: extend the codegen pipeline to fully parse external library XML models and generate
`thirdparty/*/features.cmake` from them, the same way `library/*/features.cmake` is generated
from project IRs.

## Guidance

Three layers were added — source parsing, IR conversion, cmake generation — then wired into
`common_bootstrap.py`.

### 1. Source parsing (`tools/codegen/project_source.py`)

`ProjectFeatureSource` gained a `requires` field. Two new types handle external libraries:

```python
@dataclass
class ProjectFeatureSource:
    name: str
    attrs: dict[str, str] = field(default_factory=list)
    description: str = ""
    requires: list[list[str]] = field(default_factory=list)  # added

@dataclass
class ExternalLibrarySource:
    name: str
    path: str
    prefix: str = ""
    description: str = ""
    features: list[ProjectFeatureSource] = field(default_factory=list)
    library_requires: list[list[str]] = field(default_factory=list)
```

`_parse_feature_requires(feat_elem)` handles both forms:
- `<require feature="X"/>` → single-item list (hard dependency)
- `<require><alternative feature="X"/><alternative feature="Y"/></require>` → multi-item list (OR-group)

`load_external_library_source(path)` calls `_parse_legacy_xml`, reads `<feature>` children and
top-level `<require>` children (library-level mutex groups, as in ed25519).

### 2. IR conversion (`tools/codegen/project_ir.py`)

```python
@dataclass
class IRFeatureRequire:
    alternatives: list[str] = field(default_factory=list)
    # 1 item  → hard dep ("X must be enabled")
    # N items → OR-group ("at least one of X, Y, Z must be enabled")

@dataclass
class IRFeature(IRCommented):
    name: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    requires: list[IRFeatureRequire] = field(default_factory=list)  # added

@dataclass
class IRExternalLibrary:
    name: str = ""
    prefix: str = ""
    path: str = ""
    description: str = ""
    features: list[IRFeature] = field(default_factory=list)
    library_requires: list[IRFeatureRequire] = field(default_factory=list)
```

`external_library_to_ir(source)` converts the source; `prefix` falls back to `name` when absent.

### 3. CMake generation (`tools/codegen/project_cmake_backend.py`)

Key helpers:

```python
def _render_cmake_default(value: str) -> str:
    # "off" → OFF, "${VAR}" → ${VAR} verbatim (no quotes!), else → ON
    if value.lower() == "off":
        return "OFF"
    if value.startswith("${"):
        return value
    return "ON"
```

`generate_external_library_features_cmake(lib_ir, license_text)` builds the file:

1. Scans features for `name="library"` — its `default` drives the `{PREFIX}_LIBRARY` option
   (e.g. falcon/liboqs use `${VIRGIL_POST_QUANTUM}`).
2. Emits `option(...)` for the library flag, then one per non-library feature.
3. Emits `mark_as_advanced(...)` block.
4. Per-feature dependency checks via `_emit_require_check`:
   - Single dep: `if(FLAG AND NOT DEP)` + FATAL_ERROR
   - OR-group: `if(FLAG AND NOT (A OR B OR C))` + FATAL_ERROR
5. Library-level `library_requires` groups (ed25519 pattern): pairwise mutex checks
   (`if(A AND B)`) then a mandatory-one-of check (`if(NOT (A OR B OR C))`).

### 4. Bootstrap wiring (`tools/codegen/common_bootstrap.py`)

After the main projects loop:

```python
from tools.codegen.project_cmake_backend import generate_external_library_cmake_files
from tools.codegen.project_source import load_external_library_source
from tools.codegen.project_ir import external_library_to_ir

external_models_dir = codegen_root / "models" / "external"
for lib_xml in sorted(external_models_dir.glob("library_*.xml")):
    try:
        lib_source = load_external_library_source(lib_xml)
        lib_ir = external_library_to_ir(lib_source)
        for rel_path, content in generate_external_library_cmake_files(lib_ir, license_text=_repo_license_text):
            out_path = out_root / rel_path
            ensure_parent(out_path)
            out_path.write_text(content)
            all_written.append(out_path)
    except Exception as exc:
        print(f"[external] skipped {lib_xml.name}: {exc}")
```

## Why This Matters

- **Single source of truth**: features are declared once in XML; the cmake file is derived.
- **Correctness**: `_render_cmake_default` correctly passes `${VAR}` tokens without wrapping in quotes, which CMake requires for variable references in `option()` defaults.
- **OR-group correctness**: handwritten mbedtls had `AND NOT A AND NOT B` (requires all absent) instead of `AND NOT (A OR B)` (requires at least one present). The generator uses the correct form.
- **ed25519 pairwise mutex**: three pairwise `if(A AND B)` checks plus one `if(NOT (A OR B OR C))` check match the original handwritten semantics exactly.

## When to Apply

- Adding a new external library: create `codegen/models/external/library_<name>.xml`, then run
  `python3 -m tools.codegen.common_bootstrap --project all --apply`. The `thirdparty/<name>/features.cmake`
  file will be created automatically.
- Modifying feature flags or dependencies: edit the XML; regenerate with `--apply`.
- The `name="library"` feature is a sentinel: its `default` overrides the hardcoded `ON` for
  the top-level `{PREFIX}_LIBRARY` option. Use it for libraries that are optional (tied to a
  build-time variable like `${VIRGIL_POST_QUANTUM}`).

## Examples

**XML model (falcon):**
```xml
<library name="falcon" path="../thirdparty/falcon">
    <feature name="library" default="${VIRGIL_POST_QUANTUM}"/>
    <feature name="ENABLE TESTING" default="off">On/Off tests.</feature>
    <feature name="BUILD SPEEDTEST" default="off">On/Off build of the speed program.</feature>
</library>
```

**Generated features.cmake (excerpt):**
```cmake
option(FALCON_LIBRARY "Enable build of the 'falcon' library" ${VIRGIL_POST_QUANTUM})
option(FALCON_ENABLE_TESTING "On/Off tests." OFF)
option(FALCON_BUILD_SPEEDTEST "On/Off build of the speed program." OFF)
mark_as_advanced(
        FALCON_LIBRARY
        FALCON_ENABLE_TESTING
        FALCON_BUILD_SPEEDTEST
        )
```

**XML model with OR-group dependency (mbedtls excerpt):**
```xml
<feature name="CTR_DRBG C">
    <require feature="ENTROPY C"/>
    <require>
        <alternative feature="TIMING C"/>
        <alternative feature="HAVEGE C"/>
        <alternative feature="PLATFORM ENTROPY"/>
    </require>
</feature>
```

**Generated check:**
```cmake
if(MBEDTLS_CTR_DRBG_C AND NOT MBEDTLS_ENTROPY_C)
    message(FATAL_ERROR)
endif()

if(MBEDTLS_CTR_DRBG_C AND NOT (MBEDTLS_TIMING_C OR MBEDTLS_HAVEGE_C OR MBEDTLS_PLATFORM_ENTROPY))
    message(FATAL_ERROR)
endif()
```

## Related

- `codegen/models/external/library_*.xml` — source models
- `thirdparty/*/features.cmake` — generated output (do not edit by hand)
- `tools/codegen/test_cmake_external_backend.py` — 51 unit and integration tests covering all generation paths
- Plan: `docs/plans/2026-04-26-001-feat-external-library-cmake-codegen-plan.md`
