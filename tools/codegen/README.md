# Virgil Crypto C — Code Generator

Python-based code generator that produces C library files and wrapper code for 6 languages from XML source models.

## Quick Start

```bash
# Generate all files for a project
python3 tools/codegen/common_bootstrap.py --project foundation --apply

# Generate to a temp directory (dry run)
python3 tools/codegen/common_bootstrap.py --project foundation --out /tmp/codegen_test

# Generate all projects
for proj in common foundation phe ratchet; do
    python3 tools/codegen/common_bootstrap.py --project $proj --apply
done
```

## Supported Projects

| Project    | C library |  Go   | Swift | Python | Java  |  PHP  | WASM  |
| ---------- | :-------: | :---: | :---: | :----: | :---: | :---: | :---: |
| common     |    Yes    |   -   |   -   |  Yes   |   -   |   -   |   -   |
| foundation |    Yes    |  Yes  |  Yes  |  Yes   |  Yes  |  Yes  |  Yes  |
| phe        |    Yes    |  Yes  |   -   |  Yes   |  Yes  |  Yes  |  Yes  |
| ratchet    |    Yes    |   -   |  Yes  |   -    |  Yes  |   -   |  Yes  |

## Architecture

```
codegen/models/project_*.xml    ← Source of truth (XML models)
        │
        ▼
  project_source.py             ← XML parser
        │
        ▼
    project_ir.py               ← Intermediate Representation (IRProject)
        │
  ┌─────┼─────┬─────────┬──────────┬──────────┬──────────┐
  ▼     ▼     ▼         ▼          ▼          ▼          ▼
 C    CMake   Go      Swift      WASM       PHP        Java
backend backend backend  backend   backend   backend    backend
  │     │     │         │          │          │          │
  ▼     ▼     ▼         ▼          ▼          ▼          ▼
.h/.c .cmake .go     .swift    .js+CMake  .php+.c+.h  .java+JNI
```

Each backend follows the same contract:

```python
def generate_{lang}_files(project_ir: IRProject, ...) -> list[tuple[str, str]]
```

Returns a list of `(repo_relative_path, file_content)` tuples. The orchestrator (`common_bootstrap.py`) writes them to disk.

## Backend Files

| Backend | File                        | Output                                                      | Tests                         |
| ------- | --------------------------- | ----------------------------------------------------------- | ----------------------------- |
| C       | `project_c_backend.py`      | `.h`, `.c` headers and sources                              | `test_impl_rendering.py` etc. |
| CMake   | `project_cmake_backend.py`  | `sources.cmake`, `features.cmake`, `definitions.cmake`      | —                             |
| Go      | `project_go_backend.py`     | `.go` files (CGo wrappers)                                  | `test_go_backend.py`          |
| Swift   | `project_swift_backend.py`  | `.swift` files (ObjC-bridged)                               | `test_swift_backend.py`       |
| WASM    | `project_wasm_backend.py`   | `.js` files + `CMakeLists.txt`                              | `test_wasm_backend.py`        |
| PHP     | `project_php_backend.py`    | `.php` classes + C extension (`.c`/`.h`) + `CMakeLists.txt` | `test_php_backend.py`         |
| Java    | `project_java_backend.py`   | `.java` classes + JNI `.c`/`.h`                             | `test_java_backend.py`        |
| Python  | `project_python_backend.py` | `.py` ctypes bridge + high-level classes                    | `test_python_backend.py`      |

## Shared Infrastructure

| File                  | Purpose                                                                 |
| --------------------- | ----------------------------------------------------------------------- |
| `project_ir.py`       | Intermediate Representation — all IR types + `resolve_constant_value()` |
| `project_source.py`   | XML source model parser                                                 |
| `common_bootstrap.py` | Orchestrator — dispatches to backends based on `wrappers=` attribute    |

## Running Tests

```bash
# All codegen tests (153 tests)
python3 -m unittest discover -s tools/codegen -p "test_*.py"

# Individual backend
python3 -m unittest tools.codegen.test_swift_backend -v
python3 -m unittest tools.codegen.test_go_backend -v
```

## Adding a New Wrapper Language

1. Create `tools/codegen/project_{lang}_backend.py`
2. Implement `generate_{lang}_files(project_ir: IRProject, ...) -> list[tuple[str, str]]`
3. Wire into `common_bootstrap.py` with a `if "{lang}" in wrappers_set:` block
4. Add `tools/codegen/test_{lang}_backend.py`
5. Add `{lang}` to the project XML `wrappers=` attribute

See `docs/codegen-migration/wrapper-codegen-patterns.md` for type mapping reference.

## Key Design Decisions

- **Pure IR generation**: All backends generate from `IRProject` — no resolved XML dependency
- **No per-project hardcoding**: One backend per language handles all projects
- **Constant expression resolution**: `resolve_constant_value()` handles GSL expressions and arithmetic
- **Cross-project type resolution**: `fallback_projects` on `IRProject` + per-backend prefix maps
