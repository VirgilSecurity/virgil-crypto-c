# Contributing to the Code Generator

## Development Workflow

1. Make changes to `tools/codegen/project_{lang}_backend.py`
2. Run the backend's tests: `python3 -m unittest tools.codegen.test_{lang}_backend -v`
3. Regenerate: `python3 tools/codegen/common_bootstrap.py --project foundation --apply`
4. Build and test the wrapper (see per-language instructions below)
5. Run the full test suite: `python3 -m unittest discover -s tools/codegen -p "test_*.py"`

## Per-Language Build & Test

### Go
```bash
cd wrappers/go && go build ./... && go test ./...
```

### Swift
```bash
./scripts/build_apple_frameworks.sh
./scripts/run_spm_tests_with_local_binaries.sh
```

### Python
```bash
cmake -Cconfigs/python-config.cmake -Bbuild-python -S.
cmake --build build-python --target install
cd wrappers/python && PYTHONPATH=. python3 -m unittest discover -s virgil_crypto_lib/tests -p "*_test.py"
```

### Java
```bash
JAVA_HOME=/path/to/jdk cmake -Cconfigs/java-config.cmake -Bbuild-java -S.
cmake --build build-java  # builds all 4 JNI shared libraries
```

### PHP
```bash
cmake -Cconfigs/php-config.cmake -Bbuild-php -S.
cmake --build build-php --target foundation_php
php -d "extension=$(find build-php -name 'vscf_foundation_php.so')" -r "echo 'loaded';"
```

### WASM (requires emsdk 3.1.51)
```bash
source /path/to/emsdk/emsdk_env.sh
emcmake cmake -Cconfigs/wasm-config.cmake -Bbuild-wasm -S.
cmake --build build-wasm
cd build-wasm/wrappers/wasm && npm install && npm run prepare
```

## Common Patterns

### Type Mapping

See `docs/codegen-migration/wrapper-codegen-patterns.md` for the complete reference.

Key rules:
- Always use sized integer types (`Int32`, `UInt32`) for C interop
- `class_name="self"` → resolve to the enclosing entity's type name
- `class_name="data"` / `"buffer"` → language-specific byte array types
- `access="disown"` → ownership transfer (shallow copy + pointer-to-pointer in Swift/C)
- External library types (`library="mbedtls"`) → skip in wrapper generation
- Buffer capacity → resolve from `arg.length_attrs` via `resolve_constant_value()`

### Adding a Method Body Pattern

When a backend's method body generation doesn't handle a specific IR pattern:

1. Find the method in the IR: check `arg.class_name`, `arg.access`, `arg.type_name`
2. Check the legacy output: `git show main:wrappers/{lang}/.../{entity}.{ext}`
3. Add the pattern to the backend's marshalling logic
4. Test with regeneration + build

### Constant Expression Resolution

All constant values must go through `resolve_constant_value()` from `project_ir.py`:
```python
from tools.codegen.project_ir import resolve_constant_value
value = resolve_constant_value(raw_value, entity, project_ir)
```

This handles:
- GSL references: `.(c_class_xxx_constant_yyy)` → looks up the referenced constant
- Arithmetic: `1024 * 1024 - 64` → evaluates to `1048512`
- C booleans: `true`/`false` (Python backend converts to `True`/`False`)

### Impl-Tag Dispatch

The `impl/tag` enum maps integer tags to concrete implementations. The IR omits the `BEGIN=0` sentinel, so dispatch tables start at **1**, not 0.

## File Layout

```
tools/codegen/
├── README.md                    # This file
├── ARCHITECTURE.md              # System design
├── CONTRIBUTING.md              # Development guide
├── common_bootstrap.py          # Orchestrator
├── project_ir.py                # Intermediate Representation
├── project_source.py            # XML source parser
├── project_c_backend.py         # C library generator
├── project_cmake_backend.py     # CMake file generator
├── project_go_backend.py        # Go wrapper generator
├── project_swift_backend.py     # Swift wrapper generator
├── project_wasm_backend.py      # WASM/JS wrapper generator
├── project_php_backend.py       # PHP wrapper generator
├── project_java_backend.py      # Java/JNI wrapper generator
├── project_python_backend.py    # Python/ctypes wrapper generator
├── test_*.py                    # Backend test suites
└── common_ir.py                 # Compatibility adapter
```
