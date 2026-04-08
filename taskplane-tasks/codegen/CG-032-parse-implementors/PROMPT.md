# Task: CG-032 - Parse Implementors and Implementations into Source and IR

**Created:** 2026-04-08
**Size:** M

## Review Level: 1 (Plan Only)

**Assessment:** Data-model addition following established patterns, but implementors are structurally more complex than interfaces (nested `<implementation>` elements with properties, interface bindings with constant overrides, requirements).
**Score:** 3/8 — Blast radius: 1, Pattern novelty: 1, Security: 0, Reversibility: 1

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-032-parse-implementors/
├── PROMPT.md   ← This file
├── STATUS.md   ← Execution state
├── .reviews/   ← Reviewer output
└── .DONE       ← Created when complete
```

## Mission

Add parsing of `<implementor>` elements from project XML and implementor model files into the source loader and IR. An implementor file contains one or more `<implementation>` elements, each of which is essentially a class that implements one or more interfaces. This is the most structurally complex model type in the project.

An implementor model file (e.g., `implementor_mbedtls.xml`) contains:
- One or more `<implementation>` elements, each with:
  - A name (e.g., "sha256", "aes256 gcm")
  - `<interface>` bindings with optional constant value overrides
  - `<property>` elements (struct fields, including external library types)
  - `<method>` elements (implementation-specific methods)
  - `<require>` elements (library dependencies, headers, other impls)

Reference: `codegen/models/project_foundation/implementor_mbedtls.xml`, `codegen/implementation.gsl`, `codegen/implementor.gsl`.

## Dependencies

- **Task:** CG-031 (interfaces must be in IR — implementations reference them)

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3 (load only if needed):**
- `codegen/models/project_foundation/implementor_mbedtls.xml` — complex implementor with many implementations
- `codegen/models/project_foundation/implementor_ed25519.xml` — simpler implementor
- `codegen/implementation.gsl` — legacy GSL implementation handling
- `codegen/implementor.gsl` — legacy GSL implementor resolution

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** None

## File Scope

- `tools/codegen/project_source.py`
- `tools/codegen/project_ir.py`
- `tools/codegen/test_implementor_parsing.py` (new)

## Steps

### Step 0: Preflight

- [ ] CG-031 complete: interfaces are in source/IR
- [ ] Study implementor model XML files to catalog all elements and attributes
- [ ] Study `codegen/implementation.gsl` and `codegen/implementor.gsl`

### Step 1: Add ImplementorSource and ImplementationSource to project_source.py

Model the two-level structure: an implementor contains implementations.

`ImplementationSource` fields:
- `name` — implementation name (e.g., "sha256")
- `description` — description text
- `interface_bindings` — list of interface refs with constant overrides: `[{name: "hash", constants: [{name: "digest len", value: "32"}, ...]}]`
- `properties` — reuse `PropertySource`
- `methods` — reuse `MethodSource`
- `requirements` — list of require elements (library, header, interface, impl refs)
- `attrs` — raw attributes (e.g., `scope`)

`ImplementorSource` fields:
- `name` — implementor name (e.g., "mbedtls")
- `implementations` — list of `ImplementationSource`
- `attrs` — raw attributes (e.g., `is_default`)

Add `load_implementor_source()` and update `load_project_source()` to read `<implementor>` refs.

- [ ] Create `ImplementationSource` and `ImplementorSource` dataclasses
- [ ] Create `load_implementor_source()` function
- [ ] Update `load_project_source()` to read `<implementor>` refs and load models
- [ ] Add `implementor_refs` and `implementors` to `ProjectSource`

**Artifacts:**
- `tools/codegen/project_source.py` (modified)

### Step 2: Add IRImplementation and IRImplementor to project_ir.py

Flatten implementations into the IR. Each implementation becomes an IR entity (similar to a class) with additional interface binding metadata.

`IRImplementation` fields:
- `name` — implementation name
- `description` — description text
- `implementor_name` — parent implementor name
- `interface_bindings` — list of `IRInterfaceBinding(name, constants: list[IRCConstant])`
- `properties` — `list[IRCStructField]` (reuse existing)
- `methods` — `list[IRCMethod]` (reuse existing)
- `requirements` — list of requirement dicts
- `output` — `IROutputTarget` for the main module
- `attrs` — raw attributes

Add `implementations: list[IRImplementation]` to `IRProject`.

- [ ] Create `IRInterfaceBinding` and `IRImplementation` dataclasses
- [ ] Add `implementations` field to `IRProject`
- [ ] Map source → IR in `project_to_ir()`
- [ ] Compute `IROutputTarget` for each implementation (main, defs, internal)

**Artifacts:**
- `tools/codegen/project_ir.py` (modified)

### Step 3: Add test coverage

Create `test_implementor_parsing.py`:

- [ ] Foundation has 13 implementors in source
- [ ] `implementor_mbedtls` has expected implementations (sha224, sha256, sha384, sha512, aes256_gcm, aes256_cbc, asn1rd, asn1wr)
- [ ] `sha256` implementation has interface binding to "hash" with digest_len=32, block_len=64
- [ ] `sha256` implementation has property "hash ctx" with library="mbedtls"
- [ ] `aes256_gcm` has multiple interface bindings (alg, encrypt, decrypt, cipher_info, cipher, cipher_auth_info, auth_encrypt, auth_decrypt, cipher_auth)
- [ ] Implementation methods are parsed correctly
- [ ] Implementation requirements (library, header) are parsed
- [ ] IRImplementation has correct output targets
- [ ] Total implementation count across all implementors is 53
- [ ] Common project has zero implementors

**Artifacts:**
- `tools/codegen/test_implementor_parsing.py` (new)

### Step 4: Testing & Verification

> ZERO test failures allowed.

- [ ] Run: `python3 -m pytest tools/codegen/test_implementor_parsing.py -v`
- [ ] Run existing tests: `python3 -m pytest tools/codegen/ -v`
- [ ] Build passes: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Fix all failures

### Step 5: Documentation & Delivery

- [ ] Discoveries logged in STATUS.md
- [ ] Update CONTEXT.md if needed

## Documentation Requirements

**Must Update:**
- (none)

**Check If Affected:**
- `taskplane-tasks/codegen/CONTEXT.md` — update key files if needed

## Completion Criteria

- [ ] `ImplementorSource` and `ImplementationSource` parse all model attributes
- [ ] `IRImplementation` available on `IRProject`
- [ ] Foundation has 53 implementations across 13 implementors
- [ ] Interface bindings with constant overrides are correctly parsed
- [ ] Common has 0 implementors
- [ ] All tests passing, build gate passes

## Git Commit Convention

- **Step completion:** `feat(CG-032): complete Step N — description`
- **Tests:** `test(CG-032): description`
- **Hydration:** `hydrate: CG-032 expand Step N checkboxes`

## Do NOT

- Expand task scope
- Skip tests
- Modify `project_c_backend.py` — rendering is for downstream tasks
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
