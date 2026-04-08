# Task: CG-031 - Parse Interfaces into Source and IR

**Created:** 2026-04-08
**Size:** S

## Review Level: 1 (Plan Only)

**Assessment:** Focused data-model addition following established patterns from class/enum parsing. Low blast radius, adapts existing patterns.
**Score:** 2/8 — Blast radius: 1, Pattern novelty: 0, Security: 0, Reversibility: 1

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-031-parse-interfaces/
├── PROMPT.md   ← This file
├── STATUS.md   ← Execution state
├── .reviews/   ← Reviewer output
└── .DONE       ← Created when complete
```

## Mission

Add parsing of `<interface>` elements from project XML and interface model files into the source loader (`project_source.py`) and IR (`project_ir.py`). Currently, `load_project_source()` reads `<module>`, `<class>`, and `<enum>` refs but completely skips `<interface>` elements. This task closes that gap so downstream rendering tasks can generate interface C modules.

An interface model contains:
- Methods (with arguments, returns) — the interface contract
- Constants (with name, type) — associated constants like digest lengths
- Inheritance (`<inherit interface="..."/>`) — interface extension
- Description text

Reference model files: `codegen/models/project_foundation/interface_hash.xml`, `interface_cipher.xml`, `interface_random.xml`.

## Dependencies

- **None**

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3 (load only if needed):**
- `codegen/models/project_foundation/interface_hash.xml` — simple interface example
- `codegen/models/project_foundation/interface_cipher.xml` — interface with inheritance
- `codegen/c_module_interface.gsl` — legacy GSL interface handling (reference for what attributes matter)

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** None

## File Scope

- `tools/codegen/project_source.py`
- `tools/codegen/project_ir.py`
- `tools/codegen/test_interface_parsing.py` (new)

## Steps

### Step 0: Preflight

- [ ] Required files exist: `tools/codegen/project_source.py`, `tools/codegen/project_ir.py`
- [ ] Study interface model XML files to catalog all used elements and attributes
- [ ] Study `codegen/interface.gsl` to understand interface resolution

### Step 1: Add InterfaceSource to project_source.py

Add an `InterfaceSource` dataclass and a `load_interface_source()` function. Update `load_project_source()` to parse `<interface>` refs from the project XML and load each interface model.

Key elements to capture from interface XML:
- `name` — interface name
- Description text
- `<method>` elements — reuse existing `MethodSource` / `_method_like()` parser
- `<constant>` elements — name, type, and optional value
- `<inherit interface="..."/>` elements — list of inherited interface names

Add `interface_refs` and `interfaces` fields to `ProjectSource`.

- [ ] Create `InterfaceSource` dataclass (name, description, methods, constants, inherits)
- [ ] Create `load_interface_source()` function
- [ ] Update `load_project_source()` to read `<interface>` refs and load models
- [ ] Add `interface_refs` and `interfaces` to `ProjectSource`

**Artifacts:**
- `tools/codegen/project_source.py` (modified)

### Step 2: Add IRInterface to project_ir.py

Add an `IRInterface` dataclass and map from `InterfaceSource`. Update `project_to_ir()` to include interfaces in the IR.

Key IR fields:
- `name` — interface name
- `description` — description text
- `methods: list[IRCMethod]` — interface methods (reuse existing IR method type)
- `constants: list[IRCConstant]` — interface constants
- `inherits: list[str]` — names of inherited interfaces
- `output: IROutputTarget` — output file paths
- `attrs: dict[str, str]` — raw attributes

- [ ] Create `IRInterface` dataclass
- [ ] Add `interfaces: list[IRInterface]` to `IRProject`
- [ ] Map `InterfaceSource` → `IRInterface` in `project_to_ir()`
- [ ] Compute `IROutputTarget` for interfaces (follow same pattern as classes/enums)

**Artifacts:**
- `tools/codegen/project_ir.py` (modified)

### Step 3: Add test coverage

Create `test_interface_parsing.py` with tests covering:

- [ ] Foundation project has expected number of interfaces (33+ from project XML)
- [ ] `interface_hash` has correct methods (hash, start, update, finish) and constants (digest_len, block_len)
- [ ] `interface_cipher` has inheritance from encrypt, decrypt, cipher_info
- [ ] `interface_random` has correct methods (random, reseed)
- [ ] Common project has zero interfaces
- [ ] IRInterface has correct output target paths
- [ ] Interface methods have correct arguments and return types

**Artifacts:**
- `tools/codegen/test_interface_parsing.py` (new)

### Step 4: Testing & Verification

> ZERO test failures allowed.

- [ ] Run: `python3 -m pytest tools/codegen/test_interface_parsing.py -v`
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

- [ ] `InterfaceSource` parses all interface model attributes
- [ ] `IRInterface` available on `IRProject` in the IR
- [ ] Foundation has 33+ interfaces in IR with correct methods/constants/inheritance
- [ ] Common has 0 interfaces
- [ ] All tests passing, build gate passes

## Git Commit Convention

- **Step completion:** `feat(CG-031): complete Step N — description`
- **Tests:** `test(CG-031): description`
- **Hydration:** `hydrate: CG-031 expand Step N checkboxes`

## Do NOT

- Expand task scope — add tech debt to CONTEXT.md instead
- Skip tests
- Modify `project_c_backend.py` — rendering is for downstream tasks
- Parse implementors — that is CG-032
- Commit without the task ID prefix

---

## Amendments (Added During Execution)
