# Task: CG-027 - Parse Class Dependencies into Source and IR

**Created:** 2026-04-08
**Size:** S

## Review Level: 1 (Plan Only)

**Assessment:** Focused data-model addition to existing loader and IR. Low blast radius, follows established patterns from properties/methods parsing.
**Score:** 2/8 — Blast radius: 1, Pattern novelty: 0, Security: 0, Reversibility: 1

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-027-parse-class-dependencies/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Add parsing of `<dependency>` elements from class XML models into the source loader (`project_source.py`) and IR (`project_ir.py`). Currently, class-level dependencies are ignored by `load_class_source()`, which means the C backend cannot generate dependency-aware lifecycle methods (cleanup with release calls, use/take/release methods). This task closes that gap by making dependency metadata available in the IR for downstream code generation.

The legacy GSL pipeline reads these `<dependency>` elements to generate lifecycle methods and dependency management methods. The new Python pipeline must have the same information available.

## Dependencies

- **None**

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3 (load only if needed):**
- `docs/adr/0004-universal-model-driven-codegen.md` — motivation for this work
- `codegen/c_dependency.gsl` — legacy GSL dependency handling (reference for what attributes matter)
- `codegen/c_module_class.gsl` lines 240-320 — how cleanup iterates dependencies

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** None

## File Scope

- `tools/codegen/project_source.py`
- `tools/codegen/project_ir.py`
- `tools/codegen/test_auto_discovery.py`
- `codegen/models/project_common/class_buffer.xml` (read-only reference, 0 dependencies)
- `codegen/models/project_foundation/class_ecies.xml` (read-only reference, has dependencies)

## Steps

### Step 0: Preflight

- [ ] Required files exist: `tools/codegen/project_source.py`, `tools/codegen/project_ir.py`
- [ ] Understand current `ClassSource` and `IRClass` structures
- [ ] Study `<dependency>` elements in foundation class models to catalog all used attributes

### Step 1: Add DependencySource to project_source.py

Add a `DependencySource` dataclass and parse `<dependency>` elements in `load_class_source()`.

Key attributes to capture from the XML models (cross-reference with `codegen/c_dependency.gsl`):
- `name` — dependency name (e.g., "random", "cipher")
- `interface` — interface type (e.g., "random", "cipher", "mac")
- `class` — class type (alternative to interface)
- `impl` — impl type (alternative to interface/class)
- `access` — access level
- `has_observers` — whether the dependency triggers observer callbacks
- `is_observers_return_status` — whether observer returns status

Add a `dependencies: list[DependencySource]` field to `ClassSource`.

- [ ] Create `DependencySource` dataclass with all relevant attributes
- [ ] Parse `<dependency>` elements in `load_class_source()`
- [ ] Add `dependencies` field to `ClassSource`
- [ ] Run targeted test: `python3 -c "from tools.codegen.project_source import load_class_source; ..."`

**Artifacts:**
- `tools/codegen/project_source.py` (modified)

### Step 2: Add IRDependency to project_ir.py and map from source

Add an `IRDependency` dataclass and include dependencies in `IRClass`. Update the IR mapping to convert `DependencySource` → `IRDependency`.

Key IR fields:
- `name` — dependency name
- `type_kind` — "interface", "class", or "impl" (derived from which attribute is set)
- `type_name` — the interface/class/impl name
- `has_observers` — boolean
- `is_observers_return_status` — boolean

- [ ] Create `IRDependency` dataclass
- [ ] Add `dependencies: list[IRDependency]` field to `IRClass`
- [ ] Update IR mapping from source to IR (in the function that builds `IRClass` from `ClassSource`)
- [ ] Verify: load foundation `ecies` class and confirm dependencies are in IR

**Artifacts:**
- `tools/codegen/project_ir.py` (modified)

### Step 3: Add test coverage

- [ ] Add test that loads `project_foundation.xml`, finds `ecies` class, and asserts it has the expected dependencies (random, cipher, mac, kdf, ephemeral key)
- [ ] Add test that loads `project_common.xml`, finds `buffer` class, and asserts it has zero dependencies
- [ ] Verify a dependency with `has_observers` is correctly parsed (check foundation models for examples)

**Artifacts:**
- `tools/codegen/test_auto_discovery.py` (modified) or new test file

### Step 4: Testing & Verification

> ZERO test failures allowed. This step runs the FULL test suite as a quality gate.

- [ ] Run FULL test suite: `python3 -m pytest tools/codegen/ -v` (if pytest available) or verify imports compile: `python3 -m py_compile tools/codegen/project_source.py tools/codegen/project_ir.py`
- [ ] Build passes: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Fix all failures

### Step 5: Documentation & Delivery

- [ ] Update CONTEXT.md if needed
- [ ] Discoveries logged in STATUS.md

## Documentation Requirements

**Must Update:**
- (none — IR/source internals, no external doc changes needed)

**Check If Affected:**
- `taskplane-tasks/codegen/CONTEXT.md` — update key files table if new test file created

## Completion Criteria

- [ ] `DependencySource` parses all `<dependency>` attributes from class XML models
- [ ] `IRDependency` is available on `IRClass` in the IR
- [ ] Foundation class with dependencies (e.g., ecies) has correct dependency list in IR
- [ ] Common class without dependencies (e.g., buffer) has empty dependency list
- [ ] All tests passing, build gate passes

## Git Commit Convention

- **Step completion:** `feat(CG-027): complete Step N — description`
- **Tests:** `test(CG-027): description`
- **Hydration:** `hydrate: CG-027 expand Step N checkboxes`

## Do NOT

- Expand task scope — add tech debt to CONTEXT.md instead
- Skip tests
- Modify framework/standards docs without explicit user approval
- Load docs not listed in "Context to Read First"
- Commit without the task ID prefix in the commit message
- Modify `project_c_backend.py` — that is for downstream tasks
- Generate any C code — this task is source/IR only

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
