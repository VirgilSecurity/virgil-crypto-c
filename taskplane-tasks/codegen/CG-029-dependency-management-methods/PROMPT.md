# Task: CG-029 - Generate Dependency Management Methods from Class IR

**Created:** 2026-04-08
**Size:** M

## Review Level: 2 (Plan and Code)

**Assessment:** Adds a new category of generated methods (use/take/release) that don't exist in the current Python codegen at all. Must match GSL output for all foundation classes with dependencies. Touches the shared C backend's class rendering.
**Score:** 4/8 — Blast radius: 2, Pattern novelty: 1, Security: 0, Reversibility: 1

## Canonical Task Folder

```
taskplane-tasks/codegen/CG-029-dependency-management-methods/
├── PROMPT.md   ← This file (immutable above --- divider)
├── STATUS.md   ← Execution state (worker updates this)
├── .reviews/   ← Reviewer output (created by the orchestrator runtime)
└── .DONE       ← Created when complete
```

## Mission

Generate dependency management methods (`use_X`, `take_X`, `release_X`) and observer hooks (`did_setup_X`, `did_release_X`) for each class dependency, driven by the class IR. Currently the Python codegen pipeline produces no dependency management methods — only the legacy GSL pipeline generates them. This task adds that capability to the shared C backend.

For each dependency on a class, the GSL pipeline generates:
- **use_X** — set the dependency (borrowed reference, no ownership transfer)
- **take_X** — set the dependency (ownership transfer) — only for interface/class/impl dependencies
- **release_X** — release the dependency (null out or destroy)
- **did_setup_X** (optional, if `has_observers`) — stub observer hook called after setup
- **did_release_X** (optional, if `has_observers`) — stub observer hook called after release

The reference implementation is in `codegen/c_dependency.gsl` (functions `c_dependency_add_method_use`, `c_dependency_add_method_take`, `c_dependency_add_method_release`, `c_dependency_add_method_did_setup`, `c_dependency_add_method_did_release`).

Also, dependency properties must be added to the class struct — each dependency becomes a pointer field in the struct.

## Dependencies

- **Task:** CG-028 (lifecycle body generation must be in place; this task adds to the same rendering function)

## Context to Read First

**Tier 2 (area context):**
- `taskplane-tasks/codegen/CONTEXT.md`

**Tier 3 (load only if needed):**
- `codegen/c_dependency.gsl` — full legacy GSL dependency method generation (the specification)
- `codegen/generated/foundation/c_module_vscf_ecies.xml` — resolved XML reference showing use/take/release methods
- `codegen/models/project_foundation/class_ecies.xml` — source model with dependencies

## Environment

- **Workspace:** `tools/codegen/`
- **Services required:** None

## File Scope

- `tools/codegen/project_c_backend.py`
- `tools/codegen/test_auto_discovery.py`

## Steps

### Step 0: Preflight

- [ ] CG-028 is complete: lifecycle bodies are generated from IR
- [ ] Study `codegen/c_dependency.gsl` methods: use (line 137), take (line 222), release (line 302)
- [ ] Study resolved XML for ecies to see expected method signatures and bodies
- [ ] Understand how dependency struct fields appear in the resolved XML

### Step 1: Generate dependency struct fields

Each dependency becomes a pointer property in the class struct. For interface dependencies, the field type is the interface impl type. Study the resolved XML to determine the exact field naming and type patterns.

- [ ] Add dependency struct field rendering to `render_class_c_module()` or `_render_reference_class_support()`
- [ ] Fields use the naming convention: `{prefix}_{class}_{dependency_name}` (e.g., `vscf_ecies_random`)
- [ ] Verify: foundation ecies struct has correct dependency fields in generated XML

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 2: Generate use/take/release methods

For each dependency on a class, generate:
- `use_X(self, X)` — set the dependency pointer (borrowed)
- `take_X(self, X)` — set the dependency pointer (ownership transfer) — only for interface/class/impl types
- `release_X(self)` — release the dependency

Each method body follows the patterns in `c_dependency.gsl`. The `use` method asserts ptr, checks for null dependency property, sets it, and calls did_setup if observers. The `take` method is similar but calls shallow_copy. The `release` method calls the appropriate destroy/null and did_release if observers.

- [ ] Implement `use_X` method body generation and rendering
- [ ] Implement `take_X` method body generation and rendering
- [ ] Implement `release_X` method body generation and rendering
- [ ] Verify: ecies XML output has correct use/take/release methods for all 5 dependencies

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 3: Generate observer hook stubs

For dependencies with `has_observers=true`, generate stub methods:
- `did_setup_X(self)` — private stub
- `did_release_X(self)` — private stub

These are definition="private" declaration="private" methods with stub bodies (`// TODO: This is STUB. Implement me.`).

- [ ] Implement observer hook generation (conditional on `has_observers`)
- [ ] Verify against resolved XML for classes with observer dependencies
- [ ] Run targeted tests

**Artifacts:**
- `tools/codegen/project_c_backend.py` (modified)

### Step 4: Testing & Verification

> ZERO test failures allowed.

- [ ] Run FULL test suite: `python3 -m py_compile tools/codegen/project_source.py tools/codegen/project_ir.py tools/codegen/project_c_backend.py tools/codegen/common_bootstrap.py`
- [ ] Build passes: `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Verify ecies dependency methods in generated XML match resolved XML reference
- [ ] Verify buffer (no dependencies) still generates correctly — no dependency methods added
- [ ] Fix all failures

### Step 5: Documentation & Delivery

- [ ] Discoveries logged in STATUS.md
- [ ] Update CONTEXT.md if needed

## Documentation Requirements

**Must Update:**
- (none — internal codegen changes)

**Check If Affected:**
- `taskplane-tasks/codegen/CONTEXT.md` — update if needed

## Completion Criteria

- [ ] use/take/release methods generated for all class dependencies
- [ ] Observer hooks generated for dependencies with has_observers
- [ ] Dependency struct fields added to class struct
- [ ] Buffer (no deps) unaffected
- [ ] Foundation class (ecies) dependency methods match resolved XML reference
- [ ] Build gate passes

## Git Commit Convention

- **Step completion:** `feat(CG-029): complete Step N — description`
- **Tests:** `test(CG-029): description`
- **Hydration:** `hydrate: CG-029 expand Step N checkboxes`

## Do NOT

- Expand task scope — add tech debt to CONTEXT.md instead
- Skip tests
- Modify framework/standards docs without explicit user approval
- Load docs not listed in "Context to Read First"
- Commit without the task ID prefix in the commit message
- Remove cfrag files — that is for CG-030
- Modify `project_source.py` or `project_ir.py` — those were handled by CG-027

---

## Amendments (Added During Execution)

<!-- Workers add amendments here if issues discovered during execution. -->
