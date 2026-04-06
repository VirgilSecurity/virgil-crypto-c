# CG-012: Shared Project Graph Loader for Common + Foundation — Status

**Current Step:** Not Started
**Status:** 🔵 Ready for Execution
**Last Updated:** 2026-04-05
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 0
**Size:** M

---

### Step 0: Preflight
**Status:** ⬜ Not Started

- [ ] Read the ADR and `foundation` inventory output
- [ ] Identify remaining `common`-specific assumptions in the current loader path

---

### Step 1: Generalize project-rooted loading
**Status:** ⬜ Not Started

- [ ] Support both `project_common.xml` and `project_foundation.xml` through the same loader architecture
- [ ] Keep top-level project metadata model-driven
- [ ] Preserve tolerant parsing behavior for legacy XML-like content

---

### Step 2: Add shared tests
**Status:** ⬜ Not Started

- [ ] Add tests proving the loader works for both project roots
- [ ] Avoid duplicating project-specific logic where shared structure is sufficient

---

### Step 3: Verification
**Status:** ⬜ Not Started

- [ ] Run loader tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`

---

### Step 4: Delivery
**Status:** ⬜ Not Started

- [ ] Document what is now universal in the loader and what remains project-specific only at the model-data level

---

## Reviews

| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

---

## Discoveries

| Discovery | Disposition | Location |
|-----------|-------------|----------|

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-05 | Task staged | PROMPT.md and STATUS.md created |

---

## Blockers

*None*
