# CG-008: Common Project Graph to IR — Status

**Current Step:** Not Started
**Status:** 🔵 Ready for Execution
**Last Updated:** 2026-04-04
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 0
**Size:** M

---

### Step 0: Preflight
**Status:** ⬜ Not Started

- [ ] Read the ADR and inspect the current IR shape
- [ ] Identify which project-derived metadata is still missing or implicit

---

### Step 1: Define or refine the normalized IR
**Status:** ⬜ Not Started

- [ ] Ensure the IR can represent project, modules, classes, enums, methods, constants, and output metadata needed by the C backend
- [ ] Prefer explicit structured fields over module-specific ad hoc conventions

---

### Step 2: Implement graph-to-IR lowering
**Status:** ⬜ Not Started

- [ ] Lower the project-rooted graph into the normalized IR
- [ ] Preserve enough detail to drive naming/file decisions from model metadata
- [ ] Add or update tests for the IR construction path

---

### Step 3: Verification
**Status:** ⬜ Not Started

- [ ] Run IR tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`

---

### Step 4: Delivery
**Status:** ⬜ Not Started

- [ ] Update docs describing the IR and what it now guarantees to backends

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
| 2026-04-04 | Task staged | PROMPT.md and STATUS.md created |

---

## Blockers

*None*

---

## Notes

This task establishes the model-driven IR layer for the next backend step.
