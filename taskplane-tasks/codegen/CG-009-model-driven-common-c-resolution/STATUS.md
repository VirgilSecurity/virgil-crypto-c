# CG-009: Model-Driven Common C Resolution — Status

**Current Step:** Not Started
**Status:** 🔵 Ready for Execution
**Last Updated:** 2026-04-04
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 0
**Size:** L

---

### Step 0: Preflight
**Status:** ⬜ Not Started

- [ ] Read the ADR and predecessor task outputs
- [ ] Identify project-specific metadata that is still hardcoded in the current C lowering layer

---

### Step 1: Implement model-driven C resolution
**Status:** ⬜ Not Started

- [ ] Derive names, output files, prefixes, and related metadata from the resolved project graph / IR
- [ ] Replace project-specific hardcodes where the model already defines the information
- [ ] Keep only genuinely static backend/runtime support logic as reusable backend code

---

### Step 2: Preserve current C-generation contract
**Status:** ⬜ Not Started

- [ ] Keep handwritten-code preservation behavior intact
- [ ] Preserve the working `common` build path and generated-block application flow
- [ ] Add or update tests that protect the no-hardcoded-project-metadata rule

---

### Step 3: Verification
**Status:** ⬜ Not Started

- [ ] Run the new/updated tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`
- [ ] Run `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Confirm no generated `library/common/**` artifacts remain staged for commit

---

### Step 4: Delivery
**Status:** ⬜ Not Started

- [ ] Update architecture/migration docs to explain what hardcodes were removed and what static backend logic remains acceptable

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

This task is the core refactor from mixed-mode hardcoded C lowering to a model-driven C backend.
