# CG-015: Rename and Adapt Generic Modules, Imports, and Docs — Status

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

- [ ] Review extracted shared-module outputs from predecessor tasks
- [ ] Confirm which legacy `common_*` names should remain as temporary adapters, if any

---

### Step 1: Update callers and names
**Status:** ⬜ Not Started

- [ ] Update imports/scripts/tests/docs to prefer the new generic module names
- [ ] Reduce legacy `common_*` modules to thin compatibility adapters or remove them where safe
- [ ] Keep current `common` workflows working

---

### Step 2: Verification
**Status:** ⬜ Not Started

- [ ] Run relevant tests
- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`
- [ ] Run `bash tools/codegen/build_common_with_new_codegen.sh`

---

### Step 3: Delivery
**Status:** ⬜ Not Started

- [ ] Update docs to state the new shared module names and compatibility policy

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
