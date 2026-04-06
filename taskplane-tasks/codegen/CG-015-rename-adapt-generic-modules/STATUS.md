# CG-015: Rename and Adapt Generic Modules, Imports, and Docs — Status

**Current Step:** Step 1: Update callers and names
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-06
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 2
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Review extracted shared-module outputs from predecessor tasks
- [x] Confirm which legacy `common_*` names should remain as temporary adapters, if any

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
| 2026-04-06 14:54 | Task started | Runtime V2 lane-runner execution |
| 2026-04-06 14:54 | Step 0 started | Preflight |
| 2026-04-06 15:10 | Step 0 review | Reviewed CG-012 through CG-014 outputs plus shared/adapter module boundaries; confirmed `project_source.py`, `project_ir.py`, and `project_c_backend.py` now own the shared loader/IR/backend responsibilities |
| 2026-04-06 15:12 | Worker iter 1 | done in 1067s, tools: 24 |
| 2026-04-06 15:24 | Step 0 adapter boundary | Confirmed `common_source.py`, `common_ir.py`, and `common_direct_c.py` should remain temporary thin `common` compatibility adapters, while `common_bootstrap.py` remains the current `common` CLI/workflow entrypoint |

---

## Blockers

*None*
