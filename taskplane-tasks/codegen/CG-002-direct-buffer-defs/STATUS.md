# CG-002: Direct Lowering for vsc_buffer_defs — Status

**Current Step:** Step 1: Implement direct lowering
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-04
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Read the task-area context, current direct-coverage status docs, and the `CG-001` plan
- [x] Inspect the current fallback path for `vsc_buffer_defs`

---

### Step 1: Implement direct lowering
**Status:** 🟨 In Progress

- [ ] Add direct-lowering support for `vsc_buffer_defs` in `tools/codegen/common_direct_c.py`
- [ ] Keep the implementation aligned with original-model-as-source-of-truth constraints
- [ ] Avoid introducing a dependency on resolved XML as runtime input for this module

---

### Step 2: Wire into bootstrap generation
**Status:** ⬜ Not Started

- [ ] Update `tools/codegen/common_bootstrap.py` to route `vsc_buffer_defs` through the new direct path
- [ ] Preserve existing mixed-mode behavior for any still-unmigrated `common` outputs

---

### Step 3: Verify build safety
**Status:** ⬜ Not Started

- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`
- [ ] Run `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Confirm no generated `library/common/**` artifacts remain staged for commit

---

### Step 4: Documentation and delivery
**Status:** ⬜ Not Started

- [ ] Update migration docs to reflect direct coverage for `vsc_buffer_defs`
- [ ] Summarize any parity gaps, shortcuts, or follow-up risks for `vsc_buffer`

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
| 2026-04-04 20:36 | Task started | Runtime V2 lane-runner execution |
| 2026-04-04 20:36 | Step 0 started | Preflight |
| 2026-04-04 20:43 | Step 0 completed | Preflight context and fallback path inspected |
| 2026-04-04 20:43 | Step 1 started | Implement direct lowering |

---

## Blockers

*None*

---

## Notes

This task is the first implementation slice in the remaining buffer-family migration.
