# CG-004: Direct Lowering for vsc_buffer — Status

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

- [ ] Read the task-area context and all predecessor-task outputs
- [ ] Inspect current fallback routing and generated-block behavior for `vsc_buffer`

---

### Step 1: Implement direct lowering
**Status:** ⬜ Not Started

- [ ] Add direct-lowering support for `vsc_buffer` in `tools/codegen/common_direct_c.py`
- [ ] Preserve compatibility with the current generated-block rewriting approach
- [ ] Keep original source models as the source of truth and avoid runtime dependency on resolved XML for this module

---

### Step 2: Wire into bootstrap generation
**Status:** ⬜ Not Started

- [ ] Update `tools/codegen/common_bootstrap.py` to use the direct path for `vsc_buffer`
- [ ] Keep any still-legitimate fallback behavior explicit and narrow

---

### Step 3: Verification and iteration
**Status:** ⬜ Not Started

- [ ] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`
- [ ] Run `bash tools/codegen/build_common_with_new_codegen.sh`
- [ ] Fix compile/parity issues until the `common` target succeeds again
- [ ] Confirm no generated `library/common/**` artifacts remain staged for commit

---

### Step 4: Documentation and delivery
**Status:** ⬜ Not Started

- [ ] Update migration docs and coverage status notes for `vsc_buffer`
- [ ] Record any remaining gaps, especially around support headers or intentionally retained fallback paths

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

This is the largest remaining `common` direct-lowering task.
