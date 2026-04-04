# CG-001: Buffer Family Migration Spec — Status

**Current Step:** Not Started
**Status:** 🔵 Ready for Execution
**Last Updated:** 2026-04-04
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 0
**Size:** S

---

### Step 0: Preflight
**Status:** ⬜ Not Started

- [ ] Read the task-area context and current migration docs
- [ ] Inspect current fallback handling for buffer-related files in `tools/codegen/common_bootstrap.py`

---

### Step 1: Analyze remaining buffer-family surface
**Status:** ⬜ Not Started

- [ ] Compare original source models and resolved XML inputs for `buffer` and `buffer_defs`
- [ ] Identify which generated pieces are direct-lowering candidates versus thin support/aggregation artifacts
- [ ] Record any special preservation or formatting constraints that are likely to matter

---

### Step 2: Document the execution plan
**Status:** ⬜ Not Started

- [ ] Add or update docs under `docs/codegen-migration/` describing the remaining migration map
- [ ] Explicitly sequence `buffer_defs`, `buffer`, and any support-header follow-up
- [ ] Call out expected verification commands and no-commit constraints for generated `library/common/**` files

---

### Step 3: Verification
**Status:** ⬜ Not Started

- [ ] Re-read the updated docs to ensure they are internally consistent with the current codebase

---

### Step 4: Delivery
**Status:** ⬜ Not Started

- [ ] Summarize recommended next implementation order and notable risks in the task output

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

This task prepares the final `common` migration slice so implementation tasks can run with lower ambiguity.
