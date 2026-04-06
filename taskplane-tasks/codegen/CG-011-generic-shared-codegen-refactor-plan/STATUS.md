# CG-011: Generic Shared-Codegen Refactor Plan — Status

**Current Step:** Not Started
**Status:** 🔵 Ready for Execution
**Last Updated:** 2026-04-05
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 0
**Size:** S

---

### Step 0: Preflight
**Status:** ⬜ Not Started

- [ ] Read the ADRs and current next-phase plan
- [ ] Inspect the current `common_*` module boundaries

---

### Step 1: Identify refactor boundaries
**Status:** ⬜ Not Started

- [ ] Classify what belongs in shared project graph loading, shared IR/output-targets, and shared C backend code
- [ ] Identify what can remain as thin compatibility adapters during migration
- [ ] Identify import/script/doc changes required by the rename/refactor

---

### Step 2: Document the plan
**Status:** ⬜ Not Started

- [ ] Write a concise refactor plan with a recommended sequence
- [ ] Explicitly preserve the rule that shared functionality should not branch on specific module names where metadata already expresses the distinction

---

### Step 3: Delivery
**Status:** ⬜ Not Started

- [ ] Recommend the first extraction step after the planning task

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
