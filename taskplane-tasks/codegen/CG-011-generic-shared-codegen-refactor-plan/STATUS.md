# CG-011: Generic Shared-Codegen Refactor Plan — Status

**Current Step:** Step 3: Delivery
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-06
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** S

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Read the ADRs and current next-phase plan
- [x] Inspect the current `common_*` module boundaries

---

### Step 1: Identify refactor boundaries
**Status:** ✅ Complete

- [x] Classify what belongs in shared project graph loading, shared IR/output-targets, and shared C backend code
- [x] Identify what can remain as thin compatibility adapters during migration
- [x] Identify import/script/doc changes required by the rename/refactor

---

### Step 2: Document the plan
**Status:** ✅ Complete

- [x] Write a concise refactor plan with a recommended sequence
- [x] Explicitly preserve the rule that shared functionality should not branch on specific module names where metadata already expresses the distinction

---

### Step 3: Delivery
**Status:** 🟨 In Progress

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
| 2026-04-06 12:50 | Task started | Runtime V2 lane-runner execution |
| 2026-04-06 12:50 | Step 0 started | Preflight |

---

## Blockers

*None*
