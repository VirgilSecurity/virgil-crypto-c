# CG-039: Fix Common Project Codegen Parity Issues — Status

**Current Step:** Step 1: Fix backend rendering issues
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-09
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Full verify diff captured
- [x] Each diff mapped to issue list
- [x] Responsible functions identified

---

### Step 1: Fix backend rendering issues
**Status:** ⬜ Not Started

- [ ] Method ordering fixed (constructors before delete/destroy/shallow_copy)
- [ ] Destroy description uses full function name
- [ ] init_ctx/cleanup_ctx descriptions use full names
- [ ] Hardcoded VSC_PUBLIC/VSC_NORETURN replaced with project-prefixed
- [ ] Committed

---

### Step 2: Fix C emitter rendering issues
**Status:** ⬜ Not Started

> ⚠️ Hydrate: Expand based on exact code locations identified in Step 0

- [ ] Placeholder resolution in descriptions
- [ ] Macro name-paren spacing
- [ ] Constant name casing
- [ ] Byte typedef guard
- [ ] Struct typedef pattern
- [ ] Trailing blank lines
- [ ] Committed

---

### Step 3: Testing & Verification
**Status:** ⬜ Not Started

- [ ] --verify common shows 0 non-generated warnings
- [ ] All Python tests pass
- [ ] Build gate passes

---

### Step 4: Documentation & Delivery
**Status:** ⬜ Not Started

- [ ] Discoveries logged
- [ ] CONTEXT.md updated if needed

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
| 2026-04-08 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-09 01:53 | Task started | Runtime V2 lane-runner execution |
| 2026-04-09 01:53 | Step 0 started | Preflight |

---

## Blockers

*None*

---

## Notes

*Reserved for execution notes*
