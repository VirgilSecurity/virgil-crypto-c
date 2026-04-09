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
**Status:** 🟨 In Progress

- [x] Method ordering fixed (constructors before delete/destroy/shallow_copy)
- [x] Destroy description uses full function name
- [x] init_ctx/cleanup_ctx descriptions use full names
- [x] Hardcoded VSC_PUBLIC/VSC_NORETURN replaced with project-prefixed
- [x] Placeholder resolution in method descriptions (issue 1)
- [x] Escape normalization: `\\n`→`\n`, continuation line joining (vsc_assert.c issues)
- [x] Constant name casing: use mixed case `vsc_POINTER_SIZE` not all-upper (issue 3)
- [x] Macro name-paren spacing: collapse space after placeholder in `#define` (issue 2)
- [x] Committed

---

### Step 2: Fix C emitter rendering issues
**Status:** 🟨 In Progress

> ⚠️ Hydrate: Expand based on exact code locations identified in Step 0

- [x] Placeholder resolution in descriptions (done in Step 1)
- [x] Macro name-paren spacing (done in Step 1)
- [x] Constant name casing (done in Step 1)
- [x] Byte typedef guard (render_alias → emit BYTE_DEFINED guard)
- [x] Struct typedef pattern (render_struct_full → two-line pattern)
- [x] Trailing blank lines (generate_block → preserve 2 trailing blanks)
- [x] Macro continuation alignment (render_c_code → column-align backslashes)
- [x] Extra whitespace normalization in code text (VSC_PUBLIC/ATOMIC spacing)
- [x] BSD license text whitespace in vsc_memory.c
- [x] Committed

---

### Step 3: Testing & Verification
**Status:** 🟨 In Progress

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
