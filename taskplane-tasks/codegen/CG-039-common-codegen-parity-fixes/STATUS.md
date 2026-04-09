# CG-039: Fix Common Project Codegen Parity Issues — Status

**Current Step:** Step 4: Documentation & Delivery
**Status:** ✅ Complete
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
**Status:** ✅ Complete

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
**Status:** ✅ Complete

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
**Status:** ✅ Complete

- [x] --verify common shows 0 non-generated warnings
- [x] All Python tests pass (159 tests OK)
- [x] Build gate passes (common built + verify 0 diffs)

---

### Step 4: Documentation & Delivery
**Status:** ✅ Complete

- [x] Discoveries logged
- [x] CONTEXT.md updated if needed

---

## Reviews

| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

---

## Discoveries

| Discovery | Disposition | Location |
|-----------|-------------|----------|
| XML models use double-backslash escaping (\\\\n for \\n, \\\\0 for \\0). New _normalize_c_escapes handles general de-escaping. | Fixed | project_c_backend.py:_normalize_c_escapes |
| Method code blocks in XML have backslash-continuation lines that GSL joined. New _join_continuation_lines handles this. | Fixed | project_c_backend.py:_join_continuation_lines |
| XML model code text has extra whitespace (double spaces) that GSL normalized. Fixed with _normalize_code_whitespace for method code and _fix_macro_paren_spacing for macros. | Fixed | project_c_backend.py |
| Macro continuation backslashes need column-alignment to match legacy. render_c_code now pads to max content width. | Fixed | common_bootstrap.py:render_c_code |
| Multi-line macros with internal continuation (wrapped function calls) need line joining in _prepare_macro_code. | Fixed | project_c_backend.py:_prepare_macro_code |
| verify script awk filter for outside-generated changes is unreliable when @generated markers are unchanged (appear as context, not diff lines). Zero-diff gate is the true verification. | Noted | tools/codegen/new_codegen.sh |

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
