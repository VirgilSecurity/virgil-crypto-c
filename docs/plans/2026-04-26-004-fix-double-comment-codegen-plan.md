---
title: "Fix double-comment // // in generated C files"
date: 2026-04-26
status: active
type: bug
component: codegen
---

# Fix double-comment `//  //` in generated C files

## Problem

All generated `*_private.c` and `*_impl.c` files contain section headers like:

```c
//  @description
// --------------------------------------------------------------------------
//  //
//  //  This module contains 'ml kem' implementation.
//  //
// --------------------------------------------------------------------------
```

The `//  //` lines are wrong — `//` is correct.

## Root Cause

Two-layer rendering applied to the same description text:

1. **`comment_text()` in `tools/codegen/project_c_backend.py` (line 6739–6742)**
   Encodes the description into XML IR text nodes using `//` as the block delimiters:
   ```
   //
   //  This module contains 'ml kem' implementation.
   //
   ```

2. **`c_format_description()` in `codegen/c_formatter.gsl` (line 254–264)**
   The GSL template then prefixes every line of that text with `//  ` (line 260):
   ```gsl
   my.str = "//  $(my.str:left, block, no)$(terminator)"
   ```
   This turns `//` → `//  //` and `//  text` → `//  //  text`.

The mismatch: `comment_text()` was written assuming the Python renderer would emit the text as raw C. The GSL renderer adds its own `//  ` prefix on top.

## Fix Options

### Option A — Fix `comment_text()` (Python side)
Change `comment_text()` to emit plain text without `//` delimiters. The GSL layer supplies them:

```python
def comment_text(desc: str) -> str:
    desc = desc.strip()
    if not desc:
        return ""
    return desc  # let c_format_description wrap it
```

**Risk**: `comment_text()` is also used outside GSL-rendered contexts (e.g., in Python-only renderers that write C directly). Need to audit all 20+ call sites.

### Option B — Fix `c_format_description()` (GSL side)
Strip leading `//` from each line before adding the `//  ` prefix:

```gsl
function c_format_description (str)
    # strip any existing // prefix before re-wrapping
    my.str = regexp.replace(my.str, "^//  ?", "")
    ...
endfunction
```

**Risk**: GSL regex support is limited; this may be fragile across GSL versions.

### Option C — Fix at the generated-file level via `--apply` post-processing (recommended)
Add a post-processing step in `new_codegen.sh` (or `common_bootstrap.py`) that rewrites `//  //` → `//` in generated C files immediately after codegen writes them. This is a safe, targeted fix that doesn't require understanding all call sites.

```python
import re
content = re.sub(r'^//  //', '//', content, flags=re.MULTILINE)
```

**Risk**: Lowest — it's a targeted string substitution applied only to generated output files before they're written to disk. Easy to verify, easy to revert.

## Recommended Approach

Option C as an immediate fix (zero risk of regression), followed by Option A once all `comment_text()` call sites are audited.

## Files to Change

### Option C (post-processing):
- `tools/codegen/common_bootstrap.py` — add post-processing to the file-write path
  OR
- `tools/codegen/new_codegen.sh` — pipe output through `sed 's|^//  //|//|g'` after generation

### Option A (proper fix):
- `tools/codegen/project_c_backend.py:6735–6742` — `comment_text()` function
- Audit all call sites: `grep -n "comment_text(" tools/codegen/project_c_backend.py`

### Option B (GSL fix):
- `codegen/c_formatter.gsl:254–264` — `c_format_description()` function

## Verification

After fix, run:
```bash
bash tools/codegen/new_codegen.sh --apply foundation
grep -rn "//  //" library/foundation/src/ library/foundation/include/
```

Should return no results. Also verify existing non-ML-KEM/ML-DSA files (e.g., `vscf_hkdf_private.c`) are fixed, confirming the issue is repo-wide, not scoped to new files.
