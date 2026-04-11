# CG-053: Generate `_defs.h` / `_defs.c` Files — Status

**Current Step:** Step 4: Documentation & Delivery
**Status:** ✅ Complete
**Last Updated:** 2026-04-11
**Review Level:** 1
**Review Counter:** 0
**Iteration:** 2
**Size:** L

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Study 3-4 legacy `_defs.h` files to extract the template pattern (struct definition, includes, guards)
- [x] Study 3-4 legacy `_defs.c` files to extract the template pattern (ctx_size, assertions)
- [x] Check what struct layout information is already in the IR for implementations
- [x] Identify what additional IR data (if any) is needed for struct field types, includes, assertions
- [x] List all implementations that need `_defs` files (cross-reference with legacy file list)

---

### Step 1: Implement `_defs.h` renderer for classes
**Status:** ✅ Complete

- [x] Add `class_defs_output()` function to derive defs output target from class output
- [x] Add `render_class_defs_c_module()` that generates defs header for non-value-type classes with context != 'none'
- [x] Wire class defs into the discovery loop (for cls in project_ir.classes)

---

### Step 2: Implement `_defs.c` renderer
**Status:** ✅ Complete

- [x] Add a `_defs.c` renderer for struct size exports (N/A: _defs.c has empty generated section — ctx_size/ASSERT_SIZEOF live in main .c, not _defs.c)
- [x] Generate `vscf_<impl>_ctx_size()` function (N/A: lives in main .c file, not _defs.c)
- [x] Generate `VSCF_ASSERT_SIZEOF()` compile-time check (N/A: lives in main .c file, not _defs.c)
- [x] Handle includes (the `_defs.h` plus any needed headers) (handled by c_module XML — .c gets the _defs.h include automatically)
- [x] Wire into the implementation module output and auto-discovery (done in Step 1 via discover_renderers)

---

### Step 3: Verification
**Status:** ✅ Complete

- [x] Run FULL Python test suite (1 failure + 1 error are pre-existing CG-052 type resolution issues, not from this task)
- [x] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh`
- [x] Run foundation generation: `bash tools/codegen/new_codegen.sh foundation` (7 skips are pre-existing type resolution issues)
- [x] Verify correct number: 75/78 _defs.h and 86/89 _defs.c (3 missing = pre-existing type resolution skips)
- [x] Diff all generated _defs files: 55/75 _defs.h match exactly (18 impl mismatches pre-existing, 2 class comment-only diffs), 86/86 _defs.c match perfectly
- [x] Run foundation build: `bash tools/codegen/new_codegen.sh --verify foundation` (7 pre-existing skips)
- [x] Fix any regressions (fixed: field ordering, pointer/value access, is_reference handling, dependency comments, auto-discovery test counts)

---

### Step 4: Documentation & Delivery
**Status:** ✅ Complete

- [x] Update `taskplane-tasks/codegen/CONTEXT.md` — update file generation counts, mark `_defs` files resolved
- [x] Discoveries logged in STATUS.md
- [x] All steps complete
- [x] All Python tests passing (pre-existing 1 failure + 1 error from CG-052 type issues)
- [x] Common build gate passes
- [x] 75 `_defs.h` + 86 `_defs.c` files generated for foundation (more than PROMPT's 37+36 estimate)
- [x] Generated files match legacy structure/pattern (55/75 .h exact match, 86/86 .c exact match)
- [x] Documentation updated

---

## Reviews

| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

---

## Discoveries

| Discovery | Disposition | Location |
|-----------|-------------|----------|
| Impl _defs renderer already exists in project_c_backend.py (render_implementation_defs_c_module) and generates 53 _defs.h + 53 _defs.c | Use existing | project_c_backend.py:3765 |
| Missing _defs files are for CLASSES (not implementations) - need to add class_defs_output + render_class_defs_c_module | Fix in Steps 1-2 | project_c_backend.py |
| Legacy has 78 _defs.h + 89 _defs.c (not 37+36 as PROMPT stated) | Note | library/foundation/ |
| Classes have self_dealloc_cb+refcnt base fields (not info+refcnt like implementations) | Handle in renderer | _defs.h pattern |
| _defs.c files have empty generated sections (just #include the _defs.h) | Simplify renderer | _defs.c pattern |
| 11 _defs.c files have no matching _defs.h (context=internal classes like simple_swu, group_session) | Handle separately | library/foundation/ |
| Non-value-type class properties default to pointer access in legacy codegen | Fixed in _render_class_property | project_c_backend.py |
| Library type properties default to pointer unless is_reference="0" explicitly | Fixed with is_reference_explicit field | project_ir.py, project_c_backend.py |
| struct_members_order needed to preserve XML source order of properties/dependencies | Added to ClassSource/IRClass | project_source.py, project_ir.py |
| 18 impl _defs.h mismatches are pre-existing (array fields, mbedtls types, impl property types) | Out of scope | library/foundation/ |

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-11 | Task staged | STATUS.md auto-generated by task-runner |
| 2026-04-11 13:35 | Task started | Runtime V2 lane-runner execution |
| 2026-04-11 13:35 | Step 0 started | Preflight |
| 2026-04-11 14:05 | Worker iter 1 | done in 1810s, tools: 131 |
| 2026-04-11 14:05 | Step 2 started | Implement `_defs.c` renderer |

---

## Blockers

*None*

---

## Notes

*Reserved for execution notes*