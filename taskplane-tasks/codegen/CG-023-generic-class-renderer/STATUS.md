# CG-023: Generic Class Renderer — Status

**Current Step:** Step 2: Tests
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-08
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** L

---

### Step 0: Preflight
**Status:** ✅ Complete
- [x] Identify model-derivable vs static runtime class builders

### Step 1: Implement generic class renderer
**Status:** ✅ Complete
- [x] Add generic `render_class_c_module` to shared backend
- [x] Derive struct/methods/constants from IR
- [x] Reclassify static runtime code

### Step 2: Tests
**Status:** 🟨 In Progress
- [ ] Tests for `common` classes through generic renderer
- [ ] No regressions

### Step 3: Verification
**Status:** ⬜ Not Started
- [ ] py_compile
- [ ] build_common_with_new_codegen.sh

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-07 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-08 01:11 | Task started | Runtime V2 lane-runner execution |
| 2026-04-08 01:11 | Step 0 started | Preflight |
| 2026-04-08 01:25 | Preflight classification completed | `data` struct/method signatures and `buffer_defs` struct fields are IR-derivable; `buffer`/`memory` handwritten method bodies remain static runtime support to reclassify out of Python builders |

## Notes

- `class_data.xml` already models `data` properties, variables, constructors, and methods needed for a generic class XML renderer.
- `class_buffer.xml` already models `buffer` public API surface and private struct fields that can feed generic declaration rendering; only refcount/allocator lifecycle C bodies are static runtime support.
- Shared modules `memory`, `assert`, `atomic`, and `library` still embed platform/runtime C blocks that should stay checked-in support code rather than model-derived Python literals.
