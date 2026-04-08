# CG-024: Generic Module Renderer — Status

**Current Step:** Step 3: Verification
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-08
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** L

---

### Step 0: Preflight
**Status:** ✅ Complete
- [x] Identify model-derivable vs static runtime module builders

### Step 1: Implement generic module renderer
**Status:** ✅ Complete
- [x] Add generic `render_module_c_module` to shared backend
- [x] Derive macros/methods/variables/callbacks from IR
- [x] Reclassify static runtime code

### Step 2: Tests
**Status:** ✅ Complete
- [x] Tests for `common` modules through generic renderer
- [x] No regressions

### Step 3: Verification
**Status:** 🟨 In Progress
- [ ] py_compile
- [ ] build_common_with_new_codegen.sh

---

## Notes

- 2026-04-08 preflight classification:
  - Model-derivable from shared module IR: `library`, `memory`, `assert`, and `atomic` because `project_ir.IRCModule` already carries includes, requires, callbacks, variables, methods, macros, macro groups, and top-level code blocks sourced from `codegen/models/shared/module_*.xml`.
  - Static checked-in runtime support that should stay outside a generic module renderer: handwritten buffer runtime `.cfrag` support under `tools/codegen/support/common_runtime/buffer/` and other future platform/runtime C shims that are not represented as module/class IR.
  - Migration target for Step 1: remove the module-specific Python builders from `common_direct_c.py` and teach `project_c_backend.py` to emit module C XML directly from `IRCModule` content.
  - Step 1 implementation note: `common_direct_c.py` now delegates `library` / `memory` / `assert` / `atomic` through shared `render_module_c_module(...)`; checked-in runtime support remains limited to `tools/codegen/support/common_runtime/buffer/*.cfrag` for buffer lifecycle logic.

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-07 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-08 12:23 | Task started | Runtime V2 lane-runner execution |
| 2026-04-08 12:23 | Step 0 started | Preflight |
