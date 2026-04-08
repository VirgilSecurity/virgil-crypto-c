# CG-025: Auto-Discovery of Renderable Entities — Status

**Current Step:** Step 2: Tests
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-08
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 2
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete
- [x] Inspect current entity listing/registration

### Step 1: Implement auto-discovery
**Status:** ✅ Complete
- [x] Add `discover_renderers()` to `project_c_backend.py` that walks IR and builds renderer map for all entity kinds (enums, modules, classes)
- [x] Update `project_direct_registry.py` to use auto-discovery instead of only enum-specific discovery, merging with per-project custom overrides
- [x] Update `common_direct_c.py` to export only custom overrides (buffer, data, etc.) not a full hardcoded list
- [x] Support optional entity-kind filtering parameter

### Step 2: Tests
**Status:** ✅ Complete
- [x] Auto-discovery tests for `common` and `foundation`
- [x] No regressions

### Step 3: Verification
**Status:** ⬜ Not Started
- [ ] py_compile
- [ ] build_common_with_new_codegen.sh

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-07 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-08 13:05 | Task started | Runtime V2 lane-runner execution |
| 2026-04-08 13:05 | Step 0 started | Preflight |
| 2026-04-08 13:05 | Worker iter 1 | done in 48s, tools: 10 |
| 2026-04-08 13:05 | No progress | Iteration 1: 0 new checkboxes (1/3 stall limit) |
