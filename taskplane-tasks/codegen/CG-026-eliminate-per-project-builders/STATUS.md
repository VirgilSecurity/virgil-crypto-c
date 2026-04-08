# CG-026: Eliminate Per-Project Builder Files — Status

**Current Step:** Step 2: Update imports and tests
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-08
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete
- [x] Confirm generic backend handles all entity kinds
- [x] Confirm auto-discovery works

### Step 1: Remove per-project files
**Status:** ✅ Complete
- [x] Move custom_renderer_overrides from common_direct_c.py into project_c_backend.py or a new inline location in common_bootstrap.py
- [x] Delete common_direct_c.py, foundation_direct_c.py, project_direct_registry.py
- [x] Update common_bootstrap.py to use discover_renderers directly instead of project_direct_registry

### Step 2: Update imports and tests
**Status:** 🟨 In Progress
- [ ] Fix imports
- [ ] Update tests/docs/scripts

### Step 3: Verification
**Status:** ⬜ Not Started
- [ ] py_compile
- [ ] build_common_with_new_codegen.sh
- [ ] verify_foundation_validation_gate.sh --post-quantum-off
- [ ] All codegen tests

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-07 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-08 13:11 | Task started | Runtime V2 lane-runner execution |
| 2026-04-08 13:11 | Step 0 started | Preflight |
