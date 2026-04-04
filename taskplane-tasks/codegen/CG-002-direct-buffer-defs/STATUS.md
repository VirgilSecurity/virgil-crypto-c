# CG-002: Direct Lowering for vsc_buffer_defs — Status

**Current Step:** Step 4: Documentation and delivery
**Status:** ✅ Complete
**Last Updated:** 2026-04-04
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Read the task-area context, current direct-coverage status docs, and the `CG-001` plan
- [x] Inspect the current fallback path for `vsc_buffer_defs`

---

### Step 1: Implement direct lowering
**Status:** ✅ Complete

- [x] Add direct-lowering support for `vsc_buffer_defs` in `tools/codegen/common_direct_c.py`
- [x] Keep the implementation aligned with original-model-as-source-of-truth constraints
- [x] Avoid introducing a dependency on resolved XML as runtime input for this module

---

### Step 2: Wire into bootstrap generation
**Status:** ✅ Complete

- [x] Update `tools/codegen/common_bootstrap.py` to route `vsc_buffer_defs` through the new direct path
- [x] Preserve existing mixed-mode behavior for any still-unmigrated `common` outputs

---

### Step 3: Verify build safety
**Status:** ✅ Complete

- [x] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`
- [x] Run `bash tools/codegen/build_common_with_new_codegen.sh`
- [x] Confirm no generated `library/common/**` artifacts remain staged for commit

---

### Step 4: Documentation and delivery
**Status:** ✅ Complete

- [x] Update migration docs to reflect direct coverage for `vsc_buffer_defs`
- [x] Summarize any parity gaps, shortcuts, or follow-up risks for `vsc_buffer`

---

## Reviews

| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

---

## Discoveries

| Discovery | Disposition | Location |
|-----------|-------------|----------|
| `build_common_with_new_codegen.sh` can pass in a clean worktree without exercising `vsc_buffer_defs` routing because `codegen/generated/common/c_module_vsc_buffer*.xml` is absent; a temporary fixture smoke run is useful when validating new direct branches. | Documented as a follow-up verification caveat in migration docs; no committed generated files required. | `docs/codegen-migration/common-buffer-migration-plan.md`, `tools/codegen/common_bootstrap.py` |

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-04 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-04 20:36 | Task started | Runtime V2 lane-runner execution |
| 2026-04-04 20:36 | Step 0 started | Preflight |
| 2026-04-04 20:43 | Step 0 completed | Preflight context and fallback path inspected |
| 2026-04-04 20:43 | Step 1 started | Implement direct lowering |
| 2026-04-04 20:48 | Step 1 completed | Added direct source-driven `vsc_buffer_defs` lowering helper |
| 2026-04-04 20:48 | Step 2 started | Wire bootstrap routing |
| 2026-04-04 20:50 | Step 2 completed | Bootstrap now routes `vsc_buffer_defs` through the direct path |
| 2026-04-04 20:50 | Step 3 started | Verify build safety |
| 2026-04-04 20:58 | Step 3 completed | Python compile, build gate, and no-generated-artifact checks passed |
| 2026-04-04 20:58 | Step 4 started | Documentation and delivery |
| 2026-04-04 21:03 | Step 4 completed | Migration docs updated with `vsc_buffer_defs` direct coverage and `vsc_buffer` follow-up risks |

---

## Blockers

*None*

---

## Notes

This task is the first implementation slice in the remaining buffer-family migration.
