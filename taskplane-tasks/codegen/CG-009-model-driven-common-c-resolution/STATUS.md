# CG-009: Model-Driven Common C Resolution — Status

**Current Step:** Step 4: Delivery
**Status:** ✅ Complete
**Last Updated:** 2026-04-04
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 6
**Size:** L

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Read the ADR and predecessor task outputs
- [x] Identify project-specific metadata that is still hardcoded in the current C lowering layer

---

### Step 1: Implement model-driven C resolution
**Status:** ✅ Complete

- [x] Derive names, output files, prefixes, and related metadata from the resolved project graph / IR
- [x] Replace project-specific hardcodes where the model already defines the information
- [x] Keep only genuinely static backend/runtime support logic as reusable backend code

---

### Step 2: Preserve current C-generation contract
**Status:** ✅ Complete

- [x] Keep handwritten-code preservation behavior intact
- [x] Preserve the working `common` build path and generated-block application flow
- [x] Add or update tests that protect the no-hardcoded-project-metadata rule

---

### Step 3: Verification
**Status:** ✅ Complete

- [x] Run the new/updated tests
- [x] Run `python3 -m py_compile tools/codegen/common_bootstrap.py tools/codegen/common_direct_c.py tools/codegen/common_source.py tools/codegen/common_ir.py`
- [x] Run `bash tools/codegen/build_common_with_new_codegen.sh`
- [x] Confirm no generated `library/common/**` artifacts remain staged for commit

---

### Step 4: Delivery
**Status:** ✅ Complete

- [x] Update architecture/migration docs to explain what hardcodes were removed and what static backend logic remains acceptable

---

## Reviews

| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

---

## Discoveries

| Discovery | Disposition | Location |
|-----------|-------------|----------|
| `common_direct_c.py` still hardcodes per-entity C symbol names, include/source basenames, checked-in header/source paths, once guards, generated XML selection, and several self/module type spellings (`vsc_data_t`, `vsc_buffer_t`, `vsc_dealloc_fn`) even though `project_common_to_ir()` now derives output targets and project prefix/path metadata. | Refactor Step 1-2 to resolve module/class builders from IR/output metadata and leave only backend-static code templates hardcoded. | `tools/codegen/common_direct_c.py`, `tools/codegen/common_bootstrap.py` |

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-04 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-04 23:00 | Task started | Runtime V2 lane-runner execution |
| 2026-04-04 23:00 | Step 0 started | Preflight |
| 2026-04-04 23:08 | Preflight reading | Reviewed ADR 0002, CG-008 outputs, project model, IR tests, and current `common_*` generator files to map remaining model-vs-hardcoded boundaries. |
| 2026-04-04 23:24 | Worker iter 1 | done in 1447s, tools: 50 |
| 2026-04-04 23:50 | Worker iter 2 | done in 1590s, tools: 28 |
| 2026-04-04 23:50 | No progress | Iteration 2: 0 new checkboxes (1/3 stall limit) |
| 2026-04-05 00:15 | Worker iter 3 | done in 1499s, tools: 19 |
| 2026-04-05 00:15 | No progress | Iteration 3: 0 new checkboxes (2/3 stall limit) |
| 2026-04-05 01:32 | Worker iter 4 | done in 4609s, tools: 68 |
| 2026-04-05 02:17 | Worker iter 5 | done in 2692s, tools: 0 |
| 2026-04-05 02:17 | No progress | Iteration 5: 0 new checkboxes (1/3 stall limit) |

---

## Blockers

*None*

---

## Notes

This task is the core refactor from mixed-mode hardcoded C lowering to a model-driven C backend.
