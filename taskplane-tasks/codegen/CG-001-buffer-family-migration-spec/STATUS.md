# CG-001: Buffer Family Migration Spec — Status

**Current Step:** Step 3: Verification
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-04
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** S

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Read the task-area context and current migration docs
- [x] Inspect current fallback handling for buffer-related files in `tools/codegen/common_bootstrap.py`

---

### Step 1: Analyze remaining buffer-family surface
**Status:** ✅ Complete

- [x] Compare original source models and resolved XML inputs for `buffer` and `buffer_defs`
- [x] Identify which generated pieces are direct-lowering candidates versus thin support/aggregation artifacts
- [x] Record any special preservation or formatting constraints that are likely to matter

---

### Step 2: Document the execution plan
**Status:** ✅ Complete

- [x] Add or update docs under `docs/codegen-migration/` describing the remaining migration map
- [x] Explicitly sequence `buffer_defs`, `buffer`, and any support-header follow-up
- [x] Call out expected verification commands and no-commit constraints for generated `library/common/**` files

---

### Step 3: Verification
**Status:** ⬜ Not Started

- [ ] Re-read the updated docs to ensure they are internally consistent with the current codebase

---

### Step 4: Delivery
**Status:** ⬜ Not Started

- [ ] Summarize recommended next implementation order and notable risks in the task output

---

## Reviews

| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

---

## Discoveries

| Discovery | Disposition | Location |
|-----------|-------------|----------|
| Clean worktree does not contain tracked `codegen/generated/common/c_module_vsc_buffer*.xml`; planning must treat those legacy resolved inputs as runtime-only / external reference artifacts rather than committed source. | Document in migration plan so follow-up tasks do not assume the XML is available in git. | `codegen/generated/common/`, `tools/codegen/common_bootstrap.py`, `docs/codegen-migration/resolved-models-inventory.md` |
| `vsc_buffer_defs` behaves like a thin support artifact: private struct definition in `vsc_buffer_defs.h` plus an effectively empty generated C file, both tied to `buffer` internals. | Sequence `buffer_defs` before `buffer` and treat aggregation headers as follow-up support work. | `library/common/include/virgil/crypto/common/private/vsc_buffer_defs.h`, `library/common/src/vsc_buffer_defs.c` |

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-04 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-04 19:19 | Task started | Runtime V2 lane-runner execution |
| 2026-04-04 19:19 | Step 0 started | Preflight |

---

## Blockers

*None*

---

## Notes

This task prepares the final `common` migration slice so implementation tasks can run with lower ambiguity.

Step 1 analysis notes:
- `class_buffer.xml` is the only original `common` source model in this family; `buffer_defs` appears to be resolver-derived support output rather than a first-class source-model file.
- `vsc_buffer.h` is largely generated API surface from the class model, while `vsc_buffer.c` only has its lifecycle/refcount section inside `@generated`; most operational methods remain preserved manual code and constrain the migration plan.
- Direct-lowering candidates are `vsc_buffer_defs.h` / `vsc_buffer_defs.c` first, then the generated block portions of `vsc_buffer.h` / `vsc_buffer.c`; `vsc_common_public.h` and `vsc_common_private.h` are thin include aggregators that should stay as explicit follow-up support work.
- Preservation constraints: `vsc_buffer.c` must keep its large handwritten body outside the generated block intact, support headers currently rely on existing file skeletons and include order, and follow-up tasks must continue the no-commit rule for temporary `library/common/**` regeneration.
