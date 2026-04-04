# CG-003: Support-File Fallback Audit — Status

**Current Step:** Step 3: Delivery
**Status:** ✅ Complete
**Last Updated:** 2026-04-04
**Review Level:** 1
**Review Counter:** 0
**Iteration:** 1
**Size:** S

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Review current direct coverage and fallback coverage notes
- [x] Identify the remaining support/aggregation outputs still not directly owned

---

### Step 1: Audit remaining support files
**Status:** ✅ Complete

- [x] Classify each remaining support header/output as direct candidate, acceptable fallback, or deferred work
- [x] Capture rationale for each classification

---

### Step 2: Update docs
**Status:** ✅ Complete

- [x] Write the audit into `docs/codegen-migration/`
- [x] Ensure the docs are consistent with the actual bootstrap routing in code

---

### Step 3: Delivery
**Status:** ✅ Complete

- [x] Summarize what should happen immediately after `buffer_defs` and `buffer`

---

## Reviews

| # | Type | Step | Verdict | File |
|---|------|------|---------|------|
| 1 | Plan | 1 | UNAVAILABLE | reviewer tool unavailable |
| 2 | Plan | 2 | UNAVAILABLE | reviewer tool unavailable |

---

## Discoveries

| Discovery | Disposition | Location |
|-----------|-------------|----------|
| The checked-in `vsc_common_public.h` / `vsc_common_private.h` umbrella headers currently have empty `@generated` blocks, so the active bootstrap does not materially regenerate their include lists today. | Carry into Step 2 docs as an audit finding. | `library/common/include/virgil/crypto/common/vsc_common_public.h`, `library/common/include/virgil/crypto/common/private/vsc_common_private.h` |
| `tools/codegen/common_bootstrap.py` has direct routing for `vsc_buffer_defs`, but no special-case routing for the umbrella headers; they are only described as fallback in docs/plans. | Use Step 2 to align docs with actual bootstrap behavior. | `tools/codegen/common_bootstrap.py`, `docs/codegen-migration/common-buffer-migration-plan.md` |

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-04 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-04 20:45 | Task started | Runtime V2 lane-runner execution |
| 2026-04-04 20:45 | Step 0 started | Preflight |
| 2026-04-04 20:57 | Step 0 completed | Reviewed direct/fallback notes and identified remaining support outputs |
| 2026-04-04 20:58 | Step 1 review | Plan review returned UNAVAILABLE; proceeded cautiously |
| 2026-04-04 20:59 | Step 1 completed | Classified umbrella headers and captured rationale in STATUS |
| 2026-04-04 21:01 | Step 2 review | Plan review returned UNAVAILABLE; proceeded cautiously |
| 2026-04-04 21:03 | Step 2 completed | Added audit doc and aligned migration docs with active bootstrap routing |
| 2026-04-04 21:04 | Step 3 completed | Documented the immediate post-buffer cleanup decision |
| 2026-04-04 20:49 | Worker iter 1 | done in 288s, tools: 63 |
| 2026-04-04 20:49 | Task complete | .DONE created |

---

## Blockers

*None*

---

## Notes

This task keeps the post-buffer migration boundary explicit.

Step 1 working classification:
- `vsc_common_public.h` — **deferred direct candidate** after `vsc_buffer` is direct; today it is a thin static umbrella include list and not a meaningful migration blocker.
  - Rationale: its content is project-composition glue, not entity-specific lowering logic, and the checked-in file currently carries an empty generated block.
- `vsc_common_private.h` — **deferred direct candidate** after `vsc_buffer` is direct; like the public umbrella, it is compile-sensitive but structurally trivial.
  - Rationale: its only meaningful dependency edge is `vsc_buffer_defs.h`, so deciding its final generation mode is cleaner once `buffer`/`buffer_defs` ownership is fully direct.
- No additional non-buffer support outputs were found in the active bootstrap path; `vsc_platform.h.in` appears in historical status docs, but current `common_bootstrap.py` only iterates `c_module_*.xml` and contains no dedicated platform/support emitter logic.
  - Rationale: the audit should stay focused on outputs the active bootstrap really touches, while also flagging stale status language for correction in Step 2.
