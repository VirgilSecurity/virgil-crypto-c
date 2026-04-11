# CG-048: Fix Foundation Module Header Parity — Status

**Current Step:** Step 3: Documentation & Delivery
**Status:** ✅ Complete
**Last Updated:** 2026-04-11
**Review Level:** 1
**Review Counter:** 0
**Iteration:** 1
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] All foundation build errors captured
- [x] Generated vs legacy header diffs analyzed for both modules
- [x] Error categories traced to codegen root causes
- [x] Module types identified in XML models

### Step 1: Fix declaration parity
**Status:** ✅ Complete

- [x] Fix visibility: In `_render_impl_method`, when `declaration=="public"`, use `_PUBLIC` modifier (not just when `visibility=="public"`)
- [x] Fix const qualifiers: Interface arguments without `access` attr should default to `const` (both in `_render_impl_interface_methods` and impl-specific methods)
- [x] Fix `_internal.h` path: Change `implementation_internal_output` header_path to use `src/` dir (matching legacy layout)
- [x] Verify targeted: run `new_codegen.sh --verify foundation` and confirm errors reduced (alg_info_der errors eliminated, new errors in asn1rd/asn1wr are different modules - out of scope)

### Step 2: Testing & Verification
**Status:** ✅ Complete

- [x] Python test suite passing (159+ tests)
- [x] Common build gate passes
- [x] Foundation build: 0 errors in target modules
- [x] Remaining errors in other modules documented
- [x] No regressions

### Step 3: Documentation & Delivery
**Status:** ✅ Complete

- [x] CONTEXT.md updated
- [x] Discoveries logged (especially remaining errors)

---

## Reviews

| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

## Discoveries

| Discovery | Disposition | Location |
|-----------|-------------|----------|
| vscf_asn1rd.c / vscf_asn1wr.c: 20+ type errors from pointer/array type mismatches in class methods | Out of scope — class module type resolution issue | tools/codegen/project_c_backend.py |
| _internal.h now generated for all implementations due to path fix (58 files that were previously not generated) | Beneficial side effect — resolves pattern H from CONTEXT.md | tools/codegen/project_c_backend.py:implementation_internal_output |

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-10 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-11 00:39 | Task started | Runtime V2 lane-runner execution |
| 2026-04-11 00:39 | Step 0 started | Preflight |

## Blockers
*None*

## Notes
- Modules are implementation type (within `implementor_alg_info_der.xml`)
- Actual build errors: 4 (not 24+ — build stops early on first module)
  - 2 visibility errors in deserializer.c (VSCF_PUBLIC in .c vs VSCF_PRIVATE in generated .h)
  - 2 undeclared init_ctx/cleanup_ctx in deserializer_internal.c
- Root cause 1 (visibility): `_render_impl_method` uses `visibility` for modifier but `declaration="public"` methods default visibility to "private"
- Root cause 2 (const): Interface args without `access` attr don't get `const` but legacy expects it
- Root cause 3 (init_ctx/cleanup_ctx): `implementation_internal_output` puts header in `include/private/` but legacy files are in `src/`, so _internal.h never gets generated
