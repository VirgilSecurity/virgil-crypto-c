# CG-062: Resolve Model Defaults at Load Time — Status

**Current Step:** Step 4: Documentation & Delivery
**Status:** ✅ Complete
**Last Updated:** 2026-04-12
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** L

---

### Step 0: Preflight
**Status:** ✅ Done

- [x] Catalog all places in `project_c_backend.py` that resolve defaults (search for `is_value_type`, `effective_access`, `access is None`, `access == None`, `buffer.*writeonly`, `data.*readonly`, hardcoded fallback)
- [x] Map each to the corresponding legacy GSL rule from `component.gsl`
- [x] Verify the legacy rules against the resolved XML output for 3-4 sample modules
- [x] Plan the default resolution pass location in `project_ir.py`

---

### Step 1: Add default resolution pass in `project_ir.py`
**Status:** ✅ Done

- [x] Add `resolve_defaults()` function that runs after `project_to_ir()` builds the IR
- [x] Resolve `is_reference` defaults for all arguments, returns, properties
- [x] Resolve `access` defaults for all arguments, returns, properties (context-aware: argument vs return vs property)
- [x] Resolve `access` for method self arguments based on `is_const` (N/A — self args are synthetic, not in XML IR)
- [x] Resolve `access` for impl method returns based on `is_const` (N/A — handled at render time for synthetic methods)
- [x] Mark `context="none"` classes with `lifecycle="none"` or equivalent flag
- [x] Ensure cross-project classes (`data`, `buffer` from common) are handled
- [x] Run tests after this step to catch any regressions from changed IR (159/159 pass, common builds)

---

### Step 2: Simplify `project_c_backend.py`
**Status:** ✅ Done

- [x] Remove all `effective_access` default resolution blocks (6+ occurrences) — simplified 6 blocks to use pre-resolved access
- [x] Remove hardcoded `data` value-type fallbacks (3 occurrences) — replaced with is_reference checks
- [x] Simplify `is_value_type` checks — read from IR attribute, don't re-derive (4 argument blocks simplified)
- [x] Remove buffer/data special-casing in argument/return rendering — access defaults now in IR
- [x] Simplify `return_from_source` and `argument_from_source` — trust IR defaults, removed None checks
- [x] Fix `context="none"` class rendering — skip lifecycle methods and struct when context is none
- [x] Fix `brainkey_client` missing include for library types in properties — added _library_type_header mapping + system include rendering in generate_block
- [x] Ensure no `None` access/is_reference values reach the rendering layer — all None checks simplified to direct access

---

### Step 3: Verification
**Status:** ✅ Done

- [x] Run FULL Python test suite: `PYTHONPATH=. python3 -m unittest discover -s tools/codegen -p "test_*.py"` — 159/159 pass
- [x] Run common build gate: `bash tools/codegen/build_common_with_new_codegen.sh` — PASS
- [x] Run foundation build: `bash tools/codegen/new_codegen.sh --verify foundation` — PASS
- [x] Verify 0 foundation build errors (down from 23) — 0 errors (3 pre-existing round5 third-party errors only)
- [x] Diff 10+ generated headers against legacy to verify parity is maintained — checked 12 headers (sha256, sha512, aes256_gcm, alg_factory, base64, key_provider, brainkey_client, error, random, data, buffer, buffer_defs). Common headers identical. Foundation diffs are: cosmetic line-wrapping, missing VSCF_NODISCARD (pre-existing), new API methods. Fixed const vsc_data_t regression.
- [x] Fix any regressions — fixed const qualifier on value-type class args (data)

---

### Step 4: Documentation & Delivery
**Status:** ✅ Done

- [x] Update `taskplane-tasks/codegen/CONTEXT.md` — document the defaults resolution architecture
- [x] Document the default rules in a code comment at the top of the resolution function
- [x] Discoveries logged in STATUS.md
- [x] All steps complete
- [x] All Python tests passing (159/159)
- [x] Common build gate passes
- [x] Foundation build: 0 errors (down from 23; only pre-existing round5 third-party errors)
- [x] No `None` values for `access` or `is_reference` in IR output (resolve_defaults fills all)
- [x] Backend has zero `effective_access` default blocks (6 simplified to direct access reads)
- [x] Backend has zero hardcoded `data`/`buffer` class special-cases for defaults (replaced with is_reference)
- [x] Documentation updated (CONTEXT.md updated with architecture, CG-062 entry added)

---

## Reviews

| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

---

## Discoveries

| Discovery | Disposition | Location |
|-----------|-------------|----------|
| `generate_block` doesn't render `c_include` elements in generated section | Fixed: added system include rendering for `is_system="1"` includes | `common_bootstrap.py:generate_block()` |
| `argument_from_source` applied `const` qualifier to value-type class args (data) | Fixed: only apply `is_const_type` when `accessed_by=="pointer"` | `project_c_backend.py:argument_from_source()` |
| Pre-existing: 3 round5 third-party build errors (crypto_kem redefinition) | Out of scope | `build/thirdparty/round5/` |
| Pre-existing: private methods (declaration="private") rendered in public module | Out of scope — needs separate filtering pass | `project_c_backend.py:render_class_c_module()` |

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-12 | Task staged | STATUS.md auto-generated by task-runner |
| 2026-04-12 13:00 | Task started | Runtime V2 lane-runner execution |
| 2026-04-12 13:00 | Step 0 started | Preflight |

---

## Blockers

*None*

---

## Notes

*Reserved for execution notes*