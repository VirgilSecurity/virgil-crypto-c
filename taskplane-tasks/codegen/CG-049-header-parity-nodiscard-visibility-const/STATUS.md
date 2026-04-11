# CG-049: Systematic Header Parity — Status

**Current Step:** Step 3: Fix visibility parity
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-11
**Review Level:** 1
**Review Counter:** 0
**Iteration:** 1
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Baseline error count captured (40 error lines, 20-error-limit hit on vscf_asn1wr.c)
- [x] Representative module diffs analyzed (sha256, aes256_gcm, key_alg, ecc)
- [x] Codegen code paths traced for each pattern
- [x] XML model attributes identified (NODISCARD, const, visibility)

### Step 1: Fix VSCF_NODISCARD emission (Pattern A)
**Status:** ✅ Complete

- [x] Fix render_method_signature in common_bootstrap.py to render c_attribute after closing paren
- [x] Fix interface dispatch path (line ~1441) to use c_attribute instead of c_modifier for NODISCARD
- [x] Add NODISCARD for impl own methods that return status (line ~5128)
- [x] Verified against legacy headers (sha256 exact match, ecc/aes256_gcm NODISCARD correct, 134 vs 176 legacy)

### Step 2: Fix const qualifier parity (Pattern F)
**Status:** ✅ Complete

- [x] Fix class_name (impl) args: default access=None to readonly (const) in interface method impl path
- [x] Fix class_name (impl) args: default access=None to readonly (const) in impl own methods path
- [x] Fix value types (data) not getting spurious const qualifier
- [x] Verify const parity against legacy for key_alg, ecc headers

### Step 3: Fix visibility parity (Pattern G)
**Status:** 🟨 In Progress

- [ ] Fix interface method visibility to check 'scope' attr (not just 'visibility')
- [ ] Fix interface dispatch method visibility to check 'scope' attr
- [ ] Verify visibility parity against legacy headers

### Step 4: Testing & Verification
**Status:** ⬜ Not Started

- [ ] Python test suite passing (159+ tests)
- [ ] Common build gate passes
- [ ] Foundation build error count improved
- [ ] No regressions

### Step 5: Documentation & Delivery
**Status:** ⬜ Not Started

- [ ] CONTEXT.md updated (patterns A, F, G status)
- [ ] Discoveries logged

---

## Reviews

| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

## Discoveries

| Discovery | Disposition | Location |
|-----------|-------------|----------|
| NODISCARD: interface dispatch uses c_modifier (before ret type) instead of c_attribute (after paren). Impl methods use c_attribute which is never rendered | Fix in Step 1 | project_c_backend.py:1441, 4023 |
| NODISCARD: common_bootstrap.py render_method_signature ignores c_attribute elements | Fix in Step 1 | common_bootstrap.py:585 |
| Const: class_name args default to no-const when access=None, but legacy GSL defaults all args to readonly | Fix in Step 2 | project_c_backend.py:4201 |
| Visibility: interface method impl uses method.attrs.get('visibility') but XML uses 'scope' attr | Fix in Step 3 | project_c_backend.py:4259 |

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-10 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-11 01:13 | Task started | Runtime V2 lane-runner execution |
| 2026-04-11 01:13 | Step 0 started | Preflight |

## Blockers
*None*

## Notes
*Reserved for execution notes*
