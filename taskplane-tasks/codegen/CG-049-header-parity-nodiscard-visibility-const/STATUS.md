# CG-049: Systematic Header Parity — Status

**Current Step:** Not Started
**Status:** 🔵 Ready for Execution
**Last Updated:** 2026-04-10
**Review Level:** 1
**Review Counter:** 0
**Iteration:** 0
**Size:** M

---

### Step 0: Preflight
**Status:** ⬜ Not Started

- [ ] Baseline error count captured
- [ ] Representative module diffs analyzed (4 modules)
- [ ] Codegen code paths traced for each pattern
- [ ] XML model attributes identified (NODISCARD, const, visibility)

### Step 1: Fix VSCF_NODISCARD emission (Pattern A)
**Status:** ⬜ Not Started

- [ ] Status-returning methods identified
- [ ] VSCF_NODISCARD emitted correctly
- [ ] Verified against legacy headers

### Step 2: Fix const qualifier parity (Pattern F)
**Status:** ⬜ Not Started

> ⚠️ Hydrate: Expand based on const rules discovered in Step 0

- [ ] Const rules identified from model/legacy comparison
- [ ] Parameter const qualifiers fixed
- [ ] Return type const qualifiers fixed

### Step 3: Fix visibility parity (Pattern G)
**Status:** ⬜ Not Started

> ⚠️ Hydrate: Expand based on visibility rules discovered in Step 0

- [ ] Visibility attribute handling fixed
- [ ] Correct defaults applied
- [ ] Verified against legacy headers

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

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-10 | Task staged | PROMPT.md and STATUS.md created |

## Blockers
*None*

## Notes
*Reserved for execution notes*
