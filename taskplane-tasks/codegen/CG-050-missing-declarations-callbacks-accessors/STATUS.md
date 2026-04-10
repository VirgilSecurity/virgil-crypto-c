# CG-050: Missing Declarations — Status

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
- [ ] Legacy _internal.h declaration patterns examined
- [ ] IR/source model expressions identified for each pattern
- [ ] Target output locations determined

### Step 1: Add _api(void) accessor declarations (Pattern B)
**Status:** ⬜ Not Started

- [ ] Accessor declarations emitted for implementations
- [ ] Signature matches legacy pattern
- [ ] Verified against representative implementations

### Step 2: Add did_setup/did_release callback declarations (Pattern D)
**Status:** ⬜ Not Started

> ⚠️ Hydrate: Expand based on dependency property parsing discovered in Step 0

- [ ] Dependency properties parsed from model
- [ ] did_setup/did_release declarations emitted
- [ ] Verified against legacy internal headers

### Step 3: Add init_ctx/cleanup_ctx declarations (Pattern H)
**Status:** ⬜ Not Started

- [ ] init_ctx/cleanup_ctx declarations emitted in internal output
- [ ] Signature matches legacy pattern
- [ ] Verified against legacy internal headers

### Step 4: Testing & Verification
**Status:** ⬜ Not Started

- [ ] Python test suite passing (159+ tests)
- [ ] Common build gate passes
- [ ] Foundation build error count improved
- [ ] No regressions

### Step 5: Documentation & Delivery
**Status:** ⬜ Not Started

- [ ] CONTEXT.md updated (patterns B, D, H status)
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
