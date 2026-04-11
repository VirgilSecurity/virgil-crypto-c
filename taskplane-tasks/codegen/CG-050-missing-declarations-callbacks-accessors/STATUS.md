# CG-050: Missing Declarations — Status

**Current Step:** Step 2: Add did_setup/did_release callback declarations (Pattern D)
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-11
**Review Level:** 1
**Review Counter:** 0
**Iteration:** 1
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Done

- [x] Baseline error count captured (40 errors, mostly asn1rd/asn1wr type mismatches)
- [x] Legacy _internal.h declaration patterns examined (B: decl in .h + defn in _internal.c; D: fwd decl in _internal.c; H: decl in _internal.h)
- [x] IR/source model expressions identified (B: impl.interface_bindings; D: dep.has_observers on deps; H: all impls need init_ctx/cleanup_ctx — already generated)
- [x] Target output locations determined (B: decl in main module, defn in internal module; D: fwd decl in internal module; H: already correct in internal module)

### Step 1: Add _api(void) accessor declarations (Pattern B)
**Status:** ✅ Done

- [x] Add accessor declaration in main module (render_implementation_c_module) with declaration="public"
- [x] Add accessor definition in internal module (render_implementation_internal_c_module) with definition="private"
- [x] Verify generated XML against legacy aes256_gcm and ecc patterns
- [x] Run targeted tests (30 tests passing)

### Step 2: Add did_setup/did_release callback declarations (Pattern D)
**Status:** ✅ Done

- [x] Add forward declarations in internal module for impl deps with has_observers
- [x] Class deps keep observer hooks in class module (correct for classes, no _internal.c separation)
- [x] Skip observer static stubs from main implementation module (skip_observers=True)
- [x] Run targeted tests (30 impl + 13 class_dep tests passing)

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
| 2026-04-11 02:02 | Task started | Runtime V2 lane-runner execution |
| 2026-04-11 02:02 | Step 0 started | Preflight |

## Blockers
*None*

## Notes
*Reserved for execution notes*
