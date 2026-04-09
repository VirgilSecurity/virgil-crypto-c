# CG-037: Fix Cross-Project and External Type Resolution — Status

**Current Step:** Step 1: Fix external library type resolution
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-09
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Done

- [x] Reproduce 10 failures with foundation codegen
- [x] argument_from_source/return_from_source understood
- [x] Module require rendering loop understood
- [x] Impl defs library handling confirmed

---

### Step 1: Fix external library type resolution
**Status:** 🟨 In Progress

- [x] argument_from_source handles library attribute
- [x] return_from_source handles library attribute
- [x] const prefix stripping
- [x] brainkey/mbedtls_ecp/simple_swu fixed
- [ ] Committed

---

### Step 2: Fix module require rendering
**Status:** ⬜ Not Started

- [ ] Require kind dispatch implemented
- [ ] module/class/interface/header handled
- [ ] mbedtls_bridge modules fixed
- [ ] Committed

---

### Step 3: Add tests
**Status:** ⬜ Not Started

- [ ] brainkey_client rendering test
- [ ] message_cipher rendering test
- [ ] mbedtls_bridge_random rendering test
- [ ] Foundation 0-skip integration test
- [ ] Common regression test

---

### Step 4: Testing & Verification
**Status:** ⬜ Not Started

- [ ] New tests pass
- [ ] All tests pass
- [ ] Common build gate passes
- [ ] Foundation 0 skips

---

### Step 5: Documentation & Delivery
**Status:** ⬜ Not Started

- [ ] Discoveries logged
- [ ] CONTEXT.md updated if needed

---

## Reviews

| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

---

## Discoveries

| Discovery | Disposition | Location |
|-----------|-------------|----------|

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-08 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-09 00:46 | Task started | Runtime V2 lane-runner execution |
| 2026-04-09 00:46 | Step 0 started | Preflight |

---

## Blockers

*None*

---

## Notes

*Reserved for execution notes*
