# CG-037: Fix Cross-Project and External Type Resolution — Status

**Current Step:** Step 5: Documentation & Delivery
**Status:** ✅ Complete
**Last Updated:** 2026-04-09
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] Reproduce 10 failures with foundation codegen
- [x] argument_from_source/return_from_source understood
- [x] Module require rendering loop understood
- [x] Impl defs library handling confirmed

---

### Step 1: Fix external library type resolution
**Status:** ✅ Complete

- [x] argument_from_source handles library attribute
- [x] return_from_source handles library attribute
- [x] const prefix stripping
- [x] brainkey/mbedtls_ecp/simple_swu fixed
- [x] Committed

---

### Step 2: Fix module require rendering
**Status:** ✅ Complete

- [x] Require kind dispatch implemented
- [x] module/class/interface/header handled
- [x] mbedtls_bridge modules fixed
- [x] Committed

---

### Step 3: Add tests
**Status:** ✅ Complete

- [x] brainkey_client rendering test
- [x] message_cipher rendering test
- [x] mbedtls_bridge_random rendering test
- [x] Foundation 0-skip integration test
- [x] Common regression test

---

### Step 4: Testing & Verification
**Status:** ✅ Complete

- [x] New tests pass
- [x] All tests pass
- [x] Common build gate passes
- [x] Foundation 0 skips

---

### Step 5: Documentation & Delivery
**Status:** ✅ Complete

- [x] Discoveries logged
- [x] CONTEXT.md updated if needed

---

## Reviews

| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

---

## Discoveries

| Discovery | Disposition | Location |
|-----------|-------------|----------|
| IRCArgument was missing `library` field — had to add it to both the dataclass and _arg_from_attrs parser | Fixed in project_ir.py | project_ir.py:63, 341 |
| _method_arg_dict was not forwarding the `library` attribute from IR args to dicts | Fixed in project_c_backend.py | project_c_backend.py:1770 |
| Cross-project module requires (e.g. `buffer defs` from `common`) need fallback include path construction when derived module not in IR | Fixed with convention-based fallback | project_c_backend.py:1318 |

---

## Execution Log

| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-08 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-09 00:46 | Task started | Runtime V2 lane-runner execution |
| 2026-04-09 00:46 | Step 0 started | Preflight |
| 2026-04-09 00:57 | Worker iter 1 | done in 676s, tools: 108 |
| 2026-04-09 00:57 | Task complete | .DONE created |

---

## Blockers

*None*

---

## Notes

*Reserved for execution notes*
