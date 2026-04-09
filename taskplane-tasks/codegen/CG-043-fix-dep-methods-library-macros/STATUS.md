# CG-043: Fix Dependency Methods + Library Macros — Status

**Current Step:** Step 4: Documentation & Delivery
**Status:** ✅ Complete
**Last Updated:** 2026-04-09
**Review Level:** 1
**Review Counter:** 0
**Iteration:** 1
**Size:** S

---

### Step 0: Preflight
**Status:** ✅ Complete
- [x] Dep methods missing confirmed
- [x] Library macros missing confirmed
- [x] CG-029 dependency rendering understood

### Step 1: Fix dependency methods
**Status:** ✅ Complete
- [x] Dependency rendering called in impl main
- [x] curve25519.h verified
- [x] Committed

### Step 2: Fix library assert macros
**Status:** ✅ Complete
- [x] Legacy assert module studied
- [x] Library macros generated
- [x] Committed

### Step 3: Testing & Verification
**Status:** ✅ Complete
- [x] All tests pass (159 tests OK)
- [x] Common build gate passes

### Step 4: Documentation & Delivery
**Status:** ✅ Complete
- [x] Discoveries logged

---

## Reviews
| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

## Discoveries
| Discovery | Disposition | Location |
|-----------|-------------|----------|
| `_render_dependency_methods` required entity_kind param to support implementations (not just classes) | Fixed — added `entity_kind` param to `_render_dependency_methods`, `_dependency_use_body`, `_dependency_take_body`, `_dependency_release_body`, `_render_dependency_method_element` | `project_c_backend.py` |
| Observer hooks and release methods needed direct XML construction for impl context (bypassing class-only `argument_from_source`) | Fixed — added `_render_dep_observer_method` helper | `project_c_backend.py` |
| Library `error_message_getter` code is stored in child element's `tail` in XML (not in parent `text`) | Fixed in `_parse_error_message_getter` | `project_source.py` |
| Common project has no `error_message_getter` — correctly skipped for macro generation | Expected behavior | N/A |

## Execution Log
| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-09 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-09 13:35 | Task started | Runtime V2 lane-runner execution |
| 2026-04-09 13:35 | Step 0 started | Preflight |
| 2026-04-09 13:57 | Worker iter 1 | done in 1346s, tools: 160 |
| 2026-04-09 13:57 | Task complete | .DONE created |

## Blockers
*None*

## Notes
*Reserved for execution notes*
