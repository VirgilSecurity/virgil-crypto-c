# CG-044: Foundation Codegen Full Verification — Status

**Current Step:** Step 2: Fix compilation errors
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-09
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 1
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete
- [x] CG-040-043 complete
- [x] Common verify passes
- [x] Foundation codegen runs (2 modules skipped: vscf_key, vscf_key_api — 'enum not found in IR: impl/tag')

### Step 1: Attempt foundation build
**Status:** ✅ Complete
- [x] Build attempted
- [x] Errors captured and categorized

### Step 2: Fix compilation errors
**Status:** 🟨 In Progress
> ⚠️ Hydrate: Expand based on errors found in Step 1
- [x] Fix broken C comments in api_private/impl_private (comment_text wrap)
- [x] Fix const const duplication in impl_private (remove extra const from property type)
- [x] Fix unused static function: library assert trigger methods to VSCF_PUBLIC
- [x] Fix enum arguments not resolved (add enum handling in argument_from_source)
- [x] Fix impl/tag enum name (snake_name handles / separator)
- [x] Fix impl="X" class references in IR (treat impl as class in _arg_from_attrs)
- [x] Fix class_type_symbol to fall back to implementation lookup
- [x] Fix macro double-backslash (remove trailing \\ from macro code)
- [x] Fix &address-of for pointer c_values (inherited API refs in vtable)
- [x] Add known skips handling in common_bootstrap (exit 0 for known modules)
- [x] Add missing include for vscf_list_key_value_node.h in message_info_custom_params.h
- [x] Fix data/buffer value vs pointer semantics mismatch — passed fallback_projects to impl modules for correct value type resolution
- [x] Fix vtable function casts via (void(*)(void)) intermediary to suppress -Wcast-function-type-mismatch
- [x] Fix private interface method visibility in implementation headers
- [x] Fix return type value semantics for value-type classes in _render_impl_method
- [ ] Fix missing implementation constructor generation (cipher_alg_info_new_with_members) — BLOCKER: 4 errors remain

### Step 3: Run diff check
**Status:** ⬜ Not Started
- [ ] Diff reviewed
- [ ] Functional bugs fixed
- [ ] Acceptable diffs documented

### Step 4: Run tests
**Status:** ⬜ Not Started
- [ ] Tests pass
- [ ] Test failures fixed

### Step 5: Final verification
**Status:** ⬜ Not Started
- [ ] Common verify passes
- [ ] Foundation verify passes
- [ ] Python tests pass
- [ ] Known diffs documented

### Step 6: Documentation & Delivery
**Status:** ⬜ Not Started
- [ ] CONTEXT.md updated
- [ ] Discoveries logged

---

## Reviews
| # | Type | Step | Verdict | File |
|---|------|------|---------|------|

## Discoveries
| Discovery | Disposition | Location |
|-----------|-------------|----------|
| Implementation constructor codegen missing | Needs new task | project_c_backend.py render_implementation_c_module |
| vsc_data_t value/pointer inconsistency | Fixed by passing fallback_projects | project_c_backend.py, project_ir.py |
| Broken C comments in api_private/impl_private | Fixed via comment_text() | project_c_backend.py render_api/impl_private |
| enum arguments not resolved in argument_from_source | Fixed | project_c_backend.py |
| impl attribute not handled in IR | Fixed in project_ir.py _arg_from_attrs |
| snake_name didn't handle / separator | Fixed | project_c_backend.py |
| Macro double-backslash in library assert | Fixed by removing \\  from code | project_c_backend.py |
| const const in impl_private | Fixed by removing extra const from type | project_c_backend.py |
| vscf_message_info_custom_params.h missing include | Pre-existing bug, added include | library/foundation |
| vscf_cipher_alg_info_new_with_members undeclared | Pre-existing bug, needs impl constructor codegen | library/foundation |

## Execution Log
| Timestamp | Action | Outcome |
|-----------|--------|---------|
| 2026-04-09 | Task staged | PROMPT.md and STATUS.md created |
| 2026-04-09 22:39 | Task started | Runtime V2 lane-runner execution |
| 2026-04-09 22:39 | Step 0 started | Preflight |

## Blockers
- **Implementation constructor generation missing**: `cipher_alg_info_new_with_members` is called but never declared/defined. The XML model has `<constructor name="with members">` on implementations, but the codegen only generates constructors for classes, not implementations. 4 compilation errors remain because of this. This requires a new codegen feature (constructor generation for IRImplementation), not a fix.

## Notes
*Reserved for execution notes*
