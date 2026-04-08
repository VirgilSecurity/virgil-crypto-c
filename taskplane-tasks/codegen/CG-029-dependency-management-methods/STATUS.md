# CG-029: Generate Dependency Management Methods from Class IR — Status

**Current Step:** Step 4: Testing & Verification
**Status:** 🟡 In Progress
**Last Updated:** 2026-04-08
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 2
**Size:** M

---

### Step 0: Preflight
**Status:** ✅ Complete

- [x] CG-028 complete
- [x] c_dependency.gsl methods studied
- [x] Resolved XML for ecies studied
- [x] Dependency struct field patterns understood

---

### Step 1: Generate dependency struct fields
**Status:** ✅ Complete

- [x] Add dependency property rendering in _render_reference_class_support or render_class_c_module — each dep becomes a c_property on the struct with type=vscf_impl_t for interface deps, or the class type for class deps
- [x] Add interface include (impl header) for interface deps; ensure dependency includes cover the impl_t type
- [x] Verify ecies struct fields match reference (random, cipher, mac, kdf, ephemeral_key)

---

### Step 2: Generate use/take/release methods
**Status:** ✅ Complete

- [x] Implement _render_dependency_methods() generating use/take/release for each dependency
- [x] use_X body: ASSERT_PTR(self), ASSERT_PTR(dep), assert(self->dep==NULL), is_implemented check for interface deps, self->dep = impl_shallow_copy(dep)
- [x] take_X body: same asserts + check, self->dep = dep (direct assign, no copy). Only for interface/class/impl deps
- [x] release_X body: ASSERT_PTR(self), impl_destroy(&self->dep) for interface deps or class_destroy for class deps
- [x] Wire into _render_reference_class_support after lifecycle methods
- [x] Verify ecies methods match reference

---

### Step 3: Generate observer hook stubs
**Status:** ✅ Complete

- [x] Observer hooks generated conditionally
- [x] Verified against resolved XML
- [x] Targeted tests pass

---

### Step 4: Testing & Verification
**Status:** ✅ Complete

- [x] Python compile check passes
- [x] Build gate passes
- [x] Ecies dependency methods match reference
- [x] Buffer unaffected
- [x] All failures fixed

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
| 2026-04-08 15:06 | Task started | Runtime V2 lane-runner execution |
| 2026-04-08 15:06 | Step 0 started | Preflight |
| 2026-04-08 15:36 | Worker iter 1 | done in 1838s, tools: 94 |

---

## Blockers

*None*

---

## Notes

*Reserved for execution notes*
