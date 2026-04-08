# CG-032: Parse Implementors and Implementations into Source and IR — Status

**Current Step:** Not Started
**Status:** 🔵 Ready for Execution
**Last Updated:** 2026-04-08
**Review Level:** 1
**Review Counter:** 0
**Iteration:** 0
**Size:** M

---

### Step 0: Preflight
**Status:** ⬜ Not Started

- [ ] CG-031 complete
- [ ] Implementor model XML studied
- [ ] GSL implementation/implementor studied

---

### Step 1: Add ImplementorSource/ImplementationSource
**Status:** ⬜ Not Started

- [ ] ImplementationSource and ImplementorSource dataclasses
- [ ] load_implementor_source() function
- [ ] load_project_source() updated for implementor refs
- [ ] implementor_refs and implementors on ProjectSource

---

### Step 2: Add IRImplementation to project_ir.py
**Status:** ⬜ Not Started

- [ ] IRInterfaceBinding and IRImplementation dataclasses
- [ ] implementations field on IRProject
- [ ] Source → IR mapping
- [ ] IROutputTarget computed

---

### Step 3: Add test coverage
**Status:** ⬜ Not Started

> ⚠️ Hydrate: Expand based on exact implementation counts and binding details discovered

- [ ] Foundation has 13 implementors
- [ ] mbedtls implementations correct
- [ ] sha256 interface bindings correct
- [ ] Implementation properties/methods/requirements parsed
- [ ] IRImplementation output targets correct
- [ ] Total 53 implementations
- [ ] Common has zero implementors

---

### Step 4: Testing & Verification
**Status:** ⬜ Not Started

- [ ] New tests pass
- [ ] Existing tests pass
- [ ] Build gate passes

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

---

## Blockers

*None*

---

## Notes

*Reserved for execution notes*
