# CG-028: Generate Lifecycle Method Bodies from Class IR — Status

**Current Step:** Not Started
**Status:** 🔵 Ready for Execution
**Last Updated:** 2026-04-08
**Review Level:** 2
**Review Counter:** 0
**Iteration:** 0
**Size:** M

---

### Step 0: Preflight
**Status:** ⬜ Not Started

- [ ] CG-027 complete: IRClass has dependencies
- [ ] _render_reference_class_support() understood
- [ ] GSL lifecycle functions studied
- [ ] Cfrag files read as verification targets

---

### Step 1: Implement lifecycle body generation helpers
**Status:** ⬜ Not Started

> ⚠️ Hydrate: Expand based on specific naming patterns discovered when reading project_c_backend.py helper functions

- [ ] Implement body generation helpers for all 8 lifecycle method types
- [ ] Each helper produces correct C code matching GSL template output
- [ ] Targeted test: buffer lifecycle bodies match cfrag content

---

### Step 2: Integrate into _render_reference_class_support
**Status:** ⬜ Not Started

- [ ] Lifecycle methods rendered with code bodies
- [ ] Constructor variants rendered with code bodies
- [ ] Buffer XML output matches cfrag-based reference
- [ ] Foundation class XML has correct lifecycle bodies

---

### Step 3: Testing & Verification
**Status:** ⬜ Not Started

- [ ] Python compile check passes
- [ ] Build gate passes
- [ ] Buffer lifecycle matches cfrag exactly
- [ ] All failures fixed

---

### Step 4: Documentation & Delivery
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
