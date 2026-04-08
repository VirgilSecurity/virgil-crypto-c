# CG-031: Parse Interfaces into Source and IR — Status

**Current Step:** Not Started
**Status:** 🔵 Ready for Execution
**Last Updated:** 2026-04-08
**Review Level:** 1
**Review Counter:** 0
**Iteration:** 0
**Size:** S

---

### Step 0: Preflight
**Status:** ⬜ Not Started

- [ ] Required files exist
- [ ] Interface model XML studied
- [ ] interface.gsl studied

---

### Step 1: Add InterfaceSource to project_source.py
**Status:** ⬜ Not Started

- [ ] InterfaceSource dataclass created
- [ ] load_interface_source() function created
- [ ] load_project_source() updated for interface refs
- [ ] interface_refs and interfaces added to ProjectSource

---

### Step 2: Add IRInterface to project_ir.py
**Status:** ⬜ Not Started

- [ ] IRInterface dataclass created
- [ ] interfaces field added to IRProject
- [ ] InterfaceSource → IRInterface mapping
- [ ] IROutputTarget computed for interfaces

---

### Step 3: Add test coverage
**Status:** ⬜ Not Started

- [ ] Foundation has expected interface count
- [ ] interface_hash methods and constants correct
- [ ] interface_cipher inheritance correct
- [ ] interface_random methods correct
- [ ] Common has zero interfaces
- [ ] IRInterface output targets correct
- [ ] Interface method arguments/returns correct

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
