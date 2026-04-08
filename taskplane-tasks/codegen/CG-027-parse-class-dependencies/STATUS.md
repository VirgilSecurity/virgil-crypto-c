# CG-027: Parse Class Dependencies into Source and IR — Status

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
- [ ] Understand ClassSource and IRClass structures
- [ ] Study `<dependency>` elements in foundation models

---

### Step 1: Add DependencySource to project_source.py
**Status:** ⬜ Not Started

- [ ] Create `DependencySource` dataclass
- [ ] Parse `<dependency>` elements in `load_class_source()`
- [ ] Add `dependencies` field to `ClassSource`
- [ ] Verify with quick import/load test

---

### Step 2: Add IRDependency to project_ir.py
**Status:** ⬜ Not Started

- [ ] Create `IRDependency` dataclass
- [ ] Add `dependencies` field to `IRClass`
- [ ] Update IR mapping from source
- [ ] Verify: foundation ecies dependencies appear in IR

---

### Step 3: Add test coverage
**Status:** ⬜ Not Started

- [ ] Test: foundation ecies has expected dependencies
- [ ] Test: common buffer has zero dependencies
- [ ] Test: has_observers attribute parsed correctly

---

### Step 4: Testing & Verification
**Status:** ⬜ Not Started

- [ ] Full test suite passing
- [ ] Build gate passes
- [ ] All failures fixed

---

### Step 5: Documentation & Delivery
**Status:** ⬜ Not Started

- [ ] CONTEXT.md updated if needed
- [ ] Discoveries logged

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
