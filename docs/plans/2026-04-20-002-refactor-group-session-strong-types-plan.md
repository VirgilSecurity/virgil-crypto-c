---
title: "refactor: Convert group session typedefs to strong struct types"
type: refactor
status: done
date: 2026-04-20
---

# refactor: Convert group session typedefs to strong struct types

## Overview

The five group session key/identity types (`public_key`, `private_key`, `symmetric_key`, `id`, `salt`) are currently plain array typedefs in `codegen/models/project_foundation/module_group_session_typedefs.xml`:

```c
typedef uint8_t vscf_group_session_symmetric_key_t[32];
```

C array typedefs are weak types — they decay to `uint8_t *` in function parameters, provide no type safety between distinct key/id/salt roles (all are `uint8_t[32]`), and cannot be passed by value. The goal is to replace each with a named struct:

```c
typedef struct vscf_group_session_symmetric_key_t {
    uint8_t bytes[32];
} vscf_group_session_symmetric_key_t;
```

Each type is split into its own `class_*.xml` file with `scope="internal"` so it stays an internal (non-distributed) header.

**Known defect this enables catching:** `vscf_message_cipher_setup_cipher` is declared `(self, key, salt)` but called as `setup_cipher(self, salt, key)` at both call sites (lines 333 and 350) — silently swapping the symmetric key and the salt passed to HKDF. With identical array typedefs the compiler cannot catch this. Once `vscf_group_session_symmetric_key_t` and `vscf_group_session_salt_t` are distinct struct types, the swapped arguments will produce a compile error. The actual bug fix is a separate task after this refactoring.

## Problem Frame

The five types are semantically distinct but type-system identical under the current `typedef uint8_t T[32]` scheme. A function accepting `vscf_group_session_symmetric_key_t` silently accepts `vscf_group_session_salt_t`. Struct wrapping creates genuinely distinct types, making argument-order bugs like the `setup_cipher` key/salt swap a compile error rather than a silent crypto vulnerability. It also removes reliance on array-decay semantics that make call sites fragile and implicit.

## Requirements Trace

- R1. Each of the five types becomes a named struct with a single `uint8_t bytes[32]` member.
- R2. Each type lives in its own `class_*.xml` with `scope="internal"`, `context="public"`, `lifecycle="none"`.
- R3. `module_group_session_typedefs.xml` is deleted; all XML `<require>` references updated.
- R4. The codegen regenerates cleanly with no errors.
- R5. The library builds and all tests pass after updating hand-written C callers.

## Scope Boundaries

- Only the five types in `module_group_session_typedefs.xml` (foundation project).
- `module_ratchet_typedefs.xml` follows the same pattern but is a separate task.
- No public API changes — all five types are in `scope="internal"` headers.

### Deferred to Separate Tasks

- **Fix the `setup_cipher` key/salt argument swap bug**: Once the types are distinct and the compile error surfaces (lines 333 and 350 in `vscf_message_cipher.c`), assess backward compatibility before swapping the arguments at call sites. Handled in a follow-up task.

## Context & Research

### Relevant Code and Patterns

- **Source module:** `codegen/models/project_foundation/module_group_session_typedefs.xml`
- **Pattern to follow — inline-struct class:** `codegen/models/project_foundation/class_ecies_envelope.xml`
  — uses `scope="internal"`, `context="public"`, `lifecycle="none"`; generates an inline struct in the header (no separate `_defs.h`).
- **Existing consumer class:** `codegen/models/project_foundation/class_group_session_epoch.xml`
  — has `<property name="key" class="vscf_group_session_symmetric_key_t" .../>` which will continue to reference the new class name.
- **XML models that require the typedefs module:**
  - `class_group_session.xml`
  - `class_group_session_epoch.xml`
  - `class_group_session_ticket.xml`
  - `class_message_cipher.xml` (requires with `scope="public"` — pulls typedefs into private header)
- **Generated headers (will be overwritten by codegen):**
  - `library/foundation/src/vscf_group_session_typedefs.h` (deleted after migration)
  - `library/foundation/src/vscf_group_session_epoch.h`
  - `library/foundation/src/vscf_group_session_defs.h`
  - `library/foundation/include/virgil/crypto/foundation/private/vscf_message_cipher.h`
- **Hand-written C files that use the types directly (need manual updates):**
  - `library/foundation/src/vscf_message_cipher.c` — passes types as function parameters (array-decay), then calls `vsc_data(key, sizeof(...))` treating them as `uint8_t *`
  - `library/foundation/src/vscf_group_session_ticket.c` — uses `sizeof(T)` and `vsc_buffer_use(..., ptr, sizeof(T))` where `ptr` is a raw byte pointer from protobuf
- **Scope/lifecycle rules:** `scope="internal"` + `context="public"` triggers inline struct generation (no separate `_defs.h`). `lifecycle="none"` suppresses init/new/delete/copy generation. See `tools/codegen/project_c_backend.py` inline_struct logic.

### Institutional Learnings

- `docs/solutions/` does not exist. The scope/lifecycle knowledge comes from `tools/codegen/ARCHITECTURE.md` and `class_ecies_envelope.xml` as the canonical local example.

## Key Technical Decisions

- **Field name `bytes`**: All five types hold opaque byte payloads, not semantically meaningful sub-fields. `bytes` is the most honest name and is uniform across all five types, avoiding confusion where `key` on an `_id_t` struct would be misleading.
- **`lifecycle="none"`**: These are value types (fixed-size POD structs). No heap allocation, no init/cleanup. Matches `class_ecies_envelope.xml` and `class_error.xml`.
- **`scope="internal"` + `context="public"`**: Keeps headers in `src/` (not distributed), but generates the struct definition inline in the header (not forward-declared only), so code that embeds the struct by value in other structs compiles correctly.
- **One class per type, not a single multi-type module**: Matches the user's explicit request, enables independent `<require>` at the class level, and follows the naming convention of all other foundation classes.

## Open Questions

### Resolved During Planning

- **Is `declaration="public"` on `c_alias` the same as struct-scope public?** No — `declaration` controls typedef placement within the generated file. After conversion to a class, visibility is controlled by `scope` and `context` attributes on the class element.
- **Does `class_message_cipher.xml` requiring the typedefs module `scope="public"` affect the public API?** The private header is in `include/.../private/` not `include/`, so it is private API (not distributed as the public interface). After conversion, the `<require>` entries will change to reference each new class.

### Deferred to Implementation

- **Exact XML DSL for `uint8_t bytes[32]` property**: Check `tools/codegen/project_ir.py` for how `type="byte"` with a fixed count is parsed. `class_data.xml` uses `<array length="given"/>` (variable-length pointer), not a fixed inline array. The fixed-size variant may use `length="derived"` or a `count=` attribute — confirm before writing Unit 1 XML. Note: using `class_data` (i.e., `vsc_data_t`) as the field type was considered but rejected — `vsc_data_t` is a non-owning view `{const uint8_t *; size_t}` which would break embedded struct cases like `vscf_group_session_epoch_t` that store these types inline.
- **Whether `class_message_cipher.xml` `<require>` entries need one entry per new class or can group them**: Determine from examining how other classes require multiple peer internal classes.

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance for review, not implementation specification.*

**Before (current):**
```
module_group_session_typedefs.xml
  └─ c_alias: vscf_group_session_symmetric_key_t[32] → uint8_t
  └─ c_alias: vscf_group_session_id_t[32] → uint8_t
  └─ ... (3 more)

Generated: typedef uint8_t vscf_group_session_symmetric_key_t[32];
```

**After (target):**
```
class_group_session_symmetric_key.xml  (scope=internal, context=public, lifecycle=none)
  └─ property: bytes, type=byte, count=32

Generated: typedef struct { uint8_t bytes[32]; } vscf_group_session_symmetric_key_t;
```

**Call site migration pattern (vscf_message_cipher.c):**
```
Before: vsc_data(key, sizeof(vscf_group_session_symmetric_key_t))
After:  vsc_data(key.bytes, sizeof(key.bytes))

Before: vscf_hkdf_reset(hkdf, vsc_data(salt, sizeof(vscf_group_session_salt_t)), 0)
After:  vscf_hkdf_reset(hkdf, vsc_data(salt.bytes, sizeof(salt.bytes)), 0)
```

## Implementation Units

- [ ] **Unit 1: Create class XML files for all five strong types**

**Goal:** Replace the five `<c_alias>` entries with five `class_*.xml` files, each defining a named struct with `uint8_t bytes[32]`.

**Requirements:** R1, R2

**Dependencies:** None

**Files:**
- Create: `codegen/models/project_foundation/class_group_session_public_key.xml`
- Create: `codegen/models/project_foundation/class_group_session_private_key.xml`
- Create: `codegen/models/project_foundation/class_group_session_symmetric_key.xml`
- Create: `codegen/models/project_foundation/class_group_session_id.xml`
- Create: `codegen/models/project_foundation/class_group_session_salt.xml`

**Approach:**
- Mirror `class_ecies_envelope.xml` for the outer element: `scope="internal"`, `context="public"`, `lifecycle="none"`.
- Each file contains a single property named `bytes`, type byte, fixed count 32.
- No `<require>` entries needed — these are leaf types that only need `stdint.h` (already pulled in by the generated preamble).
- Confirm the exact DSL for a fixed-size byte array property against `tools/codegen/project_ir.py` before writing (see deferred questions).

**Patterns to follow:**
- `codegen/models/project_foundation/class_ecies_envelope.xml` (scope, context, lifecycle)
- `codegen/models/project_common/class_data.xml` (may have a fixed-size byte array property)

**Test scenarios:**
- Test expectation: none — pure XML model authoring, no behavioral change yet; correctness is verified in Unit 3 after codegen runs.

**Verification:**
- Five XML files exist, each well-formed, with the correct outer element attributes.

---

- [ ] **Unit 2: Migrate XML `<require>` references and delete the typedefs module**

**Goal:** Remove all references to `module="group session typedefs"` and replace with individual class requires; delete the now-unused module file.

**Requirements:** R3

**Dependencies:** Unit 1

**Files:**
- Modify: `codegen/models/project_foundation/class_group_session.xml`
- Modify: `codegen/models/project_foundation/class_group_session_epoch.xml`
- Modify: `codegen/models/project_foundation/class_group_session_ticket.xml`
- Modify: `codegen/models/project_foundation/class_message_cipher.xml`
- Delete: `codegen/models/project_foundation/module_group_session_typedefs.xml`

**Approach:**
- In each class, replace `<require module="group session typedefs" scope="..."/>` with one `<require class="group session {type}" scope="..."/>` for each of the five new classes that the consumer actually uses (don't blindly add all five to every file — add only what each class needs).
- In `class_group_session_epoch.xml`, the `<property name="key" class="vscf_group_session_symmetric_key_t" .../>` attribute may need updating if the codegen looks up the class by XML name rather than the generated C name. Verify by checking how `class=` attribute values are resolved in `project_ir.py`.
- In `class_message_cipher.xml`, the require currently uses `scope="public"` which pulls the typedefs into the private message_cipher header. The equivalent per-class requires should preserve this scope.

**Patterns to follow:**
- Any existing class that requires multiple internal peer classes, e.g., how `class_group_session.xml` currently requires other group session submodules.

**Test scenarios:**
- Test expectation: none — XML wiring change; correctness is verified in Unit 3.

**Verification:**
- No XML file references `module="group session typedefs"`.
- `module_group_session_typedefs.xml` is deleted from the repo.

---

- [ ] **Unit 3: Regenerate C headers and verify struct shape**

**Goal:** Confirm that codegen produces well-formed struct typedefs in the correct header locations with no generation errors.

**Requirements:** R4

**Dependencies:** Units 1 and 2

**Files:**
- Overwrite (generated): `library/foundation/src/vscf_group_session_public_key.h` (new)
- Overwrite (generated): `library/foundation/src/vscf_group_session_private_key.h` (new)
- Overwrite (generated): `library/foundation/src/vscf_group_session_symmetric_key.h` (new)
- Overwrite (generated): `library/foundation/src/vscf_group_session_id.h` (new)
- Overwrite (generated): `library/foundation/src/vscf_group_session_salt.h` (new)
- Delete (generated): `library/foundation/src/vscf_group_session_typedefs.h`
- Overwrite (generated): `library/foundation/src/vscf_group_session_epoch.h`
- Overwrite (generated): `library/foundation/src/vscf_group_session_defs.h`
- Overwrite (generated): `library/foundation/include/virgil/crypto/foundation/private/vscf_message_cipher.h`

**Approach:**
- Run `python3 -m tools.codegen.common_bootstrap --project foundation --apply` (per CLAUDE.md).
- Inspect each new header for the correct struct layout: `typedef struct vscf_group_session_*_t { uint8_t bytes[32]; } vscf_group_session_*_t;`.
- Confirm headers land in `library/foundation/src/` (scope=internal), not in `include/`.
- Confirm `vscf_group_session_epoch.h` still embeds `vscf_group_session_symmetric_key_t key;` (struct member, now a by-value struct).
- Confirm `vscf_group_session_typedefs.h` no longer exists (deleted or not regenerated).
- Confirm `vscf_message_cipher.h` function signatures update to use struct parameter types.
- If codegen errors out, diagnose against deferred implementation unknowns (field property syntax).

**Test scenarios:**
- Test expectation: none — generated file inspection; compilation correctness verified in Unit 4.

**Verification:**
- Codegen runs without errors.
- Five new internal headers exist with inline struct definitions.
- `vscf_group_session_typedefs.h` is gone.
- `vscf_message_cipher.h` private header compiles (it's included in Unit 4's build check).

---

- [ ] **Unit 4: Update hand-written C callers and fix the build**

**Goal:** Migrate all hand-written C code that uses these types via array-decay semantics to use the `.bytes` struct member. Confirm the library builds and tests pass.

**Requirements:** R5

**Dependencies:** Unit 3

**Files:**
- Modify: `library/foundation/src/vscf_message_cipher.c`
- Modify: `library/foundation/src/vscf_group_session_ticket.c`
- Test: `build/` (existing ctest suite)

**Approach:**
- Grep `library/` for usages of the five type names in `.c` and hand-written `.h` files (exclude generated headers).
- In `vscf_message_cipher.c`:
  - Function parameters `const vscf_group_session_symmetric_key_t key` remain by-value struct parameters (no decay issue since the function signature is hand-written; the generated header will already reflect struct types).
  - Update all `vsc_data(key, sizeof(...))` to `vsc_data(key.bytes, sizeof(key.bytes))`.
  - Update all `vsc_data(salt, sizeof(...))` to `vsc_data(salt.bytes, sizeof(salt.bytes))`.
  - Any other array indexing (`key[i]`) → `key.bytes[i]`.
- In `vscf_group_session_ticket.c`:
  - `sizeof(vscf_group_session_symmetric_key_t)` — still valid (struct is 32 bytes, sizeof unchanged).
  - `vsc_buffer_use(&root_key, self->msg->message_pb.group_info.key, sizeof(...))` — the second argument is a raw byte pointer from the protobuf struct (not a vscf type), so this line is unaffected.
  - If any local variables of these types use array indexing, update to `.bytes`.
- Build: `cmake -DCMAKE_BUILD_TYPE=Release -Bbuild -S. && cmake --build build -j$(nproc)`.
- Fix any remaining compilation errors surfaced by the build (there may be additional callers not listed above).
- Run: `cd build && ctest --output-on-failure`.

**Patterns to follow:**
- Existing usage of `vsc_data()` throughout the codebase: `vsc_data(ptr, len)` where `ptr` is `const uint8_t *`.

**Test scenarios:**
- Happy path: Library compiles cleanly with no errors or warnings related to the five types.
- Happy path: `ctest` passes for all foundation tests (group session encrypt/decrypt flows).
- Edge case: `sizeof(vscf_group_session_symmetric_key_t)` should still be 32 — verify no padding was introduced by the struct definition (single `uint8_t` array member has no padding).
- Integration: Existing group session tests exercise encrypt/decrypt paths that call `vscf_message_cipher_pad_then_encrypt` and `vscf_message_cipher_decrypt_then_remove_pad` — these prove the call-site migration is correct end to end.

**Verification:**
- `cmake --build build` exits 0 with no new warnings.
- `ctest` passes all foundation tests.
- `sizeof(vscf_group_session_symmetric_key_t) == 32` can be confirmed via a static assert or test output.

## System-Wide Impact

- **Interaction graph:** Changes are confined to `library/foundation/`. No callbacks or observers are involved — these are plain value types.
- **Error propagation:** N/A — value types, no error-returning constructors.
- **State lifecycle risks:** None — no heap allocation or reference counting.
- **API surface parity:** Other language wrappers (Python, Java, Go, Swift, PHP, WASM) are generated by the codegen pipeline. After Unit 3 regenerates foundation, running `python3 -m tools.codegen.common_bootstrap --project all --apply` propagates the type change to all wrapper languages. This is deferred to a follow-up — the C library must compile and test first.
- **Integration coverage:** The existing ctest suite exercises the group session encrypt/decrypt flow which exercises all five types end-to-end.
- **Unchanged invariants:** The size of each type remains 32 bytes. `sizeof` usage in callers is safe. External binary protocol formats are unaffected (protobuf handles serialization separately from these C types).

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Codegen DSL has no direct syntax for `uint8_t bytes[32]` property | Check `class_data.xml` and `project_ir.py` during Unit 1. If unsupported, use a `<struct>` element or add minimal DSL support before proceeding. |
| Additional hand-written callers of these types not found in the pre-plan grep | Build in Unit 4 surfaces all remaining errors; fix them before marking done. |
| Struct padding changes `sizeof` | Single `uint8_t` array member has no padding. Verify with a static assert in Unit 4 tests. |
| Wrapper language codegen breaks | Out of scope for this plan; addressed in a separate `python3 -m tools.codegen.common_bootstrap --project all --apply` pass after the C library is verified. |

## Sources & References

- Source module: `codegen/models/project_foundation/module_group_session_typedefs.xml`
- Inline-struct class pattern: `codegen/models/project_foundation/class_ecies_envelope.xml`
- Scope/lifecycle rules: `tools/codegen/ARCHITECTURE.md`
- Codegen command: `python3 -m tools.codegen.common_bootstrap --project foundation --apply` (per `CLAUDE.md`)
