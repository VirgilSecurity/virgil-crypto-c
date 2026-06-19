---
title: "New codegen class: set context=\"public\" and make length helpers is_const (not is_static)"
date: 2026-06-18
category: docs/solutions/best-practices
module: codegen
problem_type: best_practice
component: tooling
severity: medium
applies_when:
  - Adding a new foundation class model that has a <dependency> but no <property>
  - The class needs self / new / delete / use_random (stateful, context-bearing)
  - A buffer argument uses <length method=...> to size its output
  - Verifying the Swift wrapper compiles for the new class
resolution_type: code_fix
tags:
  - codegen
  - foundation
  - context
  - swift
  - length-method
  - class-model
---

# New codegen class: set context="public" and make length helpers is_const (not is_static)

## Context
When adding a class to the IR (`codegen/models/project_foundation/class_<name>.xml`), two subtle defaults can silently produce a broken class. Both surfaced authoring `class_shamir.xml` (a stateful class with a `random` dependency and `<length method=...>`-sized buffers).

## Guidance

**1. Set `context="public"` explicitly on a stateful class.** The IR derives "context" from whether the class declares `<property>` elements. A class with a `<dependency>` but **no** `<property>` has zero struct fields, so it defaults to `context="none"` — generating *stateless* free functions with no `self`, no `new`/`delete`, and no `use_random`. The dependency alone does not flip it. From `tools/codegen/project_ir.py`:
```python
# Classes without properties are static utilities — default to context="none"
context = cls.attrs.get("context")
if context is None and len(cls.struct_fields) == 0:
    context = "none"
elif context is None:
    context = "public"
```
So declare it:
```xml
<class name="shamir" context="public">
    <require impl="ctr drbg"/>
    <dependency name="random" interface="random"/>
```

**2. Length helpers referenced from a buffer arg must be `is_const="1"`, not `is_static="1"`.** A method used in `<length method=...>` is invoked as a member of the instance. If you mark it `is_static="1"` on a context-bearing class, the **Swift** generator emits `self.sharesLen(...)` on a static member → `error: static member 'sharesLen' cannot be used on instance of type 'Shamir'`. Use `is_const="1"`:
```xml
<method name="shares len" is_const="1">
    <argument name="secret len" type="size"/>
    <argument name="share count" type="size"/>
    <return type="size"/>
</method>
<method name="split">
    <argument name="out" class="buffer">
        <length method="shares len">
            <proxy argument="secret" to="secret len" cast="data_length"/>
            <proxy argument="share count" to="share count"/>
        </length>
    </argument>
    <return enum="status"/>
</method>
```

## Why This Matters
Leaving `context` to default on a dependency-bearing crypto class yields the opposite of what you need — stateless functions with no RNG. And a `is_static` length helper compiles in C but breaks the Swift wrapper, which only fails when the Apple frameworks are built (CI / `useLocalBinaries=true`), late and far from the model edit.

## When to Apply
- A `class_*.xml` has a `<dependency>` (or needs instance state) but no `<property>` → set `context` explicitly.
- A method is referenced inside a `<length method=...>` for a `class="buffer"` argument → mark it `is_const="1"`.

## Examples
`codegen/models/project_foundation/class_shamir.xml`: `share len` / `shares len` / `recovered secret len` are `is_const="1"`; `split` and `combine` reference them from `<length>` blocks with `<proxy>` argument mapping. The over-estimate buffer-sizing follows the `vscf_base64` `decode`/`decoded_len` precedent (a length method taking a scalar size, proxied via `cast="data_length"`).

## Related
- `docs/solutions/logic-errors/oid-enum-missing-from-codegen-model-2026-04-26.md` and `docs/solutions/best-practices/external-library-cmake-codegen-2026-04-26.md` — the "XML model is the single source of truth" family.
- `docs/solutions/best-practices/codegen-test-stale-assertions-2026-05-12.md` — an `is_static`→`is_const` change shifts generated Swift output and the file-count parity assertions.
- Surfaced shipping `vscf_shamir` (PR #207).
