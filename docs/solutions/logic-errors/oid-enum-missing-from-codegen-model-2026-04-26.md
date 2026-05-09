---
title: "OID enum constants silently stripped by codegen when model XML is not updated"
date: 2026-04-26
category: docs/solutions/logic-errors
module: foundation
problem_type: logic_error
component: tooling
severity: medium
symptoms:
  - "Running `bash tools/codegen/new_codegen.sh --apply` removes manually-added enum constants from vscf_oid_id.h"
  - "Diff after codegen shows `-    vscf_oid_id_ML_KEM_768,` and `-    vscf_oid_id_ML_DSA_65` being deleted"
  - "All 7 language wrappers lose the new OID constants silently after each codegen run"
root_cause: incomplete_setup
resolution_type: code_fix
tags:
  - codegen
  - oid
  - post-quantum
  - ml-kem
  - ml-dsa
  - enum
  - model-xml
  - generated-file
---

# OID enum constants silently stripped by codegen when model XML is not updated

## Problem

`vscf_oid_id_ML_KEM_768` and `vscf_oid_id_ML_DSA_65` were added manually to the generated C header `vscf_oid_id.h` during ML-KEM/ML-DSA implementation, but were never registered in the codegen model. Every subsequent run of `new_codegen.sh --apply` silently regenerated the header from the XML model, erasing the manually-added values and leaving all 7 language wrappers out of sync.

## Symptoms

- Running `bash tools/codegen/new_codegen.sh --apply all` produces a diff removing `vscf_oid_id_ML_KEM_768` and `vscf_oid_id_ML_DSA_65` from `library/foundation/include/virgil/crypto/foundation/vscf_oid_id.h`
- After codegen, all language wrapper files (`oid_id.go`, `OidId.java`, `OidId.php`, `_vscf_oid_id.py`, `oid_id.py`, `OidId.swift`, `OidId.js`) are missing the new constants
- No error is raised — the loss is completely silent
- The issue is invisible until codegen is explicitly run and the diff inspected

## What Didn't Work

Manually editing the generated C header (`vscf_oid_id.h`) appears to work at first — the C compiler sees the values and the implementation compiles. But `vscf_oid_id.h` is a partially-generated file: the enum body lives entirely inside the `@generated` / `@end` block markers, which codegen unconditionally overwrites on every run. The manual edit creates invisible, time-delayed data loss — silently reverted the next time anyone runs codegen.

## Solution

Add the missing constants to the authoritative codegen model `codegen/models/project_foundation/enum_oid_id.xml`, then re-run codegen.

**Before** (`enum_oid_id.xml`):

```xml
    <constant name="round5 nd 1cca 5d"/>
    <constant name="random padding"/>
</enum>
```

**After**:

```xml
    <constant name="round5 nd 1cca 5d"/>
    <constant name="random padding"/>
    <constant name="ml kem 768"/>
    <constant name="ml dsa 65"/>
</enum>
```

Then regenerate:

```bash
bash tools/codegen/new_codegen.sh --apply foundation
```

This propagated both constants to all 7 language wrappers in one shot. Example — `wrappers/go/foundation/oid_id.go` gained:

```go
OidIdMlKem768 OidId = 30
OidIdMlDsa65  OidId = 31
```

And `vscf_oid_id.h` now has the values inside the `@generated` block, so they survive future codegen runs.

## Why This Works

The codegen pipeline is fully model-driven. The XML files under `codegen/models/` are the single source of truth for every enum, type, and interface. The C header and all language wrappers are outputs regenerated deterministically from the model. Editing an output file has no effect on the model, so the change is silently reverted on the next codegen run. Adding the constants to `enum_oid_id.xml` makes the model authoritative for these values — codegen produces them consistently and propagates to every wrapper in one pass.

## Prevention

- **Never edit enum values inside a `@generated` block.** Files with `This file is partially generated` and `@generated` / `@end` markers treat that block as write-once output. Edits there are unconditionally overwritten.
- **Find and update the XML model first.** For any enum in the `foundation` library, the model is at `codegen/models/project_foundation/enum_<name>.xml`. Add `<constant name="..."/>` there before writing implementation code that depends on the new value.
- **Verify codegen state before committing.** After any feature touching generated code, run `bash tools/codegen/new_codegen.sh --apply all` and check `git diff`. A clean diff confirms model and generated files are in sync.
- **Let codegen propagate to all wrappers.** Do not add wrapper-language constants by hand — running codegen after updating the XML model updates all 7 language targets at once and keeps numeric ordinal assignments consistent.

## Related Issues

- Same class of problem documented for cmake: [`docs/solutions/best-practices/external-library-cmake-codegen-2026-04-26.md`](../best-practices/external-library-cmake-codegen-2026-04-26.md) — handwritten `thirdparty/*/features.cmake` files drifting from their XML models. Same root pattern: any artifact owned by codegen must be registered in the XML model, never edited directly.
