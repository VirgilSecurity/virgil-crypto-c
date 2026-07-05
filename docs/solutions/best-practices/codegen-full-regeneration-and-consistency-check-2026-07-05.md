---
title: "Codegen: regenerate all wrappers from the model, and verify model↔code consistency with a clean-diff check"
date: 2026-07-05
category: docs/solutions/best-practices
module: codegen
problem_type: best_practice
component: tools/codegen
severity: medium
symptoms:
  - "Added/changed a foundation class or interface in the IR model and unsure which files must be committed"
  - "A hand-written wrapper test (Java/Go) fails to compile after a model change renamed a generated getter"
  - "Want to confirm the committed generated code actually matches the current IR models"
  - "Unsure whether a hand edit landed in a generated region that codegen will overwrite"
root_cause: partial_or_unverified_codegen_regeneration
resolution_type: workflow
tags:
  - codegen
  - wrappers
  - java
  - go
  - swift
  - wasm
  - python
  - consistency
  - model
---

# Codegen: regenerate all wrappers, and verify consistency with a clean-diff check

Every language wrapper in this repo (Java, Go, Swift, WASM, PHP, Python) is
**committed to the tree** — generated from the IR models under
`codegen/models/`. There is no generate-at-build step for the wrappers, so the
committed bindings and the models can silently drift. Two rules keep them in
sync.

## 1. After any model change, regenerate the whole project and commit everything

A change to a class/interface in `codegen/models/project_foundation/` fans out
to the public header, `_defs`/`_internal`, the C stub, factory/registry wiring,
**and every language wrapper**. Regenerate all of it in one go:

```bash
python3 -m tools.codegen.common_bootstrap --project foundation --apply
# or --project all --apply
```

Then commit the full diff. Do **not** hand-edit generated regions (anything
between `@generated`/`@end` tags, `_defs.*`, `_internal.*`, and the wrapper
sources) — a re-run reverts them. Only fill algorithm logic into the
hand-editable method-body regions of `vscf_<name>.c` (and `_internal.c`).

## 2. Verify consistency with a clean-diff check

To confirm the committed generated code matches the current models, regenerate
into a clean tree and diff:

```bash
git status --short            # must be clean first
python3 -m tools.codegen.common_bootstrap --project foundation --apply
git status --short            # EXPECT: empty (no drift)
```

- **Empty diff** → models and committed code are consistent.
- **Diff in canonical sources** (`library/foundation/**`, `wrappers/**` sources)
  → real drift: either the model changed without a regenerate, or someone
  hand-edited a generated region. Investigate before shipping.
- **Diff only in `wrappers/go/pkg/**/*_platform.h`** → benign. Those are
  committed Go *prebuilt* headers (build artifacts, rebuilt at release); a
  cosmetic license-comment whitespace difference there is not model drift.
  Revert it (`git checkout -- wrappers/go/pkg/`).

Revert any consistency-check output you did not intend to commit.

## Gotcha: hand-written wrapper tests can break when a model change renames a generated method

Wrapper *sources* regenerate, but hand-written wrapper *tests* do not. Adding an
interface to a class can rename its generated accessors, silently breaking a
test that still calls the old name.

Concrete case (this repo): giving `chunk_cipher` the `cipher_info` interface
changed the generated getter from `nonceLen()` to `getNonceLen()`. The
generated `ChunkCipher.java`/`.go` updated automatically, but the hand-written
`ChunkCipherTest.java` still called `cipher.nonceLen()` and failed to compile
(`Test JVM Build` red). Fix: update the test to the current binding method
(`getNonceLen()`), not a workaround.

After a model change that touches a class's interface set, grep the hand-written
wrapper tests for the affected accessors and update them. See also
[[codegen-test-stale-assertions-2026-05-12]] (pre-existing codegen pytest
drift) and [[go-cgo-stale-committed-pkg-headers-2026-06-18]] (committed Go
prebuilt libs/headers go stale until release).
