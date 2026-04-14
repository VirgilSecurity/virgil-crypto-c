---
title: "feat: Generate platform.go from cgo_link source XML"
type: feat
status: active
date: 2026-04-14
---

# feat: Generate platform.go from cgo_link source XML

## Context

The Go wrapper port (Units 1–5, commits `0a7072d8a` → `74ffc21d7` on
`feature/new-generator`) regenerates every `wrappers/go/{project}/*.go`
file from source XML — except `platform.go`. That single file was
explicitly deferred because the source XML's `<cgo_link>` entries
(4 per project) no longer match the legacy file's hand-tuned 6 entries
(`darwin,amd64`, `darwin,arm64`, `linux,amd64,!legacy`,
`linux,amd64,legacy`, `linux,arm64`, `windows`).

Git archaeology (commits `5453b6870`, `525610f4f`, `be4c75aa4`)
confirms the legacy file was hand-edited to add arm64 support
without going back to update the source XML. Re-applying the codegen
today silently regenerates a 4-entry `platform.go` that drops arm64
build targets and the legacy-linux split — a real regression.

This plan closes the last gap in the Go codegen by teaching the new
backend to emit `platform.go` from the existing 4-entry source XML
via a hardcoded expansion table. The user explicitly chose
"fully codegen it" over enriching source XML — adding new platforms
will mean editing the Python expansion table, not touching XML.

## Problem Frame

`generate_go_files` produces 124 of 125 expected files for foundation
and 11 of 12 for phe. The missing file (`platform.go`) is what cgo
uses to discover headers and link static libraries from
`wrappers/go/pkg/{platform_arch}/`. Without it, `go build` finds no
includes — every other generated file is dead weight on disk.

The source XML has 4 `<cgo_link>` entries per Go-wrapped project:

```xml
<cgo_link platform="darwin"        libraries="..."/>
<cgo_link platform="linux,!legacy" path="linux_amd64"            libraries="..."/>
<cgo_link platform="linux,legacy"  path="linux_amd64__legacy_os" libraries="..."/>
<cgo_link platform="windows"       libraries="..."/>
```

The legacy `platform.go` has 6 `// #cgo` pairs because of these
project-policy expansions:

| Source platform | Expands to | Path |
|---|---|---|
| `darwin` | `darwin,amd64` | `darwin_amd64` |
| `darwin` | `darwin,arm64` | `darwin_arm64` |
| `linux,!legacy` | `linux,amd64,!legacy` | `linux_amd64` (verbatim) |
| `linux,!legacy` | `linux,arm64` | `linux_arm64` |
| `linux,legacy` | `linux,amd64,legacy` | `linux_amd64__legacy_os` |
| `windows` | `windows` | `windows_amd64` |

The expansion is asymmetric — `linux,legacy` does NOT spawn an arm64
variant (no legacy-linux on arm64), `windows` keeps no arch suffix
in the platform spec, and `darwin` is the only one that spawns two
distinct paths.

## Requirements Trace

- R1. Generate `wrappers/go/foundation/platform.go` byte-identical to
  the legacy file
- R2. Generate `wrappers/go/phe/platform.go` byte-identical to the
  legacy file
- R3. Wire generation into `generate_go_files` so the standard
  pipeline picks it up alongside every other Go output
- R4. Skip projects without Go bindings (common, pythia, ratchet)
  even if they declare `<cgo_link>` entries — the gate is the
  `wrappers="...,go,..."` attribute, not cgo_link presence
- R5. Restore Unit 4.7's full file-count parity: 125/125 foundation,
  12/12 phe

## Scope Boundaries

- This plan only adds `platform.go` generation. Other Go output
  (enums, interfaces, classes, impls, dispatch, infrastructure)
  already works.
- The expansion table is hardcoded for the current target set. New
  platforms (e.g., `freebsd`, `riscv64`) would need a Python edit,
  not an XML change — this is the trade-off accepted in the
  planning question.
- This plan does NOT reconcile source XML with the legacy file. The
  source XML stays at 4 entries; the generator owns expansion.

### Deferred to Separate Tasks

- Cutover to make the new codegen authoritative for `platform.go`
  (ship a commit that re-applies codegen and replaces the legacy
  file): a separate slice once parity is verified.
- Retiring `codegen/go.gsl` / `codegen/go_codegen.gsl` entirely:
  separate work, blocked on this plan landing.

## Context & Research

### Relevant Code and Patterns

- `tools/codegen/project_go_backend.py::generate_go_context` and
  `generate_go_helper` — established pattern for per-project
  infrastructure file generators (no IR-driven content, mostly
  templated text)
- `tools/codegen/project_go_backend.py::generate_go_files` — the
  orchestrator that needs one new `files.append((...))` line
- `tools/codegen/project_source.py:_attrs_with_child_shapes` —
  pattern for capturing XML element attrs into a flat dict
- `tools/codegen/project_ir.py::IRProject` — dataclass to extend
  with a typed `cgo_links` field (list of dicts)
- Legacy reference for byte-parity: `wrappers/go/foundation/platform.go`
  and `wrappers/go/phe/platform.go`

### Institutional Learnings

- Six prior Go-codegen slices established that byte-for-byte parity
  against legacy files is the right verification standard — it
  catches subtle issues (whitespace, ordering, missing imports) that
  `go build` won't.
- Legacy GSL output tends to leak hand-edited drift back into the
  generator's expected output. We accepted that trade-off across
  Units 4.1–4.4. For `platform.go` the drift IS the entire reason
  for this plan — we're choosing the legacy file's intent over the
  source XML's literal content.

### Where the IR Currently Stops

The exploration confirmed:
- `ProjectSource` (parser output) does NOT capture `<cgo_link>`
  elements today
- `IRProject` likewise has no `cgo_links` field
- Source parser at `tools/codegen/project_source.py:load_project_source()`
  iterates `<require>`, `<feature>`, `<module>`, `<class>`,
  `<enum>`, `<interface>`, `<implementor>` — `<cgo_link>` is a sibling
  element that needs adding
- `project_to_ir` in `tools/codegen/project_ir.py` will need a
  pass-through for the new field

## Key Technical Decisions

- **Hardcoded expansion table in Python** (per user choice): a single
  dict in `project_go_backend.py` maps each source platform spec to
  the expanded `(platform_spec, path)` pairs. Asymmetries (no
  arm64-legacy, windows no arch suffix) live in the table, not in
  generic logic.
- **Pass-through dict on the IR**: `cgo_links: list[dict[str, str]]`
  on both `ProjectSource` and `IRProject`. The expansion is presentation
  logic owned by the wrapper backend; the IR just carries the raw
  attrs. This keeps the C backend untouched and avoids inventing a
  typed `IRCgoLink` for a single consumer.
- **Library string used verbatim**: legacy emits the source XML's
  `libraries` attribute as-is. The arm64 expansion of
  `linux,!legacy` reuses the parent's libraries string verbatim
  (which is why `linux,arm64` ends up with `-lpthread`).
- **Skip projects without Go bindings**: `cgo_link` entries exist
  in `pythia` and `ratchet` source XML even though they don't ship
  Go wrappers. The orchestrator already gates Go output on
  `wrappers="...,go,..."` — `platform.go` falls under the same gate
  with no extra logic needed.

## Open Questions

### Resolved During Planning

- **Where does platform expansion live?** Python codegen (user
  choice).
- **Is `<cgo_link>` in the IR today?** No — needs adding to both
  `ProjectSource` and `IRProject`.
- **Does anything consume `platform.go` directly?** No — it's
  cgo-discovered. No CI / Makefile references found. Means we can
  rebuild it byte-for-byte without coordinating with other systems.

### Deferred to Implementation

- **Test file location**: place `platform.go` parity tests in the
  existing `tools/codegen/test_go_backend.py` alongside other
  byte-parity tests, or split into a new file? Decide during
  implementation based on test count.
- **Behavior when source XML has unrecognized platform spec**:
  for now, skip with a warning. Tighten to a hard error if the test
  matrix proves no project uses unrecognized specs.

## High-Level Technical Design

> *This illustrates the intended approach and is directional guidance
> for review, not implementation specification. The implementing agent
> should treat it as context, not code to reproduce.*

The expansion table maps source platform-spec to a list of emitted
`(platform_spec, path_suffix_override)` pairs. `None` for the path
override means use the source's own `path` (or fall back to
`{platform}_amd64`).

```text
EXPANSIONS = {
    "darwin":        [("darwin,amd64", "darwin_amd64"),
                      ("darwin,arm64", "darwin_arm64")],
    "linux,!legacy": [("linux,amd64,!legacy", None),  # use src path
                      ("linux,arm64",         "linux_arm64")],
    "linux,legacy":  [("linux,amd64,legacy",  None)],
    "windows":       [("windows",             None)],
}
```

The generator then emits two lines per expanded pair:

```text
// #cgo {platform_spec} CFLAGS:  -I${SRCDIR}/../pkg/{path}/include/
// #cgo {platform_spec} LDFLAGS: -L${SRCDIR}/../pkg/{path}/lib {libraries}
```

Followed by a single `import "C"` and a trailing blank line — same
shape as `context.go`.

## Implementation Units

- [ ] **Unit 1: Capture `<cgo_link>` in source parser and IR**

  **Goal:** Make `<cgo_link>` elements visible to the Go backend by
  threading them through `ProjectSource` → `IRProject` as a
  pass-through dict list.

  **Requirements:** R1, R2

  **Dependencies:** None

  **Files:**
  - Modify: `tools/codegen/project_source.py`
  - Modify: `tools/codegen/project_ir.py`
  - Test: `tools/codegen/test_go_backend.py`

  **Approach:**
  - Add `cgo_links: list[dict[str, str]] = field(default_factory=list)`
    to `ProjectSource`
  - In `load_project_source`, capture `[dict(e.attrib) for e in
    root.findall("cgo_link")]` next to the existing `<require>` /
    `<feature>` collectors
  - Add the same field to `IRProject` and copy through in
    `project_to_ir`

  **Patterns to follow:**
  - `tools/codegen/project_source.py` existing collectors near
    `library_requires` and `error_message_getter`
  - `tools/codegen/project_source.py:_attrs_with_child_shapes` for
    the dict-from-attrs pattern (though here we use `dict(e.attrib)`
    directly since `<cgo_link>` has no nested children we care about)

  **Test scenarios:**
  - Happy path: load foundation source, assert `cgo_links` has 4
    entries with the expected platform/path/libraries values
  - Happy path: load phe source, assert `cgo_links` has 4 entries
  - Edge case: load common source, assert `cgo_links` is empty (no
    `<cgo_link>` in the XML)
  - Round-trip: project_to_ir preserves the field byte-identical to
    the source

  **Verification:**
  - All 75 existing Go backend tests still pass
  - The C backend tests pass unchanged (no new IR field consumed
    there)

- [ ] **Unit 2: Expansion table + `generate_go_platform`**

  **Goal:** Pure-function generator that takes an IRProject and
  returns the platform.go file content.

  **Requirements:** R1, R2

  **Dependencies:** Unit 1

  **Files:**
  - Modify: `tools/codegen/project_go_backend.py`
  - Test: `tools/codegen/test_go_backend.py`

  **Approach:**
  - Define a module-level `_PLATFORM_EXPANSIONS` dict keyed by source
    `platform` string, value = list of `(emitted_platform_spec,
    path_override_or_None)` tuples (see High-Level Technical Design)
  - `generate_go_platform(project_ir) -> str`:
    - Package header from `_package_name(project_ir)`
    - Iterate `project_ir.cgo_links` in source order
    - For each entry, look up the expansion (silently skip if
      not in table)
    - For each expanded `(spec, path_override)`:
      - Resolve path: `path_override` if set, else source's
        `path` attr, else `{platform}_amd64`
      - Emit `// #cgo {spec} CFLAGS: -I${SRCDIR}/../pkg/{path}/include/`
      - Emit `// #cgo {spec} LDFLAGS: -L${SRCDIR}/../pkg/{path}/lib {libraries}`
    - Trailing `import "C"` + blank line, matching the legacy
      file shape

  **Patterns to follow:**
  - `tools/codegen/project_go_backend.py:generate_go_context` —
    same templating shape (package + cgo + import "C" + blank line)
  - `tools/codegen/project_go_backend.py:generate_go_helper` — for
    the "no IR-driven body, just templated text" feel

  **Test scenarios:**
  - Happy path: foundation regenerates byte-identical to
    `wrappers/go/foundation/platform.go` — verify with
    `assertEqual(generate_go_platform(ir), Path(legacy).read_text())`
  - Happy path: phe regenerates byte-identical to
    `wrappers/go/phe/platform.go`
  - Edge case: when source XML has `path="X"` set, the override is
    used (linux,!legacy → linux,amd64,!legacy uses `linux_amd64`
    not the synthesized `linux_amd64`). Confirms the path attribute
    is honored
  - Edge case: when source XML omits `path` (darwin, windows), the
    fallback `{platform}_amd64` resolves correctly (darwin →
    `darwin_amd64`, windows → `windows_amd64`)
  - Edge case: an unrecognized platform spec is silently skipped (no
    crash, no output line) — verify with a synthesized IR carrying
    a fake `<cgo_link platform="freebsd" libraries="..."/>`

  **Verification:**
  - Both byte-parity tests pass against legacy
  - The generated file passes `gofmt` (mainly checking no syntax
    errors slipped in)

- [ ] **Unit 3: Wire `platform.go` into `generate_go_files`**

  **Goal:** Restore full file-count parity by adding `platform.go`
  to the orchestrator's output set for projects with Go bindings.

  **Requirements:** R3, R4, R5

  **Dependencies:** Unit 2

  **Files:**
  - Modify: `tools/codegen/project_go_backend.py`
  - Test: `tools/codegen/test_go_backend.py`

  **Approach:**
  - In `generate_go_files`, after the existing infrastructure block
    (`context.go`, `helper.go`, `{project}_error.go`), add a single
    `files.append((f"{output_dir}platform.go",
    generate_go_platform(project_ir)))` line
  - No conditional needed — the orchestrator only runs for projects
    where the wrappers attribute lists `go`, and those projects
    always declare `<cgo_link>` entries; an empty `cgo_links` list
    produces an empty (but valid) file

  **Patterns to follow:**
  - The existing infrastructure-file additions already in
    `generate_go_files` (context, helper, error)

  **Test scenarios:**
  - Happy path: `generate_go_files(foundation_ir)` includes
    `wrappers/go/foundation/platform.go` in its output
  - Happy path: `generate_go_files(phe_ir)` includes
    `wrappers/go/phe/platform.go`
  - File-count parity: total foundation file set is now 125 (was
    124 before this plan), matching legacy exactly. Same for phe
    going 11 → 12.
  - Update the existing `test_no_test_files_emitted` /
    `test_no_handwritten_crypto_layer_emitted` umbrella tests to
    include platform.go in the expected set

  **Verification:**
  - `python3 tools/codegen/common_bootstrap.py --project foundation
    --apply` writes `platform.go` alongside every other Go file
  - `git diff wrappers/go/foundation/platform.go` after applying
    shows zero changes (proves byte-parity end-to-end through the
    bootstrap pipeline, not just the unit-test path)
  - `go build wrappers/go/foundation`, `go build wrappers/go/phe`,
    `go build wrappers/go/crypto` all still succeed

## System-Wide Impact

- **Interaction graph:** The IR field is read only by the Go
  backend. The C backend, CMake backend, and umbrella-header
  generator never see `cgo_links`. Risk of cross-backend regression
  is essentially zero.
- **Error propagation:** No new failure modes — the generator
  produces an empty file when `cgo_links` is empty (impossible for
  Go-wrapper projects in practice), and silently skips unrecognized
  platform specs.
- **State lifecycle risks:** None — `platform.go` is a
  fully-generated file with no handwritten content to preserve.
- **API surface parity:** This file is consumed only by cgo at build
  time; no Go-side or external API changes.
- **Integration coverage:** Unit 3's verification step reads the
  generated file back via `git diff` after `--apply` — that catches
  any drift the unit tests miss (e.g., line-ending differences).
- **Unchanged invariants:** All 124 + 11 currently-generated Go
  files keep their exact current output. The 5 existing source
  XMLs are not modified by this plan (per the "fully codegen it"
  decision).

## Risks & Dependencies

| Risk | Mitigation |
|------|------------|
| Source XML adds a new platform spec the table doesn't know about | Silent-skip behavior keeps the build working with the platforms we DO know; Unit 2's edge-case test pins this so the failure mode is documented |
| Hand-edited `linux,arm64` entries in legacy carry idiosyncrasies (e.g., `-lpthread` order) my generator misses | Unit 2's byte-parity test against the literal legacy file is the safety net — any drift fails the test |
| Future arm64-windows or arm64-legacy-linux targets get added without updating Python | Acceptance of the user's "fully codegen it" choice — adding new platforms means a Python edit. Document this trade-off in a comment on `_PLATFORM_EXPANSIONS` |
| `gofmt` reformats the generated file in unexpected ways | The legacy file passes `gofmt` clean (verified across earlier slices); matching its byte shape inherits that property |

## Sources & References

- Origin: this plan was drafted directly (no `ce:brainstorm`
  doc) — the trigger was a deferred TODO from Unit 4.7's commit
  message
- Related code: `tools/codegen/project_go_backend.py:generate_go_context`,
  `tools/codegen/project_source.py:load_project_source`,
  `tools/codegen/project_ir.py::IRProject`
- Related commits: `17faa0fef` (Unit 4.7, where `platform.go` was
  deferred), `5453b6870` (legacy hand-edit that introduced arm64
  entries), `74ffc21d7` (most recent Go backend fix)
- Reference output: `wrappers/go/foundation/platform.go`,
  `wrappers/go/phe/platform.go`
