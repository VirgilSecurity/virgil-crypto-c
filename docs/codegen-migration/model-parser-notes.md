# Model Parser Notes

## Why parser notes are needed

During the first source-loader attempt for `common`, standard XML parsing failed on at least one real source-model file:

- `codegen/models/shared/module_atomic.xml`

The failure is caused by raw code text inside `<code>` blocks, such as unescaped `&` in C/preprocessor content.

## Practical conclusion

The source-model parser cannot assume that all model files are strict XML.

Instead, it should treat the legacy format as an **XML-like DSL** with embedded raw code regions.

## Recommended tolerant parsing strategy

### Option A — protect code blocks before XML parsing

1. scan file text
2. locate `<code ...>` ... `</code>` sections
3. replace the raw inner text with safely escaped or placeholder content
4. parse the transformed document as XML
5. restore original code text into the parsed source model

This is the recommended approach for the migration effort.

### Option B — custom parser for the full DSL

Possible, but unnecessary for the first `common` implementation slice.

## Minimum parser requirements for `common`

The parser should correctly preserve:

- project/module/class attributes
- child entity ordering where relevant
- free-form descriptive text around child nodes
- raw `<code>` text exactly enough for later emission/resolution
- nested `<argument>`, `<return>`, `<value>`, `<string>`, and `<array>` details

## Immediate implementation consequence

The current `tools/codegen/common_source.py` loader should be treated as an early scaffold and not yet the final source parser.
It should be upgraded with a tolerant preprocessing pass before it becomes the basis for direct original-XML generation.

## Project-rooted regression entrypoint

Focused regression coverage now starts from the top-level project model instead of loading `common` pieces ad hoc:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.codegen.test_project_common_source
```

That test protects these assumptions from ADR 0002:

- `codegen/models/project_common/project_common.xml` is the root entrypoint for `common`
- project metadata needed by later backends stays discoverable from the loaded graph (`namespace`, `framework`, `prefix`, `path`, `work_path`, wrappers, version, and features)
- the graph now also exposes resolved project paths for downstream consumers (`repo_root`, `codegen_root`, `model_root`, `source_root`, and `work_root`)
- referenced `common` modules and classes are resolved through the project graph rather than by hand-picked per-module calls
- tolerant parsing keeps raw code-bearing module content reachable from the graph, including atomic-module code blocks that contain legacy XML-hostile text

## Graph facts now available to the IR layer

The current project-rooted graph carries enough structure for the next IR step to lower model facts without rediscovering them from filenames or hardcoded paths:

- project identity and naming metadata (`name`, `namespace`, `framework`, `prefix`, version, and feature flags)
- resolved project-relative locations for source and generated outputs (`source_root`, `work_root`)
- explicit module/class/enum references from the project file
- loaded top-level modules plus transitive dependency modules
- loaded classes and enums with their original model attributes, descriptions, methods, properties, variables, constructors, constants, returns, and code blocks
- name-based graph helpers (`module_named()`, `class_named()`, `enum_named()`) so later lowering steps do not need repeated ad hoc scans

`common_source.load_project_common()` remains as a convenience wrapper, but the tested architecture path is the explicit project-XML entrypoint.
