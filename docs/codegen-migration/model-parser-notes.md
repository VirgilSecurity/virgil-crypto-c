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
