#!/usr/bin/env python3
"""Verify that generated lifecycle method bodies match cfrag file content.

This script extracts the method bodies from the generated vsc_buffer.c
and compares them against the corresponding .cfrag files to ensure parity
before the cfrag files are removed.
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
GENERATED_FILE = REPO_ROOT / "library" / "common" / "src" / "vsc_buffer.c"
CFRAG_DIR = REPO_ROOT / "tools" / "codegen" / "support" / "common_runtime" / "buffer"

# Map cfrag filename -> function name in generated code
CFRAG_TO_FUNC = {
    "init.cfrag": "vsc_buffer_init",
    "cleanup.cfrag": "vsc_buffer_cleanup",
    "new.cfrag": "vsc_buffer_new",
    "delete.cfrag": "vsc_buffer_delete",
    "destroy.cfrag": "vsc_buffer_destroy",
    "shallow_copy.cfrag": "vsc_buffer_shallow_copy",
    "init_with_capacity.cfrag": "vsc_buffer_init_with_capacity",
    "new_with_capacity.cfrag": "vsc_buffer_new_with_capacity",
    "init_with_data.cfrag": "vsc_buffer_init_with_data",
    "new_with_data.cfrag": "vsc_buffer_new_with_data",
}


def extract_function_body(source: str, func_name: str) -> str:
    """Extract the body of a function (content between outermost braces)."""
    # Find the function definition line
    # Pattern: func_name(...) {
    pattern = re.compile(
        rf'^{re.escape(func_name)}\b[^{{]*\{{',
        re.MULTILINE
    )
    match = pattern.search(source)
    if not match:
        raise ValueError(f"Function '{func_name}' not found in generated source")

    # Find matching closing brace
    start = match.end()
    depth = 1
    pos = start
    while pos < len(source) and depth > 0:
        if source[pos] == '{':
            depth += 1
        elif source[pos] == '}':
            depth -= 1
        pos += 1

    body = source[start:pos - 1]  # exclude the closing brace

    # Strip leading/trailing whitespace and normalize
    lines = body.strip().split('\n')
    # Remove leading indentation (4 spaces typically)
    cleaned = []
    for line in lines:
        if line.startswith('    '):
            cleaned.append(line[4:])
        else:
            cleaned.append(line)
    return '\n'.join(cleaned).strip()


def normalize_whitespace(text: str) -> str:
    """Normalize whitespace for comparison: strip trailing spaces, normalize line endings."""
    lines = text.strip().split('\n')
    return '\n'.join(line.rstrip() for line in lines)


def main():
    if not GENERATED_FILE.exists():
        print(f"ERROR: Generated file not found: {GENERATED_FILE}")
        return 1

    if not CFRAG_DIR.exists():
        print(f"ERROR: Cfrag directory not found: {CFRAG_DIR}")
        return 1

    source = GENERATED_FILE.read_text()
    failures = []
    passes = 0

    for cfrag_name, func_name in sorted(CFRAG_TO_FUNC.items()):
        cfrag_path = CFRAG_DIR / cfrag_name
        if not cfrag_path.exists():
            failures.append(f"{cfrag_name}: file not found")
            continue

        cfrag_content = normalize_whitespace(cfrag_path.read_text())

        try:
            generated_body = normalize_whitespace(extract_function_body(source, func_name))
        except ValueError as e:
            failures.append(f"{cfrag_name}: {e}")
            continue

        if generated_body == cfrag_content:
            print(f"  PASS: {cfrag_name} matches {func_name}()")
            passes += 1
        else:
            failures.append(f"{cfrag_name}: body differs from {func_name}()")
            print(f"  FAIL: {cfrag_name} differs from {func_name}()")
            print(f"    --- cfrag ---")
            print(cfrag_content)
            print(f"    --- generated ---")
            print(generated_body)
            print()

    print(f"\n{passes}/{len(CFRAG_TO_FUNC)} passed")
    if failures:
        print("Failures:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("All lifecycle method bodies match their cfrag counterparts!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
