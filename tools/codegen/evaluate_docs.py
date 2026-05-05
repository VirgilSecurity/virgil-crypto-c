#!/usr/bin/env python3
"""
Measurement harness for the codegen-docs optimization run.

Checks:
  1. Python syntax validity of the two codegen files under optimization.
  2. Codegen unit test pass rate (excludes pre-existing failures on develop).
  3. Extracts 5 key code sections for LLM-as-judge documentation evaluation.

Output (JSON on stdout):
  syntax_ok   : 1 if both files parse without SyntaxError, else 0
  tests_pass  : 1 if all applicable tests pass, else 0
  section_count : number of sections successfully extracted
  sections    : list of {id, label, file, content} for the judge
"""
from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND = REPO_ROOT / "tools/codegen/project_c_backend.py"
BOOTSTRAP = REPO_ROOT / "tools/codegen/common_bootstrap.py"

# Pre-existing failures on develop — excluded so they do not flip the gate.
_EXCLUDED_TESTS = (
    "test_impl_tag_enum_has_all_implementations",
    "test_total_method_count",
    "test_struct_has_multiple_properties",
)


def _syntax_ok(path: Path) -> bool:
    try:
        ast.parse(path.read_text(), filename=str(path))
        return True
    except SyntaxError:
        return False


def _tests_pass() -> bool:
    deselect = " or ".join(_EXCLUDED_TESTS)
    result = subprocess.run(
        [
            sys.executable, "-m", "pytest",
            "tools/codegen/test_class_dependencies.py",
            "tools/codegen/test_impl_infra_rendering.py",
            "tools/codegen/test_impl_rendering.py",
            "tools/codegen/test_interface_rendering.py",
            "-q", "--tb=short",
            f"-k", f"not ({deselect})",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _extract_function(source: str, func_name: str) -> str | None:
    """Return source text of a top-level function by name, or None."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == func_name:
            lines = source.splitlines()
            return "\n".join(lines[node.lineno - 1 : node.end_lineno])
    return None


def _extract_range(source: str, start_marker: str, end_marker: str, cap: int = 80) -> str | None:
    """Extract lines from the first occurrence of start_marker up to end_marker."""
    lines = source.splitlines()
    start_idx: int | None = None
    for i, line in enumerate(lines):
        if start_marker in line:
            start_idx = i
            break
    if start_idx is None:
        return None
    end_idx = min(start_idx + cap, len(lines))
    for i in range(start_idx + 1, end_idx):
        if end_marker in lines[i]:
            end_idx = i + 1
            break
    return "\n".join(lines[start_idx:end_idx])


def _build_sections(backend: str, bootstrap: str) -> list[dict]:
    sections: list[dict] = []

    # 1. _class_dependency_includes — main dep/arg scanning loop with impl_prefixes
    src = _extract_function(backend, "_class_dependency_includes")
    if src:
        sections.append({
            "id": "class_dep_includes",
            "label": "_class_dependency_includes function",
            "file": "tools/codegen/project_c_backend.py",
            "content": src[:3500],
        })

    # 2. render_class_c_module will_inline_struct block (~lines 2993–3028)
    block = _extract_range(
        backend,
        start_marker="will_inline_struct = ",
        end_marker="if include_own_header_public",
        cap=60,
    )
    if block:
        sections.append({
            "id": "render_class_inline_struct",
            "label": "render_class_c_module will_inline_struct block",
            "file": "tools/codegen/project_c_backend.py",
            "content": block[:2500],
        })

    # 3. render_module_c_module — require-driven library.h (post-fix: no unconditional add)
    block = _extract_range(
        backend,
        start_marker="def render_module_c_module(",
        end_marker="for require in module.requires:",
        cap=35,
    )
    if block:
        sections.append({
            "id": "render_module_library",
            "label": "render_module_c_module (start + c_includes loop)",
            "file": "tools/codegen/project_c_backend.py",
            "content": block[:2000],
        })

    # 4. render_class_defs_c_module interface handling (field_pfx / dep_prefix fix)
    block = _extract_range(
        backend,
        start_marker="def render_class_defs_c_module(",
        end_marker="def render_class_internal_c_module(",
        cap=120,
    )
    if block:
        lines = block.splitlines()
        # Trim to just the section where interface/impl includes are emitted
        marker_idx = next(
            (i for i, l in enumerate(lines) if "field_project" in l or "interface_name" in l),
            0,
        )
        trimmed = lines[max(0, marker_idx - 3): marker_idx + 45]
        sections.append({
            "id": "render_defs_interface",
            "label": "render_class_defs_c_module interface/impl include section",
            "file": "tools/codegen/project_c_backend.py",
            "content": "\n".join(trimmed)[:2000],
        })

    # 5. common_bootstrap.py _known_bare filter
    block = _extract_range(
        bootstrap,
        start_marker="renderer_pub_includes = [",
        end_marker="existing_section_includes: list[str] = []",
        cap=40,
    )
    if block:
        sections.append({
            "id": "known_bare_filter",
            "label": "_known_bare existence filter in common_bootstrap.render_one",
            "file": "tools/codegen/common_bootstrap.py",
            "content": block[:2000],
        })

    return sections


def main() -> None:
    syntax_ok = int(_syntax_ok(BACKEND) and _syntax_ok(BOOTSTRAP))
    tests_pass = int(_tests_pass()) if syntax_ok else 0

    backend_text = BACKEND.read_text()
    bootstrap_text = BOOTSTRAP.read_text()
    sections = _build_sections(backend_text, bootstrap_text) if syntax_ok else []

    print(json.dumps({
        "syntax_ok": syntax_ok,
        "tests_pass": tests_pass,
        "section_count": len(sections),
        "sections": sections,
    }, indent=2))


if __name__ == "__main__":
    main()
