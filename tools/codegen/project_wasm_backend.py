"""WASM wrapper file generation for the project-rooted codegen pipeline.

Ports the legacy ``codegen/wasm.gsl`` / ``codegen/wasm_codegen.gsl``
templates to Python, consuming the shared :class:`IRProject` and the
resolved WASM XML models.

Each entity (enum, class, implementation) becomes a single ``.js`` file.
Per-project infrastructure files (``index.js``, ``precondition.js``,
``{Project}Error.js``, ``{Project}Interface.js``, ``{Project}InterfaceTag.js``,
``{Project}ImplTag.js``) are also generated. Additionally, per-project
``CMakeLists.txt`` files are generated for the Emscripten build.

JS files and CMakeLists.txt are assembled from the resolved WASM XML
which contains pre-computed code blocks.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from tools.codegen.project_ir import IRProject


# ---------------------------------------------------------------------------
# Resolved XML loading
# ---------------------------------------------------------------------------

def _load_resolved_wasm_xml(
    project_name: str, repo_root: str | Path = "."
) -> ET.Element | None:
    """Load the resolved WASM XML for a project, or None if unavailable."""
    path = (
        Path(repo_root)
        / "codegen"
        / "generated"
        / project_name
        / f"wasm_project_{project_name}.xml"
    )
    if not path.exists():
        return None
    return ET.parse(str(path)).getroot()


# ---------------------------------------------------------------------------
# Text utilities
# ---------------------------------------------------------------------------

def _dedent_block(text: str) -> list[str]:
    """Remove common leading whitespace from a resolved XML text block.

    Returns a list of lines with relative indentation preserved.
    Multi-space runs within lines are collapsed to single spaces
    (the resolved XML stores code with alignment padding).
    """
    raw_lines = text.split("\n")
    content_lines = [l for l in raw_lines if l.strip()]
    if not content_lines:
        return []
    min_indent = min(len(l) - len(l.lstrip()) for l in content_lines)
    result: list[str] = []
    for l in raw_lines:
        if l.strip():
            stripped = l[min_indent:]
            # Preserve leading indent, collapse internal multi-spaces
            leading = len(stripped) - len(stripped.lstrip())
            indent = stripped[:leading]
            body = stripped[leading:]
            body = re.sub(r"  +", " ", body)
            result.append(indent + body)
        else:
            result.append("")
    # Strip leading and trailing empty lines
    while result and not result[0]:
        result.pop(0)
    while result and not result[-1]:
        result.pop()
    return result


def _source_dir(project_ir: IRProject) -> str:
    """Repo-relative output directory for this project's JS source files."""
    return f"wrappers/wasm/{project_ir.name}/src/"


def _cmake_dir(project_ir: IRProject) -> str:
    """Repo-relative output directory for this project's CMakeLists.txt."""
    return f"wrappers/wasm/{project_ir.name}/"


# ---------------------------------------------------------------------------
# JS file renderer from resolved XML modules
# ---------------------------------------------------------------------------

def _render_wasm_module(module: ET.Element) -> str:
    """Render a single ``<wasm_module>`` to a complete ``.js`` file.

    Handles three module types:
    - Raw code modules (precondition.js, index.js): ``<wasm_code>`` block
    - Enum modules: ``<wasm_enum>`` with ``<wasm_constant>`` children
    - Class modules: ``<wasm_class>`` with methods, constructors, etc.
    """
    lines: list[str] = []

    # License header
    lic = module.find("wasm_license")
    if lic is not None and lic.text:
        lic_lines = _dedent_block(lic.text)
        lines.extend(lic_lines)
        lines.append("")

    # Check for raw code module (precondition, index)
    code = module.find("wasm_code")
    if code is not None and code.text:
        code_lines = _dedent_block(code.text)
        lines.extend(code_lines)
        lines.append("")
        return "\n".join(lines)

    # Check for enum
    enum = module.find("wasm_enum")
    if enum is not None:
        _render_wasm_enum_module(module, enum, lines)
        return "\n".join(lines)

    # Check for class
    cls = module.find("wasm_class")
    if cls is not None:
        _render_wasm_class_module(module, cls, lines)
        return "\n".join(lines)

    return "\n".join(lines) + "\n"


def _render_wasm_enum_module(
    module: ET.Element, enum: ET.Element, lines: list[str]
) -> None:
    """Render a WASM enum module — produces Object.freeze({...})."""
    name = enum.get("name", "")

    # Require statements (if any)
    for req in module.findall("wasm_require"):
        req_code = _dedent_block(req.text) if req.text else []
        lines.extend(req_code)

    # Factory function wrapper
    lines.append(f"const init{name} = (Module, modules) => {{")

    # Build the frozen object
    constants = enum.findall("wasm_constant")
    lines.append(f"    const {name} = Object.freeze({{")

    for i, const in enumerate(constants):
        cname = const.get("name", "")
        cvalue = const.get("value", "0")
        comma = "," if i < len(constants) - 1 else ","
        lines.append(f"        {cname}: {cvalue}{comma}")

    lines.append("    });")
    lines.append("")

    # Doc comment from enum tail text
    doc = enum.tail
    if doc and doc.strip():
        doc_lines = _dedent_block(doc)
        for dl in doc_lines:
            lines.append(f"    {dl}" if dl else "")

    lines.append(f"    return {name};")
    lines.append("};")
    lines.append("")
    lines.append(f"module.exports = init{name};")
    lines.append("")


def _render_wasm_class_module(
    module: ET.Element, cls: ET.Element, lines: list[str]
) -> None:
    """Render a WASM class module — produces ES6 class with ctxPtr lifecycle."""
    name = cls.get("name", "")

    # Require statements
    for req in module.findall("wasm_require"):
        if req.text:
            req_lines = _dedent_block(req.text)
            lines.extend(req_lines)
            lines.append("")

    # Factory function wrapper
    lines.append(f"const init{name} = (Module, modules) => {{")

    # Render the class body from sub-elements
    # The resolved XML stores all class code in structured elements.
    # We emit them in XML order: constructor, static factories, delete,
    # properties/constants, methods, dependency setters.
    class_body_lines: list[str] = []

    for child in cls:
        if child.tag == "wasm_constructor":
            _render_wasm_constructor(child, name, class_body_lines)
        elif child.tag == "wasm_method":
            _render_wasm_method(child, class_body_lines)
        elif child.tag == "wasm_constant":
            _render_wasm_constant(child, class_body_lines)
        elif child.tag == "wasm_imported_function":
            pass  # These are for exported_functions.json, not JS output

    # Doc comment from class tail
    doc = cls.tail
    doc_lines_raw: list[str] = []
    if doc and doc.strip():
        doc_lines_raw = _dedent_block(doc)

    # Assemble the class
    lines.append(f"    class {name} {{")
    lines.append("")
    for bl in class_body_lines:
        if bl:
            lines.append(f"        {bl}")
        else:
            lines.append("")
    lines.append("    }")
    lines.append("")

    # Doc after class
    for dl in doc_lines_raw:
        if dl:
            lines.append(f"    {dl}")
        else:
            lines.append("")

    lines.append(f"    return {name};")
    lines.append("};")
    lines.append("")
    lines.append(f"module.exports = init{name};")
    lines.append("")


def _render_wasm_constructor(
    ctor: ET.Element, class_name: str, lines: list[str]
) -> None:
    """Render a class constructor."""
    code = ctor.find("wasm_code")
    if code is not None and code.text:
        code_lines = _dedent_block(code.text)
        # Constructor may have args
        args = ctor.findall("wasm_argument")
        arg_names = [a.get("name", "") for a in args]
        args_str = ", ".join(arg_names)

        lines.append(f"constructor({args_str}) {{")
        for cl in code_lines:
            if cl:
                lines.append(f"    {cl}")
            else:
                lines.append("")
        lines.append("}")
        lines.append("")


def _render_wasm_method(meth: ET.Element, lines: list[str]) -> None:
    """Render a class method (instance or static)."""
    name = meth.get("name", "")
    is_static = meth.get("is_static", "0") == "1"

    code = meth.find("wasm_code")
    if code is None or not code.text:
        return

    code_lines = _dedent_block(code.text)

    # Arguments
    args = meth.findall("wasm_argument")
    arg_names = [a.get("name", "") for a in args]
    args_str = ", ".join(arg_names)

    static_str = "static " if is_static else ""

    lines.append(f"{static_str}{name}({args_str}) {{")
    for cl in code_lines:
        if cl:
            lines.append(f"    {cl}")
        else:
            lines.append("")
    lines.append("}")
    lines.append("")


def _render_wasm_constant(const: ET.Element, lines: list[str]) -> None:
    """Render a class constant as a static getter."""
    name = const.get("name", "")
    value = const.get("value", "0")

    lines.append(f"static get {name}() {{")
    lines.append(f"    return {value};")
    lines.append("}")
    lines.append("")
    lines.append(f"get {name}() {{")
    lines.append(f"    return {value};")
    lines.append("}")
    lines.append("")


# ---------------------------------------------------------------------------
# CMake renderer
# ---------------------------------------------------------------------------

def _render_cmake_module(cmake_module: ET.Element) -> str:
    """Render a ``<cmake_module>`` to a CMakeLists.txt file."""
    lines: list[str] = []

    # License
    lic = cmake_module.find("cmake_license")
    if lic is not None and lic.text:
        lic_lines = _dedent_block(lic.text)
        lines.extend(lic_lines)
        lines.append("")

    # Code
    code = cmake_module.find("cmake_code")
    if code is not None and code.text:
        code_lines = _dedent_block(code.text)
        lines.extend(code_lines)
        lines.append("")

    return "\n".join(lines)


def _render_toplevel_cmake(
    project_names: list[str], repo_root: str | Path = "."
) -> str | None:
    """Render the top-level wrappers/wasm/CMakeLists.txt.

    This is assembled from the project XMLs — the first project's
    resolved XML typically has the top-level cmake info, but it's
    actually a shared file. We read it from the legacy output.
    """
    legacy_path = Path(repo_root) / "wrappers" / "wasm" / "CMakeLists.txt"
    if legacy_path.exists():
        return legacy_path.read_text()
    return None


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def generate_wasm_files(
    project_ir: IRProject, license_text: str = "",
    repo_root: str | Path = ".",
) -> list[tuple[str, str]]:
    """Generate all WASM wrapper files for a project.

    Returns a list of ``(repo_relative_path, file_content)`` tuples.
    """
    del license_text

    files: list[tuple[str, str]] = []

    xml_root = _load_resolved_wasm_xml(project_ir.name, repo_root)
    if xml_root is None:
        return files

    src_dir = _source_dir(project_ir)
    cmake_dir = _cmake_dir(project_ir)

    # --- JS source files (from wasm_module elements) ---
    for module in xml_root.findall(".//wasm_module"):
        file_name = module.get("source_file_name", "")
        if not file_name:
            continue
        content = _render_wasm_module(module)
        files.append((f"{src_dir}{file_name}", content))

    # --- Per-project CMakeLists.txt (from cmake_module element) ---
    cmake_module = xml_root.find(".//cmake_module")
    if cmake_module is not None:
        content = _render_cmake_module(cmake_module)
        files.append((f"{cmake_dir}CMakeLists.txt", content))

    return files
