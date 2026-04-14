"""Java/JNI wrapper file generation for the project-rooted codegen pipeline.

Ports the legacy ``codegen/java.gsl`` / ``codegen/java_codegen.gsl``
templates to Python, consuming the shared :class:`IRProject` and the
resolved Java XML models.

Each entity becomes a ``.java`` class file. Per-project JNI files
(``{Project}JNI.java``, ``{Project}JNI.c``, ``{Project}JNI.h``) are
also generated. All output is assembled from the resolved Java XML.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from tools.codegen.project_ir import IRProject


# ---------------------------------------------------------------------------
# Resolved XML loading
# ---------------------------------------------------------------------------

def _load_resolved_java_xml(
    project_name: str, repo_root: str | Path = "."
) -> ET.Element | None:
    """Load the resolved Java XML for a project, or None if unavailable."""
    path = (
        Path(repo_root)
        / "codegen"
        / "generated"
        / project_name
        / f"java_project_{project_name}.xml"
    )
    if not path.exists():
        return None
    return ET.parse(str(path)).getroot()


# ---------------------------------------------------------------------------
# Text utilities
# ---------------------------------------------------------------------------

def _dedent_block(text: str) -> list[str]:
    """Remove common leading whitespace from a resolved XML text block."""
    raw_lines = text.split("\n")
    content_lines = [l for l in raw_lines if l.strip()]
    if not content_lines:
        return []
    min_indent = min(len(l) - len(l.lstrip()) for l in content_lines)
    result: list[str] = []
    for l in raw_lines:
        if l.strip():
            stripped = l[min_indent:]
            leading = len(stripped) - len(stripped.lstrip())
            indent = stripped[:leading]
            body = stripped[leading:]
            body = re.sub(r"  +", " ", body)
            result.append(indent + body)
        else:
            result.append("")
    while result and not result[0]:
        result.pop(0)
    while result and not result[-1]:
        result.pop()
    return result


# ---------------------------------------------------------------------------
# Java file renderer
# ---------------------------------------------------------------------------

def _render_java_module(module: ET.Element, xml_root: ET.Element) -> str:
    """Render a ``<java_module>`` to a ``.java`` file."""
    lines: list[str] = []

    # License
    lic = module.find("java_license")
    if lic is not None and lic.text:
        lic_lines = _dedent_block(lic.text)
        lines.extend(lic_lines)
        lines.append("")

    # Package declaration (from root attrs)
    package = xml_root.get("package", "")
    if package:
        lines.append(f"package {package};")
        lines.append("")

    # Imports
    for imp in module.findall("java_import"):
        imp_text = imp.text.strip() if imp.text and imp.text.strip() else ""
        if imp_text:
            imp_lines = _dedent_block(imp.text)
            lines.extend(imp_lines)

    # Add blank after imports
    if module.findall("java_import"):
        lines.append("")

    # Class
    cls = module.find("java_class")
    if cls is not None:
        _render_java_class(cls, lines)

    lines.append("")
    return "\n".join(lines)


def _render_java_class(cls: ET.Element, lines: list[str]) -> None:
    """Render a ``<java_class>`` element."""
    name = cls.get("name", "")
    visibility = cls.get("visibility", "public")

    # Build class declaration with implements
    implements = [impl.get("type", "") for impl in cls.findall("java_implement")]
    impl_str = f" implements {', '.join(implements)}" if implements else ""

    # Check for extends
    extends = cls.get("extends", "")
    extends_str = f" extends {extends}" if extends else ""

    lines.append(f"{visibility} class {name}{extends_str}{impl_str} {{")
    lines.append("")

    # Process children in order
    for child in cls:
        if child.tag == "java_field":
            _render_java_field(child, lines)
        elif child.tag == "java_constructor":
            _render_java_constructor(child, name, lines)
        elif child.tag == "java_method":
            _render_java_method(child, lines)
        elif child.tag == "java_implement":
            pass  # Already handled in class declaration
        elif child.tag == "java_code":
            # Inline class-level code
            if child.text:
                code_lines = _dedent_block(child.text)
                for cl in code_lines:
                    if cl:
                        lines.append(f"    {cl}")
                    else:
                        lines.append("")
                lines.append("")

    lines.append("}")


def _render_java_field(field: ET.Element, lines: list[str]) -> None:
    """Render a Java field declaration."""
    name = field.get("name", "")
    ftype = field.get("type", "")
    visibility = field.get("visibility", "private")

    lines.append(f"    {visibility} {ftype} {name};")
    lines.append("")


def _render_java_constructor(ctor: ET.Element, class_name: str, lines: list[str]) -> None:
    """Render a Java constructor."""
    visibility = ctor.get("visibility", "public")

    # Arguments
    args = ctor.findall("java_argument")
    arg_parts = []
    for arg in args:
        atype = arg.get("type", "")
        aname = arg.get("name", "")
        arg_parts.append(f"{atype} {aname}")

    code = ctor.find("java_code")
    if code is not None and code.text:
        code_lines = _dedent_block(code.text)
        args_str = ", ".join(arg_parts)
        lines.append(f"    {visibility} {class_name}({args_str}) {{")
        for cl in code_lines:
            if cl:
                lines.append(f"        {cl}")
            else:
                lines.append("")
        lines.append("    }")
        lines.append("")


def _render_java_method(meth: ET.Element, lines: list[str]) -> None:
    """Render a Java method."""
    name = meth.get("name", "")
    visibility = meth.get("visibility", "public")
    is_static = meth.get("is_static", "0") == "1"
    is_native = meth.get("is_native", "0") == "1"
    throws = meth.get("throws", "")

    # Return type
    ret = meth.find("java_return")
    ret_type = ret.get("type", "void") if ret is not None else "void"

    # Arguments
    args = meth.findall("java_argument")
    arg_parts = []
    for arg in args:
        atype = arg.get("type", "")
        aname = arg.get("name", "")
        arg_parts.append(f"{atype} {aname}")

    static_str = "static " if is_static else ""
    native_str = "native " if is_native else ""
    throws_str = f" throws {throws}" if throws else ""
    args_str = ", ".join(arg_parts)

    # Doc comment
    doc = meth.text
    if doc and doc.strip():
        doc_lines = _dedent_block(doc)
        for dl in doc_lines:
            if dl:
                lines.append(f"    {dl}")

    code = meth.find("java_code")
    if code is not None and code.text:
        code_lines = _dedent_block(code.text)
        lines.append(
            f"    {visibility} {static_str}{native_str}{ret_type} "
            f"{name}({args_str}){throws_str} {{"
        )
        for cl in code_lines:
            if cl:
                lines.append(f"        {cl}")
            else:
                lines.append("")
        lines.append("    }")
        lines.append("")
    elif is_native:
        # Native method declaration (no body)
        lines.append(
            f"    {visibility} {static_str}native {ret_type} "
            f"{name}({args_str}){throws_str};"
        )
        lines.append("")


# ---------------------------------------------------------------------------
# JNI C file renderer
# ---------------------------------------------------------------------------

def _render_jni_c_module(module: ET.Element) -> str:
    """Render a ``<java_module>`` to a JNI ``.c`` file."""
    lines: list[str] = []

    # License
    lic = module.find("c_license")
    if lic is not None and lic.text:
        lic_lines = _dedent_block(lic.text)
        lines.extend(lic_lines)
        lines.append("")

    # Includes
    for inc in module.findall("c_include"):
        if inc.text and inc.text.strip():
            inc_lines = _dedent_block(inc.text)
            lines.extend(inc_lines)
            lines.append("")

    # Methods
    for meth in module.findall("c_method"):
        code = meth.find("c_code")
        if code is not None and code.text:
            code_lines = _dedent_block(code.text)
            lines.extend(code_lines)
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JNI Header renderer
# ---------------------------------------------------------------------------

def _render_jni_h_module(module: ET.Element) -> str:
    """Render a ``<java_module>`` to a JNI ``.h`` file."""
    lines: list[str] = []

    # License
    lic = module.find("c_license")
    if lic is not None and lic.text:
        lic_lines = _dedent_block(lic.text)
        lines.extend(lic_lines)
        lines.append("")

    # Includes
    for inc in module.findall("c_include"):
        if inc.text and inc.text.strip():
            inc_lines = _dedent_block(inc.text)
            lines.extend(inc_lines)
            lines.append("")

    # Method declarations (no c_code, just signatures from c_argument + c_return)
    for meth in module.findall("c_method"):
        # JNI header methods have declaration attribute
        decl = meth.get("declaration", "0")
        name = meth.get("name", "")
        if not name:
            continue

        ret = meth.find("c_return")
        ret_type = ret.get("type", "void") if ret is not None else "void"

        args = meth.findall("c_argument")
        arg_parts = []
        for arg in args:
            atype = arg.get("type", "")
            aname = arg.get("name", "")
            arg_parts.append(f"{atype} {aname}")

        args_str = ", ".join(arg_parts) if arg_parts else "void"
        lines.append(f"JNIEXPORT {ret_type} JNICALL")
        lines.append(f"{name}({args_str});")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def generate_java_files(
    project_ir: IRProject, license_text: str = "",
    repo_root: str | Path = ".",
) -> list[tuple[str, str]]:
    """Generate all Java wrapper files for a project.

    Returns a list of ``(repo_relative_path, file_content)`` tuples.
    """
    del license_text

    files: list[tuple[str, str]] = []

    xml_root = _load_resolved_java_xml(project_ir.name, repo_root)
    if xml_root is None:
        return files

    # Derive output paths from XML attributes
    package = xml_root.get("package", "")
    package_dir = xml_root.get("package_dir", package.replace(".", "/"))
    jni_source_dir = xml_root.get("jni_source_dir", "").lstrip("../")
    if not jni_source_dir.endswith("/"):
        jni_source_dir += "/"

    java_base = f"wrappers/java/{project_ir.name}/src/main/java/{package_dir}/"

    for module in xml_root.findall(".//java_module"):
        fname = module.get("source_file_name", "")
        if not fname:
            continue

        if fname.endswith(".java"):
            content = _render_java_module(module, xml_root)
            files.append((f"{java_base}{fname}", content))

        elif fname.endswith(".c"):
            content = _render_jni_c_module(module)
            files.append((f"{jni_source_dir}{fname}", content))

        elif fname.endswith(".h"):
            content = _render_jni_h_module(module)
            files.append((f"{jni_source_dir}{fname}", content))

    return files
