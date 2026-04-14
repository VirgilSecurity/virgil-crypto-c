"""PHP wrapper file generation for the project-rooted codegen pipeline.

Ports the legacy ``codegen/php.gsl`` / ``codegen/php_codegen.gsl``
templates to Python, consuming the shared :class:`IRProject` and the
resolved PHP XML models.

Each entity becomes a ``.php`` high-level class file. Per-project
C extension files (``.c``, ``.h``) and ``CMakeLists.txt`` are also
generated. All output is assembled from the resolved PHP XML.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from tools.codegen.project_ir import IRProject


# ---------------------------------------------------------------------------
# Resolved XML loading
# ---------------------------------------------------------------------------

def _load_resolved_php_xml(
    project_name: str, repo_root: str | Path = "."
) -> ET.Element | None:
    """Load the resolved PHP XML for a project, or None if unavailable."""
    path = (
        Path(repo_root)
        / "codegen"
        / "generated"
        / project_name
        / f"php_project_{project_name}.xml"
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


def _text_block(el: ET.Element) -> str:
    """Extract and dedent a text block from an element."""
    if el is None or not el.text:
        return ""
    lines = _dedent_block(el.text)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# PHP class (high-level) renderer
# ---------------------------------------------------------------------------

def _render_php_module(module: ET.Element, xml_root: ET.Element) -> str | None:
    """Render a ``<php_module>`` to a ``.php`` class file.

    Only modules with ``source_file_name`` ending in ``.php`` are rendered.
    """
    fname = module.get("source_file_name", "")
    if not fname.endswith(".php"):
        return None

    hl = module.find("high_level")
    if hl is None:
        return None

    lines: list[str] = []

    # License
    lic = module.find("php_license")
    if lic is not None and lic.text:
        lic_lines = _dedent_block(lic.text)
        lines.append("<?php")
        lines.extend(lic_lines)
    else:
        lines.append("<?php")

    lines.append("")

    # Namespace
    ns = hl.find("namespace")
    if ns is not None and ns.text:
        ns_text = ns.text.strip()
        lines.append(ns_text)

    lines.append("")

    # Class doc comment (from the entity description in the XML)
    module_name = module.get("name", "")
    # Try to find description from tail of last element
    doc = _find_class_doc(module, xml_root)
    if doc:
        lines.append("/**")
        for dl in doc.splitlines():
            lines.append(f"* {dl.strip()}" if dl.strip() else "*")
        lines.append("*/")

    # Class declaration from signature
    sig = hl.find("signature")
    if sig is not None and sig.text:
        sig_text = sig.text.strip()
        lines.append(sig_text)
    else:
        lines.append(f"class {module_name}")
    lines.append("{")
    lines.append("")

    # Property
    prop = hl.find("property")
    if prop is not None and prop.text:
        prop_lines = _dedent_block(prop.text)
        for pl in prop_lines:
            lines.append(f"    {pl}" if pl else "")
        lines.append("")

    # Constants
    consts = hl.find("constants")
    if consts is not None and consts.text and consts.text.strip():
        const_lines = _dedent_block(consts.text)
        for cl in const_lines:
            lines.append(f"    {cl}" if cl else "")
        lines.append("")

    # Methods
    for meth in hl.findall("php_method"):
        _render_php_method(meth, lines)

    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def _find_class_doc(module: ET.Element, xml_root: ET.Element) -> str | None:
    """Try to find the class description from various XML locations."""
    # Check module tail, entity descriptions, etc.
    # The class description in the legacy output matches the C entity description
    # For now, we don't have a reliable source in the resolved XML
    return None


def _render_php_method(meth: ET.Element, lines: list[str]) -> None:
    """Render a PHP method from the resolved XML metadata.

    The method body is derived from the attributes (function_name, etc.)
    since the XML doesn't contain pre-computed PHP code blocks.
    """
    name = meth.get("name", "")
    func_name = meth.get("function_name", "")
    return_type = meth.get("return_type", "void")
    declaration = meth.get("declaration", "public ").strip()
    throws = meth.get("throw_exception", "0") == "1" or meth.get("throws_exception", "0") == "1"
    return_enum = meth.get("return_enum", "0") == "1"
    return_interface = meth.get("return_interface", "0") == "1"
    return_class_impl = meth.get("return_class_impl", "0") == "1"
    instance = meth.get("instance", "0") == "1"
    is_constructor = name == "__construct"
    is_destructor = name == "__destructor"
    impl_class = meth.get("implementation_class0", "")
    namespace = meth.get("namespace", "")

    # Collect arguments from child elements
    args = meth.findall("php_argument")
    arg_parts: list[str] = []
    arg_names: list[str] = []
    for arg in args:
        arg_name = arg.get("name", "")
        arg_type = arg.get("type", "")
        is_interface_arg = arg.get("is_interface", "0") == "1"
        is_enum_arg = arg.get("is_enum", "0") == "1"
        if arg_type and not is_interface_arg and not is_enum_arg:
            arg_parts.append(f"{arg_type} ${arg_name}")
        elif is_interface_arg or is_enum_arg:
            arg_parts.append(f"{arg_type} ${arg_name}")
        else:
            arg_parts.append(f"${arg_name}")
        arg_names.append(arg_name)

    # Build doc comment
    doc_lines: list[str] = []
    # Method description from tail/text
    desc_text = ""
    for child in meth:
        if child.tail and child.tail.strip().startswith("*"):
            desc_text = child.tail.strip()
    meth_desc = meth.text.strip() if meth.text and meth.text.strip() else ""

    # Generate method signature
    if is_constructor:
        lines.append("    /**")
        lines.append("    * Create underlying C context.")
        lines.append("    * @param null $ctx")
        lines.append("    * @return void")
        lines.append("    */")
        lines.append("    public function __construct($ctx = null)")
        lines.append("    {")
        lines.append(f"        $this->ctx = is_null($ctx) ? {func_name}() : $ctx;")
        lines.append("    }")
        lines.append("")
        return

    if is_destructor:
        lines.append("    /**")
        lines.append("    * Destroy underlying C context.")
        lines.append("    * @return void")
        lines.append("    */")
        lines.append("    public function __destructor()")
        lines.append("    {")
        lines.append(f"        {func_name}($this->ctx);")
        lines.append("    }")
        lines.append("")
        return

    if name == "getCtx":
        lines.append("    /**")
        lines.append("    * Get C context.")
        lines.append("    *")
        lines.append("    * @return resource")
        lines.append("    */")
        lines.append("    public function getCtx()")
        lines.append("    {")
        lines.append("        return $this->ctx;")
        lines.append("    }")
        return

    # Build return type hint
    ret_hint = ""
    if return_type == "void":
        ret_hint = ": void"
    elif return_type == "string":
        ret_hint = ": string"
    elif return_type == "int":
        ret_hint = ": int"
    elif return_type == "bool":
        ret_hint = ": bool"
    elif return_type and return_type != "resource":
        ret_hint = f": {return_type}"

    # Build call arguments
    call_args: list[str] = []
    if "static" not in declaration:
        call_args.append("$this->ctx")
    for arg in args:
        arg_name = arg.get("name", "")
        is_interface_arg = arg.get("is_interface", "0") == "1"
        if is_interface_arg:
            call_args.append(f"${arg_name}->getCtx()")
        else:
            call_args.append(f"${arg_name}")

    call_str = ", ".join(call_args)

    # Build method body
    if return_enum:
        body = f"        $enum = {func_name}({call_str});\n        return new {return_type}($enum);"
    elif return_interface:
        ns_prefix = f"{namespace}\\" if namespace else ""
        impl_name = "".join(w.capitalize() for w in impl_class.split())
        body = f"        $ctx = {func_name}({call_str});\n        return {impl_name}::wrap{return_type}($ctx);"
    elif return_class_impl:
        body = f"        $ctx = {func_name}({call_str});\n        return new {return_type}($ctx);"
    elif return_type == "void":
        body = f"        {func_name}({call_str});"
    else:
        body = f"        return {func_name}({call_str});"

    # Doc comment
    lines.append("    /**")
    # Try to extract description
    lines.append(f"    *")
    for arg in args:
        arg_name = arg.get("name", "")
        arg_type = arg.get("type", "")
        lines.append(f"    * @param {arg_type} ${arg_name}")
    lines.append(f"    * @return {return_type}")
    if throws:
        lines.append("    * @throws \\Exception")
    lines.append("    */")

    # Method signature
    args_str = ", ".join(arg_parts)
    lines.append(f"    {declaration} function {name}({args_str}){ret_hint}")
    lines.append("    {")
    lines.append(body)
    lines.append("    }")
    lines.append("")


# ---------------------------------------------------------------------------
# C extension renderer (.c and .h files)
# ---------------------------------------------------------------------------

def _render_c_extension_file(module: ET.Element, is_header: bool) -> str:
    """Render a C extension file (.c or .h) from XML sections."""
    lines: list[str] = []

    if is_header:
        # Header file: licence + header_top + header_constants + header_registered_resources + init_func_declaration + header_bottom
        sections = ["licence", "header_top", "header_constants", "header_registered_resources",
                     "init_func_declaration", "header_bottom"]
    else:
        # Source file: licence + include + extension_status + constants + constants_func_wrapp +
        # registered_resources + registered_resources_func_wrapp + init_func_definitions +
        # func_wrapping + define_all_func_entries + module_definitions
        sections = ["licence", "include", "extension_status", "constants", "constants_func_wrapp",
                     "registered_resources", "registered_resources_func_wrapp",
                     "init_func_definitions", "func_wrapping",
                     "define_all_func_entries", "module_definitions"]

    for section_name in sections:
        el = module.find(section_name)
        if el is not None and el.text and el.text.strip():
            block = _dedent_block(el.text)
            lines.extend(block)
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CMakeLists.txt renderer
# ---------------------------------------------------------------------------

def _render_php_cmake(module: ET.Element) -> str:
    """Render a PHP extension CMakeLists.txt from a custom_code element."""
    code = module.find("custom_code")
    if code is not None and code.text:
        lines = _dedent_block(code.text)
        return "\n".join(lines) + "\n"
    return ""


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def generate_php_files(
    project_ir: IRProject, license_text: str = "",
    repo_root: str | Path = ".",
) -> list[tuple[str, str]]:
    """Generate all PHP wrapper files for a project.

    Returns a list of ``(repo_relative_path, file_content)`` tuples.
    """
    del license_text

    files: list[tuple[str, str]] = []

    xml_root = _load_resolved_php_xml(project_ir.name, repo_root)
    if xml_root is None:
        return files

    source_dir = xml_root.get("source_dir", "").lstrip("../")
    if not source_dir.endswith("/"):
        source_dir += "/"

    # --- PHP class files ---
    for module in xml_root.findall(".//php_module"):
        fname = module.get("source_file_name", "")
        if not fname:
            continue

        if fname.endswith(".php"):
            content = _render_php_module(module, xml_root)
            if content:
                files.append((f"{source_dir}{fname}", content))

        elif fname.endswith(".c") or fname.endswith(".h"):
            is_header = fname.endswith(".h")
            content = _render_c_extension_file(module, is_header)
            if content:
                # C extension files go in extensions/{project}/
                ext_dir = f"wrappers/php/VirgilCryptoWrapper/extensions/{project_ir.name}/"
                files.append((f"{ext_dir}{fname}", content))

    # --- CMakeLists.txt ---
    # Look for a module with custom_code (the CMakeLists data)
    for module in xml_root.findall(".//php_module"):
        name = module.get("name", "")
        if name == "extension status" or module.find("custom_code") is not None:
            cmake = module.find("custom_code")
            if cmake is not None and cmake.text:
                cmake_lines = _dedent_block(cmake.text)
                content = "\n".join(cmake_lines) + "\n"
                ext_dir = f"wrappers/php/VirgilCryptoWrapper/extensions/{project_ir.name}/"
                files.append((f"{ext_dir}CMakeLists.txt", content))
            break

    return files
