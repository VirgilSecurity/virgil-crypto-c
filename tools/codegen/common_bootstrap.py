from __future__ import annotations

import argparse
import html
import os
from pathlib import Path
import shutil
import sys
import textwrap
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.codegen.project_c_backend import (
    ClassFieldSpec,
    DirectCRenderer,
    DirectRendererSpec,
    argument_from_source,
    callback_symbol,
    c_module_root,
    c_module_root_attrs,
    class_ir,
    class_type_symbol,
    comment_text,
    derived_module_output_from_class,
    direct_renderer_map,
    direct_xml_name,
    discover_renderers,
    generate_umbrella_headers,
    include_file_for_entity,
    module_ir,
    render_class_c_module,
    render_module_c_module,
    return_from_source,
    snake_name,
    text_element,
    type_map,
)
from tools.codegen.project_ir import IRProject, IROutputTarget, project_to_ir
from tools.codegen.project_source import load_named_project_source


GENERATED_START = "//  @generated"
GENERATED_END = "//  @end"



# ---------------------------------------------------------------------------
# Supported projects
# ---------------------------------------------------------------------------

_SUPPORTED_PROJECTS = ("common", "foundation")


def supported_projects() -> tuple[str, ...]:
    return _SUPPORTED_PROJECTS


# ---------------------------------------------------------------------------
# Common-specific custom renderer overrides
# ---------------------------------------------------------------------------

_text = text_element
_snake = snake_name
_module_ir = module_ir
_class_ir = class_ir
_type_symbol = class_type_symbol
_c_module_root_attrs = c_module_root_attrs
_c_module_root = c_module_root
_direct_xml_name = direct_xml_name
_type_map = type_map
_comment_text = comment_text
_argument_from_source = argument_from_source
_return_from_source = return_from_source
_callback_symbol = callback_symbol


def _load_common_project(repo_root: str | Path = "."):
    return load_named_project_source("common", repo_root)


def _load_common_ir(repo_root: str | Path = ".") -> IRProject:
    return project_to_ir(_load_common_project(repo_root))


def _include_file(project_ir: IRProject, *, module_name: str | None = None, class_name: str | None = None) -> str:
    if module_name is not None:
        return include_file_for_entity(project_ir, entity_kind="module", entity_name=module_name)
    if class_name is not None:
        return include_file_for_entity(project_ir, entity_kind="class", entity_name=class_name)
    raise ValueError("either module_name or class_name must be provided")


def _buffer_defs_output(project_ir: IRProject) -> IROutputTarget:
    from typing import cast as _cast

    buffer_output = _cast(IROutputTarget, _class_ir(project_ir, "buffer").output)
    return derived_module_output_from_class(
        buffer_output,
        entity_name="buffer_defs",
        stem_suffix="defs",
        generated_source_stem="buffer_defs",
        header_visibility="private",
    )


def _buffer_argument(parent: ET.Element, attrs: dict[str, str], *, name: str, project_ir: IRProject | None = None) -> ET.Element:
    if attrs.get("class") == "self":
        extra = {"is_const_type": "1"} if attrs.get("access") == "readonly" else {}
        accessed_by = "reference" if attrs.get("passed_by") == "reference" else "pointer"
        type_name = _type_symbol(project_ir, "buffer") if project_ir is not None else "vsc_buffer_t"
        return _text(parent, "c_argument", name=name, accessed_by=accessed_by, type=type_name, type_is="class", **extra)
    if attrs.get("class") == "data":
        type_name = _type_symbol(project_ir, "data") if project_ir is not None else "vsc_data_t"
        return _text(parent, "c_argument", name=name, accessed_by="value", type=type_name, type_is="class")
    if "callback" in attrs:
        callback_type = _callback_symbol(project_ir, "dealloc") if project_ir is not None else "vsc_dealloc_fn"
        return _text(parent, "c_argument", name=name, accessed_by="value", type=callback_type, type_is="callback")

    type_name, type_kind = _type_map(attrs.get("type"))
    accessed_by = "pointer" if attrs.get("is_reference") in {"1", "true"} else "value"
    return _text(parent, "c_argument", name=name, accessed_by=accessed_by, type=type_name, type_is=type_kind)


def _buffer_return(parent: ET.Element, attrs: dict[str, str], *, project_ir: IRProject | None = None) -> ET.Element:
    if attrs.get("class") == "self":
        type_name = _type_symbol(project_ir, "buffer") if project_ir is not None else "vsc_buffer_t"
        return _text(parent, "c_return", accessed_by="pointer", type=type_name, type_is="class")
    if attrs.get("class") == "data":
        type_name = _type_symbol(project_ir, "data") if project_ir is not None else "vsc_data_t"
        return _text(parent, "c_return", accessed_by="value", type=type_name, type_is="class")
    if attrs.get("type") == "byte" and attrs.get("is_reference") in {"1", "true"}:
        extra = {"is_const_type": "1"} if attrs.get("access") != "readwrite" else {}
        return _text(parent, "c_return", accessed_by="pointer", type="byte", type_is="primitive", **extra)

    type_name, type_kind = _type_map(attrs.get("type"))
    return _text(parent, "c_return", accessed_by="value", type=type_name, type_is=type_kind)


def _buffer_public_method(root: ET.Element, name: str, description: str, *, uid: str, args: list[dict[str, dict[str, str]]] | None = None,
                          return_attrs: dict[str, str] | None = None, code: str | None = None,
                          project_ir: IRProject | None = None) -> ET.Element:
    definition = "public" if code is not None else "external"
    method = _text(root, "c_method", name=name, visibility="public", declaration="public", definition=definition, uid=uid)
    if args:
        for arg in args:
            _buffer_argument(method, arg["attrs"], name=arg["name"], project_ir=project_ir)
    else:
        _text(method, "c_argument", type="void", accessed_by="value")

    if return_attrs is None:
        _text(method, "c_return", type="void", accessed_by="value")
    else:
        _buffer_return(method, return_attrs, project_ir=project_ir)

    if code is not None:
        _text(method, "c_code", code, type="generated", lang="c")

    _text(method, "c_modifier", value="VSC_PUBLIC")
    method.text = _comment_text(description)
    return method


def build_direct_library_c_module(repo_root: str | Path = ".") -> ET.Element:
    return render_module_c_module(_load_common_ir(repo_root), _module_ir(_load_common_ir(repo_root), "library"))


def build_direct_memory_c_module(repo_root: str | Path = ".") -> ET.Element:
    return render_module_c_module(_load_common_ir(repo_root), _module_ir(_load_common_ir(repo_root), "memory"))


def build_direct_atomic_c_module(repo_root: str | Path = ".") -> ET.Element:
    return render_module_c_module(_load_common_ir(repo_root), _module_ir(_load_common_ir(repo_root), "atomic"))


def build_direct_assert_c_module(repo_root: str | Path = ".") -> ET.Element:
    return render_module_c_module(_load_common_ir(repo_root), _module_ir(_load_common_ir(repo_root), "assert"))


def build_direct_data_c_module(repo_root: str | Path = ".") -> ET.Element:
    project_ir = _load_common_ir(repo_root)
    data_cls = _class_ir(project_ir, "data")

    return render_class_c_module(
        project_ir,
        data_cls,
        feature=f"{project_ir.prefix.upper()}_DATA",
        private_includes=[
            _include_file(project_ir, module_name="memory"),
            _include_file(project_ir, module_name="assert"),
        ],
    )


def build_direct_buffer_c_module(repo_root: str | Path = ".") -> ET.Element:
    project_ir = _load_common_ir(repo_root)
    buffer_cls = _class_ir(project_ir, "buffer")

    return render_class_c_module(
        project_ir,
        buffer_cls,
        module_class_name="buffer",
        private_includes=[
            _include_file(project_ir, module_name="memory"),
            _include_file(project_ir, module_name="assert"),
            _buffer_defs_output(project_ir).include_file,
        ],
    )


def build_direct_buffer_defs_c_module(repo_root: str | Path = ".") -> ET.Element:
    project_ir = _load_common_ir(repo_root)
    buffer_cls = _class_ir(project_ir, "buffer")

    return render_class_c_module(
        project_ir,
        buffer_cls,
        output=_buffer_defs_output(project_ir),
        entity_id="buffer_defs",
        scope="private",
        module_class_name="buffer",
        public_includes=[_include_file(project_ir, module_name="atomic")],
        struct_declaration="private",
        struct_definition="public",
        include_own_header_public=False,
        generate_ctx_size=False,
        render_variables=False,
        render_reference_support=False,
        render_methods=False,
        extra_struct_fields=(
            ClassFieldSpec(name="self_dealloc_cb", attrs={"callback": ".(global_callback_dealloc)"}, description="Function do deallocate self context."),
            ClassFieldSpec(name="refcnt", attrs={"type": "VSC_ATOMIC size_t"}, description="Reference counter."),
        ),
    )


def _common_custom_overrides(repo_root: str | Path = ".") -> dict[str, DirectCRenderer]:
    """Return custom renderers for the common project that override auto-discovery defaults."""
    project_ir = _load_common_ir(repo_root)
    specs = [
        DirectRendererSpec(entity_kind="class", entity_name="data", renderer=build_direct_data_c_module),
        DirectRendererSpec(entity_kind="module", entity_name="assert", renderer=build_direct_assert_c_module),
        DirectRendererSpec(entity_kind="module", entity_name="library", renderer=build_direct_library_c_module),
        DirectRendererSpec(entity_kind="module", entity_name="atomic", renderer=build_direct_atomic_c_module),
        DirectRendererSpec(entity_kind="module", entity_name="memory", renderer=build_direct_memory_c_module),
        DirectRendererSpec(entity_kind="class", entity_name="buffer", renderer=build_direct_buffer_c_module),
        DirectRendererSpec(
            entity_kind="class",
            entity_name="buffer",
            renderer=build_direct_buffer_defs_c_module,
            output_resolver=_buffer_defs_output,
        ),
    ]
    return direct_renderer_map(project_ir, specs)


# ---------------------------------------------------------------------------
# Project renderer entry point — replaces project_direct_registry
# ---------------------------------------------------------------------------

def direct_c_renderers_for_project(
    project: str,
    repo_root: str | Path = ".",
    *,
    entity_kinds: set[str] | None = None,
) -> dict[str, DirectCRenderer]:
    """Build the complete renderer map for *project* via IR auto-discovery.

    Parameters
    ----------
    project:
        Project name (e.g. ``"common"``, ``"foundation"``).
    repo_root:
        Repository root path used to locate XML models.
    entity_kinds:
        Optional filter forwarded to :func:`discover_renderers`.
    """
    if project not in _SUPPORTED_PROJECTS:
        raise ValueError(
            f"unsupported project '{project}'; expected one of: {', '.join(supported_projects())}"
        )

    project_ir = project_to_ir(load_named_project_source(project, repo_root))

    # Cross-project fallback: foundation needs common types (e.g. data, buffer)
    if project != "common":
        common_ir = project_to_ir(load_named_project_source("common", repo_root))
        project_ir.fallback_projects = [common_ir]

    # Only common has custom overrides; other projects use pure auto-discovery
    custom_overrides: dict[str, DirectCRenderer] = {}
    if project == "common":
        custom_overrides = _common_custom_overrides(repo_root)

    return discover_renderers(
        project_ir,
        entity_kinds=entity_kinds,
        custom_overrides=custom_overrides,
    )


def direct_c_renderers(repo_root: Path, project: str = "common") -> dict[str, object]:
    return direct_c_renderers_for_project(project, repo_root)


# ---------------------------------------------------------------------------
# Text rendering utilities
# ---------------------------------------------------------------------------

def norm_text(text: str | None) -> str:
    if not text:
        return ""
    return textwrap.dedent(html.unescape(text)).strip("\n")


def split_generated_sections(content: str) -> tuple[str, str]:
    start = content.index(GENERATED_START)
    end = content.index(GENERATED_END, start)
    prefix = content[:start]
    suffix = content[end + len(GENERATED_END):]
    if suffix.startswith("\n"):
        suffix = suffix[1:]
    return prefix, suffix


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def merge_generated_section(existing: str, generated: str) -> str:
    prefix, suffix = split_generated_sections(existing)
    return prefix + generated + suffix


def iter_project_xml_paths(project_dir: Path, repo_root: Path, *, project: str = "common", include_legacy_fallback: bool = False) -> list[Path]:
    direct_paths = {project_dir / name for name in direct_c_renderers(repo_root, project).keys()}
    if not include_legacy_fallback:
        return sorted(direct_paths)

    fallback_paths = {
        path for path in project_dir.glob("c_module_*.xml")
        if not path.name.endswith("_unresolved.xml")
    }
    return sorted(direct_paths | fallback_paths)


def description_text(elem: ET.Element) -> str:
    parts: list[str] = []
    if elem.text and norm_text(elem.text):
        parts.append(norm_text(elem.text))
    for child in elem:
        if child.tail and norm_text(child.tail):
            parts.append(norm_text(child.tail))
    return "\n".join(parts).strip()


def emit_comment_block(text: str | None) -> str:
    text = norm_text(text)
    if not text:
        return ""
    return text + "\n"


def c_decl(type_name: str, name: str, accessed_by: str = "value", is_const_type: str | None = None,
           is_string: bool = False, is_array: bool = False, type_is: str | None = None,
           array_length: str | None = None) -> str:
    prefix = "const " if is_const_type == "1" else ""
    stars = ""
    if is_string or accessed_by == "pointer":
        stars = "*"
    elif is_array and not array_length:
        # Dynamic array — render as pointer
        stars = "*"
    elif accessed_by == "reference":
        stars = "**" if type_is == "class" else "*"
    rendered_type = f"{prefix}{type_name}".strip()
    # Fixed-length array: e.g. vscf_impl_t *name[LENGTH]
    if array_length:
        if stars:
            return f"{rendered_type} {stars}{name}[{array_length}]".strip()
        return f"{rendered_type} {name}[{array_length}]".strip()
    if stars:
        return f"{rendered_type} {stars}{name}".strip()
    return f"{rendered_type} {name}".strip()


def render_include(elem: ET.Element) -> str:
    file_name = elem.attrib["file"]
    is_system = elem.attrib.get("is_system") == "1"
    line = f"#include <{file_name}>" if is_system else f'#include "{file_name}"'
    cond = elem.attrib.get("if")
    if cond:
        return f"#if {cond}\n{line}\n#endif"
    return line


def render_alias(elem: ET.Element) -> str:
    name = elem.attrib['name']
    type_name = elem.attrib['type']
    comment = description_text(elem)
    # Special case: 'byte' typedef gets a BYTE_DEFINED guard (legacy GSL behavior)
    if name == 'byte':
        guard_name = f"{name.upper()}_DEFINED"
        lines = [f"#ifndef {guard_name}", f"#define {guard_name}"]
        # Extract the raw description, unwrapping all //  prefixes
        raw_desc = comment.strip()
        desc_lines = []
        for dl in raw_desc.splitlines():
            dl = dl.strip()
            if dl == '//':
                continue
            # Strip ALL '//  ' prefixes (comment_text adds one, model may add another)
            while dl.startswith('//  '):
                dl = dl[4:]
            while dl.startswith('//'):
                dl = dl[2:].lstrip()
            if dl:
                desc_lines.append(dl)
        for dl in desc_lines:
            lines.append(f"    //  {dl}")
        lines.append(f"    typedef {type_name} {name};")
        lines.append(f"#endif // {guard_name}")
        return "\n".join(lines)
    rendered_comment = emit_comment_block(comment)
    return f"{rendered_comment}typedef {type_name} {name};"


def render_c_code(elem: ET.Element) -> str:
    code = norm_text(elem.text)
    lines = code.splitlines()
    if lines and lines[0].lstrip().startswith("#define") and len(lines) > 1:
        # Find the max content width for column-aligned backslash continuation
        content_widths = []
        for idx, line in enumerate(lines):
            if idx < len(lines) - 1 and line.strip():
                content_widths.append(len(line.rstrip()))
        align_col = max(content_widths) + 1 if content_widths else 70
        rendered: list[str] = []
        for idx, line in enumerate(lines):
            if idx < len(lines) - 1 and line.strip():
                stripped = line.rstrip()
                padding = max(1, align_col - len(stripped))
                rendered.append(stripped + ' ' * padding + '\\')
            else:
                rendered.append(line)
        return "\n".join(rendered)
    return code


def render_macros(elem: ET.Element) -> str:
    comment = emit_comment_block(description_text(elem))
    code = render_c_code(elem.find("c_code"))
    return f"{comment}{code}"


def render_macroses(elem: ET.Element) -> str:
    comment = emit_comment_block(description_text(elem))
    code = render_c_code(elem.find("c_code"))
    return f"{comment}{code}"


def render_callback(elem: ET.Element) -> str:
    comment = emit_comment_block(description_text(elem))
    ret = elem.find("c_return")
    ret_type = c_decl(ret.attrib["type"], "", ret.attrib.get("accessed_by", "value"), ret.attrib.get("is_const_type"), ret.attrib.get("string") is not None, ret.attrib.get("array") is not None, ret.attrib.get("type_is")).strip()
    modifiers = " ".join(m.attrib["value"] for m in elem.findall("c_modifier"))
    args = []
    for arg in elem.findall("c_argument"):
        rendered = c_decl(arg.attrib['type'], arg.attrib.get('name',''), arg.attrib.get('accessed_by', 'value'), arg.attrib.get('is_const_type'), arg.attrib.get('string') is not None, arg.attrib.get('array') is not None, arg.attrib.get('type_is'))
        args.append(rendered)
    arg_str = ", ".join(args) if args else "void"
    left = f"typedef {modifiers} {ret_type}".replace("  ", " ").strip()
    return f"{comment}{left} (*{elem.attrib['name']})({arg_str});"


def render_enum(elem: ET.Element) -> str:
    comment = emit_comment_block(description_text(elem))
    enum_name = elem.attrib.get("name")
    typedef_name = elem.attrib.get("typedef_name")
    header = f"enum {enum_name} {{" if enum_name else "enum {"
    lines = [comment + header]
    constants = elem.findall("c_constant")
    for i, const in enumerate(constants):
        const_comment = emit_comment_block(const.text)
        if const_comment:
            lines.append(indent(const_comment.rstrip("\n"), 4))
        value = const.attrib.get("value")
        assignment = f" = {value}" if value is not None else ""
        comma = "," if i < len(constants) - 1 else ""
        lines.append(f"    {const.attrib['name']}{assignment}{comma}")
    lines.append("};")
    if typedef_name:
        enum_ref = f"enum {enum_name}" if enum_name else "enum"
        lines.append(f"typedef {enum_ref} {typedef_name};")
    return "\n".join(lines)


def render_struct_forward(elem: ET.Element) -> str:
    comment = emit_comment_block(description_text(elem))
    name = elem.attrib["name"]
    return f"{comment}typedef struct {name} {name};"


def render_struct_full(elem: ET.Element) -> str:
    comment = emit_comment_block(description_text(elem))
    name = elem.attrib["name"]
    typedef_public = elem.attrib.get("declaration") == "public"
    definition_public = elem.attrib.get("definition") == "public"
    # Legacy pattern: for public declaration + public definition, use two-line typedef
    if typedef_public and definition_public:
        lines = [comment + f"typedef struct {name} {name};", f"struct {name} {{"]
    elif typedef_public:
        lines = [comment + f"typedef struct {name} {{"]
    else:
        lines = [comment + f"struct {name} {{"]
    for prop in elem.findall("c_property"):
        prop_comment = emit_comment_block(prop.text)
        if prop_comment:
            lines.append(indent(prop_comment.rstrip("\n"), 4))
        decl = f"{c_decl(prop.attrib['type'], prop.attrib['name'], prop.attrib.get('accessed_by', 'value'), prop.attrib.get('is_const_type'), prop.attrib.get('string') is not None, prop.attrib.get('array') is not None, prop.attrib.get('type_is'), array_length=prop.attrib.get('length'))};"
        lines.append(f"    {decl}")
    if typedef_public and definition_public:
        lines.append("};")
    elif typedef_public:
        lines.append(f"}} {name};")
    else:
        lines.append("};")
    return "\n".join(lines)


def _render_c_value(cval: ET.Element) -> str:
    """Render a single c_value element, applying c_cast and address-of if present."""
    value = cval.attrib["value"]
    cast_elem = cval.find("c_cast")
    if cast_elem is not None:
        cast_type = cast_elem.attrib["type"]
        # Cast via void(*)(void) intermediary to suppress -Wcast-function-type-mismatch
        # when impl function pointers are cast to interface callback types.
        if cast_elem.attrib.get("type_is") == "callback":
            value = f"({cast_type})(void (*)(void)){value}"
        else:
            value = f"({cast_type}){value}"
    # For pointer-accessed values that reference local variables, add &
    if cval.attrib.get("accessed_by") == "pointer" and not value.startswith("&"):
        value = f"&{value}"
    return value


def _render_c_value_comment(cval: ET.Element) -> str:
    """Render the comment block for a c_value (indented for struct initializer)."""
    text = description_text(cval)
    if not text:
        return ""
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            # Already a comment line — normalize indentation
            lines.append(f"    {stripped}")
        elif stripped:
            lines.append(f"    //  {stripped}")
        else:
            lines.append("    //")
    return "\n".join(lines) + "\n"


def render_variable(elem: ET.Element) -> str:
    comment = emit_comment_block(description_text(elem))
    storage = "static " if elem.attrib.get("definition") == "private" else ""
    cvals = elem.findall("c_value")
    initializer = ""
    is_array = elem.attrib.get("array") == "derived"
    if len(cvals) > 1 or (len(cvals) == 1 and is_array):
        # Struct or array initializer with braces
        parts: list[str] = []
        for i, cval in enumerate(cvals):
            val_comment = _render_c_value_comment(cval)
            val_str = _render_c_value(cval)
            # Add comma after every value except the last
            if i < len(cvals) - 1:
                val_str += ","
            part = f"{val_comment}    {val_str}"
            parts.append(part)
        inner = "\n".join(parts)
        initializer = f" = {{\n{inner}\n}}"
    elif len(cvals) == 1:
        initializer = f" = {_render_c_value(cvals[0])}"
    decl = f"{storage}{c_decl(elem.attrib['type'], elem.attrib['name'], elem.attrib.get('accessed_by', 'value'), elem.attrib.get('is_const_type'), elem.attrib.get('string') is not None, False, elem.attrib.get('type_is'))}"
    if is_array:
        decl += "[]"
    decl += initializer + ";"
    return f"{comment}{decl}"


def render_method_signature(elem: ET.Element, for_definition: bool) -> str:
    ret = elem.find("c_return")
    ret_type = "void"
    if ret is not None:
        ret_type = c_decl(ret.attrib["type"], "", ret.attrib.get("accessed_by", "value"), ret.attrib.get("is_const_type"), ret.attrib.get("string") is not None, ret.attrib.get("array") is not None, ret.attrib.get("type_is")).strip()
    modifiers = " ".join(m.attrib["value"] for m in elem.findall("c_modifier"))
    parts = [p for p in [modifiers, ret_type] if p]
    header = " ".join(parts)
    args = []
    for arg in elem.findall("c_argument"):
        if arg.attrib.get("type") == "void" and not arg.attrib.get("name"):
            args.append("void")
        else:
            args.append(c_decl(arg.attrib['type'], arg.attrib['name'], arg.attrib.get('accessed_by', 'value'), arg.attrib.get('is_const_type'), arg.attrib.get('string') is not None, arg.attrib.get('array') is not None, arg.attrib.get('type_is')))
    arg_str = ", ".join(args) if args else "void"
    # Attributes (e.g. VSCF_NODISCARD) are placed after the closing paren — only in declarations
    if not for_definition:
        attributes = " ".join(a.attrib["value"] for a in elem.findall("c_attribute"))
        suffix = f" {attributes}" if attributes else ""
    else:
        suffix = ""
    return f"{header}\n{elem.attrib['name']}({arg_str}){suffix}"


def render_method(elem: ET.Element, for_definition: bool) -> str:
    comment = emit_comment_block(description_text(elem))
    sig = render_method_signature(elem, for_definition)
    if not for_definition:
        return f"{comment}{sig};"
    code = render_c_code(elem.find("c_code"))
    return f"{comment}{sig} {{\n\n{indent(code, 4)}\n}}"


def indent(text: str, spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(prefix + line if line else "" for line in text.splitlines())


def _append_items(out: list[str], items: list[str]) -> None:
    for item in items:
        if item:
            out.append(item)
            out.append("")


def generate_block(root: ET.Element, for_header: bool) -> str:
    out: list[str] = [
        "//  @generated",
        "// --------------------------------------------------------------------------",
        "// clang-format off",
        "//  Generated section start.",
        "// --------------------------------------------------------------------------",
        "",
    ]

    children = list(root)
    if for_header:
        # System includes needed by generated code (e.g. library types in methods)
        sys_includes = [render_include(c) for c in children if c.tag == 'c_include' and c.attrib.get('is_system') == '1' and c.attrib.get('scope') == 'public']
        _append_items(out, sys_includes)
        _append_items(out, [render_alias(c) for c in children if c.tag == 'c_alias' and c.attrib.get('declaration') == 'public'])
        _append_items(out, [render_c_code(c) for c in children if c.tag == 'c_code' and c.attrib.get('definition') == 'public'])
        _append_items(out, [render_macroses(c) for c in children if c.tag == 'c_macroses' and c.attrib.get('definition') == 'public'])
        _append_items(out, [render_macros(c) for c in children if c.tag == 'c_macros' and c.attrib.get('definition') == 'public'])
        _append_items(out, [render_enum(c) for c in children if c.tag == 'c_enum' and c.attrib.get('declaration') == 'public' and c.attrib.get('definition') == 'public'])
        _append_items(out, [render_struct_forward(c) for c in children if c.tag == 'c_struct' and c.attrib.get('declaration') == 'public' and c.attrib.get('definition') != 'public'])
        _append_items(out, [render_callback(c) for c in children if c.tag == 'c_callback' and c.attrib.get('declaration') == 'public'])
        _append_items(out, [render_struct_full(c) for c in children if c.tag == 'c_struct' and c.attrib.get('definition') == 'public'])
        _append_items(out, [render_variable(c) for c in children if c.tag == 'c_variable' and c.attrib.get('declaration') == 'public'])
        _append_items(out, [render_method(c, False) for c in children if c.tag == 'c_method' and c.attrib.get('declaration') == 'public'])
    else:
        _append_items(out, [render_alias(c) for c in children if c.tag == 'c_alias' and c.attrib.get('declaration') == 'private'])
        _append_items(out, [render_c_code(c) for c in children if c.tag == 'c_code' and c.attrib.get('definition') == 'private'])
        _append_items(out, [render_macroses(c) for c in children if c.tag == 'c_macroses' and c.attrib.get('definition') == 'private'])
        _append_items(out, [render_macros(c) for c in children if c.tag == 'c_macros' and c.attrib.get('definition') == 'private'])
        _append_items(out, [render_enum(c) for c in children if c.tag == 'c_enum' and c.attrib.get('definition') == 'private'])
        _append_items(out, [render_callback(c) for c in children if c.tag == 'c_callback' and c.attrib.get('declaration') == 'private'])
        _append_items(out, [render_struct_full(c) for c in children if c.tag == 'c_struct' and c.attrib.get('definition') == 'private'])
        _append_items(out, [render_method(c, False) for c in children if c.tag == 'c_method' and c.attrib.get('declaration') == 'private'])
        _append_items(out, [render_variable(c) for c in children if c.tag == 'c_variable' and c.attrib.get('definition') != 'external'])
        _append_items(out, [render_method(c, True) for c in children if c.tag == 'c_method' and c.attrib.get('definition') != 'external' and any(code.attrib.get('type') == 'generated' for code in c.findall('c_code'))])

    while len(out) > 1 and out[-1] == "":
        out.pop()
    # Ensure exactly 2 trailing blank lines before section end markers (matches legacy)
    out.extend(["", ""])
    out.extend([
        "// --------------------------------------------------------------------------",
        "//  Generated section end.",
        "// clang-format on",
        "// --------------------------------------------------------------------------",
        "//  @end",
    ])
    return "\n".join(out) + "\n"


def render_one(xml_path: Path, repo_root: Path, codegen_root: Path, out_root: Path, *, project: str = "common") -> list[Path]:
    renderer = direct_c_renderers(repo_root, project).get(xml_path.name)
    if renderer is not None:
        root = renderer(repo_root)
    else:
        root = ET.parse(xml_path).getroot()
    written = []
    for attr, is_header in [("header_file", True), ("source_file", False)]:
        rel = root.attrib.get(attr)
        if not rel:
            continue
        target = (codegen_root / rel).resolve()
        if not target.exists():
            continue
        existing = target.read_text()
        generated = generate_block(root, is_header)
        out_path = out_root / target.relative_to(repo_root)
        ensure_parent(out_path)
        out_path.write_text(merge_generated_section(existing, generated))
        written.append(out_path)
    return written


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--project", default="common", choices=supported_projects())
    parser.add_argument("--out", default="build/new-codegen")
    parser.add_argument("--apply", action="store_true", help="write directly into repo source tree")
    parser.add_argument(
        "--legacy-c-modules",
        action="store_true",
        help="include resolved c_module XML fallback inputs for migration/parity-only runs",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    out_root = repo_root if args.apply else (repo_root / args.out).resolve()
    codegen_root = repo_root / "codegen"
    project_dir = codegen_root / "generated" / args.project
    if not args.apply:
        if out_root.exists():
            shutil.rmtree(out_root)
        out_root.mkdir(parents=True, exist_ok=True)

    written = []
    skipped = []
    for xml_path in iter_project_xml_paths(
        project_dir,
        repo_root,
        project=args.project,
        include_legacy_fallback=args.legacy_c_modules,
    ):
        try:
            written.extend(render_one(xml_path, repo_root, codegen_root, out_root, project=args.project))
        except Exception as exc:
            skipped.append((xml_path.name, str(exc)))

    # --- Umbrella headers ---
    project_ir = project_to_ir(load_named_project_source(args.project, repo_root))
    if args.project != "common":
        common_ir = project_to_ir(load_named_project_source("common", repo_root))
        project_ir.fallback_projects = [common_ir]
    # Read license text from project XML model
    project_xml_path = codegen_root / "models" / f"project_{args.project}" / f"project_{args.project}.xml"
    license_text = ""
    if project_xml_path.exists():
        project_tree = ET.parse(project_xml_path)
        lic_elem = project_tree.getroot().find("license")
        if lic_elem is not None and lic_elem.text:
            license_text = lic_elem.text
    for rel_path, content in generate_umbrella_headers(project_ir, license_text=license_text):
        # rel_path is relative to codegen root (e.g. ../library/...)
        abs_path = (codegen_root / rel_path).resolve()
        out_path = out_root / abs_path.relative_to(repo_root)
        ensure_parent(out_path)
        out_path.write_text(content)
        written.append(out_path)

    destination = repo_root if args.apply else out_root
    print(f"generated {len(written)} files into {destination}")
    for path in written:
        print(path.relative_to(repo_root))
    # Known skips: modules that reference IR entities not yet available.
    # These are expected and should not cause a non-zero exit code.
    KNOWN_SKIPS: set[str] = set()

    unexpected_skips = [(n, e) for n, e in skipped if n not in KNOWN_SKIPS]
    known = [(n, e) for n, e in skipped if n in KNOWN_SKIPS]

    if known:
        print(f"\nskipped {len(known)} known module(s) (expected):")
        for name, err in known:
            print(f"  {name}: {err}")
    if unexpected_skips:
        print(f"\nskipped {len(unexpected_skips)} module(s) due to errors:")
        for name, err in unexpected_skips:
            print(f"  {name}: {err}")
    return 1 if unexpected_skips else 0


if __name__ == "__main__":
    raise SystemExit(main())
