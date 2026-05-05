from __future__ import annotations

import argparse
import html
import os
from pathlib import Path
import re
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
GENERATED_HEADER_INCLUDES_START = "//  @generated_header_includes"
GENERATED_END = "//  @end"



# ---------------------------------------------------------------------------
# Supported projects
# ---------------------------------------------------------------------------

_SUPPORTED_PROJECTS = ("common", "foundation", "phe", "pythia", "ratchet")


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

    project_source = load_named_project_source(project, repo_root)
    project_ir = project_to_ir(project_source)

    # Cross-project fallback: load required projects from model <require project="..."/>
    fallbacks: list[IRProject] = []
    for req in project_source.library_requires:
        if req.kind == "project":
            fallbacks.append(project_to_ir(load_named_project_source(req.name, repo_root)))
    if fallbacks:
        project_ir.fallback_projects = fallbacks

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


def split_tagged_section(content: str, start_marker: str) -> tuple[str, str]:
    lines = content.splitlines(keepends=True)
    start_idx: int | None = None
    end_idx: int | None = None

    for i, line in enumerate(lines):
        if line.rstrip("\n") == start_marker:
            start_idx = i
            break
    if start_idx is None:
        raise ValueError(f"start marker not found on its own line: {start_marker}")

    for i in range(start_idx + 1, len(lines)):
        if lines[i].rstrip("\n") == GENERATED_END:
            end_idx = i
            break
    if end_idx is None:
        raise ValueError(f"end marker not found for section starting with: {start_marker}")

    prefix = "".join(lines[:start_idx])
    suffix = "".join(lines[end_idx + 1:])
    if suffix.startswith("\n"):
        suffix = suffix[1:]
    return prefix, suffix


def split_generated_sections(content: str) -> tuple[str, str]:
    return split_tagged_section(content, GENERATED_START)


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def merge_generated_section(existing: str, generated: str) -> str:
    prefix, suffix = split_generated_sections(existing)
    # Ensure blank line separation after the generated block
    if generated and suffix and not suffix.startswith("\n"):
        generated = generated.rstrip("\n") + "\n\n"
    return prefix + generated + suffix


def merge_or_insert_tagged_section(existing: str, generated: str, *, start_marker: str, anchor_before: str | None = None) -> str:
    if start_marker in existing:
        prefix, suffix = split_tagged_section(existing, start_marker)
        # Ensure blank line separation between sections
        if generated and suffix and not suffix.startswith("\n"):
            generated = generated.rstrip("\n") + "\n\n\n"
        return prefix + generated + suffix

    if not generated:
        return existing

    if anchor_before and anchor_before in existing:
        idx = existing.index(anchor_before)
        prefix = existing[:idx].rstrip("\n")
        suffix = existing[idx:].lstrip("\n")
        return f"{prefix}\n\n{generated}\n\n{suffix}"

    return existing.rstrip("\n") + "\n\n" + generated


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

    def _guarded_typedef(guard_name: str) -> str:
        lines = [f"#ifndef {guard_name}", f"#define {guard_name}"]
        raw_desc = comment.strip()
        desc_lines = []
        for dl in raw_desc.splitlines():
            dl = dl.strip()
            if dl == '//':
                continue
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

    # Special case: 'byte' typedef gets a BYTE_DEFINED guard (legacy GSL behavior)
    if name == 'byte':
        return _guarded_typedef(f"{name.upper()}_DEFINED")

    # Legacy array typedef aliases use per-alias include guards, e.g.
    # vscr_ratchet_public_key_t[32] -> VSCR_RATCHET_PUBLIC_KEY_T_32__DEFINED
    if '[' in name and ']' in name:
        import re as _re
        normalized = _re.sub(r'[^A-Za-z0-9]+', '_', name.upper()).strip('_')
        return _guarded_typedef(f"{normalized}__DEFINED")

    rendered_comment = emit_comment_block(comment)
    return f"{rendered_comment}typedef {type_name} {name};"


def render_c_code(elem: ET.Element) -> str:
    code = norm_text(elem.text)
    lines = code.splitlines()
    if lines and lines[0].lstrip().startswith("#define") and len(lines) > 1:
        # Strip existing trailing backslash continuations before re-adding
        cleaned = [line.rstrip().rstrip("\\").rstrip() for line in lines]
        # Find the max content width for column-aligned backslash continuation
        content_widths = []
        for idx, line in enumerate(cleaned):
            if idx < len(cleaned) - 1 and line.strip():
                content_widths.append(len(line))
        align_col = max(content_widths) + 1 if content_widths else 70
        rendered: list[str] = []
        for idx, line in enumerate(cleaned):
            if idx < len(cleaned) - 1 and line.strip():
                padding = max(1, align_col - len(line))
                rendered.append(line + ' ' * padding + '\\')
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
        _arr = arg.attrib.get('array')
        _arr_len = _arr if _arr and _arr not in ('given', 'derived') else None
        rendered = c_decl(arg.attrib['type'], arg.attrib.get('name', ''), arg.attrib.get('accessed_by', 'value'), arg.attrib.get('is_const_type'), arg.attrib.get('string') is not None, _arr is not None, arg.attrib.get('type_is'), array_length=_arr_len)
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


def render_variable(elem: ET.Element, for_header: bool = False) -> str:
    comment = emit_comment_block(description_text(elem))
    modifiers = [m.attrib["value"] for m in elem.findall("c_modifier")]
    if for_header:
        # Header: extern declaration with modifiers
        storage = (" ".join(modifiers) + " extern ") if modifiers else "extern "
    elif modifiers:
        # Modifiers present → use them (e.g. VSCF_PUBLIC), not static
        storage = " ".join(modifiers) + " "
    elif elem.attrib.get("definition") == "private":
        # No modifier + definition=private → static (file-local)
        storage = "static "
    else:
        storage = ""
    cvals = elem.findall("c_value")
    initializer = ""
    array_attr = elem.attrib.get("array")
    is_array = array_attr is not None  # "derived" or a fixed size like "8"
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
        if array_attr == "derived":
            decl += "[]"
        else:
            decl += f"[{array_attr}]"  # Fixed-size array e.g. [8]
    if for_header:
        decl += ";"  # Declaration only, no initializer
    else:
        decl += initializer + ";"
    return f"{comment}{decl}"


def render_method_signature(elem: ET.Element, for_definition: bool) -> str:
    ret = elem.find("c_return")
    ret_type = "void"
    if ret is not None:
        ret_type = c_decl(ret.attrib["type"], "", ret.attrib.get("accessed_by", "value"), ret.attrib.get("is_const_type"), ret.attrib.get("string") is not None, ret.attrib.get("array") is not None, ret.attrib.get("type_is")).strip()
    modifiers = " ".join(m.attrib["value"] for m in elem.findall("c_modifier"))
    if not modifiers and elem.attrib.get("visibility") == "private" and elem.attrib.get("declaration") == "private":
        modifiers = "static"
    parts = [p for p in [modifiers, ret_type] if p]
    header = " ".join(parts)
    args = []
    for arg in elem.findall("c_argument"):
        if arg.attrib.get("type") == "void" and not arg.attrib.get("name"):
            args.append("void")
        elif arg.attrib.get("type") == "...":
            args.append("...")
        else:
            _arr = arg.attrib.get('array')
            _arr_len = _arr if _arr and _arr not in ('given', 'derived') else None
            args.append(c_decl(arg.attrib['type'], arg.attrib['name'], arg.attrib.get('accessed_by', 'value'), arg.attrib.get('is_const_type'), arg.attrib.get('string') is not None, _arr is not None, arg.attrib.get('type_is'), array_length=_arr_len))
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


def _generated_block_header(start_marker: str, title: str = "Generated section start.") -> list[str]:
    return [
        start_marker,
        "// --------------------------------------------------------------------------",
        "// clang-format off",
        f"//  {title}",
        "// --------------------------------------------------------------------------",
        "",
    ]


def _generated_block_footer() -> list[str]:
    return [
        "// --------------------------------------------------------------------------",
        "//  Generated section end.",
        "// clang-format on",
        "// --------------------------------------------------------------------------",
        "//  @end",
    ]


def generate_header_includes_block(root: ET.Element) -> str:
    children = list(root)
    sys_includes = [render_include(c) for c in children if c.tag == 'c_include' and c.attrib.get('is_system') == '1' and c.attrib.get('scope') == 'public']
    if not sys_includes:
        return ""

    out: list[str] = _generated_block_header(GENERATED_HEADER_INCLUDES_START, "Generated header includes start.")
    out.extend(sys_includes)
    out.append("")
    out.extend(_generated_block_footer())
    return "\n".join(out) + "\n"


def generate_block(root: ET.Element, for_header: bool) -> str:
    out: list[str] = _generated_block_header(GENERATED_START)

    children = list(root)
    if for_header:
        _append_items(out, [render_alias(c) for c in children if c.tag == 'c_alias' and c.attrib.get('declaration') == 'public'])
        _append_items(out, [render_c_code(c) for c in children if c.tag == 'c_code' and c.attrib.get('definition') == 'public'])
        _append_items(out, [render_macroses(c) for c in children if c.tag == 'c_macroses' and c.attrib.get('definition') == 'public'])
        _append_items(out, [render_macros(c) for c in children if c.tag == 'c_macros' and c.attrib.get('definition') == 'public'])
        _append_items(out, [render_enum(c) for c in children if c.tag == 'c_enum' and c.attrib.get('declaration') == 'public' and c.attrib.get('definition') == 'public'])
        _append_items(out, [render_struct_forward(c) for c in children if c.tag == 'c_struct' and c.attrib.get('declaration') == 'public' and c.attrib.get('definition') != 'public'])
        _append_items(out, [render_callback(c) for c in children if c.tag == 'c_callback' and c.attrib.get('declaration') == 'public'])
        _append_items(out, [render_struct_full(c) for c in children if c.tag == 'c_struct' and c.attrib.get('definition') == 'public'])
        _append_items(out, [render_variable(c, for_header=True) for c in children if c.tag == 'c_variable' and c.attrib.get('declaration') == 'public'])
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
    out.extend(_generated_block_footer())
    return "\n".join(out) + "\n"


def _find_first_untagged_end(lines: list[str]) -> int | None:
    """Find the first ``//  @end`` not preceded by a ``@generated*`` marker."""
    for i, line in enumerate(lines):
        if line.rstrip("\n") != GENERATED_END:
            continue
        has_gen_start = False
        for j in range(i - 1, -1, -1):
            sj = lines[j].rstrip("\n")
            if sj == GENERATED_START or sj == GENERATED_HEADER_INCLUDES_START:
                has_gen_start = True
                break
            if sj == GENERATED_END:
                break
        if not has_gen_start:
            return i
    return None


def _update_license_block(content: str, license_text: str) -> str:
    """Replace the @license block in an existing file with the current license text.

    Finds the block between ``//  @license`` and the first ``// clang-format off``
    (which is always the last line of the license block) and replaces it with a
    freshly rendered block built from *license_text*.  Returns *content* unchanged
    when the marker is absent or *license_text* is empty.
    """
    if not license_text:
        return content
    license_start = "//  @license\n"
    pos = content.find(license_start)
    if pos < 0:
        return content
    rest = content[pos + len(license_start):]
    end_marker = "// clang-format off\n"
    end_pos = rest.find(end_marker)
    if end_pos < 0:
        return content
    lic_lines = ["//  @license", "// " + "-" * 74]
    for line in license_text.strip().splitlines():
        line = line.strip()
        lic_lines.append(f"//  {line}" if line else "//")
    lic_lines.append("// " + "-" * 74)
    lic_lines.append("// clang-format off")
    new_block = "\n".join(lic_lines) + "\n"
    block_end = pos + len(license_start) + end_pos + len(end_marker)
    return content[:pos] + new_block + content[block_end:]


_COPYRIGHT_YEAR_RE = re.compile(
    r"(Copyright \(C\) \d{4})(?:-\d{4})?( Virgil Security)"
)


def _update_copyright_year(content: str, target_year: int | str) -> str:
    """Replace the end year in all Virgil copyright notices found in *content*.

    Works regardless of comment style (``//``, ``#``, ``*``, etc.) because it
    matches the copyright text itself, not the surrounding comment markers.
    Handles both "Virgil Security Inc." and "Virgil Security, Inc." variants.
    """
    return _COPYRIGHT_YEAR_RE.sub(rf"\g<1>-{target_year}\2", content)


def _extract_license_year(license_text: str) -> str | None:
    """Return the last year in the first copyright line of *license_text*."""
    m = re.search(r"Copyright \(C\) \d{4}-(\d{4})", license_text)
    if m:
        return m.group(1)
    m = re.search(r"Copyright \(C\) (\d{4})", license_text)
    return m.group(1) if m else None


def _extract_old_header_includes(content: str) -> tuple[str, list[str]]:
    """Extract ``#include`` lines from the first un-tagged ``@end`` block.

    Returns (cleaned_content, extracted_include_lines).  The include lines are
    stripped from the content and returned so they can be merged into the
    ``@generated_header_includes`` section.
    """
    lines = content.splitlines(keepends=True)
    first_end = _find_first_untagged_end(lines)
    if first_end is None:
        return content, []

    extracted: list[str] = []
    out: list[str] = []
    for i, line in enumerate(lines):
        if i < first_end and line.lstrip().startswith("#include "):
            extracted.append(line.strip())
            continue
        out.append(line)
    result = "".join(out)
    while "\n\n\n" in result:
        result = result.replace("\n\n\n", "\n\n")
    return result, extracted


def _create_file_skeleton(root: ET.Element, is_header: bool, *, license_text: str = "") -> str:
    """Create a full C file skeleton matching the legacy GSL codegen template.

    Produces files with the standard section ordering:
    - Header: @license, @warning, @description, #ifndef guard, includes @end,
              @generated_header_includes, extern C, @generated, extern C end, @footer
    - Source: @license, @description, @warning, includes @end, @generated
    """
    name = root.attrib.get("name", "")
    once_guard = root.attrib.get("once_guard", "").upper()

    # Read description from the root element text
    raw_desc = (root.text or "").strip()
    desc_lines = [line.strip() for line in raw_desc.splitlines() if line.strip()]

    # License block
    lic: list[str] = []
    if license_text:
        lic.append("//  @license")
        lic.append("// " + "-" * 74)
        for line in license_text.strip().splitlines():
            line = line.strip()
            lic.append(f"//  {line}" if line else "//")
        lic.append("// " + "-" * 74)
        lic.append("// clang-format off")

    # Warning block
    warn = [
        "//  @warning",
        "// " + "-" * 74,
        "//  This file is partially generated.",
        "//  Generated blocks are enclosed between tags [@<tag>, @end].",
        "//  User's code can be added between tags [@end, @<tag>].",
        "// " + "-" * 74,
    ]

    # Description block
    desc: list[str] = []
    if desc_lines:
        desc.append("//  @description")
        desc.append("// " + "-" * 74)
        for dl in desc_lines:
            desc.append(f"//  {dl}")
        desc.append("// " + "-" * 74)

    lines: list[str] = []
    if is_header:
        # Header: @license, @warning, @description, guard, includes, extern C, @generated, footer
        guard = once_guard or f"{name.upper()}_H_INCLUDED"
        lines.extend(lic)
        lines.append("")
        lines.extend(warn)
        lines.append("")
        if desc:
            lines.extend(desc)
            lines.append("")
        lines.append(f"#ifndef {guard}")
        lines.append(f"#define {guard}")
        lines.append("")
        lines.append("// clang-format on")
        lines.append("//  @end")
        lines.append("")
        lines.append("")
        lines.append("#ifdef __cplusplus")
        lines.append('extern "C" {')
        lines.append("#endif")
        lines.append("")
        lines.append("")
        lines.append("//  @generated")
        lines.append("//  @end")
        lines.append("")
        lines.append("")
        lines.append("#ifdef __cplusplus")
        lines.append("}")
        lines.append("#endif")
        lines.append("")
        lines.append("//  @footer")
        lines.append(f"#endif // {guard}")
        lines.append("//  @end")
        lines.append("")
    else:
        # Source: @license, @description, @warning, includes, @generated
        lines.extend(lic)
        lines.append("")
        lines.append("")
        if desc:
            lines.extend(desc)
            lines.append("")
            lines.append("")
        lines.extend(warn)
        lines.append("")
        c_include_file = root.attrib.get("c_include_file", "")
        if c_include_file:
            lines.append(f'#include "{c_include_file}"')
        # Add private-scope includes from the renderer
        priv_includes = [render_include(c) for c in root
                         if c.tag == "c_include" and c.attrib.get("scope") == "private"
                         and c.attrib.get("file") != c_include_file]
        for inc in priv_includes:
            lines.append(inc)
        lines.append("")
        lines.append("// clang-format on")
        lines.append("//  @end")
        lines.append("")
        lines.append("")
        lines.append("//  @generated")
        lines.append("//  @end")
        lines.append("")

    return "\n".join(lines)


def render_one(xml_path: Path, repo_root: Path, codegen_root: Path, out_root: Path, *, project: str = "common", license_text: str = "") -> list[Path]:
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
        is_new_file = not target.exists()
        if is_new_file:
            existing = _create_file_skeleton(root, is_header, license_text=license_text)
        else:
            existing = _update_license_block(target.read_text(), license_text)
        generated = generate_block(root, is_header)
        merged = merge_generated_section(existing, generated)
        if is_header:
            # Extract existing includes from the legacy first @end block
            # and merge them with codegen-produced system includes into a
            # single @generated_header_includes section.
            merged, old_includes = _extract_old_header_includes(merged)
            include_block = generate_header_includes_block(root)
            # Build combined block: user-area legacy includes + existing section includes
            # + renderer includes + system includes.
            # The renderer is authoritative for ADDING new includes.  Existing section includes
            # are preserved additively EXCEPT for cross-project bare includes (e.g. "vsc_data.h"
            # in a vscf_ header) which break CGo CFLAGS and are already covered by the
            # framework-conditional user-area blocks.
            self_include = root.attrib.get("c_include_file", "")
            self_prefix = self_include.split("_")[0] + "_" if "_" in self_include else ""
            renderer_pub_includes = [
                render_include(c) for c in root
                if c.tag == "c_include"
                and c.attrib.get("scope") == "public"
                and c.attrib.get("is_system") != "1"
                and c.attrib.get("file") != self_include
                and (not self_prefix or c.attrib.get("file", "").startswith(self_prefix))
            ]
            # Build a set of bare filenames that exist in this project's library tree so we
            # can drop stale same-prefix includes that were injected by a prior broken run.
            lib_dir = repo_root / "library" / project
            _known_bare: set[str] | None = None
            if lib_dir.is_dir():
                _known_bare = {p.name for p in lib_dir.rglob("*.h")}
            existing_section_includes: list[str] = []
            if GENERATED_HEADER_INCLUDES_START in merged:
                try:
                    sec_start = merged.index(GENERATED_HEADER_INCLUDES_START)
                    sec_end = merged.index(GENERATED_END, sec_start)
                    for ln in merged[sec_start:sec_end].splitlines():
                        stripped = ln.strip()
                        if not stripped.startswith("#include "):
                            continue
                        # Drop cross-project bare includes: they break CGo and are in user area.
                        if self_prefix and stripped.startswith('#include "'):
                            fname = stripped[len('#include "'):-1]
                            if not fname.startswith(self_prefix):
                                continue
                            # Drop same-prefix bare includes whose file doesn't exist anywhere
                            # in this project's library tree (e.g. vscr_impl.h from a buggy run).
                            if _known_bare is not None and fname not in _known_bare:
                                continue
                        existing_section_includes.append(stripped)
                except ValueError:
                    pass
            sys_lines: list[str] = []
            if include_block:
                for ln in include_block.splitlines():
                    if ln.strip().startswith("#include "):
                        sys_lines.append(ln.strip())
            seen: set[str] = set()
            combined: list[str] = []
            for inc in old_includes:
                if inc not in seen:
                    combined.append(inc)
                    seen.add(inc)
            for inc in existing_section_includes:
                if inc not in seen:
                    combined.append(inc)
                    seen.add(inc)
            for inc in renderer_pub_includes:
                if inc not in seen:
                    combined.append(inc)
                    seen.add(inc)
            for inc in sys_lines:
                if inc not in seen:
                    combined.append(inc)
                    seen.add(inc)
            if combined:
                # Separate project ("...") and system (<...>) includes
                proj = [x for x in combined if x.startswith('#include "')]
                sys = [x for x in combined if x.startswith("#include <")]
                out_lines = _generated_block_header(GENERATED_HEADER_INCLUDES_START, "Generated header includes start.")
                if proj:
                    out_lines.extend(proj)
                    if sys:
                        out_lines.append("")
                if sys:
                    out_lines.extend(sys)
                out_lines.append("")
                out_lines.extend(_generated_block_footer())
                include_block = "\n".join(out_lines) + "\n"
            if combined or include_block:
                merged = merge_or_insert_tagged_section(
                    merged,
                    include_block,
                    start_marker=GENERATED_HEADER_INCLUDES_START,
                    anchor_before="#ifdef __cplusplus",
                )
        out_path = out_root / target.relative_to(repo_root)
        ensure_parent(out_path)
        out_path.write_text(merged)
        written.append(out_path)
    return written


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--project", default="common", choices=[*supported_projects(), "all"])
    parser.add_argument("--out", default="build/new-codegen")
    parser.add_argument("--apply", action="store_true", help="write directly into repo source tree")
    parser.add_argument(
        "--legacy-c-modules",
        action="store_true",
        help="include resolved c_module XML fallback inputs for migration/parity-only runs",
    )
    args = parser.parse_args()

    projects = list(supported_projects()) if args.project == "all" else [args.project]

    repo_root = Path(args.repo_root).resolve()
    codegen_root = repo_root / "codegen"

    if not args.apply:
        out_root = (repo_root / args.out).resolve()
        if out_root.exists():
            shutil.rmtree(out_root)
        out_root.mkdir(parents=True, exist_ok=True)
    else:
        out_root = repo_root

    # Known skips: modules that reference IR entities not yet available.
    KNOWN_SKIPS: set[str] = set()

    all_written: list[Path] = []
    all_unexpected: list[tuple[str, str]] = []

    # Read license text once from repo root LICENSE file
    _license_file = repo_root / "LICENSE"
    _repo_license_text = _license_file.read_text().strip() if _license_file.exists() else ""

    for project in projects:
        project_dir = codegen_root / "generated" / project

        project_license = _repo_license_text

        written: list[Path] = []
        skipped: list[tuple[str, str]] = []
        for xml_path in iter_project_xml_paths(
            project_dir,
            repo_root,
            project=project,
            include_legacy_fallback=args.legacy_c_modules,
        ):
            try:
                written.extend(render_one(xml_path, repo_root, codegen_root, out_root, project=project, license_text=project_license))
            except Exception as exc:
                skipped.append((xml_path.name, str(exc)))

        # --- Umbrella headers ---
        project_ir = project_to_ir(load_named_project_source(project, repo_root))
        umbrella_source = load_named_project_source(project, repo_root)
        umbrella_fallbacks: list[IRProject] = []
        for req in umbrella_source.library_requires:
            if req.kind == "project":
                umbrella_fallbacks.append(project_to_ir(load_named_project_source(req.name, repo_root)))
        if umbrella_fallbacks:
            project_ir.fallback_projects = umbrella_fallbacks
        license_text = _repo_license_text
        for rel_path, content in generate_umbrella_headers(project_ir, license_text=license_text):
            abs_path = (codegen_root / rel_path).resolve()
            out_path = out_root / abs_path.relative_to(repo_root)
            ensure_parent(out_path)
            out_path.write_text(content)
            written.append(out_path)

        # --- CMake files ---
        from tools.codegen.project_cmake_backend import generate_cmake_files
        for rel_path, content in generate_cmake_files(project_ir, license_text=license_text):
            out_path = out_root / rel_path
            ensure_parent(out_path)
            out_path.write_text(content)
            written.append(out_path)

        # --- Go wrapper files ---
        # Only projects that declare ``go`` in their ``wrappers`` attribute
        # ship Go bindings. Today that's foundation and phe; other projects
        # (common, pythia, ratchet) get no Go output at all.
        wrappers_attr = project_ir.attrs.get("wrappers", "")
        wrappers_set = {w.strip() for w in wrappers_attr.split(",") if w.strip()}
        if "go" in wrappers_set:
            from tools.codegen.project_go_backend import generate_go_files
            for rel_path, content in generate_go_files(project_ir, license_text=license_text):
                out_path = out_root / rel_path
                # Test files are handwritten and must NEVER be overwritten —
                # the generator already refuses to emit them, so this is a
                # belt-and-braces guard.
                if out_path.name.endswith("_test.go"):
                    continue
                ensure_parent(out_path)
                out_path.write_text(content)
                written.append(out_path)

        # --- Python wrapper files ---
        if "python" in wrappers_set:
            from tools.codegen.project_python_backend import generate_python_files
            for rel_path, content in generate_python_files(
                project_ir, license_text=license_text,
                repo_root=str(repo_root),
            ):
                out_path = out_root / rel_path
                # Test files are handwritten and must NOT be overwritten.
                if "/tests/" in str(out_path):
                    continue
                # manual/ directory is a separate handwritten API layer.
                if "/manual/" in str(out_path):
                    continue
                ensure_parent(out_path)
                out_path.write_text(content)
                written.append(out_path)

        # --- Swift wrapper files ---
        if "swift" in wrappers_set:
            from tools.codegen.project_swift_backend import generate_swift_files
            for rel_path, content in generate_swift_files(
                project_ir, license_text=license_text,
                repo_root=str(repo_root),
            ):
                out_path = out_root / rel_path
                # Test files are handwritten and must NOT be overwritten.
                if "Test" in str(out_path.parent):
                    continue
                ensure_parent(out_path)
                out_path.write_text(content)
                written.append(out_path)

        # --- PHP wrapper files ---
        if "php" in wrappers_set:
            from tools.codegen.project_php_backend import generate_php_files
            for rel_path, content in generate_php_files(
                project_ir, license_text=license_text,
                repo_root=str(repo_root),
            ):
                out_path = out_root / rel_path
                # Test files are handwritten and must NOT be overwritten.
                if "/tests/" in str(out_path):
                    continue
                # _handwritten/ directory must NOT be touched.
                if "_handwritten" in str(out_path):
                    continue
                ensure_parent(out_path)
                out_path.write_text(content)
                written.append(out_path)

        # --- Java wrapper files ---
        if "java" in wrappers_set:
            from tools.codegen.project_java_backend import generate_java_files
            for rel_path, content in generate_java_files(
                project_ir, license_text=license_text,
                repo_root=str(repo_root),
            ):
                out_path = out_root / rel_path
                # Test files are handwritten and must NOT be overwritten.
                if "/test/" in str(out_path) or "/androidTest/" in str(out_path):
                    continue
                ensure_parent(out_path)
                out_path.write_text(content)
                written.append(out_path)

        # --- WASM wrapper files ---
        if "wasm" in wrappers_set:
            from tools.codegen.project_wasm_backend import generate_wasm_files
            for rel_path, content in generate_wasm_files(
                project_ir, license_text=license_text,
                repo_root=str(repo_root),
            ):
                out_path = out_root / rel_path
                ensure_parent(out_path)
                out_path.write_text(content)
                written.append(out_path)

        unexpected_skips = [(n, e) for n, e in skipped if n not in KNOWN_SKIPS]
        known = [(n, e) for n, e in skipped if n in KNOWN_SKIPS]

        if known:
            print(f"\n[{project}] skipped {len(known)} known module(s) (expected):")
            for name, err in known:
                print(f"  {name}: {err}")
        if unexpected_skips:
            print(f"\n[{project}] skipped {len(unexpected_skips)} module(s) due to errors:")
            for name, err in unexpected_skips:
                print(f"  {name}: {err}")

        all_written.extend(written)
        all_unexpected.extend(unexpected_skips)

    # --- External library cmake files (thirdparty/*/features.cmake) ---
    from tools.codegen.project_cmake_backend import generate_external_library_cmake_files
    from tools.codegen.project_source import load_external_library_source
    from tools.codegen.project_ir import external_library_to_ir
    external_models_dir = codegen_root / "models" / "external"
    for lib_xml in sorted(external_models_dir.glob("library_*.xml")):
        try:
            lib_source = load_external_library_source(lib_xml)
            lib_ir = external_library_to_ir(lib_source)
            for rel_path, content in generate_external_library_cmake_files(lib_ir, license_text=_repo_license_text):
                out_path = out_root / rel_path
                ensure_parent(out_path)
                out_path.write_text(content)
                all_written.append(out_path)
        except Exception as exc:
            print(f"[external] skipped {lib_xml.name}: {exc}")

    # --- License sweep: update @license blocks in legacy partially-generated files ---
    # Files not regenerated by render_one (no active XML model) still carry stale
    # copyright years.  Sweep all C/H source files in the repo that contain the
    # //  @license marker and apply _update_license_block so the year stays current.
    if args.apply and _repo_license_text:
        license_marker = "//  @license\n"
        sweep_extensions = {".c", ".h", ".h.in"}
        sweep_roots = [repo_root / "library", repo_root / "wrappers", repo_root / "tests"]
        sweep_count = 0
        for sweep_root in sweep_roots:
            if not sweep_root.exists():
                continue
            for path in sweep_root.rglob("*"):
                if path.suffix not in sweep_extensions:
                    continue
                if not path.is_file():
                    continue
                try:
                    original = path.read_text()
                except (OSError, UnicodeDecodeError):
                    continue
                if license_marker not in original:
                    continue
                updated = _update_license_block(original, _repo_license_text)
                if updated != original:
                    path.write_text(updated)
                    sweep_count += 1
        if sweep_count:
            print(f"updated license block in {sweep_count} legacy file(s)")

    # --- Copyright year sweep: update copyright year across ALL source file types ---
    # Covers generated and hand-written files in any language (Go, Java, Python,
    # CMake, PHP, Swift, JS/TS, etc.) that still carry an older end-year.  The
    # update is format-agnostic: it matches the copyright text itself so it works
    # regardless of comment style (//, #, *, ...).
    if args.apply and _repo_license_text:
        target_year = _extract_license_year(_repo_license_text)
        if target_year:
            _copyright_sweep_extensions = {
                ".c", ".h", ".h.in",          # C / C++
                ".go",                          # Go
                ".java",                        # Java / Android
                ".py",                          # Python
                ".php",                         # PHP
                ".swift",                       # Swift
                ".js", ".ts", ".mjs",           # JS / TS / WASM JS
                ".cmake",                       # CMake modules
            }
            _copyright_sweep_name_extensions = {
                "CMakeLists.txt",               # CMake list files (no suffix match)
            }
            _copyright_sweep_roots = [
                repo_root / "library",
                repo_root / "wrappers",
                repo_root / "tests",
                repo_root / "cmake",
                repo_root / "configs",
                repo_root / "scripts",
                repo_root / "codegen",
                repo_root / "tools",
            ]
            copyright_count = 0
            for sweep_root in _copyright_sweep_roots:
                if not sweep_root.exists():
                    continue
                for path in sweep_root.rglob("*"):
                    if not path.is_file():
                        continue
                    if (path.suffix not in _copyright_sweep_extensions
                            and path.name not in _copyright_sweep_name_extensions):
                        continue
                    try:
                        original = path.read_text()
                    except (OSError, UnicodeDecodeError):
                        continue
                    if "Copyright" not in original or "Virgil Security" not in original:
                        continue
                    updated = _update_copyright_year(original, target_year)
                    if updated != original:
                        path.write_text(updated)
                        copyright_count += 1
            if copyright_count:
                print(f"updated copyright year to {target_year} in {copyright_count} file(s)")

    destination = repo_root if args.apply else out_root
    print(f"generated {len(all_written)} files into {destination}")
    for path in all_written:
        print(path.relative_to(repo_root))

    return 1 if all_unexpected else 0


if __name__ == "__main__":
    raise SystemExit(main())
