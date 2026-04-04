from __future__ import annotations

import argparse
import html
import os
from pathlib import Path
import shutil
import textwrap
import xml.etree.ElementTree as ET


GENERATED_START = "//  @generated"
GENERATED_END = "//  @end"


def norm_text(text: str | None) -> str:
    if not text:
        return ""
    return textwrap.dedent(html.unescape(text)).strip("\n")


def split_generated_sections(content: str) -> tuple[str, str]:
    start = content.index(GENERATED_START)
    end = content.index(GENERATED_END, start)
    prefix = content[:start]
    suffix = content[end + len(GENERATED_END):]
    return prefix, suffix


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


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


def c_type(type_name: str, accessed_by: str = "value", is_const_type: str | None = None, is_string: bool = False) -> str:
    prefix = "const " if is_const_type == "1" else ""
    if is_string:
        return f"{prefix}{type_name} *".strip()
    if accessed_by in ("pointer", "reference"):
        return f"{prefix}{type_name} *".strip()
    return f"{prefix}{type_name}".strip()


def c_decl(type_name: str, name: str, accessed_by: str = "value", is_const_type: str | None = None, is_string: bool = False) -> str:
    rendered_type = c_type(type_name, accessed_by, is_const_type, is_string)
    if rendered_type.endswith("*"):
        return f"{rendered_type}{name}"
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
    comment = emit_comment_block(description_text(elem))
    return f"{comment}typedef {elem.attrib['type']} {elem.attrib['name']};"


def render_c_code(elem: ET.Element) -> str:
    code = norm_text(elem.text)
    lines = code.splitlines()
    if lines and lines[0].lstrip().startswith("#define") and len(lines) > 1:
        rendered: list[str] = []
        for idx, line in enumerate(lines):
            if idx < len(lines) - 1 and line.strip():
                rendered.append(line.rstrip() + " \\")
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
    ret_type = c_type(ret.attrib["type"], ret.attrib.get("accessed_by", "value"), ret.attrib.get("is_const_type"), ret.attrib.get("string") is not None)
    modifiers = " ".join(m.attrib["value"] for m in elem.findall("c_modifier"))
    args = []
    for arg in elem.findall("c_argument"):
        rendered = c_decl(arg.attrib['type'], arg.attrib.get('name',''), arg.attrib.get('accessed_by', 'value'), arg.attrib.get('is_const_type'), arg.attrib.get('string') is not None)
        args.append(rendered)
    arg_str = ", ".join(args) if args else "void"
    left = f"typedef {modifiers} {ret_type}".replace("  ", " ").strip()
    return f"{comment}{left} (*{elem.attrib['name']})({arg_str});"


def render_enum(elem: ET.Element) -> str:
    comment = emit_comment_block(description_text(elem))
    lines = [comment + "enum {"]
    constants = elem.findall("c_constant")
    for i, const in enumerate(constants):
        const_comment = emit_comment_block(const.text)
        if const_comment:
            lines.append(indent(const_comment.rstrip("\n"), 4))
        comma = "," if i < len(constants) - 1 else ""
        lines.append(f"    {const.attrib['name']} = {const.attrib['value']}{comma}")
    lines.append("};")
    return "\n".join(lines)


def render_struct(elem: ET.Element, for_header: bool) -> str:
    comment = emit_comment_block(description_text(elem))
    name = elem.attrib["name"]
    if elem.attrib.get("definition") == "external" and for_header:
        return f"{comment}typedef struct {name} {name};"

    lines = [comment + f"struct {name} {{"]
    for prop in elem.findall("c_property"):
        prop_comment = emit_comment_block(prop.text)
        if prop_comment:
            lines.append(indent(prop_comment.rstrip("\n"), 4))
        decl = f"{c_decl(prop.attrib['type'], prop.attrib['name'], prop.attrib.get('accessed_by', 'value'), prop.attrib.get('is_const_type'), prop.attrib.get('string') is not None)};"
        lines.append(f"    {decl}")
    lines.append("};")
    return "\n".join(lines)


def render_variable(elem: ET.Element) -> str:
    comment = emit_comment_block(description_text(elem))
    storage = "static " if elem.attrib.get("definition") == "private" else ""
    cval = elem.find("c_value")
    initializer = ""
    if cval is not None:
        value = cval.attrib["value"]
        if elem.attrib.get("array") == "derived":
            initializer = f" = {{\n    {value}\n}}"
        else:
            initializer = f" = {value}"
    decl = f"{storage}{c_decl(elem.attrib['type'], elem.attrib['name'], elem.attrib.get('accessed_by', 'value'), elem.attrib.get('is_const_type'), elem.attrib.get('string') is not None)}"
    if elem.attrib.get("array") == "derived":
        decl += "[]"
    decl += initializer + ";"
    return f"{comment}{decl}"


def render_method_signature(elem: ET.Element, for_definition: bool) -> str:
    ret = elem.find("c_return")
    ret_type = "void"
    if ret is not None:
        ret_type = c_type(ret.attrib["type"], ret.attrib.get("accessed_by", "value"), ret.attrib.get("is_const_type"), ret.attrib.get("string") is not None)
    modifiers = " ".join(m.attrib["value"] for m in elem.findall("c_modifier"))
    if for_definition and elem.attrib.get("definition") == "private":
        modifiers = "static"
    parts = [p for p in [modifiers, ret_type] if p]
    header = " ".join(parts)
    args = []
    for arg in elem.findall("c_argument"):
        if arg.attrib.get("type") == "void" and not arg.attrib.get("name"):
            args.append("void")
        else:
            args.append(c_decl(arg.attrib['type'], arg.attrib['name'], arg.attrib.get('accessed_by', 'value'), arg.attrib.get('is_const_type'), arg.attrib.get('string') is not None))
    arg_str = ", ".join(args) if args else "void"
    return f"{header}\n{elem.attrib['name']}({arg_str})"


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


def generate_block(root: ET.Element, for_header: bool) -> str:
    out: list[str] = [
        "//  @generated",
        "// --------------------------------------------------------------------------",
        "// clang-format off",
        "//  Generated section start.",
        "// --------------------------------------------------------------------------",
        "",
    ]

    for child in root:
        tag = child.tag
        if tag in {"c_license", "c_caution", "cmake_include_file_check"}:
            continue
        if tag == "c_include":
            continue
        elif tag == "c_alias" and for_header and child.attrib.get("declaration") == "public":
            out.append(render_alias(child))
            out.append("")
        elif tag == "c_code":
            wanted = "public" if for_header else "private"
            if child.attrib.get("definition") == wanted:
                out.append(render_c_code(child))
                out.append("")
        elif tag == "c_macroses":
            wanted = "public" if for_header else "private"
            if child.attrib.get("definition") == wanted:
                out.append(render_macroses(child))
                out.append("")
        elif tag == "c_macros":
            wanted = "public" if for_header else "private"
            if child.attrib.get("definition") == wanted:
                out.append(render_macros(child))
                out.append("")
        elif tag == "c_enum":
            decl = child.attrib.get("declaration")
            defi = child.attrib.get("definition")
            if for_header and decl == "public":
                out.append(render_enum(child))
                out.append("")
            elif (not for_header) and defi == "private":
                out.append(render_enum(child))
                out.append("")
        elif tag == "c_struct":
            decl = child.attrib.get("declaration")
            defi = child.attrib.get("definition")
            if for_header and (decl == "public" or defi == "public"):
                out.append(render_struct(child, True))
                out.append("")
            elif (not for_header) and defi == "private":
                out.append(render_struct(child, False))
                out.append("")
        elif tag == "c_callback":
            decl = child.attrib.get("declaration")
            if for_header and decl == "public":
                out.append(render_callback(child))
                out.append("")
            elif (not for_header) and decl == "private":
                out.append(render_callback(child))
                out.append("")
        elif tag == "c_variable":
            decl = child.attrib.get("declaration")
            defi = child.attrib.get("definition")
            if for_header and decl == "public":
                out.append(render_variable(child))
                out.append("")
            elif (not for_header) and (defi != "external"):
                out.append(render_variable(child))
                out.append("")
        elif tag == "c_method":
            decl = child.attrib.get("declaration")
            defi = child.attrib.get("definition")
            if for_header and decl == "public":
                out.append(render_method(child, False))
                out.append("")
            elif (not for_header) and defi != "external":
                out.append(render_method(child, True))
                out.append("")

    out.extend([
        "// --------------------------------------------------------------------------",
        "//  Generated section end.",
        "// clang-format on",
        "// --------------------------------------------------------------------------",
        "//  @end",
    ])
    return "\n".join(out).rstrip() + "\n"


def render_one(xml_path: Path, repo_root: Path, codegen_root: Path, out_root: Path) -> list[Path]:
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
        prefix, suffix = split_generated_sections(existing)
        generated = generate_block(root, is_header)
        out_path = out_root / target.relative_to(repo_root)
        ensure_parent(out_path)
        out_path.write_text(prefix + generated + suffix)
        written.append(out_path)
    return written


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--project", default="common")
    parser.add_argument("--out", default="build/new-codegen")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    out_root = (repo_root / args.out).resolve()
    codegen_root = repo_root / "codegen"
    project_dir = codegen_root / "generated" / args.project
    if out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True, exist_ok=True)

    written = []
    for xml_path in sorted(project_dir.glob("c_module_*.xml")):
        if xml_path.name.endswith("_unresolved.xml"):
            continue
        written.extend(render_one(xml_path, repo_root, codegen_root, out_root))

    print(f"generated {len(written)} files into {out_root}")
    for path in written:
        print(path.relative_to(repo_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
