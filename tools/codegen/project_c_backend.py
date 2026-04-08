from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import cast
import xml.etree.ElementTree as ET

from tools.codegen.project_ir import IRClass, IREnum, IRModule, IRProject, IROutputTarget


DirectCRenderer = Callable[[str | Path], ET.Element]
DirectOutputResolver = Callable[[IRProject], IROutputTarget]


@dataclass(frozen=True)
class DirectRendererSpec:
    entity_kind: str
    entity_name: str
    renderer: DirectCRenderer
    output_resolver: DirectOutputResolver | None = None


def text_element(parent: ET.Element, tag: str, text: str | None = None, **attrs: str) -> ET.Element:
    elem = ET.SubElement(parent, tag, {k: v for k, v in attrs.items() if v is not None})
    if text:
        elem.text = text
    return elem


def snake_name(name: str) -> str:
    return name.replace(" ", "_")


def module_ir(project_ir: IRProject, name: str) -> IRModule:
    try:
        return next(module for module in project_ir.resolved_modules if module.name == name)
    except StopIteration as exc:
        raise KeyError(f"module not found in IR: {name}") from exc



def class_ir(project_ir: IRProject, name: str) -> IRClass:
    try:
        return next(cls for cls in project_ir.classes if cls.name == name)
    except StopIteration as exc:
        raise KeyError(f"class not found in IR: {name}") from exc



def enum_ir(project_ir: IRProject, name: str) -> IREnum:
    try:
        return next(enum for enum in project_ir.enums if enum.name == name)
    except StopIteration as exc:
        raise KeyError(f"enum not found in IR: {name}") from exc



def entity_output(project_ir: IRProject, *, entity_kind: str, entity_name: str) -> IROutputTarget:
    if entity_kind == "module":
        return cast(IROutputTarget, module_ir(project_ir, entity_name).output)
    if entity_kind == "class":
        return cast(IROutputTarget, class_ir(project_ir, entity_name).output)
    if entity_kind == "enum":
        return cast(IROutputTarget, enum_ir(project_ir, entity_name).output)
    raise ValueError(f"unsupported C backend entity kind: {entity_kind}")



def class_type_symbol(project_ir: IRProject, class_name: str) -> str:
    return f"{entity_output(project_ir, entity_kind='class', entity_name=class_name).c_symbol}_t"



def include_file_for_entity(project_ir: IRProject, *, entity_kind: str, entity_name: str) -> str:
    return entity_output(project_ir, entity_kind=entity_kind, entity_name=entity_name).include_file



def derived_module_output_from_class(
    class_output: IROutputTarget,
    *,
    entity_name: str,
    stem_suffix: str,
    generated_source_stem: str,
    header_visibility: str = "private",
) -> IROutputTarget:
    stem = f"{class_output.c_symbol}_{stem_suffix}"
    header_path = class_output.header_path.replace(
        f"/{class_output.include_file}",
        f"/{header_visibility}/{stem}.h",
    )
    source_path = class_output.source_path.replace(class_output.source_file, f"{stem}.c")
    generated_header_path = class_output.generated_header_path.replace(
        class_output.include_file.removesuffix(".h"),
        stem,
    )
    generated_source_path = class_output.generated_source_path.replace(
        Path(class_output.generated_source_path).stem,
        generated_source_stem,
    )
    return IROutputTarget(
        entity_kind="module",
        entity_name=entity_name,
        c_artifact_kind="module",
        c_symbol=stem,
        stem=stem,
        include_file=f"{stem}.h",
        source_file=f"{stem}.c",
        header_path=header_path,
        source_path=source_path,
        generated_header_path=generated_header_path,
        generated_source_path=generated_source_path,
        once_guard=f"{stem}_h_included",
        header_visibility=header_visibility,
        source_visibility="public",
    )



def callback_symbol(project_ir: IRProject, callback_name: str, *, module_name: str | None = None) -> str:
    if module_name is None:
        return f"{project_ir.prefix}_{snake_name(callback_name)}_fn"
    module = module_ir(project_ir, module_name)
    return f"{module.output.c_symbol}_{snake_name(callback_name)}_fn"



def c_module_root_attrs(output: IROutputTarget, *, entity_id: str, scope: str, class_name: str = "") -> dict[str, str]:
    return {
        "lang": "C",
        "id": entity_id,
        "name": output.c_symbol,
        "class": class_name,
        "scope": scope,
        "has_cmakedefine": "0",
        "uid": f"c_module_{entity_id}",
        "c_include_file": output.include_file,
        "c_source_file": output.source_file,
        "header_file": output.header_path,
        "source_file": output.source_path,
        "once_guard": output.once_guard,
    }



def c_module_root(output: IROutputTarget, *, entity_id: str, scope: str, class_name: str = "") -> ET.Element:
    return ET.Element(
        "c_module",
        c_module_root_attrs(output, entity_id=entity_id, scope=scope, class_name=class_name),
    )



def direct_xml_name(output: IROutputTarget) -> str:
    return Path(output.generated_header_path).name



def direct_renderer_map(project_ir: IRProject, specs: list[DirectRendererSpec]) -> dict[str, DirectCRenderer]:
    return {
        direct_xml_name(
            spec.output_resolver(project_ir)
            if spec.output_resolver is not None
            else entity_output(project_ir, entity_kind=spec.entity_kind, entity_name=spec.entity_name)
        ): spec.renderer
        for spec in specs
    }



def doc_comment(text: str) -> str:
    text = text.strip()
    if not text:
        return ""
    lines = ["//"]
    lines.extend(f"//  {line}" if line else "//" for line in text.splitlines())
    lines.append("//")
    return "\n".join(lines)



def enum_type_name(enum_output: IROutputTarget) -> str:
    return f"{enum_output.c_symbol}_t"



def enum_constant_name(enum_output: IROutputTarget, constant_name: str) -> str:
    return f"{enum_output.c_symbol}_{snake_name(constant_name).upper()}"



def render_enum_c_module(project_ir: IRProject, enum: IREnum) -> ET.Element:
    del project_ir

    enum_output = cast(IROutputTarget, enum.output)
    root = c_module_root(
        enum_output,
        entity_id=snake_name(enum.name),
        scope=enum.attrs.get("scope", "public"),
    )

    enum_elem = text_element(
        root,
        "c_enum",
        declaration="public",
        definition="public",
        name=enum_type_name(enum_output),
        typedef_name=enum_type_name(enum_output),
    )
    if enum.description:
        enum_elem.text = doc_comment(enum.description)

    for constant in enum.constants:
        attrs = {
            "name": enum_constant_name(enum_output, constant.name),
            "definition": "public",
        }
        value = constant.attrs.get("value")
        if value is not None:
            attrs["value"] = value
        const_elem = text_element(enum_elem, "c_constant", **attrs)
        if constant.description:
            const_elem.text = doc_comment(constant.description)

    return root



def type_map(type_name: str | None) -> tuple[str, str]:
    mapping = {
        "boolean": ("bool", "primitive"),
        "size": ("size_t", "primitive"),
        "integer": ("int", "primitive"),
        "byte": ("byte", "primitive"),
        "char": ("char", "primitive"),
        "string": ("char", "primitive"),
    }
    if type_name in mapping:
        return mapping[type_name]
    return type_name or "void", "primitive"



def comment_text(desc: str) -> str:
    desc = desc.strip()
    if not desc:
        return ""
    return "\n" + "\n".join(f"        //  {line}" if line else "        //" for line in desc.splitlines()) + "\n    "



def argument_from_source(
    parent: ET.Element,
    src: dict,
    *,
    name: str | None = None,
    project_ir: IRProject | None = None,
    owner_class: str = "data",
) -> ET.Element:
    attrs = src
    arg_name = name if name is not None else attrs.get("name", "")
    if attrs.get("class") in {"self", "data"}:
        resolved_class = owner_class if attrs.get("class") == "self" else attrs.get("class", owner_class)
        type_name = class_type_symbol(project_ir, resolved_class) if project_ir is not None else "vsc_data_t"
        elem = text_element(parent, "c_argument", name=arg_name, accessed_by="value", type=type_name, type_is="class")
    elif attrs.get("type") == "string":
        elem = text_element(
            parent,
            "c_argument",
            name=arg_name,
            accessed_by="value",
            type="char",
            type_is="primitive",
            string="given",
            is_const_type="1",
        )
    else:
        rendered_type, kind = type_map(attrs.get("type"))
        extra = {}
        if attrs.get("type") == "byte" and attrs.get("_array") == "given":
            extra["array"] = "given"
            extra["is_const_type"] = "1"
        elem = text_element(parent, "c_argument", name=arg_name, accessed_by="value", type=rendered_type, type_is=kind, **extra)
    return elem



def return_from_source(
    parent: ET.Element,
    attrs: dict,
    *,
    project_ir: IRProject | None = None,
    owner_class: str = "data",
) -> ET.Element:
    if attrs.get("class") in {"self", "data"}:
        resolved_class = owner_class if attrs.get("class") == "self" else attrs.get("class", owner_class)
        type_name = class_type_symbol(project_ir, resolved_class) if project_ir is not None else "vsc_data_t"
        return text_element(parent, "c_return", accessed_by="value", type=type_name, type_is="class")
    if attrs.get("type") == "byte" and attrs.get("is_reference") in {"1", "true"}:
        return text_element(parent, "c_return", accessed_by="pointer", type="byte", type_is="primitive", is_const_type="1")
    rendered_type, kind = type_map(attrs.get("type"))
    return text_element(parent, "c_return", accessed_by="value", type=rendered_type, type_is=kind)
