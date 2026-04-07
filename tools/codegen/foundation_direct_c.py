from __future__ import annotations

"""Foundation-specific direct C builders over the shared backend."""

from pathlib import Path
from typing import cast
import xml.etree.ElementTree as ET

from tools.codegen.project_c_backend import (
    DirectRendererSpec,
    c_module_root,
    direct_renderer_map,
    enum_ir,
    snake_name,
    text_element,
)
from tools.codegen.project_ir import IREnum, IRProject, IROutputTarget, project_to_ir
from tools.codegen.project_source import EnumSource, ProjectSource, load_named_project_source


_enum_specs = [
    "status",
    "asn1 tag",
    "alg id",
    "oid id",
    "recipient cipher decryption state",
    "group msg type",
    "cipher state",
]


def _load_foundation_project(repo_root: str | Path = ".") -> ProjectSource:
    return load_named_project_source("foundation", repo_root)



def _load_foundation_ir(repo_root: str | Path = ".") -> IRProject:
    return project_to_ir(_load_foundation_project(repo_root))



def _doc_comment(text: str) -> str:
    text = text.strip()
    if not text:
        return ""
    lines = ["//"]
    lines.extend(f"//  {line}" if line else "//" for line in text.splitlines())
    lines.append("//")
    return "\n".join(lines)



def _enum_type_name(enum_output: IROutputTarget) -> str:
    return f"{enum_output.c_symbol}_t"



def _enum_constant_name(enum_output: IROutputTarget, constant_name: str) -> str:
    return f"{enum_output.c_symbol}_{snake_name(constant_name).upper()}"



def _build_direct_enum_c_module(project: ProjectSource, project_ir: IRProject, src: EnumSource, enum_output: IROutputTarget) -> ET.Element:
    enum_id = snake_name(src.name)
    root = c_module_root(enum_output, entity_id=enum_id, scope=src.attrs.get("scope", "public"))

    enum_elem = text_element(
        root,
        "c_enum",
        declaration="public",
        definition="public",
        name=_enum_type_name(enum_output),
        typedef_name=_enum_type_name(enum_output),
    )
    if src.description:
        enum_elem.text = _doc_comment(src.description)

    for constant in src.constants:
        attrs = {
            "name": _enum_constant_name(enum_output, constant.name),
            "definition": "public",
        }
        value = constant.attrs.get("value")
        if value is not None:
            attrs["value"] = value
        const_elem = text_element(enum_elem, "c_constant", **attrs)
        if constant.description:
            const_elem.text = _doc_comment(constant.description)

    return root



def _make_enum_renderer(enum_name: str):
    def renderer(repo_root: str | Path = ".") -> ET.Element:
        project = _load_foundation_project(repo_root)
        project_ir = project_to_ir(project)
        src = project.enum_named(enum_name)
        enum_output = cast(IROutputTarget, enum_ir(project_ir, enum_name).output)
        return _build_direct_enum_c_module(project, project_ir, src, enum_output)

    return renderer



def direct_c_renderers(repo_root: str | Path = ".") -> dict[str, object]:
    project_ir = _load_foundation_ir(repo_root)
    specs = [
        DirectRendererSpec(entity_kind="enum", entity_name=enum_name, renderer=_make_enum_renderer(enum_name))
        for enum_name in _enum_specs
    ]
    return direct_renderer_map(project_ir, specs)
