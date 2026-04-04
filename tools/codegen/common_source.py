from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
import re
import textwrap
import xml.etree.ElementTree as ET
from typing import Any


@dataclass
class NamedRef:
    kind: str
    name: str
    attrs: dict[str, str] = field(default_factory=dict)
    description: str = ""


@dataclass
class ArgumentSource:
    name: str
    attrs: dict[str, str] = field(default_factory=dict)
    description: str = ""


@dataclass
class MethodSource:
    kind: str
    name: str
    attrs: dict[str, str] = field(default_factory=dict)
    description: str = ""
    arguments: list[ArgumentSource] = field(default_factory=list)
    returns: list[dict[str, str]] = field(default_factory=list)
    code_blocks: list[dict[str, str]] = field(default_factory=list)


@dataclass
class PropertySource:
    name: str
    attrs: dict[str, str] = field(default_factory=dict)
    description: str = ""


@dataclass
class VariableSource:
    name: str
    attrs: dict[str, str] = field(default_factory=dict)
    description: str = ""
    value: dict[str, str] | None = None


@dataclass
class ModuleSource:
    name: str
    from_area: str | None = None
    path: str = ""
    description: str = ""
    requires: list[NamedRef] = field(default_factory=list)
    c_includes: list[NamedRef] = field(default_factory=list)
    callbacks: list[MethodSource] = field(default_factory=list)
    variables: list[VariableSource] = field(default_factory=list)
    methods: list[MethodSource] = field(default_factory=list)
    macroses: list[MethodSource] = field(default_factory=list)
    macro_groups: list[MethodSource] = field(default_factory=list)
    code_blocks: list[dict[str, str]] = field(default_factory=list)


@dataclass
class ClassSource:
    name: str
    path: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    description: str = ""
    properties: list[PropertySource] = field(default_factory=list)
    variables: list[VariableSource] = field(default_factory=list)
    methods: list[MethodSource] = field(default_factory=list)
    constructors: list[MethodSource] = field(default_factory=list)


@dataclass
class ProjectFeatureSource:
    name: str
    attrs: dict[str, str] = field(default_factory=dict)
    description: str = ""


@dataclass
class ProjectCommonSource:
    name: str
    path: str
    attrs: dict[str, str] = field(default_factory=dict)
    version: dict[str, str] | None = None
    feature_refs: list[ProjectFeatureSource] = field(default_factory=list)
    module_refs: list[dict[str, str]] = field(default_factory=list)
    class_refs: list[dict[str, str]] = field(default_factory=list)
    enum_refs: list[dict[str, str]] = field(default_factory=list)
    modules: list[ModuleSource] = field(default_factory=list)
    classes: list[ClassSource] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse_legacy_xml(path: Path) -> ET.Element:
    raw = path.read_text()
    protected = re.sub(
        r'(<code(?:\s[^>]*)?>)(.*?)(</code>)',
        lambda m: f"{m.group(1)}{m.group(2).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')}{m.group(3)}",
        raw,
        flags=re.DOTALL,
    )
    return ET.fromstring(protected)


def _clean(text: str | None) -> str:
    if not text:
        return ""
    return textwrap.dedent(text).strip()


def _description(elem: ET.Element) -> str:
    parts: list[str] = []
    if _clean(elem.text):
        parts.append(_clean(elem.text))
    for child in elem:
        if _clean(child.tail):
            parts.append(_clean(child.tail))
    return "\n".join(parts).strip()


def _named_ref(kind: str, elem: ET.Element) -> NamedRef:
    name = elem.attrib.get("name") or elem.attrib.get(kind) or ""
    return NamedRef(kind=kind, name=name, attrs=dict(elem.attrib), description=_description(elem))


def _argument(elem: ET.Element) -> ArgumentSource:
    return ArgumentSource(name=elem.attrib.get("name", ""), attrs=dict(elem.attrib), description=_description(elem))


def _method_like(kind: str, elem: ET.Element) -> MethodSource:
    return MethodSource(
        kind=kind,
        name=elem.attrib.get("name", ""),
        attrs=dict(elem.attrib),
        description=_description(elem),
        arguments=[_argument(a) for a in elem.findall("argument")],
        returns=[dict(r.attrib) for r in elem.findall("return")],
        code_blocks=[{"attrs": dict(c.attrib), "text": _clean(c.text)} for c in elem.findall("code")],
    )


def _variable(elem: ET.Element) -> VariableSource:
    value = elem.find("value")
    return VariableSource(
        name=elem.attrib.get("name", ""),
        attrs=dict(elem.attrib),
        description=_description(elem),
        value=(dict(value.attrib) if value is not None else None),
    )


def load_module_source(path: Path, from_area: str | None = None) -> ModuleSource:
    root = _parse_legacy_xml(path)
    return ModuleSource(
        name=root.attrib["name"],
        from_area=from_area,
        path=str(path),
        description=_description(root),
        requires=[_named_ref("require", e) for e in root.findall("require")],
        c_includes=[_named_ref("c_include", e) for e in root.findall("c_include")],
        callbacks=[_method_like("callback", e) for e in root.findall("callback")],
        variables=[_variable(e) for e in root.findall("variable")],
        methods=[_method_like("method", e) for e in root.findall("method")],
        macroses=[_method_like("macros", e) for e in root.findall("macros")],
        macro_groups=[_method_like("macroses", e) for e in root.findall("macroses")],
        code_blocks=[{"attrs": dict(c.attrib), "text": _clean(c.text)} for c in root.findall("code")],
    )


def load_class_source(path: Path) -> ClassSource:
    root = _parse_legacy_xml(path)
    return ClassSource(
        name=root.attrib["name"],
        path=str(path),
        attrs=dict(root.attrib),
        description=_description(root),
        properties=[PropertySource(name=e.attrib.get("name", ""), attrs=dict(e.attrib), description=_description(e)) for e in root.findall("property")],
        variables=[_variable(e) for e in root.findall("variable")],
        methods=[_method_like("method", e) for e in root.findall("method")],
        constructors=[_method_like("constructor", e) for e in root.findall("constructor")],
    )


def load_project_source(project_path: str | Path) -> ProjectCommonSource:
    project_path = Path(project_path).resolve()
    repo_root = project_path.parents[3]
    root = _parse_legacy_xml(project_path)
    project = ProjectCommonSource(
        name=root.attrib["name"],
        path=str(project_path),
        attrs=dict(root.attrib),
        version=(dict(root.find("version").attrib) if root.find("version") is not None else None),
        feature_refs=[
            ProjectFeatureSource(name=e.attrib.get("name", ""), attrs=dict(e.attrib), description=_description(e))
            for e in root.findall("feature")
        ],
        module_refs=[dict(e.attrib) for e in root.findall("module")],
        class_refs=[dict(e.attrib) for e in root.findall("class")],
        enum_refs=[dict(e.attrib) for e in root.findall("enum")],
    )

    for module_ref in root.findall("module"):
        from_area = module_ref.attrib.get("from")
        if from_area == "shared":
            module_path = repo_root / f"codegen/models/shared/module_{module_ref.attrib['name']}.xml"
        else:
            module_path = repo_root / f"codegen/models/project_common/module_{module_ref.attrib['name']}.xml"
        project.modules.append(load_module_source(module_path, from_area=from_area))

    for class_ref in root.findall("class"):
        class_path = repo_root / f"codegen/models/project_common/class_{class_ref.attrib['name']}.xml"
        project.classes.append(load_class_source(class_path))

    return project


def load_project_common(repo_root: str | Path = ".") -> ProjectCommonSource:
    repo_root = Path(repo_root).resolve()
    project_path = repo_root / "codegen/models/project_common/project_common.xml"
    return load_project_source(project_path)
