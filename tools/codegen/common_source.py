from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
import html
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
class ConstantSource:
    name: str
    attrs: dict[str, str] = field(default_factory=dict)
    description: str = ""


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
class EnumSource:
    name: str
    path: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    description: str = ""
    constants: list[ConstantSource] = field(default_factory=list)


@dataclass
class ProjectFeatureSource:
    name: str
    attrs: dict[str, str] = field(default_factory=dict)
    description: str = ""


@dataclass
class ProjectCommonSource:
    name: str
    path: str
    repo_root: str = ""
    model_root: str = ""
    project_dir: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    version: dict[str, str] | None = None
    feature_refs: list[ProjectFeatureSource] = field(default_factory=list)
    module_refs: list[dict[str, str]] = field(default_factory=list)
    class_refs: list[dict[str, str]] = field(default_factory=list)
    enum_refs: list[dict[str, str]] = field(default_factory=list)
    modules: list[ModuleSource] = field(default_factory=list)
    dependency_modules: list[ModuleSource] = field(default_factory=list)
    resolved_modules: list[ModuleSource] = field(default_factory=list)
    classes: list[ClassSource] = field(default_factory=list)
    enums: list[EnumSource] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


CODE_BLOCK_PATTERN = re.compile(r'(<code(?:\s[^>]*)?>)(.*?)(</code>)', flags=re.DOTALL)


def project_common_path(repo_root: str | Path = ".") -> Path:
    repo_root = Path(repo_root).resolve()
    return repo_root / "codegen/models/project_common/project_common.xml"


def _parse_legacy_xml(path: Path) -> ET.Element:
    raw = path.read_text()
    code_blocks: list[str] = []

    def protect_code_block(match: re.Match[str]) -> str:
        code_blocks.append(match.group(2))
        return f"{match.group(1)}__COMMON_SOURCE_CODE_BLOCK_{len(code_blocks) - 1}__{match.group(3)}"

    protected = CODE_BLOCK_PATTERN.sub(protect_code_block, raw)
    root = ET.fromstring(protected)

    for idx, code_elem in enumerate(root.iter("code")):
        code_elem.text = html.unescape(code_blocks[idx])

    return root


def _clean(text: str | None) -> str:
    if not text:
        return ""
    return textwrap.dedent(text).strip()


def _slug(name: str) -> str:
    return name.replace(" ", "_")


def _description(elem: ET.Element) -> str:
    parts: list[str] = []
    if _clean(elem.text):
        parts.append(_clean(elem.text))
    for child in elem:
        if _clean(child.tail):
            parts.append(_clean(child.tail))
    return "\n".join(parts).strip()


def _named_ref(kind: str, elem: ET.Element) -> NamedRef:
    name = (
        elem.attrib.get("name")
        or elem.attrib.get(kind)
        or elem.attrib.get("module")
        or elem.attrib.get("class")
        or elem.attrib.get("enum")
        or elem.attrib.get("file")
        or ""
    )
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


def _constant(elem: ET.Element) -> ConstantSource:
    return ConstantSource(
        name=elem.attrib.get("name", ""),
        attrs=dict(elem.attrib),
        description=_description(elem),
    )


def _repo_root_for_project(project_path: Path) -> Path:
    return project_path.parents[3]


def _project_model_dir(project_path: Path) -> str:
    return project_path.parent.name


def _model_path(repo_root: Path, area: str, kind: str, name: str) -> Path:
    return repo_root / f"codegen/models/{area}/{kind}_{_slug(name)}.xml"


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


def load_enum_source(path: Path) -> EnumSource:
    root = _parse_legacy_xml(path)
    return EnumSource(
        name=root.attrib["name"],
        path=str(path),
        attrs=dict(root.attrib),
        description=_description(root),
        constants=[_constant(e) for e in root.findall("constant")],
    )


def _load_module_graph(
    *,
    repo_root: Path,
    project_dir: str,
    module_name: str,
    from_area: str | None,
    resolved_modules: dict[str, ModuleSource],
) -> ModuleSource:
    area = "shared" if from_area == "shared" else (from_area or project_dir)
    module_path = _model_path(repo_root, area, "module", module_name)
    module_key = str(module_path)
    if module_key in resolved_modules:
        return resolved_modules[module_key]

    module = load_module_source(module_path, from_area=from_area)
    resolved_modules[module_key] = module

    dependency_area = from_area or project_dir
    for require in module.requires:
        _load_module_graph(
            repo_root=repo_root,
            project_dir=project_dir,
            module_name=require.name,
            from_area=require.attrs.get("from", dependency_area),
            resolved_modules=resolved_modules,
        )

    return module


def load_project_source(project_path: str | Path) -> ProjectCommonSource:
    project_path = Path(project_path).resolve()
    repo_root = _repo_root_for_project(project_path)
    model_root = repo_root / "codegen/models"
    project_dir = _project_model_dir(project_path)
    root = _parse_legacy_xml(project_path)
    project = ProjectCommonSource(
        name=root.attrib["name"],
        path=str(project_path),
        repo_root=str(repo_root),
        model_root=str(model_root),
        project_dir=project_dir,
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

    resolved_modules: dict[str, ModuleSource] = {}
    explicit_module_names = {module_ref["name"] for module_ref in project.module_refs}

    for module_ref in project.module_refs:
        project.modules.append(
            _load_module_graph(
                repo_root=repo_root,
                project_dir=project_dir,
                module_name=module_ref["name"],
                from_area=module_ref.get("from"),
                resolved_modules=resolved_modules,
            )
        )

    project.resolved_modules = list(resolved_modules.values())
    project.dependency_modules = [module for module in project.resolved_modules if module.name not in explicit_module_names]

    for class_ref in project.class_refs:
        class_path = _model_path(repo_root, project_dir, "class", class_ref["name"])
        project.classes.append(load_class_source(class_path))

    for enum_ref in project.enum_refs:
        enum_area = enum_ref.get("from") or project_dir
        enum_path = _model_path(repo_root, enum_area, "enum", enum_ref["name"])
        project.enums.append(load_enum_source(enum_path))

    return project


def load_project_common(repo_root: str | Path = ".") -> ProjectCommonSource:
    return load_project_source(project_common_path(repo_root))
