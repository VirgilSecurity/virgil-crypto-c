from __future__ import annotations

from dataclasses import asdict, dataclass, field
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
    attrs: dict[str, str] = field(default_factory=dict)
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
class ProjectSource:
    name: str
    path: str
    repo_root: str = ""
    codegen_root: str = ""
    model_root: str = ""
    project_dir: str = ""
    source_root: str = ""
    work_root: str = ""
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

    @property
    def namespace(self) -> str:
        return self.attrs.get("namespace", "")

    @property
    def framework(self) -> str:
        return self.attrs.get("framework", "")

    @property
    def prefix(self) -> str:
        return self.attrs.get("prefix", "")

    def module_named(self, name: str, *, resolved: bool = False) -> ModuleSource:
        modules = self.resolved_modules if resolved else self.modules
        try:
            return next(module for module in modules if module.name == name)
        except StopIteration as exc:
            raise KeyError(f"module not found: {name}") from exc

    def class_named(self, name: str) -> ClassSource:
        try:
            return next(cls for cls in self.classes if cls.name == name)
        except StopIteration as exc:
            raise KeyError(f"class not found: {name}") from exc

    def enum_named(self, name: str) -> EnumSource:
        try:
            return next(enum for enum in self.enums if enum.name == name)
        except StopIteration as exc:
            raise KeyError(f"enum not found: {name}") from exc

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


CODE_BLOCK_PATTERN = re.compile(r'(<code(?:\s[^>]*)?>)(.*?)(</code>)', flags=re.DOTALL)


def project_model_path(project_name: str, repo_root: str | Path = ".") -> Path:
    repo_root = Path(repo_root).resolve()
    return repo_root / f"codegen/models/project_{_slug(project_name)}/project_{_slug(project_name)}.xml"


def _parse_legacy_xml(path: Path) -> ET.Element:
    raw = path.read_text()
    code_blocks: list[str] = []

    def protect_code_block(match: re.Match[str]) -> str:
        code_blocks.append(match.group(2))
        return f"{match.group(1)}__PROJECT_SOURCE_CODE_BLOCK_{len(code_blocks) - 1}__{match.group(3)}"

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
        attrs=dict(root.attrib),
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
    explicit_module_areas: dict[str, str | None],
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
        module_name = require.attrs.get("module")
        if not module_name:
            continue

        nested_from_area = require.attrs.get("from")
        if nested_from_area is None and module_name in explicit_module_areas:
            nested_from_area = explicit_module_areas[module_name]
        if nested_from_area is None:
            nested_from_area = dependency_area

        nested_area = "shared" if nested_from_area == "shared" else (nested_from_area or project_dir)
        if not _model_path(repo_root, nested_area, "module", module_name).exists():
            continue

        _load_module_graph(
            repo_root=repo_root,
            project_dir=project_dir,
            module_name=module_name,
            from_area=nested_from_area,
            explicit_module_areas=explicit_module_areas,
            resolved_modules=resolved_modules,
        )

    return module


def load_project_source(project_path: str | Path) -> ProjectSource:
    project_path = Path(project_path).resolve()
    repo_root = _repo_root_for_project(project_path)
    codegen_root = repo_root / "codegen"
    model_root = codegen_root / "models"
    project_dir = _project_model_dir(project_path)
    root = _parse_legacy_xml(project_path)
    project_attrs = dict(root.attrib)
    project = ProjectSource(
        name=root.attrib["name"],
        path=str(project_path),
        repo_root=str(repo_root),
        codegen_root=str(codegen_root),
        model_root=str(model_root),
        project_dir=project_dir,
        source_root=str((codegen_root / project_attrs.get("path", "")).resolve()),
        work_root=str((codegen_root / project_attrs.get("work_path", "")).resolve()),
        attrs=project_attrs,
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
    explicit_module_areas = {module_ref["name"]: module_ref.get("from") for module_ref in project.module_refs}

    for module_ref in project.module_refs:
        project.modules.append(
            _load_module_graph(
                repo_root=repo_root,
                project_dir=project_dir,
                module_name=module_ref["name"],
                from_area=module_ref.get("from"),
                explicit_module_areas=explicit_module_areas,
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


def load_named_project_source(project_name: str, repo_root: str | Path = ".") -> ProjectSource:
    return load_project_source(project_model_path(project_name, repo_root))
