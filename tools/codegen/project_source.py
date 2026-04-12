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
    members: list[NamedRef] = field(default_factory=list)
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
    values: list[dict[str, str]] = field(default_factory=list)


@dataclass
class DependencySource:
    name: str
    attrs: dict[str, str] = field(default_factory=dict)
    description: str = ""


@dataclass
class ConstantSource:
    name: str
    attrs: dict[str, str] = field(default_factory=dict)
    description: str = ""


@dataclass
class AliasSource:
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
    aliases: list[AliasSource] = field(default_factory=list)
    callbacks: list[MethodSource] = field(default_factory=list)
    variables: list[VariableSource] = field(default_factory=list)
    methods: list[MethodSource] = field(default_factory=list)
    macroses: list[MethodSource] = field(default_factory=list)
    macro_groups: list[MethodSource] = field(default_factory=list)
    constants: list[ConstantSource] = field(default_factory=list)
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
    dependencies: list[DependencySource] = field(default_factory=list)
    macroses: list[MethodSource] = field(default_factory=list)
    requirements: list['RequirementSource'] = field(default_factory=list)
    struct_members_order: list[tuple[str, int]] = field(default_factory=list)
    # Ordered list of ('field', idx) and ('dep', idx) preserving XML source order.
    constants: list[ConstantSource] = field(default_factory=list)


@dataclass
class EnumSource:
    name: str
    path: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    description: str = ""
    constants: list[ConstantSource] = field(default_factory=list)


@dataclass
class InterfaceBindingConstantSource:
    name: str
    value: str
    attrs: dict[str, str] = field(default_factory=dict)


@dataclass
class InterfaceBindingSource:
    name: str
    constants: list[InterfaceBindingConstantSource] = field(default_factory=list)
    attrs: dict[str, str] = field(default_factory=dict)


@dataclass
class RequirementSource:
    attrs: dict[str, str] = field(default_factory=dict)
    description: str = ""

    @property
    def kind(self) -> str:
        for key in ("library", "header", "interface", "impl", "class", "enum", "module", "feature"):
            if key in self.attrs:
                return key
        return "unknown"

    @property
    def name(self) -> str:
        return self.attrs.get(self.kind, "")


@dataclass
class ImplementationSource:
    name: str
    description: str = ""
    interface_bindings: list[InterfaceBindingSource] = field(default_factory=list)
    properties: list[PropertySource] = field(default_factory=list)
    methods: list[MethodSource] = field(default_factory=list)
    constructors: list[MethodSource] = field(default_factory=list)
    dependencies: list[DependencySource] = field(default_factory=list)
    requirements: list[RequirementSource] = field(default_factory=list)
    constants: list['ConstantSource'] = field(default_factory=list)
    attrs: dict[str, str] = field(default_factory=dict)


@dataclass
class ImplementorSource:
    name: str
    path: str = ""
    implementations: list[ImplementationSource] = field(default_factory=list)
    attrs: dict[str, str] = field(default_factory=dict)
    description: str = ""


@dataclass
class InterfaceSource:
    name: str
    path: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    description: str = ""
    methods: list[MethodSource] = field(default_factory=list)
    constants: list[ConstantSource] = field(default_factory=list)
    inherits: list[str] = field(default_factory=list)


@dataclass
class ProjectFeatureSource:
    name: str
    attrs: dict[str, str] = field(default_factory=dict)
    description: str = ""


@dataclass
class LibraryErrorMessageGetter:
    """Parsed ``<error_message_getter>`` from a project or external library."""
    success_value: str = "0"
    header_requires: list[str] = field(default_factory=list)
    code: str = ""


@dataclass
class LibraryRequireSource:
    """A project-level ``<require ... feature='library'>`` entry."""
    kind: str = ""  # 'project' or 'library'
    name: str = ""
    error_message_getter: LibraryErrorMessageGetter | None = None


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
    interface_refs: list[dict[str, str]] = field(default_factory=list)
    implementor_refs: list[dict[str, str]] = field(default_factory=list)
    modules: list[ModuleSource] = field(default_factory=list)
    dependency_modules: list[ModuleSource] = field(default_factory=list)
    resolved_modules: list[ModuleSource] = field(default_factory=list)
    classes: list[ClassSource] = field(default_factory=list)
    enums: list[EnumSource] = field(default_factory=list)
    interfaces: list[InterfaceSource] = field(default_factory=list)
    implementors: list[ImplementorSource] = field(default_factory=list)
    library_requires: list[LibraryRequireSource] = field(default_factory=list)
    error_message_getter: LibraryErrorMessageGetter | None = None

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

    def interface_named(self, name: str) -> InterfaceSource:
        try:
            return next(iface for iface in self.interfaces if iface.name == name)
        except StopIteration as exc:
            raise KeyError(f"interface not found: {name}") from exc

    def implementor_named(self, name: str) -> ImplementorSource:
        try:
            return next(imp for imp in self.implementors if imp.name == name)
        except StopIteration as exc:
            raise KeyError(f"implementor not found: {name}") from exc

    def enum_named(self, name: str) -> EnumSource:
        try:
            return next(enum for enum in self.enums if enum.name == name)
        except StopIteration as exc:
            raise KeyError(f"enum not found: {name}") from exc

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


CODE_BLOCK_PATTERN = re.compile(r'(<code(?:\s[^>]*)?>)(.*?)(</code>)', flags=re.DOTALL)


def _parse_error_message_getter(elem: ET.Element) -> LibraryErrorMessageGetter:
    """Parse an ``<error_message_getter>`` element."""
    success_value = elem.attrib.get("success", "0")
    header_requires = [
        req.attrib["header"]
        for req in elem.findall("require")
        if "header" in req.attrib
    ]
    # The C code may be in elem.text or in the tail of the last child element.
    # In XML, text after child elements goes into the child's tail.
    code_text = elem.text or ""
    children = list(elem)
    if children:
        # Code is typically in the tail of the last child
        last_child = children[-1]
        code_text = last_child.tail or ""
    # Normalize: strip leading/trailing whitespace, dedent
    lines = code_text.splitlines()
    # Remove empty leading/trailing lines
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    if lines:
        # Find minimum indentation
        min_indent = min((len(line) - len(line.lstrip()) for line in lines if line.strip()), default=0)
        lines = [line[min_indent:] for line in lines]
    code = "\n".join(lines)
    return LibraryErrorMessageGetter(
        success_value=success_value,
        header_requires=header_requires,
        code=code,
    )


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


def _attrs_with_child_shapes(elem: ET.Element) -> dict[str, str]:
    attrs = dict(elem.attrib)
    array = elem.find("array")
    if array is not None and array.attrib.get("length"):
        attrs["array"] = array.attrib["length"]
        if array.attrib.get("length_constant"):
            attrs["array_length_constant"] = array.attrib["length_constant"]
    string = elem.find("string")
    if string is not None and string.attrib.get("length"):
        attrs["string"] = string.attrib["length"]
        if string.attrib.get("length_constant"):
            attrs["string_length_constant"] = string.attrib["length_constant"]
        if string.attrib.get("access"):
            attrs["string_access"] = string.attrib["access"]
    return attrs



def _argument(elem: ET.Element) -> ArgumentSource:
    return ArgumentSource(name=elem.attrib.get("name", ""), attrs=_attrs_with_child_shapes(elem), description=_description(elem))


def _method_like(kind: str, elem: ET.Element) -> MethodSource:
    return MethodSource(
        kind=kind,
        name=elem.attrib.get("name", ""),
        attrs=_attrs_with_child_shapes(elem),
        description=_description(elem),
        arguments=[_argument(a) for a in elem.findall("argument")],
        returns=[_attrs_with_child_shapes(r) for r in elem.findall("return")],
        members=[_named_ref("macros", e) for e in elem.findall("macros")],
        code_blocks=[{"attrs": dict(c.attrib), "text": _clean(c.text)} for c in elem.findall("code")],
    )


def _variable(elem: ET.Element) -> VariableSource:
    all_values = elem.findall("value")
    first_value = all_values[0] if all_values else None
    return VariableSource(
        name=elem.attrib.get("name", ""),
        attrs=_attrs_with_child_shapes(elem),
        description=_description(elem),
        value=(dict(first_value.attrib) if first_value is not None else None),
        values=[dict(v.attrib) for v in all_values],
    )


def _constant(elem: ET.Element) -> ConstantSource:
    return ConstantSource(
        name=elem.attrib.get("name", ""),
        attrs=dict(elem.attrib),
        description=_description(elem),
    )


def _alias(elem: ET.Element) -> AliasSource:
    return AliasSource(
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
        aliases=[_alias(e) for e in root.findall("c_alias")],
        callbacks=[_method_like("callback", e) for e in root.findall("callback")],
        variables=[_variable(e) for e in root.findall("variable")],
        methods=[_method_like("method", e) for e in root.findall("method")],
        macroses=[_method_like("macros", e) for e in root.findall("macros")],
        macro_groups=[_method_like("macroses", e) for e in root.findall("macroses")],
        constants=[_constant(e) for e in root.findall("constant")],
        code_blocks=[{"attrs": dict(c.attrib), "text": _clean(c.text)} for c in root.findall("code")],
    )


def _dependency(elem: ET.Element) -> DependencySource:
    return DependencySource(
        name=elem.attrib.get("name", ""),
        attrs=dict(elem.attrib),
        description=_description(elem),
    )


def load_class_source(path: Path) -> ClassSource:
    root = _parse_legacy_xml(path)
    properties = [PropertySource(name=e.attrib.get("name", ""), attrs=_attrs_with_child_shapes(e), description=_description(e)) for e in root.findall("property")]
    dependencies = [_dependency(e) for e in root.findall("dependency")]
    # Compute struct_members_order by scanning direct children in XML source order
    struct_members_order: list[tuple[str, int]] = []
    prop_idx = 0
    dep_idx = 0
    for child in root:
        if child.tag == "property":
            struct_members_order.append(("field", prop_idx))
            prop_idx += 1
        elif child.tag == "dependency":
            struct_members_order.append(("dep", dep_idx))
            dep_idx += 1
    return ClassSource(
        name=root.attrib["name"],
        path=str(path),
        attrs=dict(root.attrib),
        description=_description(root),
        properties=properties,
        variables=[_variable(e) for e in root.findall("variable")],
        methods=[_method_like("method", e) for e in root.findall("method")],
        constructors=[_method_like("constructor", e) for e in root.findall("constructor")],
        dependencies=dependencies,
        macroses=[_method_like("macros", e) for e in root.findall("macros")],
        requirements=[_requirement(e) for e in root.findall("require")],
        struct_members_order=struct_members_order,
        constants=[_constant(e) for e in root.findall("constant")],
    )


def load_interface_source(path: Path) -> InterfaceSource:
    root = _parse_legacy_xml(path)
    return InterfaceSource(
        name=root.attrib["name"],
        path=str(path),
        attrs=dict(root.attrib),
        description=_description(root),
        methods=[_method_like("method", e) for e in root.findall("method")],
        constants=[_constant(e) for e in root.findall("constant")],
        inherits=[e.attrib["interface"] for e in root.findall("inherit") if "interface" in e.attrib],
    )


def _interface_binding(elem: ET.Element) -> InterfaceBindingSource:
    constants = [
        InterfaceBindingConstantSource(
            name=c.attrib.get("name", ""),
            value=c.attrib.get("value", ""),
            attrs=dict(c.attrib),
        )
        for c in elem.findall("constant")
    ]
    return InterfaceBindingSource(
        name=elem.attrib.get("name", ""),
        constants=constants,
        attrs=dict(elem.attrib),
    )


def _requirement(elem: ET.Element) -> RequirementSource:
    return RequirementSource(
        attrs=dict(elem.attrib),
        description=_description(elem),
    )


def _implementation(elem: ET.Element) -> ImplementationSource:
    # Collect top-level properties and context properties (from <context> block)
    props = [PropertySource(name=e.attrib.get("name", ""), attrs=_attrs_with_child_shapes(e), description=_description(e)) for e in elem.findall("property")]
    # Context properties are struct fields that come from <context>/<property> in the XML.
    # They represent implementation-specific context (e.g. mbedtls handles).
    ctx_props = [PropertySource(name=e.attrib.get("name", ""), attrs={**_attrs_with_child_shapes(e), "is_context": "1"}, description=_description(e)) for e in elem.findall("context/property")]
    # Context requirements (headers, modules needed for context fields)
    ctx_reqs = [_requirement(e) for e in elem.findall("context/require")]
    return ImplementationSource(
        name=elem.attrib.get("name", ""),
        description=_description(elem),
        interface_bindings=[_interface_binding(e) for e in elem.findall("interface")],
        properties=props + ctx_props,
        methods=[_method_like("method", e) for e in elem.findall("method")],
        constructors=[_method_like("constructor", e) for e in elem.findall("constructor")],
        dependencies=[_dependency(e) for e in elem.findall("dependency")],
        requirements=[_requirement(e) for e in elem.findall("require")] + ctx_reqs,
        constants=[_constant(e) for e in elem.findall("constant")],
        attrs=dict(elem.attrib),
    )


def load_implementor_source(path: Path) -> ImplementorSource:
    root = _parse_legacy_xml(path)
    return ImplementorSource(
        name=root.attrib.get("name", ""),
        path=str(path),
        implementations=[_implementation(e) for e in root.findall("implementation")],
        attrs=dict(root.attrib),
        description=_description(root),
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
        interface_refs=[dict(e.attrib) for e in root.findall("interface")],
        implementor_refs=[dict(e.attrib) for e in root.findall("implementor")],
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

    for interface_ref in project.interface_refs:
        interface_area = interface_ref.get("from") or project_dir
        interface_path = _model_path(repo_root, interface_area, "interface", interface_ref["name"])
        project.interfaces.append(load_interface_source(interface_path))

    for implementor_ref in project.implementor_refs:
        implementor_area = implementor_ref.get("from") or project_dir
        implementor_path = _model_path(repo_root, implementor_area, "implementor", implementor_ref["name"])
        project.implementors.append(load_implementor_source(implementor_path))

    # --- Parse project-level library requirements ---
    for req_elem in root.findall("require"):
        if req_elem.attrib.get("feature") != "library":
            continue
        lib_req = LibraryRequireSource()
        if "library" in req_elem.attrib:
            lib_req.kind = "library"
            lib_req.name = req_elem.attrib["library"]
            # Load external library XML for error_message_getter
            lib_path = codegen_root / "models" / "external" / f"library_{lib_req.name}.xml"
            if lib_path.exists():
                lib_root = _parse_legacy_xml(lib_path)
                emg = lib_root.find("error_message_getter")
                if emg is not None:
                    lib_req.error_message_getter = _parse_error_message_getter(emg)
        elif "project" in req_elem.attrib:
            lib_req.kind = "project"
            lib_req.name = req_elem.attrib["project"]
            # Load the referenced project's error_message_getter
            try:
                ref_project_path = project_model_path(lib_req.name, repo_root)
                ref_root = _parse_legacy_xml(ref_project_path)
                emg = ref_root.find("error_message_getter")
                if emg is not None:
                    lib_req.error_message_getter = _parse_error_message_getter(emg)
            except FileNotFoundError:
                pass
        project.library_requires.append(lib_req)

    # --- Parse project's own error_message_getter ---
    emg_elem = root.find("error_message_getter")
    if emg_elem is not None:
        project.error_message_getter = _parse_error_message_getter(emg_elem)

    return project


def load_named_project_source(project_name: str, repo_root: str | Path = ".") -> ProjectSource:
    return load_project_source(project_model_path(project_name, repo_root))
