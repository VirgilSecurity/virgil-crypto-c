from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import PurePosixPath
from typing import Any

from tools.codegen.project_source import (
    AliasSource, ClassSource, DependencySource, EnumSource,
    ImplementationSource, ImplementorSource, InterfaceSource,
    MethodSource, ModuleSource, ProjectSource,
)


@dataclass
class IRCommented:
    description: str = ""


@dataclass
class IROutputTarget:
    entity_kind: str
    entity_name: str
    c_artifact_kind: str
    c_symbol: str
    stem: str
    include_file: str
    source_file: str
    header_path: str
    source_path: str
    generated_header_path: str
    generated_source_path: str
    once_guard: str
    header_visibility: str = "public"
    source_visibility: str = "public"


@dataclass
class IRFeature(IRCommented):
    name: str = ""
    attrs: dict[str, str] = field(default_factory=dict)


@dataclass
class IREntityRef(IRCommented):
    kind: str = ""
    name: str = ""
    attrs: dict[str, str] = field(default_factory=dict)


@dataclass
class IRCArgument(IRCommented):
    name: str = ""
    kind: str = "type"
    type_name: str | None = None
    callback: str | None = None
    class_name: str | None = None
    access: str | None = None
    access_explicit: bool = False
    is_reference: bool = False
    is_reference_explicit: bool = False
    is_string: bool = False
    string_length: str | None = None  # "fixed" or "null_terminated"
    string_length_constant: str | None = None  # e.g. "64"
    is_array: bool = False
    enum_name: str | None = None
    interface_name: str | None = None
    library: str | None = None
    project: str | None = None  # Source project for cross-project references
    type_size: str | None = None  # Bit-width for integer/unsigned: "1", "2", "4", "8"


@dataclass
class IRCMethod(IRCommented):
    name: str = ""
    kind: str = "method"
    declaration: str | None = None
    definition: str | None = None
    visibility: str | None = None
    attrs: dict[str, str] = field(default_factory=dict)
    arguments: list[IRCArgument] = field(default_factory=list)
    returns: list[IRCArgument] = field(default_factory=list)
    members: list[IREntityRef] = field(default_factory=list)
    code_blocks: list[dict[str, str]] = field(default_factory=list)


@dataclass
class IRCVariable(IRCommented):
    name: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    type_kind: str = "type"
    type_name: str | None = None
    type_size: str | None = None
    callback: str | None = None
    class_name: str | None = None
    access: str | None = None
    declaration: str | None = None
    definition: str | None = None
    visibility: str | None = None
    value: dict[str, str] | None = None
    values: list[dict[str, str]] = field(default_factory=list)


@dataclass
class IRCConstant(IRCommented):
    name: str = ""
    attrs: dict[str, str] = field(default_factory=dict)


@dataclass
class IRCAlias(IRCommented):
    name: str = ""
    attrs: dict[str, str] = field(default_factory=dict)


@dataclass
class IRCModule(IRCommented):
    name: str = ""
    source_path: str = ""
    origin: str = "module"
    from_area: str | None = None
    attrs: dict[str, str] = field(default_factory=dict)
    requires: list[IREntityRef] = field(default_factory=list)
    c_includes: list[IREntityRef] = field(default_factory=list)
    aliases: list[IRCAlias] = field(default_factory=list)
    callbacks: list[IRCMethod] = field(default_factory=list)
    methods: list[IRCMethod] = field(default_factory=list)
    variables: list[IRCVariable] = field(default_factory=list)
    macros: list[IRCMethod] = field(default_factory=list)
    macro_groups: list[IRCMethod] = field(default_factory=list)
    constants: list[IRCConstant] = field(default_factory=list)
    code_blocks: list[dict[str, str]] = field(default_factory=list)
    output: IROutputTarget | None = None


@dataclass
class IRDependency(IRCommented):
    name: str = ""
    type_kind: str = "interface"
    type_name: str = ""
    has_observers: bool = False
    is_observers_return_status: bool = False
    attrs: dict[str, str] = field(default_factory=dict)


@dataclass
class IRCStructField(IRCommented):
    name: str = ""
    type_kind: str = "type"
    type_name: str | None = None
    type_size: str | None = None
    class_name: str | None = None
    interface_name: str | None = None
    callback: str | None = None
    access: str | None = None
    is_reference: bool = False
    is_reference_explicit: bool = False  # True when is_reference was explicitly set in XML
    is_string: bool = False
    is_array: bool = False
    enum_name: str | None = None
    array_kind: str | None = None
    array_length_constant: str | None = None
    library: str | None = None
    project: str | None = None


@dataclass
class IRClassMacro(IRCommented):
    name: str = ""
    code: str = ""
    definition: str = "public"


@dataclass
class IRClass(IRCommented):
    name: str = ""
    source_path: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    methods: list[IRCMethod] = field(default_factory=list)
    constructors: list[IRCMethod] = field(default_factory=list)
    variables: list[IRCVariable] = field(default_factory=list)
    struct_fields: list[IRCStructField] = field(default_factory=list)
    dependencies: list[IRDependency] = field(default_factory=list)
    struct_members_order: list[tuple[str, int]] = field(default_factory=list)
    # Ordered list of (kind, index) tuples preserving XML source order.
    # kind is 'field' or 'dep', index is into struct_fields or dependencies.
    macroses: list[IRClassMacro] = field(default_factory=list)
    requirements: list['IRRequirement'] = field(default_factory=list)
    constants: list[IRCConstant] = field(default_factory=list)
    output: IROutputTarget | None = None


@dataclass
class IREnum(IRCommented):
    name: str = ""
    source_path: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    constants: list[IRCConstant] = field(default_factory=list)
    output: IROutputTarget | None = None


@dataclass
class IRInterfaceBindingConstant(IRCommented):
    name: str = ""
    value: str = ""
    attrs: dict[str, str] = field(default_factory=dict)


@dataclass
class IRInterfaceBinding(IRCommented):
    name: str = ""
    constants: list[IRInterfaceBindingConstant] = field(default_factory=list)
    attrs: dict[str, str] = field(default_factory=dict)


@dataclass
class IRRequirement(IRCommented):
    kind: str = ""
    name: str = ""
    attrs: dict[str, str] = field(default_factory=dict)


@dataclass
class IRImplementation(IRCommented):
    name: str = ""
    implementor_name: str = ""
    source_path: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    interface_bindings: list[IRInterfaceBinding] = field(default_factory=list)
    properties: list[IRCStructField] = field(default_factory=list)
    methods: list[IRCMethod] = field(default_factory=list)
    constructors: list[IRCMethod] = field(default_factory=list)
    dependencies: list[IRDependency] = field(default_factory=list)
    requirements: list[IRRequirement] = field(default_factory=list)
    constants: list[IRCConstant] = field(default_factory=list)
    output: IROutputTarget | None = None


@dataclass
class IRInterface(IRCommented):
    name: str = ""
    source_path: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    methods: list[IRCMethod] = field(default_factory=list)
    constants: list[IRCConstant] = field(default_factory=list)
    inherits: list[str] = field(default_factory=list)
    output: IROutputTarget | None = None


@dataclass
class IRLibraryErrorMessageGetter:
    """IR representation of an error_message_getter."""
    success_value: str = ""
    code: str = ""
    header_requires: list[str] = field(default_factory=list)


@dataclass
class IRLibraryRequire:
    """IR representation of a project-level library requirement."""
    kind: str = ""  # 'project' or 'library'
    name: str = ""
    error_message_getter: "IRLibraryErrorMessageGetter | None" = None


@dataclass
class IRProject:
    name: str
    attrs: dict[str, str] = field(default_factory=dict)
    version: dict[str, str] | None = None
    namespace: str = ""
    framework: str = ""
    prefix: str = ""
    project_path: str = ""
    source_root: str = ""
    work_root: str = ""
    include_namespace: str = ""
    generated_namespace: str = ""
    features: list[IRFeature] = field(default_factory=list)
    module_refs: list[IREntityRef] = field(default_factory=list)
    class_refs: list[IREntityRef] = field(default_factory=list)
    enum_refs: list[IREntityRef] = field(default_factory=list)
    modules: list[IRCModule] = field(default_factory=list)
    dependency_modules: list[IRCModule] = field(default_factory=list)
    resolved_modules: list[IRCModule] = field(default_factory=list)
    interface_refs: list[IREntityRef] = field(default_factory=list)
    classes: list[IRClass] = field(default_factory=list)
    enums: list[IREnum] = field(default_factory=list)
    interfaces: list[IRInterface] = field(default_factory=list)
    implementations: list[IRImplementation] = field(default_factory=list)
    library_requires: list[IRLibraryRequire] = field(default_factory=list)
    error_message_getter: IRLibraryErrorMessageGetter | None = None
    fallback_projects: list[Any] = field(default_factory=list, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


ProjectIR = IRProject
IRArgument = IRCArgument
IRMethod = IRCMethod
IRVariable = IRCVariable
IRConstant = IRCConstant
IRAlias = IRCAlias
IRModule = IRCModule
IRStructField = IRCStructField


def _snake(name: str) -> str:
    return name.replace(" ", "_")


def project_include_namespace(project: ProjectSource) -> str:
    namespace_parts = project.namespace.split()
    return str(PurePosixPath(*namespace_parts)) if namespace_parts else ""


def generated_namespace(project: ProjectSource) -> str:
    work_root = PurePosixPath(project.attrs.get("work_path", ""))
    return str(work_root) if str(work_root) != "." else ""


def output_once_guard(stem: str) -> str:
    return f"{stem}_h_included"


def build_output_target(project: ProjectSource, *, entity_kind: str, entity_name: str, attrs: dict[str, str]) -> IROutputTarget:
    stem = f"{project.prefix}_{_snake(entity_name)}"
    include_namespace = PurePosixPath(project_include_namespace(project))
    source_root = PurePosixPath(project.attrs.get("path", ""))
    work_root = PurePosixPath(project.attrs.get("work_path", ""))

    scope = attrs.get("scope", "")
    header_visibility = "private" if scope == "private" else "internal" if scope == "internal" else "public"
    if scope == "internal":
        # Internal-scope entities have their header in src/ alongside the implementation
        header_path = str(source_root / "src" / f"{stem}.h")
    else:
        include_dir = include_namespace / ("private" if header_visibility == "private" else "")
        header_path = str(source_root / "include" / include_dir / f"{stem}.h")
    source_path = str(source_root / "src" / f"{stem}.c")
    entity_slug = _snake(entity_name)
    c_artifact_kind = "module"
    generated_header_path = str(work_root / f"c_{c_artifact_kind}_{stem}.xml")
    generated_source_path = str(work_root / f"{entity_kind}_{entity_slug}.xml")

    return IROutputTarget(
        entity_kind=entity_kind,
        entity_name=entity_name,
        c_artifact_kind=c_artifact_kind,
        c_symbol=stem,
        stem=stem,
        include_file=f"{stem}.h",
        source_file=f"{stem}.c",
        header_path=header_path,
        source_path=source_path,
        generated_header_path=generated_header_path,
        generated_source_path=generated_source_path,
        once_guard=output_once_guard(stem),
        header_visibility=header_visibility,
        source_visibility="public",
    )


def _ref(kind: str, name: str, attrs: dict[str, str], description: str = "") -> IREntityRef:
    return IREntityRef(kind=kind, name=name, attrs=attrs, description=description)


def _arg_from_attrs(name: str, attrs: dict[str, str], description: str = "") -> IRCArgument:
    return IRCArgument(
        name=name,
        description=description,
        kind=(
            "callback" if "callback" in attrs else
            "class" if "class" in attrs or "impl" in attrs or attrs.get("type") == "self" else
            "interface" if "interface" in attrs else
            "enum" if "enum" in attrs else
            "type"
        ),
        type_name=attrs.get("type"),
        callback=attrs.get("callback"),
        class_name=attrs.get("class") or attrs.get("impl"),
        access=attrs.get("access"),
        access_explicit="access" in attrs,
        is_reference=attrs.get("is_reference") in {"1", "true"},
        is_reference_explicit="is_reference" in attrs,
        is_string=(attrs.get("type") == "string" or attrs.get("string") is not None),
        string_length=attrs.get("string"),
        string_length_constant=attrs.get("string_length_constant"),
        is_array=attrs.get("array") == "given",
        enum_name=attrs.get("enum"),
        interface_name=attrs.get("interface"),
        library=attrs.get("library"),
        project=attrs.get("project"),
        type_size=attrs.get("size"),
    )


def _method_to_ir(src: MethodSource) -> IRCMethod:
    return IRCMethod(
        name=src.name,
        kind=src.kind,
        declaration=src.attrs.get("declaration"),
        definition=src.attrs.get("definition"),
        visibility=src.attrs.get("visibility"),
        attrs=src.attrs,
        description=src.description,
        arguments=[_arg_from_attrs(a.name, a.attrs, a.description) for a in src.arguments],
        returns=[_arg_from_attrs("return", r) for r in src.returns],
        members=[_ref(m.kind, m.name, m.attrs, m.description) for m in src.members],
        code_blocks=src.code_blocks,
    )


def _variable_to_ir(src) -> IRCVariable:
    attrs = src.attrs
    return IRCVariable(
        name=src.name,
        attrs=attrs,
        description=src.description,
        type_kind=(
            "callback" if "callback" in attrs else
            "class" if "class" in attrs or "impl" in attrs else
            "type"
        ),
        type_name=attrs.get("type"),
        type_size=attrs.get("size"),
        callback=attrs.get("callback"),
        class_name=attrs.get("class") or attrs.get("impl"),
        access=attrs.get("access"),
        declaration=attrs.get("declaration"),
        definition=attrs.get("definition"),
        visibility=attrs.get("visibility"),
        value=src.value,
        values=getattr(src, 'values', []),
    )


def _field_from_attrs(name: str, attrs: dict[str, str], description: str = "") -> IRCStructField:
    return IRCStructField(
        name=name,
        description=description,
        type_kind=(
            "callback" if "callback" in attrs else
            "class" if "class" in attrs or "impl" in attrs or attrs.get("type") == "self" else
            "interface" if "interface" in attrs else
            "enum" if "enum" in attrs else
            "type"
        ),
        type_name=attrs.get("type"),
        type_size=attrs.get("size"),
        class_name=attrs.get("class") or attrs.get("impl"),
        interface_name=attrs.get("interface"),
        callback=attrs.get("callback"),
        access=attrs.get("access"),
        is_reference=attrs.get("is_reference") in {"1", "true"},
        is_reference_explicit="is_reference" in attrs,
        is_string=(attrs.get("type") == "string" or attrs.get("string") is not None),
        is_array=attrs.get("array") == "given",
        enum_name=attrs.get("enum"),
        array_kind=attrs.get("array"),
        array_length_constant=attrs.get("array_length_constant"),
        library=attrs.get("library"),
        project=attrs.get("project"),
    )


def _constant_to_ir(name: str, attrs: dict[str, str], description: str = "") -> IRCConstant:
    return IRCConstant(name=name, attrs=attrs, description=description)


def _alias_to_ir(name: str, attrs: dict[str, str], description: str = "") -> IRCAlias:
    return IRCAlias(name=name, attrs=attrs, description=description)


def module_to_ir(project: ProjectSource, src: ModuleSource) -> IRCModule:
    return IRCModule(
        name=src.name,
        source_path=src.path,
        origin="module",
        from_area=src.from_area,
        attrs={
            **src.attrs,
            **({"from": src.from_area} if src.from_area is not None else {}),
        },
        description=src.description,
        requires=[_ref("require", r.name, r.attrs, r.description) for r in src.requires],
        c_includes=[_ref("c_include", r.name, r.attrs, r.description) for r in src.c_includes],
        aliases=[_alias_to_ir(a.name, a.attrs, a.description) for a in src.aliases],
        callbacks=[_method_to_ir(c) for c in src.callbacks],
        methods=[_method_to_ir(m) for m in src.methods],
        variables=[_variable_to_ir(v) for v in src.variables],
        macros=[_method_to_ir(m) for m in src.macroses],
        macro_groups=[_method_to_ir(m) for m in src.macro_groups],
        constants=[_constant_to_ir(c.name, c.attrs, c.description) for c in src.constants],
        code_blocks=src.code_blocks,
        output=build_output_target(project, entity_kind="module", entity_name=src.name, attrs=src.attrs),
    )


def _dependency_to_ir(src: DependencySource) -> IRDependency:
    attrs = src.attrs
    if "class" in attrs:
        type_kind = "class"
        type_name = attrs["class"]
    elif "impl" in attrs:
        type_kind = "impl"
        type_name = attrs["impl"]
    else:
        type_kind = "interface"
        type_name = attrs.get("interface", "")
    return IRDependency(
        name=src.name,
        description=src.description,
        type_kind=type_kind,
        type_name=type_name,
        has_observers=attrs.get("has_observers") in {"1", "true"},
        is_observers_return_status=attrs.get("is_observers_return_status") in {"1", "true"},
        attrs=attrs,
    )


def class_to_ir(project: ProjectSource, src: ClassSource) -> IRClass:
    return IRClass(
        name=src.name,
        source_path=src.path,
        attrs=src.attrs,
        description=src.description,
        methods=[_method_to_ir(m) for m in src.methods],
        constructors=[_method_to_ir(c) for c in src.constructors],
        variables=[_variable_to_ir(v) for v in src.variables],
        struct_fields=[_field_from_attrs(p.name, p.attrs, p.description) for p in src.properties],
        dependencies=[_dependency_to_ir(d) for d in src.dependencies],
        struct_members_order=list(src.struct_members_order) if src.struct_members_order else [],
        macroses=[IRClassMacro(
            name=m.name,
            description=m.description,
            code="\n".join(cb.get("text", "") for cb in m.code_blocks) if m.code_blocks else "",
            definition=m.attrs.get("definition", "public"),
        ) for m in src.macroses],
        requirements=[
            IRRequirement(kind=r.kind, name=r.name, attrs=r.attrs, description=r.description)
            for r in src.requirements
        ],
        constants=[_constant_to_ir(c.name, c.attrs, c.description) for c in src.constants],
        output=build_output_target(project, entity_kind="class", entity_name=src.name, attrs=src.attrs),
    )


def interface_to_ir(project: ProjectSource, src: InterfaceSource) -> IRInterface:
    return IRInterface(
        name=src.name,
        source_path=src.path,
        attrs=src.attrs,
        description=src.description,
        methods=[_method_to_ir(m) for m in src.methods],
        constants=[_constant_to_ir(c.name, c.attrs, c.description) for c in src.constants],
        inherits=list(src.inherits),
        output=build_output_target(project, entity_kind="interface", entity_name=src.name, attrs=src.attrs),
    )


def enum_to_ir(project: ProjectSource, src: EnumSource) -> IREnum:
    return IREnum(
        name=src.name,
        source_path=src.path,
        attrs=src.attrs,
        description=src.description,
        constants=[_constant_to_ir(c.name, c.attrs, c.description) for c in src.constants],
        output=build_output_target(project, entity_kind="enum", entity_name=src.name, attrs=src.attrs),
    )


def implementation_to_ir(project: ProjectSource, src: ImplementationSource, implementor: ImplementorSource) -> IRImplementation:
    return IRImplementation(
        name=src.name,
        implementor_name=implementor.name,
        source_path=implementor.path,
        attrs=src.attrs,
        description=src.description,
        interface_bindings=[
            IRInterfaceBinding(
                name=b.name,
                constants=[
                    IRInterfaceBindingConstant(name=c.name, value=c.value, attrs=c.attrs)
                    for c in b.constants
                ],
                attrs=b.attrs,
            )
            for b in src.interface_bindings
        ],
        properties=[_field_from_attrs(p.name, p.attrs, p.description) for p in src.properties],
        methods=[_method_to_ir(m) for m in src.methods],
        constructors=[_method_to_ir(c) for c in src.constructors],
        dependencies=[_dependency_to_ir(d) for d in src.dependencies],
        requirements=[
            IRRequirement(kind=r.kind, name=r.name, attrs=r.attrs, description=r.description)
            for r in src.requirements
        ],
        constants=[
            _constant_to_ir(c.name, c.attrs, c.description)
            for c in src.constants
        ],
        output=build_output_target(project, entity_kind="implementation", entity_name=src.name, attrs=src.attrs),
    )


def _synthetic_impl_tag_enum(project: ProjectSource) -> IREnum:
    """Create a synthetic 'impl/tag' enum from the set of all implementations.

    The legacy codegen generates an ``impl_tag`` enum (one constant per
    implementation) inside the project-global ``impl`` module.  Other entities
    reference this enum via ``enum="impl/tag"`` in the XML models, so it must
    be discoverable in the IR's enum list.
    """
    impl_names = sorted(
        impl.name
        for implementor in project.implementors
        for impl in implementor.implementations
    )
    prefix = project.prefix
    stem = f"{prefix}_impl"
    enum_stem = f"{prefix}_impl_tag"
    include_namespace = project_include_namespace(project)
    source_root = PurePosixPath(project.attrs.get("path", ""))
    work_root = PurePosixPath(project.attrs.get("work_path", ""))

    output = IROutputTarget(
        entity_kind="enum",
        entity_name="impl/tag",
        c_artifact_kind="module",
        c_symbol=enum_stem,
        stem=enum_stem,
        # The enum lives inside the impl module header, not its own file.
        include_file=f"{stem}.h",
        source_file=f"{stem}.c",
        header_path=str(source_root / "include" / include_namespace / f"{stem}.h"),
        source_path=str(source_root / "src" / f"{stem}.c"),
        generated_header_path=str(work_root / f"c_module_{stem}.xml"),
        generated_source_path=str(work_root / f"enum_impl_tag.xml"),
        once_guard=output_once_guard(stem),
        header_visibility="public",
        source_visibility="public",
    )

    constants = [
        IRCConstant(name=name, attrs={}, description="")
        for name in impl_names
    ]

    return IREnum(
        name="impl/tag",
        source_path="",
        attrs={},
        description="Enumerates all possible implementations within crypto library.",
        constants=constants,
        output=output,
    )


def project_to_ir(project: ProjectSource) -> IRProject:
    explicit_module_paths = {module.path for module in project.modules}
    resolved_modules = [module_to_ir(project, m) for m in project.resolved_modules]

    # Build the synthetic impl/tag enum if the project has implementations.
    impl_tag_enums: list[IREnum] = []
    if project.implementors:
        impl_tag_enums.append(_synthetic_impl_tag_enum(project))

    ir = IRProject(
        name=project.name,
        attrs=project.attrs,
        version=project.version,
        namespace=project.namespace,
        framework=project.framework,
        prefix=project.prefix,
        project_path=project.path,
        source_root=project.source_root,
        work_root=project.work_root,
        include_namespace=project_include_namespace(project),
        generated_namespace=generated_namespace(project),
        features=[IRFeature(name=feature.name, attrs=feature.attrs, description=feature.description) for feature in project.feature_refs],
        module_refs=[_ref("module", ref["name"], ref) for ref in project.module_refs],
        class_refs=[_ref("class", ref["name"], ref) for ref in project.class_refs],
        enum_refs=[_ref("enum", ref["name"], ref) for ref in project.enum_refs],
        interface_refs=[_ref("interface", ref["name"], ref) for ref in project.interface_refs],
        modules=[module for module in resolved_modules if module.source_path in explicit_module_paths],
        dependency_modules=[module for module in resolved_modules if module.source_path not in explicit_module_paths],
        resolved_modules=resolved_modules,
        classes=[class_to_ir(project, c) for c in project.classes],
        enums=[enum_to_ir(project, e) for e in project.enums] + impl_tag_enums,
        interfaces=[interface_to_ir(project, i) for i in project.interfaces],
        implementations=[
            implementation_to_ir(project, impl, implementor)
            for implementor in project.implementors
            for impl in implementor.implementations
        ],
        library_requires=[
            IRLibraryRequire(
                kind=lr.kind,
                name=lr.name,
                error_message_getter=(
                    IRLibraryErrorMessageGetter(
                        success_value=lr.error_message_getter.success_value,
                        header_requires=list(lr.error_message_getter.header_requires),
                        code=lr.error_message_getter.code,
                    )
                    if lr.error_message_getter else None
                ),
            )
            for lr in project.library_requires
        ],
        error_message_getter=(
            IRLibraryErrorMessageGetter(
                success_value=project.error_message_getter.success_value,
                header_requires=list(project.error_message_getter.header_requires),
                code=project.error_message_getter.code,
            )
            if project.error_message_getter else None
        ),
    )
    resolve_defaults(ir)
    return ir


# ---------------------------------------------------------------------------
#   Default resolution pass
#
#   Resolves all None values for `access` and `is_reference` on IR nodes,
#   matching the legacy GSL rules from component.gsl.
#
#   Rules for is_reference:
#     - class (general): True (pointer)
#     - class="data":    False (value — vsc_data_t passed by value)
#     - class="buffer":  True (pointer)
#     - interface/impl/api: True (pointer)
#     - type/enum/callback: False (value)
#
#   Rules for access:
#     - General default: "readonly"
#     - class="data" (any context): "readonly"
#     - class="buffer" + argument:  "writeonly"
#     - class="buffer" + return:    "disown"
#     - class="buffer" + property/variable: "readwrite"
#     - property (non-buffer): "readwrite"
#     - interface/impl self argument in is_const method: "readonly"
#     - interface/impl self argument in non-const method: "readwrite"
#     - impl return in is_const method: "readonly"
#     - impl return in non-const method: "readwrite"
#     - api (interface api): access forced to "readonly"
# ---------------------------------------------------------------------------


def _resolve_arg_is_reference(arg: IRCArgument) -> None:
    """Resolve is_reference for an argument if not explicitly set."""
    # is_reference is already a bool with default False.
    # We only need to set it to True for class/interface/impl/api kinds
    # when it wasn't explicitly set in the XML.
    # The _arg_from_attrs already reads is_reference from XML attrs.
    # But when the XML doesn't set it, the default False is wrong for
    # class/interface/impl kinds (except data which should stay False).
    # We need to know if it was explicitly set. Currently we don't track that
    # for arguments like we do for struct fields (is_reference_explicit).
    # The logic: if kind is class/interface and is_reference is False,
    # it was likely not set (since XML would need is_reference="0" to override).
    # But data class should remain False. Let's check:
    pass  # Handled inline in resolve_defaults for arguments


def _resolve_arg_defaults(arg: IRCArgument, context: str, method_is_const: bool = False) -> None:
    """Resolve access and is_reference defaults for an argument.

    Args:
        arg: The argument IR node.
        context: One of 'argument', 'return', 'property', 'variable'.
        method_is_const: Whether the parent method has is_const=True.
    """
    # --- is_reference ---
    # For class kinds: default to True (pointer), except data→False
    if arg.kind == "class":
        if arg.class_name == "data":
            arg.is_reference = False
        elif arg.is_reference_explicit:
            pass  # Respect explicit is_reference="0" or is_reference="1"
        elif not arg.is_reference:
            # class/impl default to pointer when not explicitly set
            arg.is_reference = True
    elif arg.kind == "interface":
        if not arg.is_reference and not arg.is_reference_explicit:
            arg.is_reference = True
    # type, enum, callback → is_reference stays False (default)

    # --- access ---
    if arg.access is not None:
        return  # Explicitly set in XML, don't override

    if arg.class_name == "data":
        arg.access = "readonly"
    elif arg.class_name == "buffer":
        if context == "argument":
            arg.access = "writeonly"
        elif context == "return":
            arg.access = "disown"
        elif context in ("property", "variable"):
            arg.access = "readwrite"
        else:
            arg.access = "readonly"
    elif context == "property":
        arg.access = "readwrite"
    else:
        arg.access = "readonly"


def _resolve_field_defaults(field: IRCStructField, context: str) -> None:
    """Resolve access and is_reference defaults for a struct field / property.

    Args:
        field: The struct field IR node.
        context: 'property' or 'field'.
    """
    # --- is_reference ---
    if not field.is_reference_explicit:
        if field.type_kind == "class":
            if field.class_name == "data":
                field.is_reference = False
            else:
                field.is_reference = True
        elif field.type_kind in ("interface",):
            field.is_reference = True
        # type, enum, callback → False (default)

    # --- access ---
    if field.access is not None:
        return

    if field.class_name == "data":
        field.access = "readonly"
    elif field.class_name == "buffer":
        field.access = "readwrite"  # buffer properties/variables default to readwrite
    else:
        field.access = "readwrite"  # properties default to readwrite per GSL


def _resolve_variable_defaults(var: IRCVariable) -> None:
    """Resolve access defaults for a variable."""
    if var.access is not None:
        return
    if var.class_name == "data":
        var.access = "readonly"
    elif var.class_name == "buffer":
        var.access = "readwrite"
    else:
        var.access = "readwrite"  # variables default to readwrite


def _resolve_method_defaults(method: IRCMethod) -> None:
    """Resolve defaults for all arguments and returns in a method."""
    is_const = method.attrs.get("is_const") in {"1", "true"}

    for arg in method.arguments:
        _resolve_arg_defaults(arg, context="argument", method_is_const=is_const)

    for ret in method.returns:
        _resolve_arg_defaults(ret, context="return", method_is_const=is_const)


def resolve_defaults(ir: IRProject) -> None:
    """Resolve all default values in the IR, eliminating None access/is_reference.

    This must be called after project_to_ir() builds the IR. After this pass,
    no argument, return, property, or variable will have access=None.
    """
    # --- Modules ---
    for module in ir.resolved_modules:
        for method in module.methods:
            _resolve_method_defaults(method)
        for callback in module.callbacks:
            _resolve_method_defaults(callback)
        for macro in module.macros:
            _resolve_method_defaults(macro)
        for macro in module.macro_groups:
            _resolve_method_defaults(macro)
        for var in module.variables:
            _resolve_variable_defaults(var)

    # --- Classes ---
    for cls in ir.classes:
        # Classes without properties are static utilities — default to context="none"
        context = cls.attrs.get("context")
        if context is None and len(cls.struct_fields) == 0:
            context = "none"
            cls.attrs["context"] = "none"
        elif context is None:
            context = "public"
        if context == "none":
            cls.attrs["lifecycle"] = "none"
            # All methods in context=none classes are static by default
            for method in cls.methods:
                if method.attrs.get("is_static") is None:
                    method.attrs["is_static"] = "1"

        for method in cls.methods:
            _resolve_method_defaults(method)
        for constructor in cls.constructors:
            _resolve_method_defaults(constructor)
        for field in cls.struct_fields:
            _resolve_field_defaults(field, context="property")
        for var in cls.variables:
            _resolve_variable_defaults(var)

    # --- Interfaces ---
    for iface in ir.interfaces:
        for method in iface.methods:
            _resolve_method_defaults(method)

    # --- Implementations ---
    for impl in ir.implementations:
        for method in impl.methods:
            _resolve_method_defaults(method)
        for constructor in impl.constructors:
            _resolve_method_defaults(constructor)
        for prop in impl.properties:
            _resolve_field_defaults(prop, context="property")

    # --- Enums (no access/is_reference to resolve) ---
    # Enums only have constants, no access/is_reference attributes.
