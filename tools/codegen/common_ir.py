from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from tools.codegen.common_source import ClassSource, MethodSource, ModuleSource, ProjectCommonSource


@dataclass
class IRCommented:
    description: str = ""


@dataclass
class IRCArgument(IRCommented):
    name: str = ""
    kind: str = "type"
    type_name: str | None = None
    callback: str | None = None
    class_name: str | None = None
    access: str | None = None
    is_reference: bool = False
    is_string: bool = False
    is_array: bool = False


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
    code_blocks: list[dict[str, str]] = field(default_factory=list)


@dataclass
class IRCVariable(IRCommented):
    name: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    type_kind: str = "type"
    type_name: str | None = None
    callback: str | None = None
    class_name: str | None = None
    access: str | None = None
    declaration: str | None = None
    definition: str | None = None
    visibility: str | None = None
    value: dict[str, str] | None = None


@dataclass
class IRCModule(IRCommented):
    name: str = ""
    origin: str = "module"
    requires: list[dict[str, str]] = field(default_factory=list)
    c_includes: list[dict[str, str]] = field(default_factory=list)
    callbacks: list[IRCMethod] = field(default_factory=list)
    methods: list[IRCMethod] = field(default_factory=list)
    variables: list[IRCVariable] = field(default_factory=list)
    macros: list[IRCMethod] = field(default_factory=list)


@dataclass
class IRCStructField(IRCommented):
    name: str = ""
    type_kind: str = "type"
    type_name: str | None = None
    class_name: str | None = None
    callback: str | None = None
    access: str | None = None
    is_reference: bool = False
    is_string: bool = False
    is_array: bool = False


@dataclass
class IRCStruct(IRCommented):
    name: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    fields: list[IRCStructField] = field(default_factory=list)


@dataclass
class IRClass(IRCommented):
    name: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    methods: list[IRCMethod] = field(default_factory=list)
    constructors: list[IRCMethod] = field(default_factory=list)
    variables: list[IRCVariable] = field(default_factory=list)
    struct_fields: list[IRCStructField] = field(default_factory=list)


@dataclass
class IRProjectCommon:
    name: str
    modules: list[IRCModule] = field(default_factory=list)
    classes: list[IRClass] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _arg_from_attrs(name: str, attrs: dict[str, str], description: str = "") -> IRCArgument:
    return IRCArgument(
        name=name,
        description=description,
        kind=(
            "callback" if "callback" in attrs else
            "class" if "class" in attrs or attrs.get("type") == "self" else
            "type"
        ),
        type_name=attrs.get("type"),
        callback=attrs.get("callback"),
        class_name=attrs.get("class"),
        access=attrs.get("access"),
        is_reference=attrs.get("is_reference") in {"1", "true"},
        is_string=(attrs.get("type") == "string"),
        is_array=False,
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
            "class" if "class" in attrs else
            "type"
        ),
        type_name=attrs.get("type"),
        callback=attrs.get("callback"),
        class_name=attrs.get("class"),
        access=attrs.get("access"),
        declaration=attrs.get("declaration"),
        definition=attrs.get("definition"),
        visibility=attrs.get("visibility"),
        value=src.value,
    )


def module_to_ir(src: ModuleSource) -> IRCModule:
    return IRCModule(
        name=src.name,
        description=src.description,
        requires=[r.attrs for r in src.requires],
        c_includes=[r.attrs for r in src.c_includes],
        callbacks=[_method_to_ir(c) for c in src.callbacks],
        methods=[_method_to_ir(m) for m in src.methods],
        variables=[_variable_to_ir(v) for v in src.variables],
        macros=[_method_to_ir(m) for m in src.macroses],
    )


def class_to_ir(src: ClassSource) -> IRClass:
    fields = []
    for p in src.properties:
        attrs = p.attrs
        fields.append(IRCStructField(
            name=p.name,
            description=p.description,
            type_kind=(
                "callback" if "callback" in attrs else
                "class" if "class" in attrs or attrs.get("type") == "self" else
                "type"
            ),
            type_name=attrs.get("type"),
            class_name=attrs.get("class"),
            callback=attrs.get("callback"),
            access=attrs.get("access"),
            is_reference=attrs.get("is_reference") in {"1", "true"},
            is_string=(attrs.get("type") == "string"),
            is_array=False,
        ))

    return IRClass(
        name=src.name,
        attrs=src.attrs,
        description=src.description,
        methods=[_method_to_ir(m) for m in src.methods],
        constructors=[_method_to_ir(c) for c in src.constructors],
        variables=[_variable_to_ir(v) for v in src.variables],
        struct_fields=fields,
    )


def project_common_to_ir(project: ProjectCommonSource) -> IRProjectCommon:
    return IRProjectCommon(
        name=project.name,
        modules=[module_to_ir(m) for m in project.modules],
        classes=[class_to_ir(c) for c in project.classes],
    )
