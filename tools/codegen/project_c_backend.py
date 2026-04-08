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


@dataclass(frozen=True)
class ClassFieldSpec:
    name: str
    attrs: dict[str, str]
    description: str = ""


@dataclass(frozen=True)
class ClassMethodSpec:
    name: str
    description: str
    arguments: tuple[dict[str, str], ...] = ()
    return_attrs: dict[str, str] | None = None
    visibility: str = "public"
    declaration: str = "public"
    definition: str = "external"
    modifiers: tuple[str, ...] = ("VSC_PUBLIC",)
    code: str | None = None
    code_path: str | Path | None = None
    uid: str | None = None


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



def c_identifier(name: str, *, callback: bool = False) -> str:
    ident = snake_name(name)
    if callback and not ident.endswith("_cb"):
        ident = f"{ident}_cb"
    return ident



def callback_name_from_ref(callback_ref: str | None) -> str:
    if not callback_ref:
        return "dealloc"
    token = callback_ref.split("_")[-1]
    return token.removesuffix(")")



def load_support_code(code: str | None = None, code_path: str | Path | None = None) -> str | None:
    if code is not None:
        return code
    if code_path is None:
        return None
    return Path(code_path).read_text(encoding="utf-8").rstrip("\n")



def class_method_symbol(project_ir: IRProject, cls: IRClass, method_name: str) -> str:
    return f"{entity_output(project_ir, entity_kind='class', entity_name=cls.name).c_symbol}_{snake_name(method_name)}"



def _reference_ctor_suffix(ctor_name: str) -> str:
    return snake_name(ctor_name.removeprefix("with "))



def class_constructor_symbol(project_ir: IRProject, cls: IRClass, ctor_name: str) -> str:
    class_symbol = entity_output(project_ir, entity_kind='class', entity_name=cls.name).c_symbol
    if cls.attrs.get("is_value_type") in {"1", "true"}:
        suffix = "" if ctor_name == cls.name else f"_{snake_name(ctor_name)}"
        return f"{class_symbol}{suffix}"
    return f"{class_symbol}_init_with_{_reference_ctor_suffix(ctor_name)}"



def _class_new_constructor_symbol(project_ir: IRProject, cls: IRClass, ctor_name: str) -> str:
    class_symbol = entity_output(project_ir, entity_kind='class', entity_name=cls.name).c_symbol
    return f"{class_symbol}_new_with_{_reference_ctor_suffix(ctor_name)}"



def _class_runtime_symbol(project_ir: IRProject, cls: IRClass, suffix: str) -> str:
    class_symbol = entity_output(project_ir, entity_kind='class', entity_name=cls.name).c_symbol
    return f"{class_symbol}_{suffix}"



def _class_uses_library_types(cls: IRClass) -> bool:
    scalar_type_names = {"boolean", "size", "integer", "byte", "char", "string"}
    for field in cls.struct_fields:
        if field.type_kind == "callback" or field.type_name in scalar_type_names:
            return True
    for variable in cls.variables:
        if variable.type_kind == "callback" or variable.type_name in scalar_type_names:
            return True
    for method in [*cls.constructors, *cls.methods]:
        for arg in [*method.arguments, *method.returns]:
            if arg.kind == "callback" or arg.type_name in scalar_type_names:
                return True
    return False



def _class_dependency_includes(project_ir: IRProject, cls: IRClass) -> list[str]:
    includes: list[str] = []
    seen: set[str] = set()

    def add_include(class_name: str | None) -> None:
        if not class_name or class_name == "self" or class_name == cls.name:
            return
        include = include_file_for_entity(project_ir, entity_kind="class", entity_name=class_name)
        if include not in seen:
            seen.add(include)
            includes.append(include)

    for field in cls.struct_fields:
        add_include(field.class_name)
    for variable in cls.variables:
        add_include(variable.class_name)
    for method in [*cls.constructors, *cls.methods]:
        for arg in [*method.arguments, *method.returns]:
            add_include(arg.class_name)

    return includes



def render_class_c_module(
    project_ir: IRProject,
    cls: IRClass,
    *,
    output: IROutputTarget | None = None,
    entity_id: str | None = None,
    scope: str | None = None,
    module_class_name: str = "",
    feature: str | None = None,
    public_includes: list[str] | None = None,
    private_includes: list[str] | None = None,
    struct_declaration: str | None = None,
    struct_definition: str | None = None,
    extra_struct_fields: tuple[ClassFieldSpec, ...] = (),
    extra_methods: tuple[ClassMethodSpec, ...] = (),
    include_own_header_public: bool = True,
    generate_ctx_size: bool = True,
    render_variables: bool = True,
    render_reference_support: bool = True,
    render_methods: bool = True,
) -> ET.Element:
    class_output = cast(IROutputTarget, cls.output) if output is None else output
    is_value_type = cls.attrs.get("is_value_type") in {"1", "true"}
    root = c_module_root(
        class_output,
        entity_id=entity_id or snake_name(cls.name),
        scope=scope or cls.attrs.get("scope", "public"),
        class_name=module_class_name,
    )
    if feature is not None:
        root.set("feature", feature)

    resolved_private_includes = [class_output.include_file, *(private_includes or [])]
    resolved_public_includes = list(public_includes or [])
    if _class_uses_library_types(cls):
        library_include = include_file_for_entity(project_ir, entity_kind="module", entity_name="library")
        if library_include not in resolved_public_includes:
            resolved_public_includes.append(library_include)
    for include in _class_dependency_includes(project_ir, cls):
        if include not in resolved_public_includes:
            resolved_public_includes.append(include)
    if include_own_header_public and class_output.include_file not in resolved_public_includes:
        resolved_public_includes.append(class_output.include_file)

    for include in resolved_private_includes:
        text_element(root, "c_include", file=include, is_system="0", scope="private")
    for include in resolved_public_includes:
        text_element(root, "c_include", file=include, is_system="0", scope="public")

    struct = text_element(
        root,
        "c_struct",
        name=class_type_symbol(project_ir, cls.name),
        visibility="public",
        declaration=struct_declaration or ("public" if is_value_type else "public"),
        definition=struct_definition or ("public" if is_value_type else "external"),
        uid=f"c_class_{snake_name(cls.name)}_struct_{snake_name(cls.name)}",
    )
    struct.text = comment_text(f"Handle '{cls.name}' context.")

    if is_value_type:
        field_specs = [
            ClassFieldSpec(name=field.name, attrs={
                **({"class": field.class_name} if field.class_name is not None else {}),
                **({"callback": field.callback} if field.callback is not None else {}),
                **({"type": field.type_name} if field.type_name is not None else {}),
                **({"access": field.access} if field.access is not None else {}),
                **({"is_reference": "1"} if field.is_reference else {}),
                **({"array": "given"} if field.is_array else {}),
            }, description=field.description)
            for field in cls.struct_fields
        ]
    else:
        field_specs = [*extra_struct_fields, *[
            ClassFieldSpec(name=field.name, attrs={
                **({"class": field.class_name} if field.class_name is not None else {}),
                **({"callback": field.callback} if field.callback is not None else {}),
                **({"type": field.type_name} if field.type_name is not None else {}),
                **({"access": field.access} if field.access is not None else {}),
                **({"is_reference": "1"} if field.is_reference else {}),
                **({"array": "given"} if field.is_array else {}),
            }, description=field.description)
            for field in cls.struct_fields
        ]]

    if is_value_type or extra_struct_fields:
        for field_spec in field_specs:
            _render_class_property(struct, field_spec, project_ir=project_ir, owner_class=cls.name)

    if render_variables:
        for variable in cls.variables:
            _render_class_variable(root, variable, project_ir=project_ir, owner_class=cls.name)

    if generate_ctx_size:
        _render_ctx_size_method(root, project_ir=project_ir, cls=cls)

    if is_value_type and render_methods:
        for ctor in cls.constructors:
            _render_ir_method(
                root,
                name=class_constructor_symbol(project_ir, cls, ctor.name),
                description=ctor.description,
                arguments=tuple(_method_arg_dict(arg) for arg in ctor.arguments),
                return_attrs={"class": "self"},
                owner_class=cls.name,
                project_ir=project_ir,
                uid=f"direct_{snake_name(cls.name)}_ctor_{snake_name(ctor.name)}",
            )
    elif render_reference_support:
        _render_reference_class_support(
            root,
            project_ir=project_ir,
            cls=cls,
            overridden_method_names={method.name for method in extra_methods},
        )

    if render_methods:
        for method in cls.methods:
            method_args = list(_method_arg_dict(arg) for arg in method.arguments)
            if not is_value_type:
                self_attrs: dict[str, str] = {"class": "self"}
                if method.attrs.get("is_const") in {"1", "true"}:
                    self_attrs["access"] = "readonly"
                method_args.insert(0, {"name": "self", **self_attrs})
            else:
                method_args.insert(0, {"name": "self", "class": "self"})
            return_attrs = _method_arg_dict(method.returns[0]) if method.returns else {"type": "void"}
            _render_ir_method(
                root,
                name=class_method_symbol(project_ir, cls, method.name),
                description=method.description,
                arguments=tuple(method_args),
                return_attrs=return_attrs,
                owner_class=cls.name,
                project_ir=project_ir,
                uid=f"direct_{snake_name(cls.name)}_method_{snake_name(method.name)}",
            )

    for method in extra_methods:
        _render_ir_method(
            root,
            name=method.name,
            description=method.description,
            arguments=method.arguments,
            return_attrs=method.return_attrs,
            visibility=method.visibility,
            declaration=method.declaration,
            definition=method.definition,
            modifiers=method.modifiers,
            code=load_support_code(method.code, method.code_path),
            owner_class=cls.name,
            project_ir=project_ir,
            uid=method.uid,
        )

    return root



def _method_arg_dict(arg: object) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for attr_name, key in (("class_name", "class"), ("callback", "callback"), ("type_name", "type"), ("access", "access")):
        value = getattr(arg, attr_name, None)
        if value is not None:
            attrs[key] = value
    if getattr(arg, "is_reference", False):
        attrs["is_reference"] = "1"
    if getattr(arg, "is_string", False):
        attrs["type"] = "string"
    if getattr(arg, "is_array", False):
        attrs["_array"] = "given"
    name = getattr(arg, "name", "")
    rendered_name = name if name == "return" else c_identifier(name, callback=getattr(arg, "callback", None) is not None)
    return {"name": rendered_name, **attrs}



def _render_class_property(parent: ET.Element, field: ClassFieldSpec, *, project_ir: IRProject, owner_class: str) -> ET.Element:
    attrs = dict(field.attrs)
    callback = attrs.get("callback")
    field_attrs: dict[str, str] = {
        "name": c_identifier(field.name, callback=callback is not None),
    }
    if attrs.get("class") is not None:
        resolved_class = owner_class if attrs.get("class") == "self" else attrs.get("class")
        field_attrs.update({
            "type": class_type_symbol(project_ir, cast(str, resolved_class)),
            "type_is": "class",
            "accessed_by": "pointer" if attrs.get("is_reference") in {"1", "true"} else "value",
        })
    elif callback is not None:
        field_attrs.update({
            "type": callback_symbol(project_ir, callback_name_from_ref(callback)),
            "type_is": "callback",
            "accessed_by": "value",
        })
    else:
        rendered_type, kind = type_map(attrs.get("type"))
        field_attrs.update({
            "type": rendered_type,
            "type_is": kind,
            "accessed_by": "pointer" if attrs.get("is_reference") in {"1", "true"} else "value",
        })
        if attrs.get("type") == "byte" and attrs.get("access") != "readwrite":
            field_attrs["is_const_type"] = "1"
        if attrs.get("array") == "given" or attrs.get("_array") == "given":
            field_attrs["array"] = "given"
    prop = text_element(parent, "c_property", **field_attrs)
    if field.description:
        prop.text = comment_text(field.description)
    return prop



def _render_class_variable(parent: ET.Element, variable: object, *, project_ir: IRProject, owner_class: str) -> ET.Element:
    attrs = getattr(variable, "attrs")
    callback = attrs.get("callback")
    variable_attrs: dict[str, str] = {
        "name": c_identifier(getattr(variable, "name"), callback=callback is not None),
        "uid": f"c_class_{snake_name(owner_class)}_variable_{snake_name(getattr(variable, 'name'))}",
        "visibility": getattr(variable, "visibility", None) or "public",
        "declaration": getattr(variable, "declaration", None) or "private",
        "definition": getattr(variable, "definition", None) or "private",
    }
    if getattr(variable, "class_name", None) is not None:
        resolved_class = owner_class if getattr(variable, "class_name") == "self" else getattr(variable, "class_name")
        variable_attrs.update({"accessed_by": "value", "type": class_type_symbol(project_ir, cast(str, resolved_class)), "type_is": "class"})
    elif callback is not None:
        variable_attrs.update({"accessed_by": "value", "type": callback_symbol(project_ir, callback_name_from_ref(callback)), "type_is": "callback"})
    else:
        rendered_type, kind = type_map(getattr(variable, "type_name", None))
        variable_attrs.update({"accessed_by": "value", "type": rendered_type, "type_is": kind})
        if attrs.get("array") == "derived":
            variable_attrs["array"] = "derived"
        if getattr(variable, "type_name", None) == "byte" and attrs.get("access") != "readwrite":
            variable_attrs["is_const_type"] = "1"
    var_elem = text_element(parent, "c_variable", **{k: v for k, v in variable_attrs.items() if v is not None})
    if getattr(variable, "value", None) is not None:
        value = cast(dict[str, str], getattr(variable, "value"))
        text_element(var_elem, "c_value", value=value["value"], accessed_by="value", type=variable_attrs["type"], type_is=variable_attrs["type_is"])
    for modifier in ["VSC_PUBLIC"] if variable_attrs["visibility"] == "public" else []:
        text_element(var_elem, "c_modifier", value=modifier)
    if getattr(variable, "description", ""):
        var_elem.text = comment_text(getattr(variable, "description"))
    return var_elem



def _render_ctx_size_method(parent: ET.Element, *, project_ir: IRProject, cls: IRClass) -> ET.Element:
    method = text_element(
        parent,
        "c_method",
        name=_class_runtime_symbol(project_ir, cls, "ctx_size"),
        visibility="public",
        declaration="public",
        definition="private",
        uid=f"c_class_{snake_name(cls.name)}_method_ctx_size",
    )
    text_element(method, "c_argument", type="void", accessed_by="value")
    text_element(method, "c_return", accessed_by="value", type="size_t", type_is="primitive")
    text_element(method, "c_code", f"return sizeof({class_type_symbol(project_ir, cls.name)});", lang="c", type="generated")
    text_element(method, "c_modifier", value="VSC_PUBLIC")
    method.text = comment_text(f"Return size of '{class_type_symbol(project_ir, cls.name)}'.")
    return method



def _render_ir_method(
    parent: ET.Element,
    *,
    name: str,
    description: str,
    arguments: tuple[dict[str, str], ...],
    return_attrs: dict[str, str] | None,
    project_ir: IRProject,
    owner_class: str,
    visibility: str = "public",
    declaration: str = "public",
    definition: str = "external",
    modifiers: tuple[str, ...] = ("VSC_PUBLIC",),
    code: str | None = None,
    uid: str | None = None,
) -> ET.Element:
    resolved_definition = visibility if code is not None and definition == "external" else definition
    method = text_element(
        parent,
        "c_method",
        name=name,
        visibility=visibility,
        declaration=declaration,
        definition=resolved_definition,
        uid=uid or f"direct_{snake_name(owner_class)}_{snake_name(name)}",
    )
    if arguments:
        for argument in arguments:
            argument_from_source(method, argument, name=argument.get("name"), project_ir=project_ir, owner_class=owner_class)
    else:
        text_element(method, "c_argument", type="void", accessed_by="value")
    if return_attrs is None:
        text_element(method, "c_return", type="void", accessed_by="value")
    else:
        return_from_source(method, return_attrs, project_ir=project_ir, owner_class=owner_class)
    if code is not None:
        text_element(method, "c_code", code, type="generated", lang="c")
    for modifier in modifiers:
        text_element(method, "c_modifier", value=modifier)
    if description:
        method.text = comment_text(description)
    return method



def _render_reference_class_support(
    parent: ET.Element,
    *,
    project_ir: IRProject,
    cls: IRClass,
    overridden_method_names: set[str] | None = None,
) -> None:
    overridden_method_names = overridden_method_names or set()
    ctor_by_name = {ctor.name: ctor for ctor in cls.constructors}
    for name, description, arguments in [
        (
            _class_runtime_symbol(project_ir, cls, "init_ctx"),
            "Perform context specific initialization.\nNote, this method is called automatically when method init() is called.\nNote, that context is already zeroed.",
            ({"name": "self", "class": "self"},),
        ),
        (
            _class_runtime_symbol(project_ir, cls, "cleanup_ctx"),
            "Release all inner resources.\nNote, this method is called automatically once when class is completely cleaning up.\nNote, that context will be zeroed automatically next this method.",
            ({"name": "self", "class": "self"},),
        ),
    ]:
        _render_ir_method(
            parent,
            name=name,
            description=description,
            arguments=arguments,
            return_attrs={"type": "void"},
            project_ir=project_ir,
            owner_class=cls.name,
            visibility="private",
            declaration="private",
            definition="external",
            modifiers=("static",),
            uid=f"direct_{snake_name(cls.name)}_private_{snake_name(name)}",
        )

    for ctor in cls.constructors:
        ctor_args = ({"name": "self", "class": "self"}, *tuple(_method_arg_dict(arg) for arg in ctor.arguments))
        _render_ir_method(
            parent,
            name=_class_runtime_symbol(project_ir, cls, f"init_ctx_with_{_reference_ctor_suffix(ctor.name)}"),
            description=ctor_by_name[ctor.name].description,
            arguments=ctor_args,
            return_attrs={"type": "void"},
            project_ir=project_ir,
            owner_class=cls.name,
            visibility="private",
            declaration="private",
            definition="external",
            modifiers=("static",),
            uid=f"direct_{snake_name(cls.name)}_private_init_ctx_with_{_reference_ctor_suffix(ctor.name)}",
        )

    for name, description, arguments, return_attrs in [
        (_class_runtime_symbol(project_ir, cls, "init"), "Perform initialization of pre-allocated context.", ({"name": "self", "class": "self"},), {"type": "void"}),
        (_class_runtime_symbol(project_ir, cls, "cleanup"), "Release all inner resources including class dependencies.", ({"name": "self", "class": "self"},), {"type": "void"}),
        (_class_runtime_symbol(project_ir, cls, "new"), "Allocate context and perform it's initialization.", (), {"class": "self"}),
        (_class_runtime_symbol(project_ir, cls, "delete"), "Release all inner resources and deallocate context if needed.\nIt is safe to call this method even if the context was statically allocated.", ({"name": "self", "class": "self"},), {"type": "void"}),
        (_class_runtime_symbol(project_ir, cls, "destroy"), "Delete given context and nullifies reference.\nThis is a reverse action of the function 'new ()'.", ({"name": "self_ref", "class": "self", "access": "readwrite", "passed_by": "reference"},), {"type": "void"}),
        (_class_runtime_symbol(project_ir, cls, "shallow_copy"), "Copy given class context by increasing reference counter.", ({"name": "self", "class": "self"},), {"class": "self"}),
    ]:
        if name not in overridden_method_names:
            _render_ir_method(parent, name=name, description=description, arguments=arguments, return_attrs=return_attrs, project_ir=project_ir, owner_class=cls.name)

    for ctor in cls.constructors:
        args = tuple(_method_arg_dict(arg) for arg in ctor.arguments)
        init_name = class_constructor_symbol(project_ir, cls, ctor.name)
        new_name = _class_new_constructor_symbol(project_ir, cls, ctor.name)
        if init_name not in overridden_method_names:
            _render_ir_method(
                parent,
                name=init_name,
                description=f"Perform initialization of pre-allocated context.\n{ctor.description}",
                arguments=({"name": "self", "class": "self"}, *args),
                return_attrs={"type": "void"},
                project_ir=project_ir,
                owner_class=cls.name,
                uid=f"direct_{snake_name(cls.name)}_init_with_{snake_name(ctor.name)}",
            )
        if new_name not in overridden_method_names:
            _render_ir_method(
                parent,
                name=new_name,
                description=f"Allocate class context and perform it's initialization.\n{ctor.description}",
                arguments=args,
                return_attrs={"class": "self"},
                project_ir=project_ir,
                owner_class=cls.name,
                uid=f"direct_{snake_name(cls.name)}_new_with_{snake_name(ctor.name)}",
            )



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
    if attrs.get("class") is not None:
        resolved_class = owner_class if attrs.get("class") == "self" else attrs.get("class", owner_class)
        type_name = class_type_symbol(project_ir, cast(str, resolved_class)) if project_ir is not None else "vsc_data_t"
        accessed_by = "value"
        if attrs.get("class") == "self" and attrs.get("passed_by") == "reference":
            accessed_by = "reference"
        elif attrs.get("class") == "self" and project_ir is not None and class_ir(project_ir, owner_class).attrs.get("is_value_type") not in {"1", "true"}:
            accessed_by = "pointer"
        extra = {"is_const_type": "1"} if attrs.get("access") == "readonly" else {}
        return text_element(parent, "c_argument", name=arg_name, accessed_by=accessed_by, type=type_name, type_is="class", **extra)
    if attrs.get("callback") is not None:
        callback_type = callback_symbol(project_ir, callback_name_from_ref(attrs.get("callback"))) if project_ir is not None else "vsc_dealloc_fn"
        return text_element(parent, "c_argument", name=c_identifier(arg_name, callback=True), accessed_by="value", type=callback_type, type_is="callback")
    if attrs.get("type") == "string":
        return text_element(
            parent,
            "c_argument",
            name=arg_name,
            accessed_by="value",
            type="char",
            type_is="primitive",
            string="given",
            is_const_type="1",
        )
    rendered_type, kind = type_map(attrs.get("type"))
    extra = {}
    if attrs.get("type") == "byte" and attrs.get("_array") == "given":
        extra["array"] = "given"
        extra["is_const_type"] = "1"
    elif attrs.get("type") == "byte" and attrs.get("is_reference") in {"1", "true"} and attrs.get("access") != "readwrite":
        extra["is_const_type"] = "1"
    accessed_by = "pointer" if attrs.get("is_reference") in {"1", "true"} else "value"
    return text_element(parent, "c_argument", name=arg_name, accessed_by=accessed_by, type=rendered_type, type_is=kind, **extra)



def return_from_source(
    parent: ET.Element,
    attrs: dict,
    *,
    project_ir: IRProject | None = None,
    owner_class: str = "data",
) -> ET.Element:
    if attrs.get("class") is not None:
        resolved_class = owner_class if attrs.get("class") == "self" else attrs.get("class", owner_class)
        type_name = class_type_symbol(project_ir, cast(str, resolved_class)) if project_ir is not None else "vsc_data_t"
        accessed_by = "value"
        if attrs.get("class") == "self" and project_ir is not None and class_ir(project_ir, owner_class).attrs.get("is_value_type") not in {"1", "true"}:
            accessed_by = "pointer"
        return text_element(parent, "c_return", accessed_by=accessed_by, type=type_name, type_is="class")
    if attrs.get("type") == "byte" and attrs.get("is_reference") in {"1", "true"}:
        extra = {"is_const_type": "1"} if attrs.get("access") != "readwrite" else {}
        return text_element(parent, "c_return", accessed_by="pointer", type="byte", type_is="primitive", **extra)
    rendered_type, kind = type_map(attrs.get("type"))
    return text_element(parent, "c_return", accessed_by="value", type=rendered_type, type_is=kind)
