from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import re
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


_PLACEHOLDER_RE = re.compile(r"\.\(([^)]+)\)")


def _module_member_owner(module: IRModule, attrs: dict[str, str], *, kind: str) -> str:
    if kind == "variable":
        return f"class_{snake_name(module.name)}"
    owner = attrs.get("of_class")
    if owner == "global":
        return "global"
    if owner:
        return f"class_{snake_name(owner)}"
    if module.attrs.get("of_class") == "global":
        return "global"
    return f"class_{snake_name(module.name)}"


def _module_method_symbol(project_ir: IRProject, module: IRModule, method: object) -> str:
    attrs = getattr(method, "attrs")
    owner = attrs.get("of_class")
    base = project_ir.prefix if owner == "global" or (owner is None and module.attrs.get("of_class") == "global") else module.output.c_symbol
    if owner and owner != "global":
        base = f"{project_ir.prefix}_{snake_name(owner)}"
    return f"{base}_{snake_name(getattr(method, 'name'))}"


def _module_macro_symbol(project_ir: IRProject, module: IRModule, macro: object) -> str:
    return _module_method_symbol(project_ir, module, macro).upper()


def _module_callback_symbol(project_ir: IRProject, module: IRModule, callback: object) -> str:
    attrs = getattr(callback, "attrs")
    if attrs.get("of_class") == "global" or (attrs.get("of_class") is None and module.attrs.get("of_class") == "global"):
        return callback_symbol(project_ir, getattr(callback, "name"))
    return callback_symbol(project_ir, getattr(callback, "name"), module_name=module.name)


def _module_constant_symbol(project_ir: IRProject, module: IRModule, constant: object) -> str:
    owner = getattr(constant, "attrs", {}).get("of_class")
    base = project_ir.prefix if owner == "global" or (owner is None and module.attrs.get("of_class") == "global") else module.output.c_symbol
    if owner and owner != "global":
        base = f"{project_ir.prefix}_{snake_name(owner)}"
    return f"{base}_{snake_name(getattr(constant, 'name')).upper()}".upper()


def _module_member_uid(module: IRModule, attrs: dict[str, str], *, kind: str, name: str) -> str:
    return f"c_{_module_member_owner(module, attrs, kind=kind)}_{kind}_{snake_name(name)}"


def _module_placeholder_map(project_ir: IRProject) -> dict[str, str]:
    placeholders = {
        f"project_version_{part}": (project_ir.version or {}).get(part, "0")
        for part in ("major", "minor", "patch")
    }
    for module in project_ir.resolved_modules:
        placeholders[f"module_{snake_name(module.name)}"] = cast(IROutputTarget, module.output).c_symbol
        for alias in module.aliases:
            placeholders[_module_member_uid(module, alias.attrs, kind="alias", name=alias.name)] = alias.attrs.get("name", alias.name)
        for constant in module.constants:
            placeholders[_module_member_uid(module, constant.attrs, kind="constant", name=constant.name)] = _module_constant_symbol(project_ir, module, constant)
        for callback in module.callbacks:
            token = _module_member_uid(module, callback.attrs, kind="callback", name=callback.name)
            placeholders[token] = _module_callback_symbol(project_ir, module, callback)
            placeholders[token.removeprefix("c_")] = placeholders[token]
        for variable in module.variables:
            token = _module_member_uid(module, variable.attrs, kind="variable", name=variable.name)
            placeholders[token] = c_identifier(variable.name, callback=variable.callback is not None)
        for method in module.methods:
            token = _module_member_uid(module, method.attrs, kind="method", name=method.name)
            placeholders[token] = _module_method_symbol(project_ir, module, method)
            placeholders[token.removeprefix("c_")] = placeholders[token]
        for macro in [*module.macros, *module.macro_groups]:
            token = _module_member_uid(module, macro.attrs, kind="macros", name=macro.name)
            placeholders[token] = _module_macro_symbol(project_ir, module, macro)
            placeholders[token.removeprefix("c_")] = placeholders[token]
        for group in module.macro_groups:
            for member in group.members:
                token = _module_member_uid(module, member.attrs, kind="macros", name=member.name)
                placeholders[token] = _module_macro_symbol(project_ir, module, type("MacroRef", (), {"name": member.name, "attrs": member.attrs})())
                placeholders[token.removeprefix("c_")] = placeholders[token]
    return placeholders


def _resolve_module_placeholders(text: str | None, placeholders: dict[str, str], *, project_prefix: str, args: tuple[object, ...] = ()) -> str | None:
    if text is None:
        return None
    arg_map = {
        f"_argument_{snake_name(getattr(arg, 'name', '') if not isinstance(arg, dict) else arg.get('name', ''))}": c_identifier(
            getattr(arg, 'name', '') if not isinstance(arg, dict) else arg.get('name', ''),
            callback=(getattr(arg, 'callback', None) if not isinstance(arg, dict) else arg.get('callback')) is not None,
        )
        for arg in args
        if (getattr(arg, 'name', '') if not isinstance(arg, dict) else arg.get('name'))
    }

    def repl(match: re.Match[str]) -> str:
        token = match.group(1)
        if token in arg_map:
            return arg_map[token]
        if token in placeholders:
            return placeholders[token]
        if token.startswith("c_global_macros_"):
            return f"{project_prefix.upper()}_{token.removeprefix('c_global_macros_').upper()}"
        raise ValueError(f"unresolved module placeholder: {token}")

    return _PLACEHOLDER_RE.sub(repl, text)


def _module_callback_name_from_ref(project_ir: IRProject, module: IRModule, callback_ref: str | None) -> str:
    callback_name = callback_name_from_ref(callback_ref)
    if callback_ref and "global_callback_" in callback_ref:
        return callback_symbol(project_ir, callback_name)
    return callback_symbol(project_ir, callback_name, module_name=module.name)


def _module_argument_from_source(parent: ET.Element, src: dict[str, str], *, project_ir: IRProject, module: IRModule) -> ET.Element:
    attrs = dict(src)
    if attrs.get("callback") is not None:
        return text_element(
            parent,
            "c_argument",
            name=c_identifier(attrs.get("name", ""), callback=True),
            accessed_by="value",
            type=_module_callback_name_from_ref(project_ir, module, attrs.get("callback")),
            type_is="callback",
        )
    if attrs.get("class") == "any":
        return text_element(
            parent,
            "c_argument",
            name=attrs.get("name", ""),
            accessed_by="pointer",
            type="void",
            type_is="any",
        )
    return argument_from_source(parent, attrs, name=attrs.get("name"), project_ir=project_ir, owner_class="data")


def _module_return_from_source(parent: ET.Element, src: dict[str, str], *, project_ir: IRProject, module: IRModule) -> ET.Element:
    attrs = dict(src)
    if attrs.get("callback") is not None:
        return text_element(
            parent,
            "c_return",
            accessed_by="value",
            type=_module_callback_name_from_ref(project_ir, module, attrs.get("callback")),
            type_is="callback",
        )
    if attrs.get("class") == "any":
        return text_element(parent, "c_return", accessed_by="pointer", type="void", type_is="any")
    return return_from_source(parent, attrs, project_ir=project_ir, owner_class="data")


def render_module_c_module(project_ir: IRProject, module: IRModule) -> ET.Element:
    output = cast(IROutputTarget, module.output)
    placeholders = _module_placeholder_map(project_ir)
    root = c_module_root(output, entity_id=snake_name(module.name), scope=module.attrs.get("scope", "public"))
    root.set("has_cmakedefine", module.attrs.get("has_cmakedefine", "0"))

    text_element(root, "c_include", file=output.include_file, is_system="0", scope="private")
    for include in module.c_includes:
        include_attrs = dict(include.attrs)
        include_attrs["file"] = _resolve_module_placeholders(include_attrs.get("file") or include.name, placeholders, project_prefix=project_ir.prefix) or ""
        if "if" in include_attrs:
            include_attrs["if"] = _resolve_module_placeholders(include_attrs["if"], placeholders, project_prefix=project_ir.prefix) or ""
        include_attrs.setdefault("scope", "public")
        text_element(root, "c_include", **include_attrs)
    for require in module.requires:
        text_element(
            root,
            "c_include",
            file=include_file_for_entity(project_ir, entity_kind="module", entity_name=require.name),
            is_system="0",
            scope=require.attrs.get("scope", "public"),
        )

    for alias in module.aliases:
        alias_elem = text_element(root, "c_alias", name=alias.name, type=alias.attrs.get("type", "void"), declaration=alias.attrs.get("declaration", "public"))
        if alias.description:
            alias_elem.text = comment_text(alias.description)

    if module.constants:
        enum_elem = text_element(root, "c_enum", declaration="public", definition="public")
        if module.constants[0].description:
            enum_elem.text = comment_text("Public integral constants.")
        for constant in module.constants:
            const_elem = text_element(
                enum_elem,
                "c_constant",
                name=_module_constant_symbol(project_ir, module, constant),
                value=_resolve_module_placeholders(constant.attrs.get("value"), placeholders, project_prefix=project_ir.prefix) or "",
                definition=constant.attrs.get("definition", "public"),
                uid=_module_member_uid(module, constant.attrs, kind="constant", name=constant.name),
            )
            if constant.description:
                const_elem.text = comment_text(constant.description)

    for callback in module.callbacks:
        callback_elem = text_element(
            root,
            "c_callback",
            name=_module_callback_symbol(project_ir, module, callback),
            uid=_module_member_uid(module, callback.attrs, kind="callback", name=callback.name),
            declaration=callback.declaration or callback.attrs.get("declaration", "public"),
        )
        for argument in callback.arguments:
            _module_argument_from_source(callback_elem, _method_arg_dict(argument), project_ir=project_ir, module=module)
        if callback.returns:
            _module_return_from_source(callback_elem, _method_arg_dict(callback.returns[0]), project_ir=project_ir, module=module)
        else:
            text_element(callback_elem, "c_return", type="void", accessed_by="value")
        if callback.attrs.get("noreturn") in {"1", "true"}:
            text_element(callback_elem, "c_modifier", value="VSC_NORETURN")
        if callback.description:
            callback_elem.text = comment_text(callback.description)

    for variable in module.variables:
        callback_ref = variable.callback
        variable_attrs: dict[str, str] = {
            "name": c_identifier(variable.name, callback=callback_ref is not None),
            "uid": _module_member_uid(module, variable.attrs, kind="variable", name=variable.name),
            "visibility": variable.visibility or "public",
            "declaration": variable.declaration or "private",
            "definition": variable.definition or "private",
        }
        if callback_ref is not None:
            variable_attrs.update({"accessed_by": "value", "type": _module_callback_name_from_ref(project_ir, module, callback_ref), "type_is": "callback"})
        elif variable.class_name is not None:
            resolved_class = variable.class_name
            variable_attrs.update({"accessed_by": "value", "type": class_type_symbol(project_ir, resolved_class), "type_is": "class"})
        else:
            rendered_type, kind = type_map(variable.type_name)
            variable_attrs.update({"accessed_by": "value", "type": rendered_type, "type_is": kind})
            if variable.attrs.get("array") == "derived":
                variable_attrs["array"] = "derived"
            if variable.type_name == "byte" and variable.access != "readwrite":
                variable_attrs["is_const_type"] = "1"
        variable_elem = text_element(root, "c_variable", **variable_attrs)
        if variable.value is not None:
            text_element(
                variable_elem,
                "c_value",
                value=_resolve_module_placeholders(variable.value.get("value"), placeholders, project_prefix=project_ir.prefix) or "",
                accessed_by="value",
                type=variable_attrs["type"],
                type_is=variable_attrs["type_is"],
            )
        if variable_attrs["visibility"] == "public":
            text_element(variable_elem, "c_modifier", value="VSC_PUBLIC")
        if variable.description:
            variable_elem.text = comment_text(variable.description)

    for macro in module.macros:
        macro_elem = text_element(
            root,
            "c_macros",
            name=_module_macro_symbol(project_ir, module, macro),
            uid=_module_member_uid(module, macro.attrs, kind="macros", name=macro.name),
            definition=macro.definition or macro.attrs.get("definition", "public"),
            is_method=macro.attrs.get("is_method", "0"),
        )
        code = _resolve_module_placeholders(macro.code_blocks[0]["text"] if macro.code_blocks else None, placeholders, project_prefix=project_ir.prefix)
        if code is not None:
            text_element(macro_elem, "c_code", code, lang="c", type="generated")
        if macro.description:
            macro_elem.text = comment_text(macro.description)

    for group in module.macro_groups:
        group_elem = text_element(root, "c_macroses", definition=group.definition or group.attrs.get("definition", "public"))
        for nested in group.members:
            text_element(
                group_elem,
                "c_macros",
                name=_module_macro_symbol(project_ir, module, type("MacroRef", (), {"name": nested.name, "attrs": nested.attrs})()),
                uid=_module_member_uid(module, nested.attrs, kind="macros", name=nested.name),
                definition=group.definition or group.attrs.get("definition", "public"),
                is_method=nested.attrs.get("is_method", "0"),
            )
        code = _resolve_module_placeholders(group.code_blocks[0]["text"] if group.code_blocks else None, placeholders, project_prefix=project_ir.prefix)
        if code is not None:
            text_element(group_elem, "c_code", code, lang="c", type="generated")
        if group.description:
            group_elem.text = comment_text(group.description)

    for method in module.methods:
        code = _resolve_module_placeholders(method.code_blocks[0]["text"] if method.code_blocks else None, placeholders, project_prefix=project_ir.prefix, args=tuple(method.arguments))
        visibility = method.visibility or method.attrs.get("visibility", "public")
        declaration = method.declaration or method.attrs.get("declaration", "public")
        definition = method.definition or method.attrs.get("definition", ("private" if code is not None else "external"))
        method_elem = text_element(
            root,
            "c_method",
            name=_module_method_symbol(project_ir, module, method),
            visibility=visibility,
            declaration=declaration,
            definition=definition,
            uid=_module_member_uid(module, method.attrs, kind="method", name=method.name),
        )
        if method.arguments:
            for argument in method.arguments:
                _module_argument_from_source(method_elem, _method_arg_dict(argument), project_ir=project_ir, module=module)
        else:
            text_element(method_elem, "c_argument", type="void", accessed_by="value")
        if method.returns:
            _module_return_from_source(method_elem, _method_arg_dict(method.returns[0]), project_ir=project_ir, module=module)
        else:
            text_element(method_elem, "c_return", type="void", accessed_by="value")
        if code is not None:
            text_element(method_elem, "c_code", code, type="generated", lang="c")
        if visibility == "public":
            text_element(method_elem, "c_modifier", value="VSC_PUBLIC")
        elif visibility == "private":
            text_element(method_elem, "c_modifier", value="static")
        if method.attrs.get("noreturn") in {"1", "true"}:
            text_element(method_elem, "c_modifier", value="VSC_NORETURN")
        if method.description:
            method_elem.text = comment_text(method.description)

    for code_block in module.code_blocks:
        attrs = {key: (_resolve_module_placeholders(value, placeholders, project_prefix=project_ir.prefix) or "") for key, value in code_block["attrs"].items()}
        text_element(root, "c_code", _resolve_module_placeholders(code_block["text"], placeholders, project_prefix=project_ir.prefix), **attrs)

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
