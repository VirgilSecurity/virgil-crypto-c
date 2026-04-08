from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
import re
from typing import cast
import xml.etree.ElementTree as ET

from tools.codegen.project_ir import IRClass, IRCStructField, IRDependency, IREnum, IRImplementation, IRInterface, IRModule, IRProject, IROutputTarget


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



def interface_ir(project_ir: IRProject, name: str) -> IRInterface:
    try:
        return next(iface for iface in project_ir.interfaces if iface.name == name)
    except StopIteration as exc:
        raise KeyError(f"interface not found in IR: {name}") from exc



def implementation_ir(project_ir: IRProject, name: str) -> IRImplementation:
    try:
        return next(impl for impl in project_ir.implementations if impl.name == name)
    except StopIteration as exc:
        raise KeyError(f"implementation not found in IR: {name}") from exc



def entity_output(project_ir: IRProject, *, entity_kind: str, entity_name: str) -> IROutputTarget:
    if entity_kind == "module":
        return cast(IROutputTarget, module_ir(project_ir, entity_name).output)
    if entity_kind == "class":
        return cast(IROutputTarget, class_ir(project_ir, entity_name).output)
    if entity_kind == "enum":
        return cast(IROutputTarget, enum_ir(project_ir, entity_name).output)
    if entity_kind == "interface":
        return cast(IROutputTarget, interface_ir(project_ir, entity_name).output)
    if entity_kind == "implementation":
        return cast(IROutputTarget, implementation_ir(project_ir, entity_name).output)
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



def interface_api_output(iface_output: IROutputTarget) -> IROutputTarget:
    """Derive the API module output target from an interface's output target.

    The API module lives under the ``private`` include directory and uses
    the ``<prefix>_<iface>_api`` stem convention.
    """
    stem = f"{iface_output.c_symbol}_api"
    header_path = iface_output.header_path.replace(
        f"/{iface_output.include_file}",
        f"/private/{stem}.h",
    )
    source_path = iface_output.source_path.replace(iface_output.source_file, f"{stem}.c")
    generated_header_path = iface_output.generated_header_path.replace(
        iface_output.include_file.removesuffix(".h"),
        stem,
    )
    generated_source_path = iface_output.generated_source_path.replace(
        Path(iface_output.generated_source_path).stem,
        f"interface_{snake_name(iface_output.entity_name)}_api",
    )
    return IROutputTarget(
        entity_kind="module",
        entity_name=f"{iface_output.entity_name} api",
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
        header_visibility="private",
        source_visibility="public",
    )



def implementation_defs_output(impl_output: IROutputTarget) -> IROutputTarget:
    """Derive the defs module output target from an implementation's output target.

    The defs module lives under the ``private`` include directory and uses
    the ``<prefix>_<impl>_defs`` stem convention.
    """
    stem = f"{impl_output.c_symbol}_defs"
    header_path = impl_output.header_path.replace(
        f"/{impl_output.include_file}",
        f"/private/{stem}.h",
    )
    source_path = impl_output.source_path.replace(impl_output.source_file, f"{stem}.c")
    generated_header_path = impl_output.generated_header_path.replace(
        impl_output.include_file.removesuffix(".h"),
        stem,
    )
    generated_source_path = impl_output.generated_source_path.replace(
        Path(impl_output.generated_source_path).stem,
        f"implementation_{snake_name(impl_output.entity_name)}_defs",
    )
    return IROutputTarget(
        entity_kind="module",
        entity_name=f"{impl_output.entity_name} defs",
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
        header_visibility="private",
        source_visibility="public",
    )



def implementation_internal_output(impl_output: IROutputTarget) -> IROutputTarget:
    """Derive the internal module output target from an implementation's output target.

    The internal module lives under the ``private`` include directory and uses
    the ``<prefix>_<impl>_internal`` stem convention.
    """
    stem = f"{impl_output.c_symbol}_internal"
    header_path = impl_output.header_path.replace(
        f"/{impl_output.include_file}",
        f"/private/{stem}.h",
    )
    source_path = impl_output.source_path.replace(impl_output.source_file, f"{stem}.c")
    generated_header_path = impl_output.generated_header_path.replace(
        impl_output.include_file.removesuffix(".h"),
        stem,
    )
    generated_source_path = impl_output.generated_source_path.replace(
        Path(impl_output.generated_source_path).stem,
        f"implementation_{snake_name(impl_output.entity_name)}_internal",
    )
    return IROutputTarget(
        entity_kind="module",
        entity_name=f"{impl_output.entity_name} internal",
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
        header_visibility="private",
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



def discover_renderers(
    project_ir: IRProject,
    *,
    entity_kinds: set[str] | None = None,
    custom_overrides: dict[str, DirectCRenderer] | None = None,
) -> dict[str, DirectCRenderer]:
    """Walk the project IR and build a complete renderer map for all renderable entities.

    Parameters
    ----------
    project_ir:
        The fully-resolved project IR.
    entity_kinds:
        Optional filter.  When provided only entities whose kind is in the set
        are included (e.g. ``{"enum"}`` or ``{"module", "class"}``).
        When *None* (the default) all supported kinds are discovered.
    custom_overrides:
        A ``{xml_name: renderer}`` dict of custom renderers that replace the
        default IR-driven renderer for the corresponding output file.
    """
    overrides = custom_overrides or {}
    renderers: dict[str, DirectCRenderer] = {}
    include_all = entity_kinds is None

    if include_all or "enum" in entity_kinds:  # type: ignore[operator]
        for enum in project_ir.enums:
            xml_name = direct_xml_name(cast(IROutputTarget, enum.output))
            if xml_name in overrides:
                renderers[xml_name] = overrides[xml_name]
            else:
                renderers[xml_name] = (
                    lambda _repo_root, _pir=project_ir, _e=enum: render_enum_c_module(_pir, _e)
                )

    if include_all or "module" in entity_kinds:  # type: ignore[operator]
        for module in project_ir.modules:
            xml_name = direct_xml_name(cast(IROutputTarget, module.output))
            if xml_name in overrides:
                renderers[xml_name] = overrides[xml_name]
            else:
                renderers[xml_name] = (
                    lambda _repo_root, _pir=project_ir, _m=module: render_module_c_module(_pir, _m)
                )

    if include_all or "class" in entity_kinds:  # type: ignore[operator]
        for cls in project_ir.classes:
            xml_name = direct_xml_name(cast(IROutputTarget, cls.output))
            if xml_name in overrides:
                renderers[xml_name] = overrides[xml_name]
            else:
                renderers[xml_name] = (
                    lambda _repo_root, _pir=project_ir, _c=cls: render_class_c_module(_pir, _c)
                )

    # Include any overrides whose keys don't correspond to an IR entity
    # (e.g. derived outputs like buffer_defs).
    for xml_name, renderer in overrides.items():
        if xml_name not in renderers:
            renderers[xml_name] = renderer

    return renderers


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


# ---------------------------------------------------------------------------
#   Interface rendering
# ---------------------------------------------------------------------------

def _interface_callback_symbol(iface_output: IROutputTarget, method_name: str) -> str:
    """Return the callback typedef symbol: ``<prefix>_<iface>_api_<method>_fn``."""
    return f"{iface_output.c_symbol}_api_{snake_name(method_name)}_fn"


def _interface_api_struct_symbol(iface_output: IROutputTarget) -> str:
    """Return the API struct type name: ``<prefix>_<iface>_api_t``."""
    return f"{iface_output.c_symbol}_api_t"


def _interface_callback_return(
    parent: ET.Element,
    ret: object,
    *,
    project_ir: IRProject,
) -> ET.Element:
    """Render a return element inside a callback typedef."""
    attrs = _method_arg_dict(ret)
    if attrs.get("enum") is not None:
        enum_name = attrs["enum"]
        enum_out = entity_output(project_ir, entity_kind="enum", entity_name=enum_name)
        return text_element(parent, "c_return", accessed_by="value", type=enum_type_name(enum_out), type_is="enum")
    return return_from_source(parent, attrs, project_ir=project_ir, owner_class="data")


def _add_interface_type_includes(root: ET.Element, iface: IRInterface, *, project_ir: IRProject) -> None:
    """Add c_include elements for types used in interface method arguments/returns."""
    included: set[str] = set()
    for method in iface.methods:
        for arg in method.arguments:
            cls = arg.class_name
            if cls is not None and cls not in included:
                try:
                    inc = include_file_for_entity(project_ir, entity_kind="class", entity_name=cls)
                    text_element(root, "c_include", file=inc, is_system="0", scope="public")
                    included.add(cls)
                except KeyError:
                    pass
        for ret in method.returns:
            cls = ret.class_name
            if cls is not None and cls not in included:
                try:
                    inc = include_file_for_entity(project_ir, entity_kind="class", entity_name=cls)
                    text_element(root, "c_include", file=inc, is_system="0", scope="public")
                    included.add(cls)
                except KeyError:
                    pass
            attrs_dict = _method_arg_dict(ret)
            if attrs_dict.get("enum") is not None:
                ename = attrs_dict["enum"]
                if ename not in included:
                    try:
                        inc = include_file_for_entity(project_ir, entity_kind="enum", entity_name=ename)
                        text_element(root, "c_include", file=inc, is_system="0", scope="public")
                        included.add(ename)
                    except KeyError:
                        pass


def _resolve_class_type_symbol(project_ir: IRProject, class_name: str, *, fallback_projects: list[IRProject] | None = None) -> str:
    """Resolve a class type symbol, trying the primary project then fallbacks."""
    try:
        return class_type_symbol(project_ir, class_name)
    except KeyError:
        if fallback_projects:
            for fp in fallback_projects:
                try:
                    return class_type_symbol(fp, class_name)
                except KeyError:
                    continue
        raise


def _interface_argument_from_source(
    parent: ET.Element,
    src: dict,
    *,
    project_ir: IRProject,
    fallback_projects: list[IRProject] | None = None,
) -> ET.Element:
    """Render an argument for an interface callback, handling cross-project classes."""
    cls_name = src.get("class")
    if cls_name is not None:
        try:
            type_symbol = _resolve_class_type_symbol(project_ir, cls_name, fallback_projects=fallback_projects)
        except KeyError:
            type_symbol = f"{project_ir.prefix}_{snake_name(cls_name)}_t"
        accessed_by = "value"
        extra: dict[str, str] = {}
        if src.get("access") == "readonly":
            extra["is_const_type"] = "1"
        return text_element(parent, "c_argument", name=src.get("name", ""), accessed_by=accessed_by, type=type_symbol, type_is="class", **extra)
    # For non-class arguments, delegate to argument_from_source
    return argument_from_source(parent, src, name=src.get("name"), project_ir=project_ir, owner_class="data")


def render_interface_api_c_module(
    project_ir: IRProject,
    iface: IRInterface,
    *,
    fallback_projects: list[IRProject] | None = None,
) -> ET.Element:
    """Render the private API module for an interface.

    Produces:
    - Callback typedefs for each interface method
    - API struct with api_tag, impl_tag, inherited API pointers, callback fields, constant fields
    """
    iface_output = cast(IROutputTarget, iface.output)
    api_output = interface_api_output(iface_output)

    root = c_module_root(
        api_output,
        entity_id=f"{snake_name(iface.name)}_api",
        scope="private",
        class_name=f"{iface_output.c_symbol}_api",
    )

    # --- includes ---
    text_element(root, "c_include", file=f"{project_ir.prefix}_library.h", is_system="0", scope="public")
    text_element(root, "c_include", file=f"{project_ir.prefix}_api.h", is_system="0", scope="public")
    text_element(root, "c_include", file=f"{project_ir.prefix}_impl.h", is_system="0", scope="public")

    for inherited_name in iface.inherits:
        inherited_output = entity_output(project_ir, entity_kind="interface", entity_name=inherited_name)
        text_element(root, "c_include", file=inherited_output.include_file, is_system="0", scope="public")

    _add_interface_type_includes(root, iface, project_ir=project_ir)

    # --- callback typedefs ---
    for method in iface.methods:
        is_static = method.attrs.get("is_static") in {"1", "true"}
        is_const = method.attrs.get("is_const") in {"1", "true"}
        cb_name = _interface_callback_symbol(iface_output, method.name)

        cb_elem = text_element(
            root,
            "c_callback",
            name=cb_name,
            declaration="public",
        )
        desc = method.description.strip() if method.description else ""
        if desc:
            cb_elem.text = comment_text(f"Callback. {desc}")

        # Non-static methods get impl as first arg
        if not is_static:
            impl_type = f"{project_ir.prefix}_impl_t"
            if is_const:
                text_element(cb_elem, "c_argument", name="impl", accessed_by="pointer", type=impl_type, type_is="class", is_const_type="1")
            else:
                text_element(cb_elem, "c_argument", name="impl", accessed_by="pointer", type=impl_type, type_is="class")

        for arg in method.arguments:
            _interface_argument_from_source(cb_elem, _method_arg_dict(arg), project_ir=project_ir, fallback_projects=fallback_projects)

        if method.returns:
            _interface_callback_return(cb_elem, method.returns[0], project_ir=project_ir)
        else:
            text_element(cb_elem, "c_return", type="void", accessed_by="value")

    # --- API struct ---
    api_struct_name = _interface_api_struct_symbol(iface_output)
    struct_elem = text_element(
        root,
        "c_struct",
        name=api_struct_name,
        declaration="public",
        definition="external",
    )
    struct_elem.text = comment_text(f"Contains API requirements of the interface '{iface.name}'.")

    # api_tag field
    text_element(
        struct_elem, "c_property",
        name="api_tag",
        type=f"{project_ir.prefix}_api_tag_t",
        type_is="enum",
        accessed_by="value",
    ).text = comment_text(
        f"API's unique identifier, MUST be first in the structure.\n"
        f"For interface '{iface.name}' MUST be equal to the "
        f"'{project_ir.prefix}_api_tag_{snake_name(iface.name).upper()}'."
    )

    # impl_tag field
    text_element(
        struct_elem, "c_property",
        name="impl_tag",
        type=f"{project_ir.prefix}_impl_tag_t",
        type_is="enum",
        accessed_by="value",
    ).text = comment_text("Implementation unique identifier, MUST be second in the structure.")

    # Inherited API pointer fields
    for inherited_name in iface.inherits:
        inherited_output = entity_output(project_ir, entity_kind="interface", entity_name=inherited_name)
        inherited_api_type = _interface_api_struct_symbol(inherited_output)
        field_name = f"{snake_name(inherited_name)}_api"
        prop = text_element(
            struct_elem, "c_property",
            name=field_name,
            type=inherited_api_type,
            type_is="class",
            accessed_by="pointer",
            is_const_type="1",
        )
        prop.text = comment_text(f"Link to the inherited interface API '{inherited_name}'.")

    # Method callback pointer fields
    for method in iface.methods:
        cb_type = _interface_callback_symbol(iface_output, method.name)
        field_name = f"{snake_name(method.name)}_cb"
        prop = text_element(
            struct_elem, "c_property",
            name=field_name,
            type=cb_type,
            type_is="callback",
            accessed_by="value",
        )
        desc = method.description.strip() if method.description else ""
        if desc:
            prop.text = comment_text(desc)

    # Constant fields
    for constant in iface.constants:
        const_type = constant.attrs.get("type", "size")
        rendered_type, type_is = type_map(const_type)
        field_name = snake_name(constant.name)
        prop = text_element(
            struct_elem, "c_property",
            name=field_name,
            type=rendered_type,
            type_is=type_is,
            accessed_by="value",
        )
        desc = constant.description.strip() if constant.description else ""
        if desc:
            prop.text = comment_text(desc)

    return root



def render_interface_c_module(
    project_ir: IRProject,
    iface: IRInterface,
    *,
    fallback_projects: list[IRProject] | None = None,
) -> ET.Element:
    """Render the public dispatch module for an interface.

    Produces:
    - Forward declaration of API struct
    - Dispatch methods (stateful and static) calling through the vtable
    - Constant getter methods
    - Utility methods: _api(), _is_implemented(), _api_tag()
    - Inherited API getter methods
    """
    iface_output = cast(IROutputTarget, iface.output)
    api_output = interface_api_output(iface_output)
    prefix = project_ir.prefix
    api_struct_name = _interface_api_struct_symbol(iface_output)
    api_var_name = f"{snake_name(iface.name)}_api"

    root = c_module_root(
        iface_output,
        entity_id=snake_name(iface.name),
        scope="public",
        class_name=iface_output.c_symbol,
    )

    # --- includes ---
    text_element(root, "c_include", file=f"{prefix}_library.h", is_system="0", scope="public")
    text_element(root, "c_include", file=f"{prefix}_impl.h", is_system="0", scope="public")

    for inherited_name in iface.inherits:
        inherited_output = entity_output(project_ir, entity_kind="interface", entity_name=inherited_name)
        text_element(root, "c_include", file=inherited_output.include_file, is_system="0", scope="public")

    _add_interface_type_includes(root, iface, project_ir=project_ir)

    text_element(root, "c_include", file=f"{prefix}_api.h", is_system="0", scope="public")
    text_element(root, "c_include", file=f"{prefix}_assert.h", is_system="0", scope="private")
    text_element(root, "c_include", file=api_output.include_file, is_system="0", scope="private")

    # --- forward declaration of API struct ---
    text_element(
        root,
        "c_struct",
        name=api_struct_name,
        declaration="public",
        definition="external",
    )

    # --- dispatch methods ---
    for method in iface.methods:
        _render_dispatch_method(root, method, iface=iface, project_ir=project_ir,
                                fallback_projects=fallback_projects)

    # --- constant getter methods ---
    for constant in iface.constants:
        _render_constant_getter(root, constant, iface=iface, project_ir=project_ir)

    # --- _api() utility ---
    _render_api_method(root, iface=iface, project_ir=project_ir)

    # --- inherited API getter methods ---
    for inherited_name in iface.inherits:
        _render_inherited_api_getter(root, inherited_name, iface=iface, project_ir=project_ir)

    # --- _is_implemented() ---
    _render_is_implemented_method(root, iface=iface, project_ir=project_ir)

    # --- _api_tag() ---
    _render_api_tag_method(root, iface=iface, project_ir=project_ir)

    return root


def _render_dispatch_method(
    parent: ET.Element,
    method: IRCMethod,
    *,
    iface: IRInterface,
    project_ir: IRProject,
    fallback_projects: list[IRProject] | None = None,
) -> ET.Element:
    """Render a single dispatch method (stateful or static) with vtable call body."""
    iface_output = cast(IROutputTarget, iface.output)
    prefix = project_ir.prefix
    is_static = method.attrs.get("is_static") in {"1", "true"}
    is_const = method.attrs.get("is_const") in {"1", "true"}
    visibility = method.attrs.get("visibility", "public")
    api_struct_name = _interface_api_struct_symbol(iface_output)
    api_var_name = f"{snake_name(iface.name)}_api"
    method_symbol = f"{iface_output.c_symbol}_{snake_name(method.name)}"
    cb_field = f"{snake_name(method.name)}_cb"

    method_attrs: dict[str, str] = {
        "name": method_symbol,
        "declaration": "public" if visibility == "public" else "private",
    }
    if visibility == "private":
        method_attrs["visibility"] = "private"

    method_elem = text_element(parent, "c_method", **method_attrs)

    desc = method.description.strip() if method.description else ""
    if desc:
        method_elem.text = comment_text(desc)

    # Arguments
    if is_static:
        # Static methods take api struct as first arg
        text_element(
            method_elem, "c_argument",
            name=api_var_name,
            type=api_struct_name,
            type_is="class",
            accessed_by="pointer",
            is_const_type="1",
        )
    else:
        # Non-static methods take impl as first arg
        impl_type = f"{prefix}_impl_t"
        if is_const:
            text_element(method_elem, "c_argument", name="impl", accessed_by="pointer", type=impl_type, type_is="class", is_const_type="1")
        else:
            text_element(method_elem, "c_argument", name="impl", accessed_by="pointer", type=impl_type, type_is="class")

    for arg in method.arguments:
        _interface_argument_from_source(method_elem, _method_arg_dict(arg), project_ir=project_ir, fallback_projects=fallback_projects)

    # Return type
    if method.returns:
        _interface_callback_return(method_elem, method.returns[0], project_ir=project_ir)
    else:
        text_element(method_elem, "c_return", type="void", accessed_by="value")

    # Method body (c_code)
    has_return = bool(method.returns) and not all(
        getattr(r, "type_name", None) in {"nothing", None} and getattr(r, "class_name", None) is None and _method_arg_dict(r).get("enum") is None
        for r in method.returns
    )
    return_prefix = "return " if has_return else ""

    # Build argument list for callback call
    arg_names: list[str] = []
    if not is_static:
        arg_names.append("impl")
    for arg in method.arguments:
        arg_names.append(_method_arg_dict(arg).get("name", ""))

    args_str = ", ".join(arg_names)

    if is_static:
        body_lines = [
            f"{prefix.upper()}_ASSERT_PTR ({api_var_name});",
            "",
            f"{prefix.upper()}_ASSERT_PTR ({api_var_name}->{cb_field});",
            f"{return_prefix}{api_var_name}->{cb_field} ({args_str});",
        ]
    else:
        body_lines = [
            f"const {api_struct_name} *{api_var_name} = {iface_output.c_symbol}_api(impl);",
            f"{prefix.upper()}_ASSERT_PTR ({api_var_name});",
            "",
            f"{prefix.upper()}_ASSERT_PTR ({api_var_name}->{cb_field});",
            f"{return_prefix}{api_var_name}->{cb_field} ({args_str});",
        ]

    code_text = "\n".join(body_lines)
    text_element(method_elem, "c_code", type="stub").text = code_text

    return method_elem


def _render_constant_getter(
    parent: ET.Element,
    constant: IRCConstant,
    *,
    iface: IRInterface,
    project_ir: IRProject,
) -> ET.Element:
    """Render a constant getter method."""
    iface_output = cast(IROutputTarget, iface.output)
    prefix = project_ir.prefix
    api_struct_name = _interface_api_struct_symbol(iface_output)
    api_var_name = f"{snake_name(iface.name)}_api"
    method_symbol = f"{iface_output.c_symbol}_{snake_name(constant.name)}"
    field_name = snake_name(constant.name)

    method_elem = text_element(parent, "c_method", name=method_symbol, declaration="public")
    method_elem.text = comment_text(f"Returns constant '{constant.name}'.")

    # API struct argument
    text_element(
        method_elem, "c_argument",
        name=api_var_name,
        type=api_struct_name,
        type_is="class",
        accessed_by="pointer",
        is_const_type="1",
    )

    # Return type
    const_type = constant.attrs.get("type", "size")
    rendered_type, type_is = type_map(const_type)
    text_element(method_elem, "c_return", type=rendered_type, type_is=type_is, accessed_by="value")

    # Body
    body_lines = [
        f"{prefix.upper()}_ASSERT_PTR ({api_var_name});",
        "",
        f"return {api_var_name}->{field_name};",
    ]
    text_element(method_elem, "c_code", type="stub").text = "\n".join(body_lines)

    return method_elem


def _render_api_method(
    parent: ET.Element,
    *,
    iface: IRInterface,
    project_ir: IRProject,
) -> ET.Element:
    """Render the _api() utility method."""
    iface_output = cast(IROutputTarget, iface.output)
    prefix = project_ir.prefix
    api_struct_name = _interface_api_struct_symbol(iface_output)
    api_tag = f"{prefix}_api_tag_{snake_name(iface.name).upper()}"
    method_symbol = f"{iface_output.c_symbol}_api"

    method_elem = text_element(parent, "c_method", name=method_symbol, declaration="public", is_const="1")
    method_elem.text = comment_text(f"Return {iface.name} API, or NULL if it is not implemented.")

    # impl argument
    impl_type = f"{prefix}_impl_t"
    text_element(method_elem, "c_argument", name="impl", accessed_by="pointer", type=impl_type, type_is="class", is_const_type="1")

    # Return type
    text_element(method_elem, "c_return", type=api_struct_name, type_is="class", accessed_by="pointer", is_const_type="1")

    # Body
    body_lines = [
        f"{prefix.upper()}_ASSERT_PTR (impl);",
        "",
        f"const {prefix}_api_t *api = {prefix}_impl_api(impl, {api_tag});",
        f"return (const {api_struct_name} *) api;",
    ]
    text_element(method_elem, "c_code", type="stub").text = "\n".join(body_lines)

    return method_elem


def _render_inherited_api_getter(
    parent: ET.Element,
    inherited_name: str,
    *,
    iface: IRInterface,
    project_ir: IRProject,
) -> ET.Element:
    """Render an inherited API getter method (e.g. cipher_encrypt_api)."""
    iface_output = cast(IROutputTarget, iface.output)
    prefix = project_ir.prefix
    api_struct_name = _interface_api_struct_symbol(iface_output)
    api_var_name = f"{snake_name(iface.name)}_api"
    inherited_output = entity_output(project_ir, entity_kind="interface", entity_name=inherited_name)
    inherited_api_type = _interface_api_struct_symbol(inherited_output)
    field_name = f"{snake_name(inherited_name)}_api"
    method_symbol = f"{iface_output.c_symbol}_{field_name}"

    method_elem = text_element(parent, "c_method", name=method_symbol, declaration="public")
    method_elem.text = comment_text(f"Return {inherited_name} API.")

    # API struct argument
    text_element(
        method_elem, "c_argument",
        name=api_var_name,
        type=api_struct_name,
        type_is="class",
        accessed_by="pointer",
        is_const_type="1",
    )

    # Return
    text_element(method_elem, "c_return", type=inherited_api_type, type_is="class", accessed_by="pointer", is_const_type="1")

    # Body
    body_lines = [
        f"{prefix.upper()}_ASSERT_PTR ({api_var_name});",
        "",
        f"return {api_var_name}->{field_name};",
    ]
    text_element(method_elem, "c_code", type="stub").text = "\n".join(body_lines)

    return method_elem


def _render_is_implemented_method(
    parent: ET.Element,
    *,
    iface: IRInterface,
    project_ir: IRProject,
) -> ET.Element:
    """Render the _is_implemented() utility method."""
    iface_output = cast(IROutputTarget, iface.output)
    prefix = project_ir.prefix
    api_tag = f"{prefix}_api_tag_{snake_name(iface.name).upper()}"
    method_symbol = f"{iface_output.c_symbol}_is_implemented"

    method_elem = text_element(parent, "c_method", name=method_symbol, declaration="public", is_const="1")
    method_elem.text = comment_text(f"Check if given object implements interface '{iface.name}'.")

    # impl argument
    impl_type = f"{prefix}_impl_t"
    text_element(method_elem, "c_argument", name="impl", accessed_by="pointer", type=impl_type, type_is="class", is_const_type="1")

    # Return
    text_element(method_elem, "c_return", type="bool", type_is="primitive", accessed_by="value")

    # Body
    body_lines = [
        f"{prefix.upper()}_ASSERT_PTR (impl);",
        "",
        f"return {prefix}_impl_api(impl, {api_tag}) != NULL;",
    ]
    text_element(method_elem, "c_code", type="stub").text = "\n".join(body_lines)

    return method_elem


def _render_api_tag_method(
    parent: ET.Element,
    *,
    iface: IRInterface,
    project_ir: IRProject,
) -> ET.Element:
    """Render the _api_tag() utility method."""
    iface_output = cast(IROutputTarget, iface.output)
    prefix = project_ir.prefix
    api_struct_name = _interface_api_struct_symbol(iface_output)
    api_var_name = f"{snake_name(iface.name)}_api"
    method_symbol = f"{iface_output.c_symbol}_api_tag"

    method_elem = text_element(parent, "c_method", name=method_symbol, declaration="public")
    method_elem.text = comment_text("Returns interface unique identifier.")

    # API struct argument
    text_element(
        method_elem, "c_argument",
        name=api_var_name,
        type=api_struct_name,
        type_is="class",
        accessed_by="pointer",
        is_const_type="1",
    )

    # Return
    text_element(method_elem, "c_return", type=f"{prefix}_api_tag_t", type_is="enum", accessed_by="value")

    # Body
    body_lines = [
        f"{prefix.upper()}_ASSERT_PTR ({api_var_name});",
        "",
        f"return {api_var_name}->api_tag;",
    ]
    text_element(method_elem, "c_code", type="stub").text = "\n".join(body_lines)

    return method_elem



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


def _append_symbol(base: str, member_name: str) -> str:
    suffix = snake_name(member_name)
    if base.endswith(f"_{suffix}"):
        return base
    return f"{base}_{suffix}"


def _module_method_symbol(project_ir: IRProject, module: IRModule, method: object) -> str:
    attrs = getattr(method, "attrs")
    owner = attrs.get("of_class")
    base = project_ir.prefix if owner == "global" or (owner is None and module.attrs.get("of_class") == "global") else module.output.c_symbol
    if owner and owner != "global":
        base = f"{project_ir.prefix}_{snake_name(owner)}"
    return _append_symbol(base, getattr(method, 'name'))


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
    return _append_symbol(base, getattr(constant, 'name')).upper()


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
            placeholders[token] = c_identifier(variable.name)
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


def _normalize_c_escapes(text: str) -> str:
    return text.replace("'\\\\0'", "'\\0'").replace("'\\\\\\\\'", "'\\\\'")


def _prepare_macro_code(code: str | None) -> str | None:
    if code is None:
        return None
    lines = code.splitlines()
    if lines and lines[0].lstrip().startswith("#define") and len(lines) > 1:
        return "\n".join(line.rstrip().removesuffix("\\").rstrip() for line in lines)
    return code


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

    return _normalize_c_escapes(_PLACEHOLDER_RE.sub(repl, text))


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
        extra = {"is_const_type": "1"} if attrs.get("access") not in {"readwrite", "writeonly"} else {}
        return text_element(
            parent,
            "c_argument",
            name=attrs.get("name", ""),
            accessed_by="pointer",
            type="void",
            type_is="any",
            **extra,
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
    if attrs.get("type") == "string":
        extra = {"is_const_type": "1"} if attrs.get("access") != "readwrite" else {}
        return text_element(parent, "c_return", accessed_by="value", type="char", type_is="primitive", string="null_terminated", **extra)
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
            "name": c_identifier(variable.name),
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
        code = _prepare_macro_code(_resolve_module_placeholders(macro.code_blocks[0]["text"] if macro.code_blocks else None, placeholders, project_prefix=project_ir.prefix))
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
        code = _prepare_macro_code(_resolve_module_placeholders(group.code_blocks[0]["text"] if group.code_blocks else None, placeholders, project_prefix=project_ir.prefix))
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



def _dependency_type_symbol(project_ir: IRProject, dep: IRDependency) -> str:
    """Return the C type symbol for a dependency field.

    For interface/impl dependencies the type is the framework impl_t.
    For class dependencies the type is the class's own type symbol.
    """
    if dep.type_kind in {"interface", "impl"}:
        return f"{project_ir.prefix}_impl_t"
    return class_type_symbol(project_ir, dep.type_name)


def _dependency_destroy_call(project_ir: IRProject, dep: IRDependency) -> str:
    """Return the destroy call expression for releasing a dependency.

    For interface/impl dependencies: ``{prefix}_impl_destroy``.
    For class dependencies: ``{class_symbol}_destroy``.
    """
    if dep.type_kind in {"interface", "impl"}:
        return f"{project_ir.prefix}_impl_destroy"
    class_sym = entity_output(project_ir, entity_kind="class", entity_name=dep.type_name).c_symbol
    return f"{class_sym}_destroy"


def _dependency_shallow_copy_call(project_ir: IRProject, dep: IRDependency) -> str:
    """Return the shallow_copy call expression for a dependency (use method).

    For interface/impl dependencies: ``{prefix}_impl_shallow_copy``.
    For class dependencies: ``{class_symbol}_shallow_copy``.
    """
    if dep.type_kind in {"interface", "impl"}:
        return f"{project_ir.prefix}_impl_shallow_copy"
    class_sym = entity_output(project_ir, entity_kind="class", entity_name=dep.type_name).c_symbol
    return f"{class_sym}_shallow_copy"


def _dependency_is_implemented_check(project_ir: IRProject, dep: IRDependency) -> str | None:
    """Return the is_implemented assertion for interface dependencies, or None."""
    if dep.type_kind == "interface":
        iface_snake = snake_name(dep.type_name)
        return f"{project_ir.prefix.upper()}_ASSERT({project_ir.prefix}_{iface_snake}_is_implemented({snake_name(dep.name)}));"
    return None


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

    # Dependency includes: class-type deps need their class header;
    # interface/impl deps need the interface header for is_implemented checks.
    for dep in cls.dependencies:
        if dep.type_kind == "class":
            add_include(dep.type_name)
        elif dep.type_kind in {"interface", "impl"}:
            iface_include = f"{project_ir.prefix}_{snake_name(dep.type_name)}.h"
            if iface_include not in seen:
                seen.add(iface_include)
                includes.append(iface_include)

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

    # Dependency struct fields — each dependency becomes a pointer property.
    if not is_value_type:
        for dep in cls.dependencies:
            dep_type = _dependency_type_symbol(project_ir, dep)
            dep_field_name = snake_name(dep.name)
            prop = text_element(
                struct,
                "c_property",
                name=dep_field_name,
                type=dep_type,
                type_is="class",
                accessed_by="pointer",
            )
            prop.text = comment_text(f"Dependency to the {dep.type_kind} '{dep.type_name}'.")

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



# ---------------------------------------------------------------------------
#   Lifecycle method body generation helpers.
# ---------------------------------------------------------------------------

def _lifecycle_init_body(
    project_ir: IRProject,
    cls: IRClass,
) -> str:
    """Generate the body for the init() lifecycle method."""
    struct_type = class_type_symbol(project_ir, cls.name)
    init_ctx = _class_runtime_symbol(project_ir, cls, "init_ctx")
    return (
        f"VSC_ASSERT_PTR(self);\n"
        f"\n"
        f"vsc_zeroize(self, sizeof({struct_type}));\n"
        f"\n"
        f"self->refcnt = 1;\n"
        f"\n"
        f"{init_ctx}(self);"
    )


def _lifecycle_cleanup_body(
    project_ir: IRProject,
    cls: IRClass,
) -> str:
    """Generate the body for the cleanup() lifecycle method."""
    struct_type = class_type_symbol(project_ir, cls.name)
    cleanup_ctx = _class_runtime_symbol(project_ir, cls, "cleanup_ctx")
    class_symbol = entity_output(project_ir, entity_kind='class', entity_name=cls.name).c_symbol

    lines = [
        "if (self == NULL) {",
        "    return;",
        "}",
        "",
        f"{cleanup_ctx}(self);",
    ]

    # Release each dependency
    for dep in cls.dependencies:
        release_method = f"{class_symbol}_release_{snake_name(dep.name)}"  
        lines.append("")
        lines.append(f"{release_method}(self);")

    lines.append("")
    lines.append(f"vsc_zeroize(self, sizeof({struct_type}));")

    return "\n".join(lines)


def _lifecycle_new_body(
    project_ir: IRProject,
    cls: IRClass,
) -> str:
    """Generate the body for the new() lifecycle method."""
    struct_type = class_type_symbol(project_ir, cls.name)
    init_method = _class_runtime_symbol(project_ir, cls, "init")
    return (
        f"{struct_type} *self = ({struct_type} *) vsc_alloc(sizeof ({struct_type}));\n"
        f"VSC_ASSERT_ALLOC(self);\n"
        f"\n"
        f"{init_method}(self);\n"
        f"\n"
        f"self->self_dealloc_cb = vsc_dealloc;\n"
        f"\n"
        f"return self;"
    )


def _lifecycle_delete_body(
    project_ir: IRProject,
    cls: IRClass,
) -> str:
    """Generate the body for the delete() lifecycle method."""
    prefix_upper = project_ir.prefix.upper()
    cleanup_method = _class_runtime_symbol(project_ir, cls, "cleanup")
    return (
        f"if (self == NULL) {{\n"
        f"    return;\n"
        f"}}\n"
        f"\n"
        f"size_t old_counter = self->refcnt;\n"
        f"{prefix_upper}_ASSERT(old_counter != 0);\n"
        f"size_t new_counter = old_counter - 1;\n"
        f"\n"
        f"#if defined({prefix_upper}_ATOMIC_COMPARE_EXCHANGE_WEAK)\n"
        f"//  CAS loop\n"
        f"while (!{prefix_upper}_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {{\n"
        f"    old_counter = self->refcnt;\n"
        f"    {prefix_upper}_ASSERT(old_counter != 0);\n"
        f"    new_counter = old_counter - 1;\n"
        f"}}\n"
        f"#else\n"
        f"self->refcnt = new_counter;\n"
        f"#endif\n"
        f"\n"
        f"if (new_counter > 0) {{\n"
        f"    return;\n"
        f"}}\n"
        f"\n"
        f"{project_ir.prefix}_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;\n"
        f"\n"
        f"{cleanup_method}(self);\n"
        f"\n"
        f"if (self_dealloc_cb != NULL) {{\n"
        f"    self_dealloc_cb(self);\n"
        f"}}"
    )


def _lifecycle_destroy_body(
    project_ir: IRProject,
    cls: IRClass,
) -> str:
    """Generate the body for the destroy() lifecycle method."""
    prefix_upper = project_ir.prefix.upper()
    struct_type = class_type_symbol(project_ir, cls.name)
    delete_method = _class_runtime_symbol(project_ir, cls, "delete")
    return (
        f"{prefix_upper}_ASSERT_PTR(self_ref);\n"
        f"\n"
        f"{struct_type} *self = *self_ref;\n"
        f"*self_ref = NULL;\n"
        f"\n"
        f"{delete_method}(self);"
    )


def _lifecycle_shallow_copy_body(
    project_ir: IRProject,
    cls: IRClass,
) -> str:
    """Generate the body for the shallow_copy() lifecycle method."""
    prefix_upper = project_ir.prefix.upper()
    return (
        f"{prefix_upper}_ASSERT_PTR(self);\n"
        f"\n"
        f"#if defined({prefix_upper}_ATOMIC_COMPARE_EXCHANGE_WEAK)\n"
        f"//  CAS loop\n"
        f"size_t old_counter;\n"
        f"size_t new_counter;\n"
        f"do {{\n"
        f"    old_counter = self->refcnt;\n"
        f"    new_counter = old_counter + 1;\n"
        f"}} while (!{prefix_upper}_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));\n"
        f"#else\n"
        f"++self->refcnt;\n"
        f"#endif\n"
        f"\n"
        f"return self;"
    )


def _lifecycle_constructor_init_body(
    project_ir: IRProject,
    cls: IRClass,
    ctor_name: str,
    ctor_arg_names: list[str],
) -> str:
    """Generate the body for the init_with_X() constructor lifecycle method."""
    prefix_upper = project_ir.prefix.upper()
    struct_type = class_type_symbol(project_ir, cls.name)
    init_ctx_method = _class_runtime_symbol(project_ir, cls, f"init_ctx_with_{_reference_ctor_suffix(ctor_name)}")
    proxy_args = ", ".join(["self"] + ctor_arg_names)
    return (
        f"{prefix_upper}_ASSERT_PTR(self);\n"
        f"\n"
        f"vsc_zeroize(self, sizeof({struct_type}));\n"
        f"\n"
        f"self->refcnt = 1;\n"
        f"\n"
        f"{init_ctx_method}({proxy_args});"
    )


def _lifecycle_constructor_new_body(
    project_ir: IRProject,
    cls: IRClass,
    ctor_name: str,
    ctor_arg_names: list[str],
) -> str:
    """Generate the body for the new_with_X() constructor lifecycle method."""
    struct_type = class_type_symbol(project_ir, cls.name)
    init_method = class_constructor_symbol(project_ir, cls, ctor_name)
    proxy_args = ", ".join(["self"] + ctor_arg_names)
    return (
        f"{struct_type} *self = ({struct_type} *) vsc_alloc(sizeof ({struct_type}));\n"
        f"VSC_ASSERT_ALLOC(self);\n"
        f"\n"
        f"{init_method}({proxy_args});\n"
        f"\n"
        f"self->self_dealloc_cb = vsc_dealloc;\n"
        f"\n"
        f"return self;"
    )


# ---------------------------------------------------------------------------
#   Dependency management method generation helpers.
# ---------------------------------------------------------------------------

def _dependency_use_body(
    project_ir: IRProject,
    cls: IRClass,
    dep: "IRDependency",
) -> str:
    """Generate the body for the use_X() dependency method."""
    prefix_upper = project_ir.prefix.upper()
    class_symbol = entity_output(project_ir, entity_kind='class', entity_name=cls.name).c_symbol
    dep_field = snake_name(dep.name)
    shallow_copy = _dependency_shallow_copy_call(project_ir, dep)
    is_impl_check = _dependency_is_implemented_check(project_ir, dep)

    lines = [
        f"{prefix_upper}_ASSERT_PTR(self);",
        f"{prefix_upper}_ASSERT_PTR({dep_field});",
        f"{prefix_upper}_ASSERT(self->{dep_field} == NULL);",
    ]
    if is_impl_check:
        lines.append("")
        lines.append(is_impl_check)
    lines.append("")
    lines.append(f"self->{dep_field} = {shallow_copy}({dep_field});")
    if dep.has_observers:
        did_setup = f"{class_symbol}_did_setup_{dep_field}"
        if dep.is_observers_return_status:
            lines.append("")
            lines.append(f"return {did_setup}(self);")
        else:
            lines.append("")
            lines.append(f"{did_setup}(self);")
    return "\n".join(lines)


def _dependency_take_body(
    project_ir: IRProject,
    cls: IRClass,
    dep: "IRDependency",
) -> str:
    """Generate the body for the take_X() dependency method."""
    prefix_upper = project_ir.prefix.upper()
    class_symbol = entity_output(project_ir, entity_kind='class', entity_name=cls.name).c_symbol
    dep_field = snake_name(dep.name)
    is_impl_check = _dependency_is_implemented_check(project_ir, dep)

    lines = [
        f"{prefix_upper}_ASSERT_PTR(self);",
        f"{prefix_upper}_ASSERT_PTR({dep_field});",
        f"{prefix_upper}_ASSERT(self->{dep_field} == NULL);",
    ]
    if is_impl_check:
        lines.append("")
        lines.append(is_impl_check)
    lines.append("")
    lines.append(f"self->{dep_field} = {dep_field};")
    if dep.has_observers:
        did_setup = f"{class_symbol}_did_setup_{dep_field}"
        if dep.is_observers_return_status:
            lines.append("")
            lines.append(f"return {did_setup}(self);")
        else:
            lines.append("")
            lines.append(f"{did_setup}(self);")
    return "\n".join(lines)


def _dependency_release_body(
    project_ir: IRProject,
    cls: IRClass,
    dep: "IRDependency",
) -> str:
    """Generate the body for the release_X() dependency method."""
    prefix_upper = project_ir.prefix.upper()
    class_symbol = entity_output(project_ir, entity_kind='class', entity_name=cls.name).c_symbol
    dep_field = snake_name(dep.name)
    destroy = _dependency_destroy_call(project_ir, dep)

    lines = [
        f"{prefix_upper}_ASSERT_PTR(self);",
        "",
        f"{destroy}(&self->{dep_field});",
    ]
    if dep.has_observers:
        did_release = f"{class_symbol}_did_release_{dep_field}"
        lines.append("")
        lines.append(f"{did_release}(self);")
    return "\n".join(lines)


def _render_dependency_method_element(
    parent: ET.Element,
    *,
    name: str,
    description: str,
    dep_arg_name: str,
    dep_arg_type: str,
    return_type: str,
    code: str,
    owner_class: str,
    project_ir: IRProject,
    uid: str,
) -> ET.Element:
    """Render a dependency use/take method with a typed dependency argument.

    This bypasses ``_render_ir_method`` because the dependency argument
    is not a class/type/callback in the IR sense — it's a raw C type
    (e.g. ``vscf_impl_t``) that must appear as ``type_is='class'``
    and ``accessed_by='pointer'`` in the generated XML.
    """
    class_type = class_type_symbol(project_ir, owner_class)
    method = text_element(
        parent,
        "c_method",
        name=name,
        visibility="public",
        declaration="public",
        definition="public",
        uid=uid,
    )
    # self argument
    text_element(method, "c_argument", name="self", accessed_by="pointer", type=class_type, type_is="class")
    # dependency argument
    text_element(method, "c_argument", name=dep_arg_name, accessed_by="pointer", type=dep_arg_type, type_is="class")
    # return
    if return_type == "void":
        text_element(method, "c_return", accessed_by="value", type="void")
    else:
        text_element(method, "c_return", accessed_by="value", type=return_type, type_is="primitive")
    # code
    text_element(method, "c_code", code, type="generated", lang="c")
    # modifier
    text_element(method, "c_modifier", value="VSC_PUBLIC")
    # description
    if description:
        method.text = comment_text(description)
    return method


def _render_dependency_methods(
    parent: ET.Element,
    *,
    project_ir: IRProject,
    cls: IRClass,
) -> None:
    """Render use/take/release methods for each class dependency.

    Also renders did_setup/did_release observer hooks for dependencies
    that have ``has_observers`` set.
    """
    class_symbol = entity_output(project_ir, entity_kind='class', entity_name=cls.name).c_symbol
    class_snake = snake_name(cls.name)

    for dep in cls.dependencies:
        dep_field = snake_name(dep.name)
        dep_type = _dependency_type_symbol(project_ir, dep)

        # --- Observer hooks (rendered before use/take/release so forward decls work) ---
        if dep.has_observers:
            # did_setup
            did_setup_name = f"{class_symbol}_did_setup_{dep_field}"
            did_setup_return: dict[str, str] | None = {"type": "void"}
            did_setup_code = "// TODO: This is STUB. Implement me."
            if dep.is_observers_return_status:
                did_setup_return = {"type": "status", "enum": "status"}
                did_setup_code = "// TODO: This is STUB. Implement me.\nreturn vscf_status_SUCCESS;"
            _render_ir_method(
                parent,
                name=did_setup_name,
                description=f"This method is called when {dep.type_kind} '{dep.type_name}' was setup.",
                arguments=({"name": "self", "class": "self"},),
                return_attrs=did_setup_return,
                project_ir=project_ir,
                owner_class=cls.name,
                visibility="private",
                declaration="private",
                definition="private",
                modifiers=("static",),
                code=did_setup_code,
                uid=f"direct_{class_snake}_did_setup_{dep_field}",
            )
            # did_release
            did_release_name = f"{class_symbol}_did_release_{dep_field}"
            _render_ir_method(
                parent,
                name=did_release_name,
                description=f"This method is called when {dep.type_kind} '{dep.type_name}' was released.",
                arguments=({"name": "self", "class": "self"},),
                return_attrs={"type": "void"},
                project_ir=project_ir,
                owner_class=cls.name,
                visibility="private",
                declaration="private",
                definition="private",
                modifiers=("static",),
                code="// TODO: This is STUB. Implement me.",
                uid=f"direct_{class_snake}_did_release_{dep_field}",
            )

        # --- use_X ---
        use_desc = dep.description.strip() + "\n\nNote, ownership is shared." if dep.description.strip() else f"Setup dependency to the {dep.type_kind} '{dep.type_name}' with shared ownership."
        use_return_type = "void"
        if dep.has_observers and dep.is_observers_return_status:
            use_return_type = "status"
        use_method = _render_dependency_method_element(
            parent,
            name=f"{class_symbol}_use_{dep_field}",
            description=use_desc,
            dep_arg_name=dep_field,
            dep_arg_type=dep_type,
            return_type=use_return_type,
            code=_dependency_use_body(project_ir, cls, dep),
            owner_class=cls.name,
            project_ir=project_ir,
            uid=f"direct_{class_snake}_use_{dep_field}",
        )

        # --- take_X (only for interface/class/impl deps) ---
        if dep.type_kind in {"interface", "class", "impl"}:
            take_desc = dep.description.strip() + "\n\nNote, ownership is transfered.\nNote, transfer ownership does not mean that object is uniquely owned by the target object." if dep.description.strip() else f"Setup dependency to the {dep.type_kind} '{dep.type_name}' and transfer ownership.\nNote, transfer ownership does not mean that object is uniquely owned by the target object."
            take_return_type = "void"
            if dep.has_observers and dep.is_observers_return_status:
                take_return_type = "status"
            _render_dependency_method_element(
                parent,
                name=f"{class_symbol}_take_{dep_field}",
                description=take_desc,
                dep_arg_name=dep_field,
                dep_arg_type=dep_type,
                return_type=take_return_type,
                code=_dependency_take_body(project_ir, cls, dep),
                owner_class=cls.name,
                project_ir=project_ir,
                uid=f"direct_{class_snake}_take_{dep_field}",
            )

        # --- release_X ---
        _render_ir_method(
            parent,
            name=f"{class_symbol}_release_{dep_field}",
            description=f"Release dependency to the {dep.type_kind} '{dep.type_name}'.",
            arguments=({"name": "self", "class": "self"},),
            return_attrs={"type": "void"},
            project_ir=project_ir,
            owner_class=cls.name,
            code=_dependency_release_body(project_ir, cls, dep),
            uid=f"direct_{class_snake}_release_{dep_field}",
        )


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
) -> None:
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

    for name, description, arguments, return_attrs, body in [
        (_class_runtime_symbol(project_ir, cls, "init"), "Perform initialization of pre-allocated context.", ({"name": "self", "class": "self"},), {"type": "void"}, _lifecycle_init_body(project_ir, cls)),
        (_class_runtime_symbol(project_ir, cls, "cleanup"), "Release all inner resources including class dependencies.", ({"name": "self", "class": "self"},), {"type": "void"}, _lifecycle_cleanup_body(project_ir, cls)),
        (_class_runtime_symbol(project_ir, cls, "new"), "Allocate context and perform it's initialization.", (), {"class": "self"}, _lifecycle_new_body(project_ir, cls)),
        (_class_runtime_symbol(project_ir, cls, "delete"), "Release all inner resources and deallocate context if needed.\nIt is safe to call this method even if the context was statically allocated.", ({"name": "self", "class": "self"},), {"type": "void"}, _lifecycle_delete_body(project_ir, cls)),
        (_class_runtime_symbol(project_ir, cls, "destroy"), "Delete given context and nullifies reference.\nThis is a reverse action of the function 'new ()'.", ({"name": "self_ref", "class": "self", "access": "readwrite", "passed_by": "reference"},), {"type": "void"}, _lifecycle_destroy_body(project_ir, cls)),
        (_class_runtime_symbol(project_ir, cls, "shallow_copy"), "Copy given class context by increasing reference counter.", ({"name": "self", "class": "self"},), {"class": "self"}, _lifecycle_shallow_copy_body(project_ir, cls)),
    ]:
        _render_ir_method(parent, name=name, description=description, arguments=arguments, return_attrs=return_attrs, project_ir=project_ir, owner_class=cls.name, code=body)

    # Dependency management methods: use/take/release (+ observer hooks).
    _render_dependency_methods(parent, project_ir=project_ir, cls=cls)

    for ctor in cls.constructors:
        args = tuple(_method_arg_dict(arg) for arg in ctor.arguments)
        ctor_arg_names = [_method_arg_dict(arg)["name"] for arg in ctor.arguments]
        init_name = class_constructor_symbol(project_ir, cls, ctor.name)
        new_name = _class_new_constructor_symbol(project_ir, cls, ctor.name)
        _render_ir_method(
            parent,
            name=init_name,
            description=f"Perform initialization of pre-allocated context.\n{ctor.description}",
            arguments=({"name": "self", "class": "self"}, *args),
            return_attrs={"type": "void"},
            project_ir=project_ir,
            owner_class=cls.name,
            uid=f"direct_{snake_name(cls.name)}_init_with_{snake_name(ctor.name)}",
            code=_lifecycle_constructor_init_body(project_ir, cls, ctor.name, ctor_arg_names),
        )
        _render_ir_method(
            parent,
            name=new_name,
            description=f"Allocate class context and perform it's initialization.\n{ctor.description}",
            arguments=args,
            return_attrs={"class": "self"},
            project_ir=project_ir,
            owner_class=cls.name,
            uid=f"direct_{snake_name(cls.name)}_new_with_{snake_name(ctor.name)}",
            code=_lifecycle_constructor_new_body(project_ir, cls, ctor.name, ctor_arg_names),
        )



# ---------------------------------------------------------------------------
#   Implementation rendering
# ---------------------------------------------------------------------------


def _resolve_impl_property_type(
    prop: IRCStructField,
    *,
    project_ir: IRProject,
    impl: IRImplementation,
    fallback_projects: list[IRProject] | None = None,
) -> dict[str, str]:
    """Resolve an implementation property to its C struct field attributes.

    Returns a dict of attributes suitable for a ``c_property`` XML element.
    """
    impl_output = cast(IROutputTarget, impl.output)
    attrs: dict[str, str] = {"name": snake_name(prop.name)}

    if prop.enum_name is not None:
        # Enum property → resolve to the enum type symbol
        enum_name = prop.enum_name
        # Handle cross-module enum references (e.g. "impl/tag")
        if "/" in enum_name:
            parts = enum_name.split("/")
            enum_name = " ".join(parts)
        try:
            enum_output = entity_output(project_ir, entity_kind="enum", entity_name=enum_name)
            type_sym = f"{enum_output.c_symbol}_t"
        except (KeyError, ValueError):
            type_sym = f"{project_ir.prefix}_{snake_name(enum_name)}_t"
        attrs.update({
            "type": type_sym,
            "type_is": "primitive",
            "accessed_by": "value",
        })
    elif prop.class_name is not None:
        # Class property — could be external library type or project class
        if prop.library:
            # External library type (e.g. mbedtls_sha256_context) — use as-is
            attrs.update({
                "type": prop.class_name,
                "type_is": "class",
                "accessed_by": "pointer" if prop.is_reference else "value",
            })
        else:
            # Project class (e.g. buffer → vsc_buffer_t)
            try:
                type_sym = _resolve_class_type_symbol(
                    project_ir, prop.class_name, fallback_projects=fallback_projects
                )
            except KeyError:
                type_sym = f"{project_ir.prefix}_{snake_name(prop.class_name)}_t"
            attrs.update({
                "type": type_sym,
                "type_is": "class",
                "accessed_by": "pointer" if not prop.is_reference else "pointer",
            })
            # Project classes are always accessed by pointer in struct properties
            attrs["accessed_by"] = "pointer"
    else:
        # Primitive type (byte, size, etc.)
        rendered_type, kind = type_map(prop.type_name)
        attrs.update({
            "type": rendered_type,
            "type_is": kind,
            "accessed_by": "value",
        })

    # Handle fixed-length array properties
    if prop.array_kind == "fixed" and prop.array_length_constant:
        attrs["array"] = "fixed"
        # Resolve length_constant: extract constant name from GSL uid reference
        length_ref = prop.array_length_constant
        if length_ref.startswith(".") and "_constant_" in length_ref:
            const_part = length_ref.split("_constant_", 1)[1].rstrip(")")
            attrs["length"] = f"{impl_output.c_symbol}_{const_part.upper()}"
        else:
            attrs["length"] = length_ref

    return attrs


def _impl_binding_constant_symbol(impl_output: IROutputTarget, constant_name: str) -> str:
    """Return the C constant symbol for an interface binding constant."""
    return f"{impl_output.c_symbol}_{snake_name(constant_name).upper()}"


def render_implementation_defs_c_module(
    project_ir: IRProject,
    impl: IRImplementation,
    *,
    fallback_projects: list[IRProject] | None = None,
) -> ET.Element:
    """Render the defs module for an implementation.

    The defs module defines the implementation struct with the ``vscf_impl_t``
    base fields (info + refcnt) followed by the implementation-specific
    properties.
    """
    impl_output = cast(IROutputTarget, impl.output)
    defs_output = implementation_defs_output(impl_output)
    prefix = project_ir.prefix
    prefix_upper = prefix.upper()

    root = c_module_root(
        defs_output,
        entity_id=f"{snake_name(impl.name)}_defs",
        scope="private",
    )
    root.set("feature", f"{prefix_upper}_{snake_name(impl.name).upper()}")

    # Standard includes
    text_element(root, "c_include", file=f"{prefix}_library.h", is_system="0", scope="public")
    text_element(root, "c_include", file=f"{prefix}_impl_private.h", is_system="0", scope="public")
    text_element(root, "c_include", file=impl_output.include_file, is_system="0", scope="public")
    text_element(root, "c_include", file=f"{prefix}_atomic.h", is_system="0", scope="public")

    # Library header includes (from requirements)
    for req in impl.requirements:
        if req.kind == "header":
            text_element(root, "c_include", file=req.name, is_system="1", scope="public")

    # Struct definition
    struct_name = f"{impl_output.c_symbol}_t"
    struct_elem = text_element(
        root,
        "c_struct",
        name=struct_name,
        visibility="public",
        declaration="external",
        definition="public",
        uid=f"c_class_{snake_name(impl.name)}_struct_{snake_name(impl.name)}",
    )

    # Base fields: info (pointer to impl_info_t) and refcnt
    info_prop = text_element(
        struct_elem,
        "c_property",
        name="info",
        accessed_by="pointer",
        type=f"{prefix}_impl_info_t",
        type_is="class",
        is_const_type="1",
        uid=f"c_class_{snake_name(impl.name)}_struct_{snake_name(impl.name)}_property_info",
    )
    info_prop.text = comment_text("Compile-time known information about this implementation.")

    refcnt_prop = text_element(
        struct_elem,
        "c_property",
        name="refcnt",
        accessed_by="value",
        type=f"{prefix_upper}_ATOMIC size_t",
        type_is="primitive",
        uid=f"c_class_{snake_name(impl.name)}_struct_{snake_name(impl.name)}_property_refcnt",
    )
    refcnt_prop.text = comment_text("Reference counter.")

    # Implementation-specific properties
    for prop in impl.properties:
        prop_attrs = _resolve_impl_property_type(
            prop, project_ir=project_ir, impl=impl, fallback_projects=fallback_projects
        )
        prop_name = prop_attrs.pop("name")
        uid = f"c_class_{snake_name(impl.name)}_struct_{snake_name(impl.name)}_property_{prop_name}"
        prop_elem = text_element(
            struct_elem,
            "c_property",
            name=prop_name,
            uid=uid,
            **prop_attrs,
        )
        prop_elem.text = comment_text("Implementation specific context.")

    struct_elem.text = (struct_elem.text or "") + "\n" + doc_comment(
        "Handles implementation details."
    ) + "\n    "

    root.text = (root.text or "") + "\n" + doc_comment(
        f"Types of the '{impl.name}' implementation.\n"
        f"This types SHOULD NOT be used directly.\n"
        f"The only purpose of including this module is to place implementation\n"
        f"object in the stack memory."
    ) + "\n"

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
