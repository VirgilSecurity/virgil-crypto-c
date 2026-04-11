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
    return name.replace("/", "_").replace(" ", "_")


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
    projects = [project_ir, *getattr(project_ir, 'fallback_projects', [])]
    lookup_fns = {
        "module": lambda pir: cast(IROutputTarget, module_ir(pir, entity_name).output),
        "class": lambda pir: cast(IROutputTarget, class_ir(pir, entity_name).output),
        "enum": lambda pir: cast(IROutputTarget, enum_ir(pir, entity_name).output),
        "interface": lambda pir: cast(IROutputTarget, interface_ir(pir, entity_name).output),
        "implementation": lambda pir: cast(IROutputTarget, implementation_ir(pir, entity_name).output),
    }
    fn = lookup_fns.get(entity_kind)
    if fn is None:
        raise ValueError(f"unsupported C backend entity kind: {entity_kind}")
    for pir in projects:
        try:
            return fn(pir)
        except (KeyError, StopIteration):
            continue
    raise KeyError(f"{entity_kind} not found in IR: {entity_name}")



def class_type_symbol(project_ir: IRProject, class_name: str) -> str:
    try:
        return f"{entity_output(project_ir, entity_kind='class', entity_name=class_name).c_symbol}_t"
    except KeyError:
        # Fall back to implementation lookup (handles impl="X" references)
        return f"{entity_output(project_ir, entity_kind='implementation', entity_name=class_name).c_symbol}_t"



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

    The internal module header lives alongside the source file (in ``src/``)
    and uses the ``<prefix>_<impl>_internal`` stem convention.
    """
    stem = f"{impl_output.c_symbol}_internal"
    # Legacy layout: _internal.h lives in src/ alongside the .c files
    header_path = impl_output.source_path.replace(impl_output.source_file, f"{stem}.h")
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



def class_internal_output(class_output: IROutputTarget) -> IROutputTarget:
    """Derive the internal module output target from a class's output target.

    The internal module lives under the ``src`` directory (next to .c files)
    and uses the ``<prefix>_<class>_internal`` stem convention.
    It is header-only.
    """
    stem = f"{class_output.c_symbol}_internal"
    # Internal headers live in src/, not in include/
    header_path = class_output.source_path.replace(class_output.source_file, f"{stem}.h")
    source_path = class_output.source_path.replace(class_output.source_file, f"{stem}.c")
    generated_header_path = class_output.generated_header_path.replace(
        class_output.include_file.removesuffix(".h"),
        stem,
    )
    generated_source_path = class_output.generated_source_path.replace(
        Path(class_output.generated_source_path).stem,
        f"class_{snake_name(class_output.entity_name)}_internal",
    )
    return IROutputTarget(
        entity_kind="module",
        entity_name=f"{class_output.entity_name} internal",
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



# ---------------------------------------------------------------------------
# Project-global impl infrastructure output targets
# ---------------------------------------------------------------------------

def _impl_infra_output(
    project_ir: IRProject,
    *,
    entity_name: str,
    scope: str = "public",
) -> IROutputTarget:
    """Build an :class:`IROutputTarget` for a project-global impl infrastructure module.

    These modules (api, api_private, impl, impl_private) don't correspond to
    any model-level entity; they are *derived* from the full set of interfaces
    and implementations in the project.
    """
    prefix = project_ir.prefix
    stem = f"{prefix}_{snake_name(entity_name)}"
    include_namespace = project_ir.include_namespace
    # Use the relative path (from project attrs) so header_path/source_path
    # match the pattern used by build_output_target in project_ir.py.
    source_root = project_ir.attrs.get("path", project_ir.source_root).rstrip("/")
    work_root = project_ir.attrs.get("work_path", project_ir.work_root).rstrip("/")
    header_visibility = "private" if scope == "private" else "public"
    include_dir = f"{include_namespace}/private" if header_visibility == "private" else include_namespace
    header_path = f"{source_root}/include/{include_dir}/{stem}.h"
    source_path = f"{source_root}/src/{stem}.c"
    generated_header_path = f"{work_root}/c_module_{stem}.xml"
    generated_source_path = f"{work_root}/module_{snake_name(entity_name)}.xml"
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


# ---------------------------------------------------------------------------
# Render: api module (api_tag enum + api_t forward declaration)
# ---------------------------------------------------------------------------

def render_api_c_module(project_ir: IRProject) -> ET.Element:
    """Render the project-global ``api`` module.

    Contains:
    - ``api_tag`` enum — one constant per interface (alphabetical), with
      BEGIN=0 and END sentinels.
    - ``api_t`` forward-declared struct.
    """
    output = _impl_infra_output(project_ir, entity_name="api")
    root = c_module_root(output, entity_id="api", scope="public", class_name="api")
    prefix = project_ir.prefix

    # --- require: library -----------------------------------------------
    text_element(root, "c_include", file=include_file_for_entity(project_ir, entity_kind="module", entity_name="library"))

    # --- api_tag enum ---------------------------------------------------
    iface_names = sorted(i.name for i in project_ir.interfaces)
    enum_sym = f"{prefix}_api_tag"
    enum_el = text_element(root, "c_enum", name=f"{enum_sym}_t", typedef_name=f"{enum_sym}_t", declaration="public", definition="public")
    enum_el.text = comment_text("Enumerates all possible interfaces within crypto library.")

    text_element(enum_el, "c_constant", name=f"{enum_sym}_BEGIN", value="0")
    for iname in iface_names:
        tag = snake_name(iname).upper()
        text_element(enum_el, "c_constant", name=f"{enum_sym}_{tag}")
    text_element(enum_el, "c_constant", name=f"{enum_sym}_END")

    # --- api_t forward declaration -------------------------------------
    struct_el = text_element(root, "c_struct", name=f"{prefix}_api_t", declaration="public", definition="external")
    struct_el.text = comment_text("Generic type for any 'API' object.")

    return root


# ---------------------------------------------------------------------------
# Render: api_private module (api_t struct definition)
# ---------------------------------------------------------------------------

def render_api_private_c_module(project_ir: IRProject) -> ET.Element:
    """Render the project-global ``api_private`` module.

    Contains the *definition* of ``api_t`` — the base struct for all
    interface API structs, with ``api_tag`` and ``impl_tag`` fields.
    """
    output = _impl_infra_output(project_ir, entity_name="api_private", scope="private")
    root = c_module_root(output, entity_id="api_private", scope="private", class_name="api")
    prefix = project_ir.prefix

    # --- includes -------------------------------------------------------
    text_element(root, "c_include", file=f"{prefix}_library.h")
    text_element(root, "c_include", file=f"{prefix}_api.h")
    text_element(root, "c_include", file=f"{prefix}_impl.h")

    # --- api_t full struct definition -----------------------------------
    struct_el = text_element(
        root, "c_struct",
        name=f"{prefix}_api_t",
        declaration="external",
        definition="public",
    )
    struct_el.text = comment_text(
        "This structure contains common part of any 'API' interface structure.\n"
        "It is used for runtime type casting and checking."
    )
    prop1 = text_element(struct_el, "c_property", name="api_tag", type=f"{prefix}_api_tag_t", accessed_by="value", type_is="enum")
    prop1.text = comment_text("Interface unique identifier.")
    prop2 = text_element(struct_el, "c_property", name="impl_tag", type=f"{prefix}_impl_tag_t", accessed_by="value", type_is="enum")
    prop2.text = comment_text("Implementation unique identifier.")

    return root


# ---------------------------------------------------------------------------
# Render: impl module (impl_tag enum + dispatch methods)
# ---------------------------------------------------------------------------

def render_impl_c_module(project_ir: IRProject) -> ET.Element:
    """Render the project-global ``impl`` module.

    Contains:
    - ``impl_tag`` enum — one constant per implementation (alphabetical),
      with BEGIN=0 and END sentinels.
    - ``impl_t`` forward-declared struct.
    - Dispatch methods: api, tag, cleanup, delete, destroy, shallow_copy,
      shallow_copy_const.
    """
    output = _impl_infra_output(project_ir, entity_name="impl")
    root = c_module_root(output, entity_id="impl", scope="public", class_name="impl")
    prefix = project_ir.prefix
    PREFIX = prefix.upper()

    # --- public includes ------------------------------------------------
    text_element(root, "c_include", file=f"{prefix}_library.h")
    text_element(root, "c_include", file=f"{prefix}_api.h")

    # --- private includes (source-only) ---------------------------------
    for inc in (f"{prefix}_api_private.h", f"{prefix}_impl_private.h", f"{prefix}_assert.h", f"{prefix}_atomic.h"):
        text_element(root, "c_include", file=inc, scope="private")

    # --- impl_tag enum --------------------------------------------------
    impl_names = sorted(i.name for i in project_ir.implementations)
    enum_sym = f"{prefix}_impl_tag"
    enum_el = text_element(root, "c_enum", name=f"{enum_sym}_t", typedef_name=f"{enum_sym}_t", declaration="public", definition="public")
    enum_el.text = comment_text("Enumerates all possible implementations within crypto library.")

    text_element(enum_el, "c_constant", name=f"{enum_sym}_BEGIN", value="0")
    for iname in impl_names:
        tag = snake_name(iname).upper()
        text_element(enum_el, "c_constant", name=f"{enum_sym}_{tag}")
    text_element(enum_el, "c_constant", name=f"{enum_sym}_END")

    # --- impl_t forward declaration ------------------------------------
    struct_el = text_element(root, "c_struct", name=f"{prefix}_impl_t", declaration="public", definition="external")
    struct_el.text = comment_text("Generic type for any 'implementation'.")

    # --- dispatch method: api ------------------------------------------
    _impl_dispatch_api(root, prefix, PREFIX)
    # --- dispatch method: tag ------------------------------------------
    _impl_dispatch_tag(root, prefix, PREFIX)
    # --- dispatch method: cleanup --------------------------------------
    _impl_dispatch_cleanup(root, prefix, PREFIX)
    # --- dispatch method: delete ---------------------------------------
    _impl_dispatch_delete(root, prefix, PREFIX)
    # --- dispatch method: destroy --------------------------------------
    _impl_dispatch_destroy(root, prefix, PREFIX)
    # --- dispatch method: shallow_copy ---------------------------------
    _impl_dispatch_shallow_copy(root, prefix, PREFIX)
    # --- dispatch method: shallow_copy_const ---------------------------
    _impl_dispatch_shallow_copy_const(root, prefix, PREFIX)

    return root


def _impl_method(root: ET.Element, *, name: str, uid: str, description: str,
                 args: list[tuple[str, str, str]], return_attrs: dict[str, str] | None = None,
                 code: str, visibility: str = "public", prefix: str = "") -> ET.Element:
    """Helper to add a dispatch method element to the impl module."""
    definition = "public"
    declaration = "public"
    method = text_element(
        root, "c_method",
        name=name,
        visibility=visibility,
        declaration=declaration,
        definition=definition,
        uid=uid,
    )
    method.text = comment_text(description)
    for arg_name, arg_type, arg_accessed_by in args:
        extra: dict[str, str] = {}
        if arg_type.endswith("_t") and "tag" in arg_type:
            extra["type_is"] = "enum"
        elif arg_type.endswith("_t"):
            extra["type_is"] = "class"
        if "const" in arg_type:
            actual_type = arg_type.replace("const ", "")
            extra["is_const_type"] = "1"
            extra["type_is"] = "class"
            text_element(method, "c_argument", name=arg_name, type=actual_type, accessed_by=arg_accessed_by, **extra)
        else:
            text_element(method, "c_argument", name=arg_name, type=arg_type, accessed_by=arg_accessed_by, **extra)
    if return_attrs is not None:
        ret_extra: dict[str, str] = {}
        ret_type = return_attrs["type"]
        if "const" in ret_type:
            ret_type = ret_type.replace("const ", "")
            ret_extra["is_const_type"] = "1"
        if ret_type.endswith("_t") and "tag" in ret_type:
            ret_extra["type_is"] = "enum"
        elif ret_type.endswith("_t"):
            ret_extra["type_is"] = "class"
        text_element(method, "c_return", type=ret_type, accessed_by=return_attrs.get("accessed_by", "value"), **ret_extra)
    else:
        text_element(method, "c_return", type="void", accessed_by="value")
    text_element(method, "c_code", code, type="generated", lang="c")
    text_element(method, "c_modifier", value=f"{prefix.upper()}_PUBLIC")
    return method


def _impl_dispatch_api(root: ET.Element, prefix: str, PREFIX: str) -> None:
    _impl_method(
        root,
        name=f"{prefix}_impl_api",
        uid=f"c_module_{prefix}_impl_method_api",
        description=(
            "Return 'API' object that is fulfiled with a meta information\n"
            "specific to the given implementation object.\n"
            "Or NULL if object does not implement requested 'API'."
        ),
        args=[
            ("impl", f"const {prefix}_impl_t", "pointer"),
            ("api_tag", f"{prefix}_api_tag_t", "value"),
        ],
        return_attrs={"type": f"const {prefix}_api_t", "accessed_by": "pointer"},
        code=(
            f"{PREFIX}_ASSERT_PTR(impl);\n"
            f"{PREFIX}_ASSERT_PTR(impl->info);\n"
            f"\n"
            f"if (impl->info->find_api_cb == NULL) {{\n"
            f"    return NULL;\n"
            f"}}\n"
            f"\n"
            f"return impl->info->find_api_cb(api_tag);"
        ),
        prefix=prefix,
    )


def _impl_dispatch_tag(root: ET.Element, prefix: str, PREFIX: str) -> None:
    _impl_method(
        root,
        name=f"{prefix}_impl_tag",
        uid=f"c_module_{prefix}_impl_method_tag",
        description="Return unique 'Implementation TAG'.",
        args=[
            ("impl", f"const {prefix}_impl_t", "pointer"),
        ],
        return_attrs={"type": f"{prefix}_impl_tag_t", "accessed_by": "value"},
        code=(
            f"{PREFIX}_ASSERT_PTR (impl);\n"
            f"{PREFIX}_ASSERT_PTR (impl->info);\n"
            f"\n"
            f"return impl->info->impl_tag;"
        ),
        prefix=prefix,
    )


def _impl_dispatch_cleanup(root: ET.Element, prefix: str, PREFIX: str) -> None:
    _impl_method(
        root,
        name=f"{prefix}_impl_cleanup",
        uid=f"c_module_{prefix}_impl_method_cleanup",
        description="Cleanup implementation object and it's dependencies.",
        args=[
            ("impl", f"{prefix}_impl_t", "pointer"),
        ],
        code=(
            f"{PREFIX}_ASSERT_PTR (impl);\n"
            f"{PREFIX}_ASSERT_PTR (impl->info);\n"
            f"{PREFIX}_ASSERT_PTR (impl->info->self_cleanup_cb);\n"
            f"\n"
            f"impl->info->self_cleanup_cb (impl);"
        ),
        prefix=prefix,
    )


def _impl_dispatch_delete(root: ET.Element, prefix: str, PREFIX: str) -> None:
    _impl_method(
        root,
        name=f"{prefix}_impl_delete",
        uid=f"c_module_{prefix}_impl_method_delete",
        description="Delete implementation object and it's dependencies.",
        args=[
            ("impl", f"{prefix}_impl_t", "pointer"),
        ],
        code=(
            f"if (impl) {{\n"
            f"    {PREFIX}_ASSERT_PTR (impl->info);\n"
            f"    {PREFIX}_ASSERT_PTR (impl->info->self_delete_cb);\n"
            f"    impl->info->self_delete_cb (impl);\n"
            f"}}"
        ),
        prefix=prefix,
    )


def _impl_dispatch_destroy(root: ET.Element, prefix: str, PREFIX: str) -> None:
    _impl_method(
        root,
        name=f"{prefix}_impl_destroy",
        uid=f"c_module_{prefix}_impl_method_destroy",
        description="Destroy implementation object and it's dependencies.",
        args=[
            ("impl_ref", f"{prefix}_impl_t", "reference"),
        ],
        code=(
            f"{PREFIX}_ASSERT_PTR (impl_ref);\n"
            f"\n"
            f"{prefix}_impl_t* impl = *impl_ref;\n"
            f"*impl_ref = NULL;\n"
            f"\n"
            f"{prefix}_impl_delete (impl);"
        ),
        prefix=prefix,
    )


def _impl_dispatch_shallow_copy(root: ET.Element, prefix: str, PREFIX: str) -> None:
    _impl_method(
        root,
        name=f"{prefix}_impl_shallow_copy",
        uid=f"c_module_{prefix}_impl_method_shallow_copy",
        description="Copy implementation object by increasing reference counter.",
        args=[
            ("impl", f"{prefix}_impl_t", "pointer"),
        ],
        return_attrs={"type": f"{prefix}_impl_t", "accessed_by": "pointer"},
        code=(
            f"{PREFIX}_ASSERT_PTR (impl);\n"
            f"\n"
            f"#if defined({PREFIX}_ATOMIC_COMPARE_EXCHANGE_WEAK)\n"
            f"//  CAS loop\n"
            f"size_t old_counter;\n"
            f"size_t new_counter;\n"
            f"do {{\n"
            f"    old_counter = impl->refcnt;\n"
            f"    new_counter = old_counter + 1;\n"
            f"}} while (!{PREFIX}_ATOMIC_COMPARE_EXCHANGE_WEAK(&impl->refcnt, &old_counter, new_counter));\n"
            f"#else\n"
            f"++impl->refcnt;\n"
            f"#endif\n"
            f"\n"
            f"return impl;"
        ),
        prefix=prefix,
    )


def _impl_dispatch_shallow_copy_const(root: ET.Element, prefix: str, PREFIX: str) -> None:
    _impl_method(
        root,
        name=f"{prefix}_impl_shallow_copy_const",
        uid=f"c_module_{prefix}_impl_method_shallow_copy_const",
        description=(
            "Copy implementation object by increasing reference counter.\n"
            "Reference counter is internally synchronized, so constness is presumed."
        ),
        args=[
            ("impl", f"const {prefix}_impl_t", "pointer"),
        ],
        return_attrs={"type": f"const {prefix}_impl_t", "accessed_by": "pointer"},
        code=f"return {prefix}_impl_shallow_copy(({prefix}_impl_t *)impl);",
        prefix=prefix,
    )


# ---------------------------------------------------------------------------
# Render: impl_private module (callback typedefs + impl_info_t + impl_t)
# ---------------------------------------------------------------------------

def render_impl_private_c_module(project_ir: IRProject) -> ET.Element:
    """Render the project-global ``impl_private`` module.

    Contains:
    - Callback typedefs: cleanup_fn, delete_fn, find_api_fn.
    - ``impl_info_t`` struct — holds impl_tag, find_api, cleanup, delete callbacks.
    - ``impl_t`` struct definition — impl_info pointer + refcount.
    """
    output = _impl_infra_output(project_ir, entity_name="impl_private", scope="private")
    root = c_module_root(output, entity_id="impl_private", scope="private", class_name="impl")
    prefix = project_ir.prefix
    PREFIX = prefix.upper()

    # --- includes -------------------------------------------------------
    text_element(root, "c_include", file=f"{prefix}_library.h")
    text_element(root, "c_include", file=f"{prefix}_impl.h")
    text_element(root, "c_include", file=f"{prefix}_atomic.h")
    text_element(root, "c_include", file=f"{prefix}_api.h")

    # --- callback: cleanup_fn -------------------------------------------
    cb_cleanup = text_element(root, "c_callback", name=f"{prefix}_impl_cleanup_fn", declaration="public")
    cb_cleanup.text = comment_text("Callback type for cleanup action.")
    text_element(cb_cleanup, "c_argument", name="impl", type=f"{prefix}_impl_t", accessed_by="pointer", type_is="class")
    text_element(cb_cleanup, "c_return", type="void", accessed_by="value")

    # --- callback: delete_fn --------------------------------------------
    cb_delete = text_element(root, "c_callback", name=f"{prefix}_impl_delete_fn", declaration="public")
    cb_delete.text = comment_text("Callback type for delete action.")
    text_element(cb_delete, "c_argument", name="impl", type=f"{prefix}_impl_t", accessed_by="pointer", type_is="class")
    text_element(cb_delete, "c_return", type="void", accessed_by="value")

    # --- callback: find_api_fn ------------------------------------------
    cb_find = text_element(root, "c_callback", name=f"{prefix}_impl_find_api_fn", declaration="public")
    cb_find.text = comment_text(
        "Returns API of the requested interface if implemented,\n"
        "otherwise - NULL."
    )
    text_element(cb_find, "c_argument", name="api_tag", type=f"{prefix}_api_tag_t", accessed_by="value", type_is="enum")
    text_element(cb_find, "c_return", type=f"{prefix}_api_t", accessed_by="pointer", is_const_type="1", type_is="class")

    # --- struct: impl_info_t --------------------------------------------
    info_struct = text_element(
        root, "c_struct",
        name=f"{prefix}_impl_info_t",
        declaration="public",
        definition="public",
    )
    info_struct.text = comment_text("Contains common properties for any 'API' implementation object.")
    p1 = text_element(info_struct, "c_property", name="impl_tag", type=f"{prefix}_impl_tag_t", accessed_by="value", type_is="enum")
    p1.text = comment_text("Implementation unique identifier, MUST be first in the structure.")
    p2 = text_element(info_struct, "c_property", name="find_api_cb", type=f"{prefix}_impl_find_api_fn", accessed_by="value", type_is="callback")
    p2.text = comment_text(
        "Callback that returns API of the requested interface if implemented, otherwise - NULL.\n"
        "MUST be second in the structure."
    )
    p3 = text_element(info_struct, "c_property", name="self_cleanup_cb", type=f"{prefix}_impl_cleanup_fn", accessed_by="value", type_is="callback")
    p3.text = comment_text("Release acquired inner resources.")
    p4 = text_element(info_struct, "c_property", name="self_delete_cb", type=f"{prefix}_impl_delete_fn", accessed_by="value", type_is="callback")
    p4.text = comment_text("Self destruction, according to destruction policy.")

    # --- struct: impl_t definition --------------------------------------
    impl_struct = text_element(
        root, "c_struct",
        name=f"{prefix}_impl_t",
        declaration="external",
        definition="public",
    )
    impl_struct.text = comment_text(
        "Contains header of any 'API' implementation structure.\n"
        "It is used for runtime type casting and checking."
    )
    ip1 = text_element(impl_struct, "c_property", name="info", type=f"{prefix}_impl_info_t", accessed_by="pointer", is_const_type="1", type_is="class")
    ip1.text = comment_text("Compile-time known information.")
    ip2 = text_element(impl_struct, "c_property", name="refcnt", type=f"{PREFIX}_ATOMIC size_t", accessed_by="value")
    ip2.text = comment_text("Reference counter.")

    return root


# ---------------------------------------------------------------------------
# Impl infrastructure: registration in discover_renderers
# ---------------------------------------------------------------------------

def _register_impl_infra_renderers(
    project_ir: IRProject,
    renderers: dict[str, DirectCRenderer],
    overrides: dict[str, DirectCRenderer],
) -> None:
    """Add renderers for api, api_private, impl, impl_private modules.

    Only applicable when the project has interfaces or implementations.
    """
    if not project_ir.interfaces and not project_ir.implementations:
        return

    specs: list[tuple[str, str, Callable[[IRProject], ET.Element]]] = [
        ("api", "public", render_api_c_module),
        ("api_private", "private", render_api_private_c_module),
        ("impl", "public", render_impl_c_module),
        ("impl_private", "private", render_impl_private_c_module),
    ]
    for entity_name, scope, render_fn in specs:
        output = _impl_infra_output(project_ir, entity_name=entity_name, scope=scope)
        xml_name = direct_xml_name(output)
        if xml_name in overrides:
            renderers[xml_name] = overrides[xml_name]
        else:
            renderers[xml_name] = (
                lambda _repo_root, _pir=project_ir, _fn=render_fn: _fn(_pir)
            )


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
            # Internal module for classes with internal-scope methods
            has_internal = any(m.attrs.get("scope") == "internal" for m in cls.methods)
            if has_internal:
                internal_out = class_internal_output(cast(IROutputTarget, cls.output))
                internal_xml = direct_xml_name(internal_out)
                if internal_xml in overrides:
                    renderers[internal_xml] = overrides[internal_xml]
                else:
                    renderers[internal_xml] = (
                        lambda _repo_root, _pir=project_ir, _c=cls: render_class_internal_c_module(_pir, _c)
                    )

    if include_all or "interface" in entity_kinds:  # type: ignore[operator]
        for iface in project_ir.interfaces:
            iface_output = cast(IROutputTarget, iface.output)
            # Dispatch module
            dispatch_xml = direct_xml_name(iface_output)
            if dispatch_xml in overrides:
                renderers[dispatch_xml] = overrides[dispatch_xml]
            else:
                renderers[dispatch_xml] = (
                    lambda _repo_root, _pir=project_ir, _i=iface: render_interface_c_module(_pir, _i)
                )
            # API module
            api_out = interface_api_output(iface_output)
            api_xml = direct_xml_name(api_out)
            if api_xml in overrides:
                renderers[api_xml] = overrides[api_xml]
            else:
                renderers[api_xml] = (
                    lambda _repo_root, _pir=project_ir, _i=iface: render_interface_api_c_module(_pir, _i)
                )

    if include_all or "implementation" in entity_kinds:  # type: ignore[operator]
        for impl in project_ir.implementations:
            impl_output = cast(IROutputTarget, impl.output)
            # Main module
            main_xml = direct_xml_name(impl_output)
            if main_xml in overrides:
                renderers[main_xml] = overrides[main_xml]
            else:
                renderers[main_xml] = (
                    lambda _repo_root, _pir=project_ir, _im=impl, _fp=getattr(project_ir, 'fallback_projects', None): render_implementation_c_module(_pir, _im, fallback_projects=_fp)
                )
            # Defs module
            defs_out = implementation_defs_output(impl_output)
            defs_xml = direct_xml_name(defs_out)
            if defs_xml in overrides:
                renderers[defs_xml] = overrides[defs_xml]
            else:
                renderers[defs_xml] = (
                    lambda _repo_root, _pir=project_ir, _im=impl, _fp=getattr(project_ir, 'fallback_projects', None): render_implementation_defs_c_module(_pir, _im, fallback_projects=_fp)
                )
            # Internal module
            internal_out = implementation_internal_output(impl_output)
            internal_xml = direct_xml_name(internal_out)
            if internal_xml in overrides:
                renderers[internal_xml] = overrides[internal_xml]
            else:
                renderers[internal_xml] = (
                    lambda _repo_root, _pir=project_ir, _im=impl, _fp=getattr(project_ir, 'fallback_projects', None): render_implementation_internal_c_module(_pir, _im, fallback_projects=_fp)
                )

    # --- project-global impl infrastructure modules ---
    # Only registered during full discovery (no entity_kinds filter)
    if include_all:
        _register_impl_infra_renderers(project_ir, renderers, overrides)

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


def _interface_dispatch_symbol(iface_output: IROutputTarget, iface_name: str, method_name: str) -> str:
    """Return the dispatch method symbol, deduplicating when method name == interface name."""
    if snake_name(method_name) == snake_name(iface_name):
        return iface_output.c_symbol
    return f"{iface_output.c_symbol}_{snake_name(method_name)}"


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
    if fallback_projects is None:
        fallback_projects = getattr(project_ir, 'fallback_projects', [])
    cls_name = src.get("class")
    if cls_name is not None:
        try:
            type_symbol = _resolve_class_type_symbol(project_ir, cls_name, fallback_projects=fallback_projects)
        except KeyError:
            type_symbol = f"{project_ir.prefix}_{snake_name(cls_name)}_t"
        # Determine accessed_by: value types (like data) are passed by value,
        # non-value types (like buffer) are passed by pointer.
        accessed_by = "value"
        is_value_type = False
        for pir in [project_ir] + (fallback_projects or []):
            try:
                cls = class_ir(pir, cls_name)
                is_value_type = cls.attrs.get("is_value_type") in {"1", "true"}
                break
            except (KeyError, StopIteration):
                continue
        if not is_value_type:
            accessed_by = "pointer"
        extra: dict[str, str] = {}
        # Legacy defaults: buffer→writeonly, everything else→readonly
        # Value types don't use const qualifier (meaningless for pass-by-value)
        effective_access = src.get("access")
        if effective_access is None:
            effective_access = "writeonly" if cls_name == "buffer" else "readonly"
        if effective_access == "readonly" and not is_value_type:
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
        declaration="external",
        definition="public",
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
    fwd_struct = text_element(
        root,
        "c_struct",
        name=api_struct_name,
        declaration="public",
        definition="external",
    )
    fwd_struct.text = comment_text(f"Contains API requirements of the interface '{iface.name}'.")

    # --- dispatch methods: non-static first, then static ---
    non_static_methods = [m for m in iface.methods if m.attrs.get("is_static") not in {"1", "true"}]
    static_methods = [m for m in iface.methods if m.attrs.get("is_static") in {"1", "true"}]
    for method in non_static_methods:
        _render_dispatch_method(root, method, iface=iface, project_ir=project_ir,
                                fallback_projects=fallback_projects)
    for method in static_methods:
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
    method_symbol = _interface_dispatch_symbol(iface_output, iface.name, method.name)
    cb_field = f"{snake_name(method.name)}_cb"

    method_attrs: dict[str, str] = {
        "name": method_symbol,
        "declaration": "public",
    }
    if visibility == "private":
        method_attrs["visibility"] = "private"

    method_elem = text_element(parent, "c_method", **method_attrs)

    # Add visibility modifier
    vis_modifier = f"{prefix.upper()}_PRIVATE" if visibility == "private" else f"{prefix.upper()}_PUBLIC"
    text_element(method_elem, "c_modifier", value=vis_modifier)

    # Add NODISCARD attribute for status-returning methods (placed after closing paren)
    if method.returns:
        ret_dict = _method_arg_dict(method.returns[0])
        if ret_dict.get("enum") == "status":
            text_element(method_elem, "c_attribute", value=f"{prefix.upper()}_NODISCARD")

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
    text_element(method_elem, "c_code", type="generated").text = code_text

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
    text_element(method_elem, "c_modifier", value=f"{prefix.upper()}_PUBLIC")
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
    text_element(method_elem, "c_code", type="generated").text = "\n".join(body_lines)

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
    text_element(method_elem, "c_modifier", value=f"{prefix.upper()}_PUBLIC")
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
    text_element(method_elem, "c_code", type="generated").text = "\n".join(body_lines)

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
    text_element(method_elem, "c_modifier", value=f"{prefix.upper()}_PUBLIC")
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
    text_element(method_elem, "c_code", type="generated").text = "\n".join(body_lines)

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
    text_element(method_elem, "c_modifier", value=f"{prefix.upper()}_PUBLIC")
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
    text_element(method_elem, "c_code", type="generated").text = "\n".join(body_lines)

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
    text_element(method_elem, "c_modifier", value=f"{prefix.upper()}_PUBLIC")
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
    text_element(method_elem, "c_code", type="generated").text = "\n".join(body_lines)

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
    # Use mixed case: preserve prefix case, uppercase only the name part
    suffix = snake_name(getattr(constant, 'name')).upper()
    if base.endswith(f"_{suffix.lower()}"):
        return base[:-len(suffix)] + suffix
    return f"{base}_{suffix}"


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
    # Un-double backslash escapes from XML model notation.
    # XML models use doubled backslashes (e.g. \\n for C's \n, \\0 for \0).
    # Replace all double-backslash sequences with single backslash.
    return text.replace('\\\\', '\\')


def _normalize_code_whitespace(text: str) -> str:
    """Normalize multiple spaces to single in code text (preserving leading indent)."""
    import re
    lines = text.splitlines()
    result = []
    for line in lines:
        stripped = line.lstrip()
        indent_part = line[:len(line) - len(stripped)]
        # Collapse multiple spaces to single in the content part
        normalized = re.sub(r'  +', ' ', stripped)
        result.append(indent_part + normalized)
    return '\n'.join(result)


def _join_continuation_lines(text: str) -> str:
    """Join lines ending with backslash continuation (for non-macro code blocks).

    Collapses 'text \\ \n  next' into 'text next' preserving exactly one space.
    """
    import re
    # Replace: optional-space, backslash, newline, leading-whitespace → single space
    result = re.sub(r'\s*\\\n\s*', ' ', text)
    # Fix cases where the join created space after ( or before )
    result = re.sub(r'\(\s+', '(', result)
    return result


def _fix_macro_paren_spacing(code: str) -> str:
    """Collapse '#define NAME (' to '#define NAME(' for function-like macros.
    Also normalizes multiple spaces in #define lines."""
    import re
    # Collapse space between macro name and ( for function-like macros
    code = re.sub(r'(#\s*define\s+\w+)\s+\(', r'\1(', code)
    # Normalize multiple spaces to single space in #define expansion (after name/params)
    lines = code.splitlines()
    result = []
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith('#') and 'define' in stripped:
            indent_part = line[:len(line) - len(stripped)]
            # Collapse multiple spaces in the #define line (outside of string literals)
            # Simple approach: collapse runs of 2+ spaces to single space after the macro name/params
            match = re.match(r'(#\s*define\s+\S+)(.*)', stripped)
            if match:
                macro_head = match.group(1)
                macro_body = match.group(2)
                # Collapse multiple spaces in body
                macro_body = re.sub(r'  +', ' ', macro_body)
                result.append(indent_part + macro_head + macro_body)
            else:
                result.append(line)
        else:
            result.append(line)
    return '\n'.join(result)


def _prepare_macro_code(code: str | None) -> str | None:
    if code is None:
        return None
    code = _fix_macro_paren_spacing(code)
    lines = code.splitlines()
    if lines and lines[0].lstrip().startswith("#define") and len(lines) > 1:
        # Strip trailing backslash continuation from each line
        stripped = [line.rstrip().removesuffix("\\").rstrip() for line in lines]
        # Join continuation lines: if a line ended with \ in the original,
        # and the next line has MORE indentation, join them (it's a wrapped call)
        merged: list[str] = []
        i = 0
        while i < len(stripped):
            current = stripped[i]
            # Check if original line had continuation and next line has deeper indent
            while (i < len(lines) - 1 and
                   lines[i].rstrip().endswith('\\') and
                   i + 1 < len(stripped) and
                   len(stripped[i + 1]) - len(stripped[i + 1].lstrip()) >
                   len(current.split('\n')[-1]) - len(current.split('\n')[-1].lstrip())):
                i += 1
                current = current.rstrip() + ' ' + stripped[i].lstrip()
            merged.append(current)
            i += 1
        return "\n".join(merged)
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
        req_attrs = require.attrs
        scope = req_attrs.get("scope", "public")
        if req_attrs.get("header"):
            # Direct header include (e.g. <require header="mbedtls/entropy.h"/>)
            text_element(root, "c_include", file=req_attrs["header"], is_system="0", scope=scope)
        elif req_attrs.get("module"):
            # Module require — resolve include via IR
            try:
                inc_file = include_file_for_entity(project_ir, entity_kind="module", entity_name=req_attrs["module"])
            except KeyError:
                # Derived module (e.g. "buffer defs") not in IR — construct include file from convention
                target_prefix = project_ir.prefix
                if req_attrs.get("project"):
                    # Cross-project require — use target project's prefix
                    for fp in getattr(project_ir, 'fallback_projects', []):
                        if getattr(fp, 'name', '') == req_attrs["project"]:
                            target_prefix = fp.prefix
                            break
                inc_file = f"{target_prefix}_{snake_name(req_attrs['module'])}.h"
            text_element(
                root,
                "c_include",
                file=inc_file,
                is_system="0",
                scope=scope,
            )
        elif req_attrs.get("class"):
            # Class require — resolve include via IR (skip if not found, e.g. framework types like "impl")
            try:
                text_element(
                    root,
                    "c_include",
                    file=include_file_for_entity(project_ir, entity_kind="class", entity_name=req_attrs["class"]),
                    is_system="0",
                    scope=scope,
                )
            except KeyError:
                pass  # Framework type not in IR (e.g. "impl") — skip
        elif req_attrs.get("interface"):
            # Interface require
            try:
                text_element(
                    root,
                    "c_include",
                    file=include_file_for_entity(project_ir, entity_kind="interface", entity_name=req_attrs["interface"]),
                    is_system="0",
                    scope=scope,
                )
            except KeyError:
                pass  # Interface not in IR — skip
        elif req_attrs.get("enum"):
            # Enum require
            try:
                text_element(
                    root,
                    "c_include",
                    file=include_file_for_entity(project_ir, entity_kind="enum", entity_name=req_attrs["enum"]),
                    is_system="0",
                    scope=scope,
                )
            except KeyError:
                pass
        # Skip library-only requires and unknown kinds gracefully

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
            text_element(callback_elem, "c_modifier", value=f"{project_ir.prefix.upper()}_NORETURN")
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
            text_element(variable_elem, "c_modifier", value=f"{project_ir.prefix.upper()}_PUBLIC")
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
        if code is not None:
            code = _join_continuation_lines(code)
            code = _normalize_code_whitespace(code)
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
            text_element(method_elem, "c_modifier", value=f"{project_ir.prefix.upper()}_PUBLIC")
        elif visibility == "private":
            text_element(method_elem, "c_modifier", value="static")
        if method.attrs.get("noreturn") in {"1", "true"}:
            text_element(method_elem, "c_modifier", value=f"{project_ir.prefix.upper()}_NORETURN")
        if method.description:
            resolved_desc = _resolve_module_placeholders(method.description, placeholders, project_prefix=project_ir.prefix) or method.description
            method_elem.text = comment_text(resolved_desc)

    for code_block in module.code_blocks:
        attrs = {key: (_resolve_module_placeholders(value, placeholders, project_prefix=project_ir.prefix) or "") for key, value in code_block["attrs"].items()}
        text_element(root, "c_code", _resolve_module_placeholders(code_block["text"], placeholders, project_prefix=project_ir.prefix), **attrs)

    # --- Library-specific assert macros ---
    if module.name == "assert" and project_ir.library_requires:
        _render_library_assert_macros(root, project_ir=project_ir)

    return root



def _render_library_assert_macros(
    parent: ET.Element,
    *,
    project_ir: IRProject,
) -> None:
    """Render library-specific assert macros for each library requirement.

    For each ``<require library="X" feature="library"/>`` or
    ``<require project="X" feature="library"/>`` in the project,
    generates:
      - A method: trigger_unhandled_error_of_{kind}_{name}
      - A macro: ASSERT_{KIND}_{NAME}_UNHANDLED_ERROR
      - A macro: ASSERT_{KIND}_{NAME}_SUCCESS
    """
    prefix = project_ir.prefix
    prefix_upper = prefix.upper()
    assert_trigger = f"{prefix}_assert_trigger"
    assert_macro = f"{prefix_upper}_ASSERT"

    for lib_req in project_ir.library_requires:
        emg = lib_req.error_message_getter
        if emg is None:
            continue

        kind_id = snake_name(lib_req.kind)
        name_id = snake_name(lib_req.name)
        kind_name_upper = f"{kind_id.upper()}_{name_id.upper()}"

        # Add header includes for the error message getter
        for header in emg.header_requires:
            text_element(parent, "c_include", file=header, is_system="1", scope="private")

        # --- Trigger method ---
        trigger_method_name = f"{prefix}_assert_trigger_unhandled_error_of_{kind_id}_{name_id}"
        trigger_code = emg.code + f"\n{assert_trigger}(error_message, file, line);"

        method_elem = text_element(
            parent,
            "c_method",
            name=trigger_method_name,
            visibility="public",
            declaration="public",
            definition="public",
            uid=f"c_class_assert_method_trigger_unhandled_error_of_{kind_id}_{name_id}",
        )
        text_element(method_elem, "c_argument", name="error", accessed_by="value", type="int", type_is="primitive")
        text_element(method_elem, "c_argument", name="file", accessed_by="value", type="char", type_is="primitive", string="given", is_const_type="1")
        text_element(method_elem, "c_argument", name="line", accessed_by="value", type="int", type_is="primitive")
        text_element(method_elem, "c_return", accessed_by="value", type="void")
        text_element(method_elem, "c_code", trigger_code, type="generated", lang="c")
        method_elem.text = comment_text(
            f"Tell assertion handler that error of {lib_req.kind} '{lib_req.name}' is not handled."
        )

        # --- UNHANDLED_ERROR macro ---
        unhandled_macro_name = f"{prefix_upper}_ASSERT_{kind_name_upper}_UNHANDLED_ERROR"
        unhandled_code = (
            f"#define {unhandled_macro_name}(error)"
            f"\n    do {{"
            f"\n        {assert_macro}((error) != {emg.success_value});"
            f"\n        {trigger_method_name}((int)(error), {prefix_upper}_FILE_PATH_OR_NAME, __LINE__);"
            f"\n    }} while (0)"
        )
        macro_elem = text_element(
            parent,
            "c_macros",
            name=unhandled_macro_name,
            uid=f"c_class_assert_macros_{kind_id}_{name_id}_unhandled_error",
            definition="public",
            is_method="1",
        )
        text_element(macro_elem, "c_code", unhandled_code, lang="c", type="generated")
        macro_elem.text = comment_text(
            f"This macros can be used as {lib_req.kind} '{lib_req.name}' error handling post-condition."
        )

        # --- SUCCESS macro ---
        success_macro_name = f"{prefix_upper}_ASSERT_{kind_name_upper}_SUCCESS"
        success_code = (
            f"#define {success_macro_name}(status)"
            f"\n    do {{"
            f"\n        if ((status) != {emg.success_value}) {{"
            f"\n            {unhandled_macro_name}(status);"
            f"\n        }}"
            f"\n    }} while (0)"
        )
        success_elem = text_element(
            parent,
            "c_macros",
            name=success_macro_name,
            uid=f"c_class_assert_macros_{kind_id}_{name_id}_success",
            definition="public",
            is_method="1",
        )
        text_element(success_elem, "c_code", success_code, lang="c", type="generated")
        success_elem.text = comment_text(
            f"This macros can be used to ensure that {lib_req.kind} '{lib_req.name}' operation "
            f"returns success status code."
        )


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


def _class_dependency_includes(project_ir: IRProject, cls: IRClass, *, scope_filter: str | None = None) -> list[str]:
    """Collect includes needed by *cls*.

    When *scope_filter* is ``None`` (default) only public-scope items are
    considered (struct fields, variables, public methods).  When set to a
    specific scope string (e.g. ``"internal"``) only methods matching that
    scope are scanned.
    """
    includes: list[str] = []
    seen: set[str] = set()

    def add_include(class_name: str | None) -> None:
        if not class_name or class_name == "self" or class_name == cls.name:
            return
        try:
            include = include_file_for_entity(project_ir, entity_kind="class", entity_name=class_name)
        except KeyError:
            return
        if include not in seen:
            seen.add(include)
            includes.append(include)

    cls_scope = cls.attrs.get("scope", "public")
    if scope_filter is None:
        # Public module: struct fields, variables, and matching-scope methods
        for field in cls.struct_fields:
            add_include(field.class_name)
        for variable in cls.variables:
            add_include(variable.class_name)
        for method in [*cls.constructors, *cls.methods]:
            method_scope = method.attrs.get("scope", cls_scope)
            if method_scope != cls_scope:
                continue  # belongs to a different scope module
            for arg in [*method.arguments, *method.returns]:
                add_include(arg.class_name)

        # Dependency includes
        for dep in cls.dependencies:
            if dep.type_kind == "class":
                add_include(dep.type_name)
            elif dep.type_kind in {"interface", "impl"}:
                iface_include = f"{project_ir.prefix}_{snake_name(dep.type_name)}.h"
                if iface_include not in seen:
                    seen.add(iface_include)
                    includes.append(iface_include)
    else:
        # Extended module (e.g. internal): only methods with matching scope
        for method in cls.methods:
            if method.attrs.get("scope") != scope_filter:
                continue
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

    # Macros
    for macro in cls.macroses:
        _render_class_macro(root, macro, project_ir=project_ir, cls=cls)

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
        # Determine module scope — only render methods whose scope matches
        module_scope = scope or cls.attrs.get("scope", "public")
        for method in cls.methods:
            method_scope = method.attrs.get("scope", module_scope)
            if method_scope != module_scope:
                # Method belongs to a different scope module (e.g. internal)
                continue
            method_args = list(_method_arg_dict(arg) for arg in method.arguments)
            has_context = cls.attrs.get("context", "public") != "none"
            is_static_method = method.attrs.get("is_static") in {"1", "true"}
            if has_context and not is_static_method:
                if not is_value_type:
                    self_attrs: dict[str, str] = {"class": "self"}
                    if method.attrs.get("is_const") in {"1", "true"}:
                        self_attrs["access"] = "readonly"
                    method_args.insert(0, {"name": "self", **self_attrs})
                else:
                    method_args.insert(0, {"name": "self", "class": "self"})
            return_attrs = _method_arg_dict(method.returns[0]) if method.returns else {"type": "void"}
            method_vis = method.attrs.get("visibility", "public")
            _render_ir_method(
                root,
                name=class_method_symbol(project_ir, cls, method.name),
                description=method.description,
                arguments=tuple(method_args),
                return_attrs=return_attrs,
                owner_class=cls.name,
                project_ir=project_ir,
                visibility=method_vis,
                uid=f"direct_{snake_name(cls.name)}_method_{snake_name(method.name)}",
            )

    return root



def render_class_internal_c_module(
    project_ir: IRProject,
    cls: IRClass,
) -> ET.Element:
    """Render the *internal* module for a class.

    Contains methods marked ``scope='internal'`` that shouldn't be in the
    public header.  The module is header-only and lives in ``src/``.
    """
    class_output = cast(IROutputTarget, cls.output)
    internal_output = class_internal_output(class_output)
    root = c_module_root(
        internal_output,
        entity_id=f"{snake_name(cls.name)}_internal",
        scope="internal",
        class_name=cls.name,
    )
    root.set("header_only", "1")

    # Require the main class module
    text_element(root, "c_include", file=class_output.include_file, is_system="0", scope="public")

    # Add dependency includes needed by internal methods
    for include in _class_dependency_includes(project_ir, cls, scope_filter="internal"):
        text_element(root, "c_include", file=include, is_system="0", scope="public")

    is_value_type = cls.attrs.get("is_value_type") in {"1", "true"}
    has_context = cls.attrs.get("context", "public") != "none"
    for method in cls.methods:
        if method.attrs.get("scope") != "internal":
            continue
        method_args = list(_method_arg_dict(arg) for arg in method.arguments)
        is_static_method = method.attrs.get("is_static") in {"1", "true"}
        if has_context and not is_static_method:
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
            uid=f"direct_{snake_name(cls.name)}_internal_method_{snake_name(method.name)}",
        )

    return root


def _method_arg_dict(arg: object) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for attr_name, key in (("class_name", "class"), ("interface_name", "interface"), ("callback", "callback"), ("type_name", "type"), ("access", "access"), ("library", "library"), ("enum_name", "enum")):
        value = getattr(arg, attr_name, None)
        if value is not None:
            attrs[key] = value
    if getattr(arg, "is_reference", False):
        attrs["is_reference"] = "1"
    if getattr(arg, "is_string", False):
        attrs["type"] = "string"
    if getattr(arg, "is_array", False):
        attrs["_array"] = "given"
    type_size = getattr(arg, "type_size", None)
    if type_size is not None:
        attrs["size"] = type_size
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
    for modifier in [f"{project_ir.prefix.upper()}_PUBLIC"] if variable_attrs["visibility"] == "public" else []:
        text_element(var_elem, "c_modifier", value=modifier)
    if getattr(variable, "description", ""):
        var_elem.text = comment_text(getattr(variable, "description"))
    return var_elem



def _render_class_macro(parent: ET.Element, macro, *, project_ir: IRProject, cls: IRClass) -> ET.Element:
    """Render a class macro (e.g. VSCF_ERROR_SAFE_UPDATE)."""
    from tools.codegen.project_ir import IRClassMacro
    class_output = cast(IROutputTarget, cls.output)
    # Macro public name uses {PREFIX}_{CLASS}_{MACRO_NAME} without 'macros' infix
    macro_upper = f"{class_output.c_symbol}_{snake_name(macro.name)}".upper()
    # Resolve code: replace .(c_class_X_macros_Y) and .(c_class_X_method_Z) references
    code = macro.code
    # Remove trailing space after GSL reference to avoid space before macro args
    code = code.replace(f".(c_class_{snake_name(cls.name)}_macros_{snake_name(macro.name)}) ", f"{macro_upper}")
    code = code.replace(f".(c_class_{snake_name(cls.name)}_macros_{snake_name(macro.name)})", macro_upper)
    # Replace method references like .(c_class_error_method_update)
    for method in cls.methods:
        method_sym = class_method_symbol(project_ir, cls, method.name)
        code = code.replace(f".(c_class_{snake_name(cls.name)}_method_{snake_name(method.name)})", method_sym)
    macros_elem = text_element(
        parent,
        "c_macros",
        name=macro_upper,
        definition="public",
        uid=f"c_class_{snake_name(cls.name)}_macros_{snake_name(macro.name)}",
    )
    text_element(macros_elem, "c_code", code.strip(), type="generated", lang="c")
    if macro.description:
        macros_elem.text = comment_text(macro.description)
    return macros_elem


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
    text_element(method, "c_modifier", value=f"{project_ir.prefix.upper()}_PUBLIC")
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
#   Implementation constructor helpers.
# ---------------------------------------------------------------------------


def impl_constructor_symbol(project_ir: IRProject, impl: IRImplementation, ctor_name: str) -> str:
    """Return the C symbol for an implementation's init_with_X constructor."""
    impl_output = cast(IROutputTarget, impl.output)
    return f"{impl_output.c_symbol}_init_{snake_name(ctor_name)}"


def _impl_new_constructor_symbol(project_ir: IRProject, impl: IRImplementation, ctor_name: str) -> str:
    """Return the C symbol for an implementation's new_with_X constructor."""
    impl_output = cast(IROutputTarget, impl.output)
    return f"{impl_output.c_symbol}_new_{snake_name(ctor_name)}"


def _impl_lifecycle_constructor_init_body(
    project_ir: IRProject,
    impl: IRImplementation,
    ctor_name: str,
    ctor_arg_names: list[str],
) -> str:
    """Generate the body for the implementation init_with_X() constructor."""
    impl_output = cast(IROutputTarget, impl.output)
    prefix_upper = project_ir.prefix.upper()
    struct_type = f"{impl_output.c_symbol}_t"
    init_ctx_method = f"{impl_output.c_symbol}_init_ctx_{snake_name(ctor_name)}"
    proxy_args = ", ".join(["self"] + ctor_arg_names)
    return (
        f"{prefix_upper}_ASSERT_PTR(self);\n"
        f"\n"
        f"{project_ir.prefix}_zeroize(self, sizeof({struct_type}));\n"
        f"\n"
        f"self->info = &info;\n"
        f"self->refcnt = 1;\n"
        f"\n"
        f"{init_ctx_method}({proxy_args});"
    )


def _impl_lifecycle_constructor_new_body(
    project_ir: IRProject,
    impl: IRImplementation,
    ctor_name: str,
    ctor_arg_names: list[str],
) -> str:
    """Generate the body for the implementation new_with_X() constructor."""
    impl_output = cast(IROutputTarget, impl.output)
    struct_type = f"{impl_output.c_symbol}_t"
    new_method = f"{impl_output.c_symbol}_new"
    init_method = impl_constructor_symbol(project_ir, impl, ctor_name)
    proxy_args = ", ".join(["self"] + ctor_arg_names)
    return (
        f"{struct_type} *self = {new_method}();\n"
        f"\n"
        f"{init_method}({proxy_args});\n"
        f"\n"
        f"return self;"
    )


def _build_impl_ctor_args(
    ctor: "IRCMethod",
    project_ir: IRProject,
    fallback_projects: list[IRProject] | None = None,
) -> list[dict[str, str]]:
    """Build argument dict list for an implementation constructor.

    Handles access='disown' by switching accessed_by to 'reference'
    and appending '_ref' to the argument name.
    """
    ctor_args: list[dict[str, str]] = []
    for arg in ctor.arguments:
        arg_name = snake_name(arg.name)
        arg_dict: dict[str, str] = {"name": arg_name}
        if arg.class_name:
            arg_dict["class"] = arg.class_name
            if arg.access == "readonly":
                arg_dict["is_const"] = "1"
            is_value = False
            for fp in (fallback_projects or []):
                try:
                    cls_ir = class_ir(fp, arg.class_name)
                    if cls_ir.attrs.get("is_value_type") in {"1", "true"}:
                        is_value = True
                    break
                except KeyError:
                    pass
            if not is_value:
                try:
                    cls_ir = class_ir(project_ir, arg.class_name)
                    if cls_ir.attrs.get("is_value_type") in {"1", "true"}:
                        is_value = True
                except KeyError:
                    pass
            if arg.access == "disown":
                arg_dict["accessed_by"] = "reference"
                arg_dict["name"] = f"{arg_name}_ref"
            else:
                arg_dict["accessed_by"] = "value" if is_value else "pointer"
        elif arg.interface_name:
            arg_dict["class"] = "impl"
            if arg.access == "readonly":
                arg_dict["is_const"] = "1"
            if arg.access == "disown":
                arg_dict["accessed_by"] = "reference"
                arg_dict["name"] = f"{arg_name}_ref"
            else:
                arg_dict["accessed_by"] = "pointer"
        elif arg.enum_name:
            arg_dict["enum"] = arg.enum_name
        elif arg.type_name:
            arg_dict["type"] = arg.type_name
        ctor_args.append(arg_dict)
    return ctor_args


# ---------------------------------------------------------------------------
#   Dependency management method generation helpers.
# ---------------------------------------------------------------------------

def _dependency_use_body(
    project_ir: IRProject,
    cls: IRClass | IRImplementation,
    dep: "IRDependency",
    *,
    entity_kind: str = "class",
) -> str:
    """Generate the body for the use_X() dependency method."""
    prefix_upper = project_ir.prefix.upper()
    class_symbol = entity_output(project_ir, entity_kind=entity_kind, entity_name=cls.name).c_symbol
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
    cls: IRClass | IRImplementation,
    dep: "IRDependency",
    *,
    entity_kind: str = "class",
) -> str:
    """Generate the body for the take_X() dependency method."""
    prefix_upper = project_ir.prefix.upper()
    class_symbol = entity_output(project_ir, entity_kind=entity_kind, entity_name=cls.name).c_symbol
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
    cls: IRClass | IRImplementation,
    dep: "IRDependency",
    *,
    entity_kind: str = "class",
) -> str:
    """Generate the body for the release_X() dependency method."""
    prefix_upper = project_ir.prefix.upper()
    class_symbol = entity_output(project_ir, entity_kind=entity_kind, entity_name=cls.name).c_symbol
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
    owner_entity_kind: str = "class",
) -> ET.Element:
    """Render a dependency use/take method with a typed dependency argument.

    This bypasses ``_render_ir_method`` because the dependency argument
    is not a class/type/callback in the IR sense — it's a raw C type
    (e.g. ``vscf_impl_t``) that must appear as ``type_is='class'``
    and ``accessed_by='pointer'`` in the generated XML.
    """
    class_type = f"{entity_output(project_ir, entity_kind=owner_entity_kind, entity_name=owner_class).c_symbol}_t"
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
    text_element(method, "c_modifier", value=f"{project_ir.prefix.upper()}_PUBLIC")
    # NODISCARD attribute for status-returning methods
    if return_type == "status":
        text_element(method, "c_attribute", value=f"{project_ir.prefix.upper()}_NODISCARD")
    # description
    if description:
        method.text = comment_text(description)
    return method


def _render_dep_observer_method(
    parent: ET.Element,
    *,
    name: str,
    description: str,
    return_attrs: dict[str, str] | None,
    project_ir: IRProject,
    owner_name: str,
    entity_kind: str = "class",
    code: str = "// TODO: This is STUB. Implement me.",
    uid: str = "",
) -> None:
    """Render observer hook (did_setup/did_release) for a dependency.

    Uses ``_render_ir_method`` for classes and direct XML construction for
    implementations, avoiding the class-only lookup in ``argument_from_source``.
    """
    if entity_kind == "class":
        _render_ir_method(
            parent,
            name=name,
            description=description,
            arguments=({"name": "self", "class": "self"},),
            return_attrs=return_attrs,
            project_ir=project_ir,
            owner_class=owner_name,
            visibility="private",
            declaration="private",
            definition="private",
            modifiers=("static",),
            code=code,
            uid=uid,
        )
    else:
        owner_type = f"{entity_output(project_ir, entity_kind=entity_kind, entity_name=owner_name).c_symbol}_t"
        method = text_element(
            parent,
            "c_method",
            name=name,
            visibility="private",
            declaration="private",
            definition="private",
            uid=uid,
        )
        text_element(method, "c_argument", name="self", accessed_by="pointer", type=owner_type, type_is="class")
        if return_attrs is None or return_attrs.get("type") == "void":
            text_element(method, "c_return", accessed_by="value", type="void")
        elif return_attrs.get("enum"):
            enum_name = return_attrs["enum"]
            try:
                enum_out = entity_output(project_ir, entity_kind="enum", entity_name=enum_name)
                rendered_type = f"{enum_out.c_symbol}_t"
            except (KeyError, ValueError):
                rendered_type = f"{project_ir.prefix}_{snake_name(enum_name)}_t"
            text_element(method, "c_return", accessed_by="value", type=rendered_type, type_is="primitive")
        else:
            rendered_type, kind = type_map(return_attrs.get("type"))
            text_element(method, "c_return", accessed_by="value", type=rendered_type, type_is=kind)
        text_element(method, "c_code", code, type="generated", lang="c")
        text_element(method, "c_modifier", value="static")
        if description:
            method.text = comment_text(description)


def _render_dependency_methods(
    parent: ET.Element,
    *,
    project_ir: IRProject,
    cls: IRClass | IRImplementation,
    entity_kind: str = "class",
    skip_observers: bool = False,
) -> None:
    """Render use/take/release methods for each class/implementation dependency.

    Also renders did_setup/did_release observer hooks for dependencies
    that have ``has_observers`` set.
    """
    class_symbol = entity_output(project_ir, entity_kind=entity_kind, entity_name=cls.name).c_symbol
    class_snake = snake_name(cls.name)

    for dep in cls.dependencies:
        dep_field = snake_name(dep.name)
        dep_type = _dependency_type_symbol(project_ir, dep)

        # --- Observer hooks (rendered before use/take/release so forward decls work) ---
        if dep.has_observers and not skip_observers:
            # did_setup
            did_setup_name = f"{class_symbol}_did_setup_{dep_field}"
            did_setup_return: dict[str, str] | None = {"type": "void"}
            did_setup_code = "// TODO: This is STUB. Implement me."
            if dep.is_observers_return_status:
                did_setup_return = {"type": "status", "enum": "status"}
                did_setup_code = "// TODO: This is STUB. Implement me.\nreturn vscf_status_SUCCESS;"
            _render_dep_observer_method(
                parent,
                name=did_setup_name,
                description=f"This method is called when {dep.type_kind} '{dep.type_name}' was setup.",
                return_attrs=did_setup_return,
                project_ir=project_ir,
                owner_name=cls.name,
                entity_kind=entity_kind,
                code=did_setup_code,
                uid=f"direct_{class_snake}_did_setup_{dep_field}",
            )
            # did_release
            did_release_name = f"{class_symbol}_did_release_{dep_field}"
            _render_dep_observer_method(
                parent,
                name=did_release_name,
                description=f"This method is called when {dep.type_kind} '{dep.type_name}' was released.",
                return_attrs={"type": "void"},
                project_ir=project_ir,
                owner_name=cls.name,
                entity_kind=entity_kind,
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
            code=_dependency_use_body(project_ir, cls, dep, entity_kind=entity_kind),
            owner_class=cls.name,
            project_ir=project_ir,
            uid=f"direct_{class_snake}_use_{dep_field}",
            owner_entity_kind=entity_kind,
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
                code=_dependency_take_body(project_ir, cls, dep, entity_kind=entity_kind),
                owner_class=cls.name,
                project_ir=project_ir,
                uid=f"direct_{class_snake}_take_{dep_field}",
                owner_entity_kind=entity_kind,
            )

        # --- release_X ---
        release_code = _dependency_release_body(project_ir, cls, dep, entity_kind=entity_kind)
        release_name = f"{class_symbol}_release_{dep_field}"
        release_desc = f"Release dependency to the {dep.type_kind} '{dep.type_name}'."
        if entity_kind == "class":
            _render_ir_method(
                parent,
                name=release_name,
                description=release_desc,
                arguments=({"name": "self", "class": "self"},),
                return_attrs={"type": "void"},
                project_ir=project_ir,
                owner_class=cls.name,
                code=release_code,
                uid=f"direct_{class_snake}_release_{dep_field}",
            )
        else:
            # For implementations, build release method directly to avoid
            # class_type_symbol lookup which only handles classes.
            owner_type = f"{entity_output(project_ir, entity_kind=entity_kind, entity_name=cls.name).c_symbol}_t"
            method = text_element(
                parent,
                "c_method",
                name=release_name,
                visibility="public",
                declaration="public",
                definition="public",
                uid=f"direct_{class_snake}_release_{dep_field}",
            )
            text_element(method, "c_argument", name="self", accessed_by="pointer", type=owner_type, type_is="class")
            text_element(method, "c_return", accessed_by="value", type="void")
            text_element(method, "c_code", release_code, type="generated", lang="c")
            text_element(method, "c_modifier", value=f"{project_ir.prefix.upper()}_PUBLIC")
            if release_desc:
                method.text = comment_text(release_desc)


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
    modifiers: tuple[str, ...] | None = None,
    code: str | None = None,
    uid: str | None = None,
) -> ET.Element:
    if modifiers is None:
        if visibility == "private":
            modifiers = (f"{project_ir.prefix.upper()}_PRIVATE",)
        else:
            modifiers = (f"{project_ir.prefix.upper()}_PUBLIC",)
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
            f"Perform context specific initialization.\nNote, this method is called automatically when method {_class_runtime_symbol(project_ir, cls, 'init')}() is called.\nNote, that context is already zeroed.",
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

    class_symbol = _class_runtime_symbol(project_ir, cls, "")
    # Emit: init, cleanup, new
    for name, description, arguments, return_attrs, body in [
        (_class_runtime_symbol(project_ir, cls, "init"), "Perform initialization of pre-allocated context.", ({"name": "self", "class": "self"},), {"type": "void"}, _lifecycle_init_body(project_ir, cls)),
        (_class_runtime_symbol(project_ir, cls, "cleanup"), "Release all inner resources including class dependencies.", ({"name": "self", "class": "self"},), {"type": "void"}, _lifecycle_cleanup_body(project_ir, cls)),
        (_class_runtime_symbol(project_ir, cls, "new"), "Allocate context and perform it's initialization.", (), {"class": "self"}, _lifecycle_new_body(project_ir, cls)),
    ]:
        _render_ir_method(parent, name=name, description=description, arguments=arguments, return_attrs=return_attrs, project_ir=project_ir, owner_class=cls.name, code=body)

    # Emit constructor variants (init_with_X, new_with_X) — between new and delete to match legacy ordering
    for ctor in cls.constructors:
        args = tuple(_method_arg_dict(arg) for arg in ctor.arguments)
        ctor_arg_names = [_method_arg_dict(arg)["name"] for arg in ctor.arguments]
        init_name = class_constructor_symbol(project_ir, cls, ctor.name)
        new_name = _class_new_constructor_symbol(project_ir, cls, ctor.name)
        ctor_vis = ctor.attrs.get("visibility", "public")
        _render_ir_method(
            parent,
            name=init_name,
            description=f"Perform initialization of pre-allocated context.\n{ctor.description}",
            arguments=({"name": "self", "class": "self"}, *args),
            return_attrs={"type": "void"},
            project_ir=project_ir,
            owner_class=cls.name,
            visibility=ctor_vis,
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
            visibility=ctor_vis,
            uid=f"direct_{snake_name(cls.name)}_new_with_{snake_name(ctor.name)}",
            code=_lifecycle_constructor_new_body(project_ir, cls, ctor.name, ctor_arg_names),
        )

    # Emit: delete, destroy, shallow_copy
    full_new_name = _class_runtime_symbol(project_ir, cls, "new")
    for name, description, arguments, return_attrs, body in [
        (_class_runtime_symbol(project_ir, cls, "delete"), "Release all inner resources and deallocate context if needed.\nIt is safe to call this method even if the context was statically allocated.", ({"name": "self", "class": "self"},), {"type": "void"}, _lifecycle_delete_body(project_ir, cls)),
        (_class_runtime_symbol(project_ir, cls, "destroy"), f"Delete given context and nullifies reference.\nThis is a reverse action of the function '{full_new_name} ()'.", ({"name": "self_ref", "class": "self", "access": "readwrite", "passed_by": "reference"},), {"type": "void"}, _lifecycle_destroy_body(project_ir, cls)),
        (_class_runtime_symbol(project_ir, cls, "shallow_copy"), "Copy given class context by increasing reference counter.", ({"name": "self", "class": "self"},), {"class": "self"}, _lifecycle_shallow_copy_body(project_ir, cls)),
    ]:
        _render_ir_method(parent, name=name, description=description, arguments=arguments, return_attrs=return_attrs, project_ir=project_ir, owner_class=cls.name, code=body)

    # Dependency management methods: use/take/release (+ observer hooks).
    _render_dependency_methods(parent, project_ir=project_ir, cls=cls)



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

    if prop.interface_name is not None:
        # Interface property → resolve to {prefix}_impl_t pointer
        attrs.update({
            "type": f"{project_ir.prefix}_impl_t",
            "type_is": "class",
            "accessed_by": "pointer",
        })
    elif prop.enum_name is not None:
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
        accessed_by = "pointer" if prop.is_reference else "value"
        attrs.update({
            "type": rendered_type,
            "type_is": kind,
            "accessed_by": accessed_by,
        })
        # Handle const qualifier for readonly pointer properties
        if prop.is_reference and prop.access == "readonly":
            attrs["is_const_type"] = "1"

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

    # Dependency fields — each dependency becomes a {prefix}_impl_t pointer
    for dep in impl.dependencies:
        dep_name = snake_name(dep.name)
        dep_uid = f"c_class_{snake_name(impl.name)}_struct_{snake_name(impl.name)}_property_{dep_name}"
        dep_elem = text_element(
            struct_elem,
            "c_property",
            name=dep_name,
            accessed_by="pointer",
            type=f"{prefix}_impl_t",
            type_is="class",
            uid=dep_uid,
        )
        dep_elem.text = comment_text(dep.description or f"Dependency '{dep.name}'.")

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


def _impl_lifecycle_init_body(
    project_ir: IRProject,
    impl: IRImplementation,
) -> str:
    """Generate the body for the implementation init() method."""
    impl_output = cast(IROutputTarget, impl.output)
    struct_type = f"{impl_output.c_symbol}_t"
    prefix_upper = project_ir.prefix.upper()
    init_ctx = f"{impl_output.c_symbol}_init_ctx"
    return (
        f"{prefix_upper}_ASSERT_PTR(self);\n"
        f"\n"
        f"{project_ir.prefix}_zeroize(self, sizeof({struct_type}));\n"
        f"\n"
        f"self->info = &info;\n"
        f"self->refcnt = 1;\n"
        f"\n"
        f"{init_ctx}(self);"
    )


def _impl_lifecycle_cleanup_body(
    project_ir: IRProject,
    impl: IRImplementation,
) -> str:
    """Generate the body for the implementation cleanup() method."""
    impl_output = cast(IROutputTarget, impl.output)
    struct_type = f"{impl_output.c_symbol}_t"
    cleanup_ctx = f"{impl_output.c_symbol}_cleanup_ctx"
    return (
        f"if (self == NULL) {{\n"
        f"    return;\n"
        f"}}\n"
        f"\n"
        f"{cleanup_ctx}(self);\n"
        f"\n"
        f"{project_ir.prefix}_zeroize(self, sizeof({struct_type}));"
    )


def _impl_lifecycle_new_body(
    project_ir: IRProject,
    impl: IRImplementation,
) -> str:
    """Generate the body for the implementation new() method."""
    impl_output = cast(IROutputTarget, impl.output)
    struct_type = f"{impl_output.c_symbol}_t"
    prefix_upper = project_ir.prefix.upper()
    init_method = f"{impl_output.c_symbol}_init"
    return (
        f"{struct_type} *self = ({struct_type} *) {project_ir.prefix}_alloc(sizeof ({struct_type}));\n"
        f"{prefix_upper}_ASSERT_ALLOC(self);\n"
        f"\n"
        f"{init_method}(self);\n"
        f"\n"
        f"return self;"
    )


def _impl_lifecycle_delete_body(
    project_ir: IRProject,
    impl: IRImplementation,
) -> str:
    """Generate the body for the implementation delete() method."""
    impl_output = cast(IROutputTarget, impl.output)
    prefix_upper = project_ir.prefix.upper()
    cleanup_method = f"{impl_output.c_symbol}_cleanup"
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
        f"{cleanup_method}(self);\n"
        f"\n"
        f"{project_ir.prefix}_dealloc(self);"
    )


def _impl_lifecycle_destroy_body(
    project_ir: IRProject,
    impl: IRImplementation,
) -> str:
    """Generate the body for the implementation destroy() method."""
    impl_output = cast(IROutputTarget, impl.output)
    struct_type = f"{impl_output.c_symbol}_t"
    prefix_upper = project_ir.prefix.upper()
    delete_method = f"{impl_output.c_symbol}_delete"
    return (
        f"{prefix_upper}_ASSERT_PTR(self_ref);\n"
        f"\n"
        f"{struct_type} *self = *self_ref;\n"
        f"*self_ref = NULL;\n"
        f"\n"
        f"{delete_method}(self);"
    )


def _impl_lifecycle_shallow_copy_body(
    project_ir: IRProject,
    impl: IRImplementation,
) -> str:
    """Generate the body for the implementation shallow_copy() method."""
    impl_output = cast(IROutputTarget, impl.output)
    struct_type = f"{impl_output.c_symbol}_t"
    return (
        f"// Proxy to the parent implementation.\n"
        f"return ({struct_type} *){project_ir.prefix}_impl_shallow_copy(({project_ir.prefix}_impl_t *)self);"
    )


def _render_impl_method(
    parent: ET.Element,
    *,
    name: str,
    description: str,
    impl: IRImplementation,
    project_ir: IRProject,
    arguments: list[dict[str, str]] | None = None,
    return_type: str | None = None,
    return_class: str | None = None,
    return_is_const: bool = False,
    return_accessed_by: str = "value",
    code: str | None = None,
    code_type: str = "generated",
    visibility: str = "public",
    declaration: str = "public",
    definition: str = "external",
    modifiers: tuple[str, ...] = (),
    attributes: tuple[str, ...] = (),
    fallback_projects: list[IRProject] | None = None,
) -> ET.Element:
    """Render a method element for an implementation module."""
    impl_output = cast(IROutputTarget, impl.output)
    struct_type = f"{impl_output.c_symbol}_t"
    prefix_upper = project_ir.prefix.upper()
    impl_snake = snake_name(impl.name)

    method = text_element(
        parent,
        "c_method",
        name=name,
        visibility=visibility,
        declaration=declaration,
        definition=definition,
        uid=f"c_class_{impl_snake}_method_{snake_name(name.removeprefix(impl_output.c_symbol + '_'))}",
    )

    # Attributes (e.g. VSCF_NODISCARD)
    for attr_val in attributes:
        text_element(method, "c_attribute", value=attr_val)

    # Arguments
    if arguments is not None:
        for arg in arguments:
            arg_name = arg.get("name", "")
            if arg.get("is_self"):
                extra: dict[str, str] = {}
                if arg.get("is_const"):
                    extra["is_const_type"] = "1"
                accessed_by = "reference" if arg.get("passed_by") == "reference" else "pointer"
                text_element(
                    method, "c_argument",
                    name=arg_name,
                    accessed_by=accessed_by,
                    type=struct_type,
                    type_is="class",
                    uid=f"c_class_{impl_snake}_method_{snake_name(name.removeprefix(impl_output.c_symbol + '_'))}_argument_{snake_name(arg_name)}",
                    **extra,
                )
            elif arg.get("class"):
                cls_name = arg["class"]
                if cls_name == "self":
                    # class="self" refers to the owning implementation's concrete type
                    type_sym = struct_type
                else:
                    try:
                        type_sym = _resolve_class_type_symbol(
                            project_ir, cls_name, fallback_projects=fallback_projects
                        )
                    except KeyError:
                        type_sym = f"{project_ir.prefix}_{snake_name(cls_name)}_t"
                extra = {}
                if arg.get("is_const"):
                    extra["is_const_type"] = "1"
                text_element(
                    method, "c_argument",
                    name=arg_name,
                    accessed_by=arg.get("accessed_by", "pointer"),
                    type=type_sym,
                    type_is="class",
                    uid=f"c_class_{impl_snake}_method_{snake_name(name.removeprefix(impl_output.c_symbol + '_'))}_argument_{snake_name(arg_name)}",
                    **extra,
                )
            elif arg.get("enum"):
                enum_name = arg["enum"]
                try:
                    enum_out = entity_output(project_ir, entity_kind="enum", entity_name=enum_name)
                    rendered_type = f"{enum_out.c_symbol}_t"
                except (KeyError, ValueError):
                    rendered_type = f"{project_ir.prefix}_{snake_name(enum_name)}_t"
                text_element(
                    method, "c_argument",
                    name=arg_name,
                    accessed_by="value",
                    type=rendered_type,
                    type_is="primitive",
                    uid=f"c_class_{impl_snake}_method_{snake_name(name.removeprefix(impl_output.c_symbol + '_'))}_argument_{snake_name(arg_name)}",
                )
            elif arg.get("type"):
                rendered_type, kind = type_map(arg.get("type"))
                extra = {}
                if arg.get("is_const"):
                    extra["is_const_type"] = "1"
                text_element(
                    method, "c_argument",
                    name=arg_name,
                    accessed_by=arg.get("accessed_by", "value"),
                    type=rendered_type,
                    type_is=kind,
                    uid=f"c_class_{impl_snake}_method_{snake_name(name.removeprefix(impl_output.c_symbol + '_'))}_argument_{snake_name(arg_name)}",
                    **extra,
                )
            else:
                text_element(method, "c_argument", type="void", accessed_by="value")
    else:
        text_element(method, "c_argument", type="void", accessed_by="value")

    # Return
    if return_type:
        if return_type == "status":
            # Status is a project-specific enum type
            rendered_type = f"{project_ir.prefix}_status_t"
            kind = "primitive"
        elif return_type.startswith("enum:"):
            # Resolved enum type
            enum_name = return_type[5:]
            try:
                enum_out = entity_output(project_ir, entity_kind="enum", entity_name=enum_name)
                rendered_type = f"{enum_out.c_symbol}_t"
            except (KeyError, ValueError):
                rendered_type = f"{project_ir.prefix}_{snake_name(enum_name)}_t"
            kind = "primitive"
        else:
            rendered_type, kind = type_map(return_type)
        extra = {}
        if return_is_const:
            extra["is_const_type"] = "1"
        text_element(method, "c_return", accessed_by=return_accessed_by, type=rendered_type, type_is=kind, **extra)
    elif return_class:
        if return_class == "self_impl":
            type_sym = struct_type
        elif return_class == "impl":
            type_sym = f"{project_ir.prefix}_impl_t"
        else:
            try:
                type_sym = _resolve_class_type_symbol(
                    project_ir, return_class, fallback_projects=fallback_projects
                )
            except KeyError:
                type_sym = f"{project_ir.prefix}_{snake_name(return_class)}_t"
        extra = {}
        if return_is_const:
            extra["is_const_type"] = "1"
        # Determine accessed_by: value types (like data) returned by value
        ret_accessed_by = "pointer"
        if return_class not in ("self_impl", "impl"):
            for pir in [project_ir] + (fallback_projects or []):
                try:
                    ret_cls = class_ir(pir, return_class)
                    if ret_cls.attrs.get("is_value_type") in {"1", "true"}:
                        ret_accessed_by = "value"
                    break
                except (KeyError, StopIteration):
                    continue
        text_element(method, "c_return", accessed_by=ret_accessed_by, type=type_sym, type_is="class", **extra)
    else:
        text_element(method, "c_return", type="void", accessed_by="value")

    # Code
    if code is not None:
        text_element(method, "c_code", code, type=code_type, lang="c")

    # Modifiers
    if not modifiers:
        if visibility == "public":
            modifiers = (f"{prefix_upper}_PUBLIC",)
        elif declaration == "private" and definition == "private":
            modifiers = ("static",)
        else:
            modifiers = (f"{prefix_upper}_PRIVATE",)
    for mod in modifiers:
        text_element(method, "c_modifier", value=mod)

    if description:
        method.text = comment_text(description)

    return method


def _render_impl_interface_methods(
    parent: ET.Element,
    *,
    impl: IRImplementation,
    project_ir: IRProject,
    fallback_projects: list[IRProject] | None = None,
) -> None:
    """Render interface method stubs for all bound interfaces."""
    impl_output = cast(IROutputTarget, impl.output)

    for binding in impl.interface_bindings:
        try:
            iface = interface_ir(project_ir, binding.name)
        except KeyError:
            continue

        for method in iface.methods:
            method_name = f"{impl_output.c_symbol}_{snake_name(method.name)}"
            is_static = method.attrs.get("is_static") == "1"

            # Build argument list
            args: list[dict[str, str]] = []
            if not is_static:
                # Non-static methods get self as first arg
                is_const_self = method.attrs.get("is_const") == "1"
                args.append({"name": "self", "is_self": "1", **({
                    "is_const": "1"} if is_const_self else {})})

            for arg in method.arguments:
                arg_dict: dict[str, str] = {"name": snake_name(arg.name)}
                if arg.class_name:
                    arg_dict["class"] = arg.class_name
                    # Resolve effective access: legacy defaults to 'readonly' except
                    # buffer arguments which default to 'writeonly'
                    effective_access = arg.access
                    if effective_access is None:
                        if arg.class_name == "buffer":
                            effective_access = "writeonly"
                        else:
                            effective_access = "readonly"
                    # Determine accessed_by: value types (data) passed by value
                    is_value = arg.kind == "value"
                    if not is_value:
                        # Check if the class is a value type via IR lookup
                        for fp in (fallback_projects or []):
                            try:
                                cls = class_ir(fp, arg.class_name)
                                if cls.attrs.get("is_value_type") in {"1", "true"}:
                                    is_value = True
                                break
                            except KeyError:
                                pass
                        if not is_value:
                            try:
                                cls = class_ir(project_ir, arg.class_name)
                                if cls.attrs.get("is_value_type") in {"1", "true"}:
                                    is_value = True
                            except KeyError:
                                pass
                    arg_dict["accessed_by"] = "value" if is_value else "pointer"
                    # Apply const for non-value readonly args
                    if effective_access == "readonly" and not is_value:
                        arg_dict["is_const"] = "1"
                elif arg.interface_name:
                    # Interface arguments are passed as impl_t pointers
                    arg_dict["class"] = "impl"
                    if arg.access in ("readonly", None):
                        arg_dict["is_const"] = "1"
                    arg_dict["accessed_by"] = "pointer"
                elif arg.type_name:
                    resolved_arg_type, _ = type_map(arg.type_name, getattr(arg, 'type_size', None))
                    arg_dict["type"] = resolved_arg_type
                    is_pointer = arg.is_reference or arg.is_array
                    accessed_by = "pointer" if is_pointer else "value"
                    arg_dict["accessed_by"] = accessed_by
                    if is_pointer and arg.access in ("readonly", None) and not arg.is_array:
                        arg_dict["is_const"] = "1"
                args.append(arg_dict)

            # Return type
            ret_type = None
            ret_class = None
            ret_is_const = False
            ret_accessed_by = "value"
            attrs_list: tuple[str, ...] = ()
            if method.returns:
                ret = method.returns[0]
                if ret.enum_name:
                    # Enum return — resolve to C type name
                    ret_type = f"enum:{ret.enum_name}"
                elif ret.interface_name:
                    # Interface return — returns impl_t pointer
                    ret_class = "impl"
                elif ret.class_name:
                    ret_class = ret.class_name
                elif ret.type_name:
                    resolved_ret_type, _ = type_map(ret.type_name, getattr(ret, 'type_size', None))
                    ret_type = resolved_ret_type
                    if ret.is_reference:
                        ret_accessed_by = "pointer"
                        if ret.access == "readonly":
                            ret_is_const = True

            # Check for NODISCARD / status return
            if method.returns and method.returns[0].enum_name == "status":
                attrs_list = (f"{project_ir.prefix.upper()}_NODISCARD",)
                ret_type = "status"

            method_visibility = method.attrs.get("visibility", "public")
            _render_impl_method(
                parent,
                name=method_name,
                description=method.description or f"Implementation of the {iface.name} interface method.",
                impl=impl,
                project_ir=project_ir,
                arguments=args if args else None,
                return_type=ret_type,
                return_class=ret_class,
                return_is_const=ret_is_const,
                return_accessed_by=ret_accessed_by,
                code="//  TODO: This is STUB. Implement me.",
                code_type="stub",
                visibility=method_visibility,
                declaration="public",
                definition="private",
                attributes=attrs_list,
                fallback_projects=fallback_projects,
            )


def render_implementation_internal_c_module(
    project_ir: IRProject,
    impl: IRImplementation,
    *,
    fallback_projects: list[IRProject] | None = None,
) -> ET.Element:
    """Render the internal module for an implementation.

    Produces:
    - Static API table variables — one per implemented interface, each populated
      with function pointers to the concrete implementations
    - The ``impl_info`` variable — describes the implementation
    - Lifecycle methods (init, cleanup, new, delete, destroy, shallow_copy)
      with ``definition="private"`` (the definitions live here)
    - The ``find_api`` static method
    - init_ctx / cleanup_ctx with ``declaration="public"`` / ``definition="external"``
    """
    impl_output = cast(IROutputTarget, impl.output)
    internal_output = implementation_internal_output(impl_output)
    defs_output = implementation_defs_output(impl_output)
    prefix = project_ir.prefix
    prefix_upper = prefix.upper()
    impl_snake = snake_name(impl.name)
    struct_type = f"{impl_output.c_symbol}_t"

    root = c_module_root(
        internal_output,
        entity_id=f"{impl_snake} internal",
        scope="internal",
    )
    root.set("feature", f"{prefix_upper}_{impl_snake.upper()}")

    # --- includes ---
    # Self-include (private)
    text_element(root, "c_include", file=internal_output.include_file, is_system="0", scope="private")
    # Standard library / utility includes
    text_element(root, "c_include", file=f"{prefix}_library.h", is_system="0", scope="public")
    text_element(root, "c_include", file=f"{prefix}_memory.h", is_system="0", scope="private")
    text_element(root, "c_include", file=f"{prefix}_assert.h", is_system="0", scope="private")
    # Implementation's own header and defs header
    text_element(root, "c_include", file=impl_output.include_file, is_system="0", scope="public")
    text_element(root, "c_include", file=defs_output.include_file, is_system="0", scope="private")

    # Interface dispatch + api headers for each bound interface (and its ancestors)
    seen_iface_includes: set[str] = set()
    for binding in impl.interface_bindings:
        _add_interface_includes_recursive(
            root, binding.name, project_ir=project_ir, seen=seen_iface_includes,
        )

    # --- did_setup / did_release forward declarations (Pattern D) ---
    # These are forward declarations for observer hooks whose definitions
    # live in the handwritten .c file.
    for dep in impl.dependencies:
        if not dep.has_observers:
            continue
        dep_field = snake_name(dep.name)
        # did_setup
        did_setup_name = f"{impl_output.c_symbol}_did_setup_{dep_field}"
        did_setup_method = text_element(
            root,
            "c_method",
            name=did_setup_name,
            visibility="private",
            declaration="private",
            definition="external",
            uid=f"c_class_{impl_snake}_method_did_setup_{dep_field}",
        )
        text_element(did_setup_method, "c_argument", name="self", accessed_by="pointer", type=struct_type, type_is="class")
        if dep.is_observers_return_status:
            try:
                enum_out = entity_output(project_ir, entity_kind="enum", entity_name="status")
                rendered_type = f"{enum_out.c_symbol}_t"
            except (KeyError, ValueError):
                rendered_type = f"{prefix}_status_t"
            text_element(did_setup_method, "c_return", accessed_by="value", type=rendered_type, type_is="primitive")
            text_element(did_setup_method, "c_attribute", value=f"{prefix_upper}_NODISCARD")
        else:
            text_element(did_setup_method, "c_return", accessed_by="value", type="void")
        text_element(did_setup_method, "c_modifier", value=f"{prefix_upper}_PRIVATE")
        did_setup_method.text = comment_text(f"This method is called when {dep.type_kind} '{dep.type_name}' was setup.")

        # did_release
        did_release_name = f"{impl_output.c_symbol}_did_release_{dep_field}"
        did_release_method = text_element(
            root,
            "c_method",
            name=did_release_name,
            visibility="private",
            declaration="private",
            definition="external",
            uid=f"c_class_{impl_snake}_method_did_release_{dep_field}",
        )
        text_element(did_release_method, "c_argument", name="self", accessed_by="pointer", type=struct_type, type_is="class")
        text_element(did_release_method, "c_return", accessed_by="value", type="void")
        text_element(did_release_method, "c_modifier", value=f"{prefix_upper}_PRIVATE")
        did_release_method.text = comment_text(f"This method is called when {dep.type_kind} '{dep.type_name}' was released.")

    # --- API table variables (one per bound interface) ---
    api_var_names: list[tuple[str, str]] = []  # (iface_name, var_name)
    for binding in impl.interface_bindings:
        try:
            iface = interface_ir(project_ir, binding.name)
        except KeyError:
            continue
        iface_output = cast(IROutputTarget, iface.output)
        var_name = f"{snake_name(binding.name)}_api"
        api_tag = f"{prefix}_api_tag_{snake_name(binding.name).upper()}"
        impl_tag = f"{prefix}_impl_tag_{impl_snake.upper()}"
        api_type = _interface_api_struct_symbol(iface_output)

        var_elem = text_element(
            root,
            "c_variable",
            name=var_name,
            uid=f"c_class_{impl_snake}_variable_{var_name}",
            visibility="public",
            declaration="private",
            definition="private",
            accessed_by="value",
            type=api_type,
            type_is="class",
            is_const_type="1",
        )

        # api_tag value
        val = text_element(
            var_elem, "c_value",
            value=api_tag, accessed_by="value",
            type=f"{prefix}_api_tag_t", type_is="primitive",
        )
        val.text = comment_text(
            f"API's unique identifier, MUST be first in the structure.\n"
            f"For interface '{binding.name}' MUST be equal to the  '{api_tag}'."
        )

        # impl_tag value
        val = text_element(
            var_elem, "c_value",
            value=impl_tag, accessed_by="value",
            type=f"{prefix}_impl_tag_t", type_is="primitive",
        )
        val.text = comment_text("Implementation unique identifier, MUST be second in the structure.")

        # Inherited API pointers
        for inherited_name in iface.inherits:
            inherited_var_name = f"{snake_name(inherited_name)}_api"
            try:
                inherited_iface_output = entity_output(project_ir, entity_kind="interface", entity_name=inherited_name)
                inherited_api_type = _interface_api_struct_symbol(inherited_iface_output)
            except (KeyError, ValueError):
                inherited_api_type = f"{prefix}_{snake_name(inherited_name)}_api_t"
            val = text_element(
                var_elem, "c_value",
                value=inherited_var_name, accessed_by="pointer",
                type=inherited_api_type, type_is="class",
                is_const_type="1",
            )
            val.text = comment_text(f"Link to the inherited interface API '{inherited_name}'.")

        # Method callback function pointers
        for method in iface.methods:
            fn_name = f"{impl_output.c_symbol}_{snake_name(method.name)}"
            cb_type = _interface_callback_symbol(iface_output, method.name)
            val = text_element(
                var_elem, "c_value",
                value=fn_name, accessed_by="value",
                type=cb_type, type_is="callback",
            )
            # Add c_cast child element
            text_element(
                val, "c_cast",
                accessed_by="value",
                type=cb_type, type_is="callback",
            )
            desc = method.description.strip() if method.description else ""
            if desc:
                val.text = comment_text(desc)

        # Constant values from interface binding
        for const in binding.constants:
            const_symbol = _impl_binding_constant_symbol(impl_output, const.name)
            # Determine the type from the interface constant definition
            iface_const = next(
                (c for c in iface.constants if c.name == const.name), None
            )
            const_c_type = "size_t"
            const_type_is = "primitive"
            if iface_const:
                const_c_type, const_type_is = type_map(iface_const.attrs.get("type", "size"))
            val = text_element(
                var_elem, "c_value",
                value=const_symbol, accessed_by="value",
                type=const_c_type, type_is=const_type_is,
            )
            desc = ""
            if iface_const and iface_const.description:
                desc = iface_const.description.strip()
            if desc:
                val.text = comment_text(desc)

        # Modifier
        text_element(var_elem, "c_modifier", value=f"{prefix_upper}_PUBLIC")
        var_elem.text = comment_text(f"Configuration of the interface API '{binding.name} api'.")
        api_var_names.append((binding.name, var_name))

    # --- impl_info variable ---
    info_elem = text_element(
        root,
        "c_variable",
        name="info",
        uid=f"c_class_{impl_snake}_variable_info",
        visibility="public",
        declaration="private",
        definition="private",
        accessed_by="value",
        type=f"{prefix}_impl_info_t",
        type_is="class",
        is_const_type="1",
    )
    # impl_tag
    val = text_element(
        info_elem, "c_value",
        value=f"{prefix}_impl_tag_{impl_snake.upper()}",
        accessed_by="value",
        type=f"{prefix}_impl_tag_t", type_is="primitive",
    )
    val.text = comment_text("Implementation unique identifier, MUST be first in the structure.")
    # find_api callback
    val = text_element(
        info_elem, "c_value",
        value=f"{impl_output.c_symbol}_find_api",
        accessed_by="value",
        type=f"{prefix}_impl_find_api_fn", type_is="callback",
    )
    val.text = comment_text(
        "Callback that returns API of the requested interface if implemented, otherwise - NULL.\n"
        "MUST be second in the structure."
    )
    # cleanup callback
    val = text_element(
        info_elem, "c_value",
        value=f"{impl_output.c_symbol}_cleanup",
        accessed_by="value",
        type=f"{prefix}_impl_cleanup_fn", type_is="callback",
    )
    text_element(
        val, "c_cast",
        accessed_by="value",
        type=f"{prefix}_impl_cleanup_fn", type_is="callback",
    )
    val.text = comment_text("Release acquired inner resources.")
    # delete callback
    val = text_element(
        info_elem, "c_value",
        value=f"{impl_output.c_symbol}_delete",
        accessed_by="value",
        type=f"{prefix}_impl_delete_fn", type_is="callback",
    )
    text_element(
        val, "c_cast",
        accessed_by="value",
        type=f"{prefix}_impl_delete_fn", type_is="callback",
    )
    val.text = comment_text("Self destruction, according to destruction policy.")
    text_element(info_elem, "c_modifier", value=f"{prefix_upper}_PUBLIC")
    info_elem.text = comment_text(f"Compile-time known information about '{impl.name}' implementation.")

    # --- Lifecycle methods (definition="private", declaration="external") ---
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_init",
        description="Perform initialization of preallocated implementation context.",
        impl=impl, project_ir=project_ir,
        arguments=[{"name": "self", "is_self": "1"}],
        code=_impl_lifecycle_init_body(project_ir, impl),
        declaration="external",
        definition="private",
    )
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_cleanup",
        description="Cleanup implementation context and release dependencies.\n"
                    f"This is a reverse action of the function '{impl_output.c_symbol}_init()'.",
        impl=impl, project_ir=project_ir,
        arguments=[{"name": "self", "is_self": "1"}],
        code=_impl_lifecycle_cleanup_body(project_ir, impl),
        declaration="external",
        definition="private",
    )
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_new",
        description="Allocate implementation context and perform it's initialization.\n"
                    "Postcondition: check memory allocation result.",
        impl=impl, project_ir=project_ir,
        return_class="self_impl",
        code=_impl_lifecycle_new_body(project_ir, impl),
        declaration="external",
        definition="private",
    )
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_delete",
        description="Delete given implementation context and it's dependencies.\n"
                    f"This is a reverse action of the function '{impl_output.c_symbol}_new()'.",
        impl=impl, project_ir=project_ir,
        arguments=[{"name": "self", "is_self": "1"}],
        code=_impl_lifecycle_delete_body(project_ir, impl),
        declaration="external",
        definition="private",
    )
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_destroy",
        description="Destroy given implementation context and it's dependencies.\n"
                    f"This is a reverse action of the function '{impl_output.c_symbol}_new()'.\n"
                    "Given reference is nullified.",
        impl=impl, project_ir=project_ir,
        arguments=[{"name": "self_ref", "is_self": "1", "passed_by": "reference"}],
        code=_impl_lifecycle_destroy_body(project_ir, impl),
        declaration="external",
        definition="private",
    )
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_shallow_copy",
        description="Copy given implementation context by increasing reference counter.",
        impl=impl, project_ir=project_ir,
        arguments=[{"name": "self", "is_self": "1"}],
        return_class="self_impl",
        code=_impl_lifecycle_shallow_copy_body(project_ir, impl),
        declaration="external",
        definition="private",
    )

    # --- init_ctx / cleanup_ctx (declaration="public", definition="external") ---
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_init_ctx",
        description="Provides initialization of the implementation specific context.\n"
                    f"Note, this method is called automatically when method {impl_output.c_symbol}_init() is called.\n"
                    "Note, that context is already zeroed.",
        impl=impl, project_ir=project_ir,
        arguments=[{"name": "self", "is_self": "1"}],
        code="//  TODO: This is STUB. Implement me.",
        code_type="stub",
        visibility="private",
        declaration="public",
        definition="external",
    )
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_cleanup_ctx",
        description="Release resources of the implementation specific context.\n"
                    "Note, this method is called automatically once when class is completely cleaning up.\n"
                    "Note, that context will be zeroed automatically next this method.",
        impl=impl, project_ir=project_ir,
        arguments=[{"name": "self", "is_self": "1"}],
        code="//  TODO: This is STUB. Implement me.",
        code_type="stub",
        visibility="private",
        declaration="public",
        definition="external",
    )

    # --- Constructor lifecycle methods (init_with_X, new_with_X) definitions ---
    for ctor in impl.constructors:
        ctor_suffix = snake_name(ctor.name)
        ctor_visibility = ctor.attrs.get("visibility", "public")
        ctor_new_args = _build_impl_ctor_args(ctor, project_ir, fallback_projects)
        ctor_args = [{"name": "self", "is_self": "1"}, *ctor_new_args]
        ctor_arg_names = [a["name"] for a in ctor_new_args]
        init_method_name = impl_constructor_symbol(project_ir, impl, ctor.name)
        new_method_name = _impl_new_constructor_symbol(project_ir, impl, ctor.name)
        init_description = f"Perform initialization of pre-allocated context.\n{ctor.description or ''}".strip()
        new_description = f"Allocate implementation context and perform it's initialization.\n{ctor.description or ''}".strip()

        # init_with_X definition in internal module
        _render_impl_method(
            root,
            name=init_method_name,
            description=init_description,
            impl=impl,
            project_ir=project_ir,
            arguments=ctor_args,
            code=_impl_lifecycle_constructor_init_body(project_ir, impl, ctor.name, ctor_arg_names),
            visibility=ctor_visibility,
            declaration="external",
            definition="private",
            fallback_projects=fallback_projects,
        )

        # new_with_X definition in internal module
        _render_impl_method(
            root,
            name=new_method_name,
            description=new_description,
            impl=impl,
            project_ir=project_ir,
            arguments=ctor_new_args if ctor_new_args else None,
            return_class="self_impl",
            code=_impl_lifecycle_constructor_new_body(project_ir, impl, ctor.name, ctor_arg_names),
            visibility=ctor_visibility,
            declaration="external",
            definition="private",
            fallback_projects=fallback_projects,
        )

    # --- init_ctx_with_X stubs (one per constructor) ---
    for ctor in impl.constructors:
        ctor_suffix = snake_name(ctor.name)
        ctor_ctx_args = [{"name": "self", "is_self": "1"}, *_build_impl_ctor_args(ctor, project_ir, fallback_projects)]

        _render_impl_method(
            root,
            name=f"{impl_output.c_symbol}_init_ctx_{ctor_suffix}",
            description=f"{ctor.description or ''}".strip() or "Provides initialization of the implementation specific context.",
            impl=impl, project_ir=project_ir,
            arguments=ctor_ctx_args,
            code="//  TODO: This is STUB. Implement me.",
            code_type="stub",
            visibility="private",
            declaration="public",
            definition="external",
            fallback_projects=fallback_projects,
        )

    # --- impl_size method ---
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_impl_size",
        description=f"Return size of '{struct_type}' type.",
        impl=impl, project_ir=project_ir,
        return_type="size",
        code=f"return sizeof ({struct_type});",
        declaration="external",
        definition="private",
    )

    # --- impl() cast method ---
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_impl",
        description="Cast to the 'vscf_impl_t' type.",
        impl=impl, project_ir=project_ir,
        arguments=[{"name": "self", "is_self": "1"}],
        return_class="impl",
        code=f"{prefix_upper}_ASSERT_PTR(self);\nreturn ({prefix}_impl_t *)(self);",
        declaration="external",
        definition="private",
        fallback_projects=fallback_projects,
    )

    # --- impl_const() cast method ---
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_impl_const",
        description="Cast to the const 'vscf_impl_t' type.",
        impl=impl, project_ir=project_ir,
        arguments=[{"name": "self", "is_self": "1", "is_const": "1"}],
        return_class="impl",
        return_is_const=True,
        code=f"{prefix_upper}_ASSERT_PTR(self);\nreturn (const {prefix}_impl_t *)(self);",
        declaration="external",
        definition="private",
        fallback_projects=fallback_projects,
    )

    # --- find_api static method ---
    switch_cases = []
    for iface_name, var_name in sorted(api_var_names, key=lambda x: snake_name(x[0]).upper()):
        tag = f"{prefix}_api_tag_{snake_name(iface_name).upper()}"
        switch_cases.append(
            f"case {tag}:\n"
            f"    return (const {prefix}_api_t *){' ' * 17}&{var_name};"
        )
    find_api_body = (
        "switch(api_tag) {\n"
        + "\n".join(f"    {case}" for case in switch_cases)
        + "\n    default:\n        return NULL;\n}"
    )
    find_api = text_element(
        root,
        "c_method",
        name=f"{impl_output.c_symbol}_find_api",
        visibility="public",
        declaration="private",
        definition="private",
        uid=f"c_class_{impl_snake}_method_find_api",
    )
    text_element(
        find_api, "c_argument",
        name="api_tag", accessed_by="value",
        type=f"{prefix}_api_tag_t", type_is="primitive",
        uid=f"c_class_{impl_snake}_method_find_api_argument_api_tag",
    )
    text_element(
        find_api, "c_return",
        accessed_by="pointer",
        type=f"{prefix}_api_t", type_is="class",
        is_const_type="1",
    )
    text_element(find_api, "c_code", find_api_body, type="generated", lang="c")
    text_element(find_api, "c_modifier", value="static")

    # --- Interface API accessor functions (Pattern B) ---
    # e.g. vscf_aes256_gcm_cipher_info_api(void) → returns &cipher_info_api;
    for binding in impl.interface_bindings:
        try:
            iface = interface_ir(project_ir, binding.name)
        except KeyError:
            continue
        iface_output = cast(IROutputTarget, iface.output)
        iface_snake = snake_name(binding.name)
        api_type = _interface_api_struct_symbol(iface_output)
        accessor_name = f"{impl_output.c_symbol}_{iface_snake}_api"
        var_name = f"{iface_snake}_api"

        accessor = text_element(
            root,
            "c_method",
            name=accessor_name,
            visibility="public",
            declaration="external",
            definition="private",
            uid=f"c_class_{impl_snake}_method_{iface_snake}_api",
        )
        text_element(
            accessor, "c_return",
            accessed_by="pointer",
            type=api_type, type_is="class",
            is_const_type="1",
        )
        text_element(accessor, "c_code", f"return &{var_name};", type="generated", lang="c")
        text_element(accessor, "c_modifier", value=f"{prefix_upper}_PUBLIC")
        accessor.text = comment_text(f"Returns instance of the implemented interface '{binding.name}'.")

    root.text = comment_text(
        "This module contains logic for interface/implementation architecture.\n"
        "Do not use this module in any part of the code."
    )

    return root


def _add_interface_includes_recursive(
    root: ET.Element,
    iface_name: str,
    *,
    project_ir: IRProject,
    seen: set[str],
) -> None:
    """Add dispatch + api includes for an interface and all its ancestors."""
    if iface_name in seen:
        return
    seen.add(iface_name)
    try:
        iface = interface_ir(project_ir, iface_name)
    except KeyError:
        return
    iface_output = cast(IROutputTarget, iface.output)
    api_output = interface_api_output(iface_output)
    text_element(root, "c_include", file=iface_output.include_file, is_system="0", scope="private")
    text_element(root, "c_include", file=api_output.include_file, is_system="0", scope="private")
    for inherited_name in iface.inherits:
        _add_interface_includes_recursive(root, inherited_name, project_ir=project_ir, seen=seen)


def render_implementation_c_module(
    project_ir: IRProject,
    impl: IRImplementation,
    *,
    fallback_projects: list[IRProject] | None = None,
) -> ET.Element:
    """Render the main module for an implementation.

    Produces:
    - Interface binding constants (enum)
    - Struct declaration (definition is in defs module)
    - Lifecycle methods: init, cleanup, new, delete, destroy, shallow_copy
    - impl_size, impl, impl_const cast helpers
    - init_ctx, cleanup_ctx stubs
    - Interface method implementation stubs
    """
    impl_output = cast(IROutputTarget, impl.output)
    defs_output = implementation_defs_output(impl_output)
    internal_output = implementation_internal_output(impl_output)
    prefix = project_ir.prefix
    prefix_upper = prefix.upper()
    impl_snake = snake_name(impl.name)
    struct_type = f"{impl_output.c_symbol}_t"

    root = c_module_root(
        impl_output,
        entity_id=impl_snake,
        scope="public",
    )
    root.set("feature", f"{prefix_upper}_{impl_snake.upper()}")

    # --- includes ---
    text_element(root, "c_include", file=f"{prefix}_library.h", is_system="0", scope="public")
    text_element(root, "c_include", file=f"{prefix}_assert.h", is_system="0", scope="private")
    text_element(root, "c_include", file=f"{prefix}_memory.h", is_system="0", scope="private")

    # Library header includes (context scope — for the struct type in implementation)
    for req in impl.requirements:
        if req.kind == "header":
            text_element(root, "c_include", file=req.name, is_system="1", scope="context")

    # Interface/impl requirement includes
    for req in impl.requirements:
        if req.kind == "interface":
            try:
                iface_out = entity_output(project_ir, entity_kind="interface", entity_name=req.name)
                text_element(root, "c_include", file=iface_out.include_file, is_system="0", scope="private")
            except (KeyError, ValueError):
                pass
        elif req.kind == "impl":
            # Requirement for another implementation (e.g. simple_alg_info)
            try:
                impl_out = entity_output(project_ir, entity_kind="implementation", entity_name=req.name)
                text_element(root, "c_include", file=impl_out.include_file, is_system="0", scope="private")
            except (KeyError, ValueError):
                pass

    # Interface binding headers (public scope — needed for _api(void) accessor return types)
    for binding in impl.interface_bindings:
        try:
            iface_out = entity_output(project_ir, entity_kind="interface", entity_name=binding.name)
            text_element(root, "c_include", file=iface_out.include_file, is_system="0", scope="public")
        except (KeyError, ValueError):
            pass

    # Defs and internal headers
    text_element(root, "c_include", file=defs_output.include_file, is_system="0", scope="private")
    text_element(root, "c_include", file=internal_output.include_file, is_system="0", scope="private")

    # --- Interface binding constants (as enum) ---
    # Build a lookup of interface constant descriptions for enrichment (D7)
    _iface_const_descs: dict[str, dict[str, str]] = {}
    for binding in impl.interface_bindings:
        try:
            iface = interface_ir(project_ir, binding.name)
            _iface_const_descs[binding.name] = {c.name: c.description for c in iface.constants}
        except KeyError:
            _iface_const_descs[binding.name] = {}

    all_constants = []
    for binding in impl.interface_bindings:
        iface_descs = _iface_const_descs.get(binding.name, {})
        for const in binding.constants:
            const_symbol = _impl_binding_constant_symbol(impl_output, const.name)
            desc = const.description or iface_descs.get(const.name, "")
            all_constants.append((const_symbol, const.value, desc))

    if all_constants:
        enum_elem = text_element(
            root,
            "c_enum",
            declaration="public",
            definition="public",
        )
        for const_symbol, value, desc in all_constants:
            const_elem = text_element(
                enum_elem,
                "c_constant",
                name=const_symbol,
                value=value,
                definition="public",
                uid=f"c_class_{impl_snake}_constant_{snake_name(const_symbol.removeprefix(impl_output.c_symbol + '_').lower())}",
            )
            if desc:
                const_elem.text = comment_text(desc)
        enum_elem.text = comment_text("Public integral constants.")

    # --- Struct declaration (definition is external / in defs module) ---
    struct_elem = text_element(
        root,
        "c_struct",
        name=struct_type,
        visibility="public",
        declaration="public",
        definition="external",
        uid=f"c_class_{impl_snake}_struct_{impl_snake}",
    )
    # Re-declare struct properties for the declaration (same as defs)
    info_prop = text_element(
        struct_elem, "c_property",
        name="info", accessed_by="pointer",
        type=f"{prefix}_impl_info_t", type_is="class", is_const_type="1",
        uid=f"c_class_{impl_snake}_struct_{impl_snake}_property_info",
    )
    info_prop.text = comment_text("Compile-time known information about this implementation.")
    refcnt_prop = text_element(
        struct_elem, "c_property",
        name="refcnt", accessed_by="value",
        type=f"{prefix_upper}_ATOMIC size_t", type_is="primitive",
        uid=f"c_class_{impl_snake}_struct_{impl_snake}_property_refcnt",
    )
    refcnt_prop.text = comment_text("Reference counter.")
    for prop in impl.properties:
        prop_attrs = _resolve_impl_property_type(
            prop, project_ir=project_ir, impl=impl, fallback_projects=fallback_projects
        )
        prop_name = prop_attrs.pop("name")
        uid = f"c_class_{impl_snake}_struct_{impl_snake}_property_{prop_name}"
        prop_elem = text_element(struct_elem, "c_property", name=prop_name, uid=uid, **prop_attrs)
        prop_elem.text = comment_text("Implementation specific context.")
    # Dependency fields (same as defs)
    for dep in impl.dependencies:
        dep_name = snake_name(dep.name)
        dep_uid = f"c_class_{impl_snake}_struct_{impl_snake}_property_{dep_name}"
        dep_elem = text_element(
            struct_elem, "c_property",
            name=dep_name,
            accessed_by="pointer",
            type=f"{prefix}_impl_t",
            type_is="class",
            uid=dep_uid,
        )
        dep_elem.text = comment_text(dep.description or f"Dependency '{dep.name}'.")
    struct_elem.text = comment_text("Handles implementation details.")

    # --- impl_size method ---
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_impl_size",
        description=f"Return size of '{struct_type}' type.",
        impl=impl, project_ir=project_ir,
        return_type="size",
        code=f"return sizeof ({struct_type});",
    )

    # --- impl() cast method ---
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_impl",
        description="Cast to the 'vscf_impl_t' type.",
        impl=impl, project_ir=project_ir,
        arguments=[{"name": "self", "is_self": "1"}],
        return_class="impl",
        code=f"{prefix_upper}_ASSERT_PTR(self);\nreturn ({prefix}_impl_t *)(self);",
        fallback_projects=fallback_projects,
    )

    # --- impl_const() cast method ---
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_impl_const",
        description="Cast to the const 'vscf_impl_t' type.",
        impl=impl, project_ir=project_ir,
        arguments=[{"name": "self", "is_self": "1", "is_const": "1"}],
        return_class="impl",
        return_is_const=True,
        code=f"{prefix_upper}_ASSERT_PTR(self);\nreturn (const {prefix}_impl_t *)(self);",
        fallback_projects=fallback_projects,
    )

    # --- Lifecycle methods ---
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_init",
        description="Perform initialization of preallocated implementation context.",
        impl=impl, project_ir=project_ir,
        arguments=[{"name": "self", "is_self": "1"}],
        code=_impl_lifecycle_init_body(project_ir, impl),
    )
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_cleanup",
        description="Cleanup implementation context and release dependencies.\nThis is a reverse action of the function '{}_init()'.".format(impl_output.c_symbol),
        impl=impl, project_ir=project_ir,
        arguments=[{"name": "self", "is_self": "1"}],
        code=_impl_lifecycle_cleanup_body(project_ir, impl),
    )
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_new",
        description="Allocate implementation context and perform it's initialization.\nPostcondition: check memory allocation result.",
        impl=impl, project_ir=project_ir,
        return_class="self_impl",
        code=_impl_lifecycle_new_body(project_ir, impl),
    )
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_delete",
        description="Delete given implementation context and it's dependencies.\nThis is a reverse action of the function '{}_new()'.".format(impl_output.c_symbol),
        impl=impl, project_ir=project_ir,
        arguments=[{"name": "self", "is_self": "1"}],
        code=_impl_lifecycle_delete_body(project_ir, impl),
    )
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_destroy",
        description="Destroy given implementation context and it's dependencies.\nThis is a reverse action of the function '{}_new()'.\nGiven reference is nullified.".format(impl_output.c_symbol),
        impl=impl, project_ir=project_ir,
        arguments=[{"name": "self_ref", "is_self": "1", "passed_by": "reference"}],
        code=_impl_lifecycle_destroy_body(project_ir, impl),
    )
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_shallow_copy",
        description="Copy given implementation context by increasing reference counter.",
        impl=impl, project_ir=project_ir,
        arguments=[{"name": "self", "is_self": "1"}],
        return_class="self_impl",
        code=_impl_lifecycle_shallow_copy_body(project_ir, impl),
    )

    # --- init_ctx / cleanup_ctx stubs ---
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_init_ctx",
        description="Provides initialization of the implementation specific context.\n"
                    f"Note, this method is called automatically when method {impl_output.c_symbol}_init() is called.\n"
                    "Note, that context is already zeroed.",
        impl=impl, project_ir=project_ir,
        arguments=[{"name": "self", "is_self": "1"}],
        code="//  TODO: This is STUB. Implement me.",
        code_type="stub",
        visibility="private",
        declaration="external",
        definition="private",
    )
    _render_impl_method(
        root, name=f"{impl_output.c_symbol}_cleanup_ctx",
        description="Release resources of the implementation specific context.\n"
                    "Note, this method is called automatically once when class is completely cleaning up.\n"
                    "Note, that context will be zeroed automatically next this method.",
        impl=impl, project_ir=project_ir,
        arguments=[{"name": "self", "is_self": "1"}],
        code="//  TODO: This is STUB. Implement me.",
        code_type="stub",
        visibility="private",
        declaration="external",
        definition="private",
    )

    # --- Dependency management methods: use/take/release ---
    if impl.dependencies:
        _render_dependency_methods(root, project_ir=project_ir, cls=impl, entity_kind="implementation", skip_observers=True)

    # --- Constructor methods (init_with_X, new_with_X) ---
    for ctor in impl.constructors:
        ctor_suffix = snake_name(ctor.name)
        ctor_visibility = ctor.attrs.get("visibility", "public")
        ctor_args = _build_impl_ctor_args(ctor, project_ir, fallback_projects)
        ctor_arg_names = [a["name"] for a in ctor_args]
        init_method_name = impl_constructor_symbol(project_ir, impl, ctor.name)
        new_method_name = _impl_new_constructor_symbol(project_ir, impl, ctor.name)
        init_description = f"Perform initialization of pre-allocated context.\n{ctor.description or ''}".strip()
        new_description = f"Allocate implementation context and perform it's initialization.\n{ctor.description or ''}".strip()

        # init_with_X: declaration in public header, definition in internal module
        _render_impl_method(
            root,
            name=init_method_name,
            description=init_description,
            impl=impl,
            project_ir=project_ir,
            arguments=[{"name": "self", "is_self": "1"}, *(ctor_args if ctor_args else [])],
            code=_impl_lifecycle_constructor_init_body(project_ir, impl, ctor.name, ctor_arg_names),
            visibility=ctor_visibility,
            declaration="public",
            definition="external",
            fallback_projects=fallback_projects,
        )

        # new_with_X: declaration in public header, definition in internal module
        _render_impl_method(
            root,
            name=new_method_name,
            description=new_description,
            impl=impl,
            project_ir=project_ir,
            arguments=ctor_args if ctor_args else None,
            return_class="self_impl",
            code=_impl_lifecycle_constructor_new_body(project_ir, impl, ctor.name, ctor_arg_names),
            visibility=ctor_visibility,
            declaration="public",
            definition="external",
            fallback_projects=fallback_projects,
        )

    # --- Interface method implementations ---
    _render_impl_interface_methods(
        root, impl=impl, project_ir=project_ir, fallback_projects=fallback_projects
    )

    # --- Implementation-specific methods ---
    for method in impl.methods:
        method_name = f"{impl_output.c_symbol}_{snake_name(method.name)}"
        method_vis = method.attrs.get("visibility", method.attrs.get("scope",
            method.attrs.get("declaration", "private")))
        if method_vis == "internal":
            method_vis = "private"
        method_decl = method.attrs.get("declaration", "private")
        # Skip methods with explicit declaration="private" — their declarations are hand-written
        if "declaration" in method.attrs and method_decl == "private":
            continue

        args: list[dict[str, str]] = []
        is_static = method.attrs.get("is_static") == "1"
        is_const_self = method.attrs.get("is_const") == "1"
        if not is_static:
            args.append({"name": "self", "is_self": "1", **(
                {"is_const": "1"} if is_const_self else {})})

        for arg in method.arguments:
            arg_dict: dict[str, str] = {"name": snake_name(arg.name)}
            if arg.class_name:
                arg_dict["class"] = arg.class_name
                # Resolve effective access: legacy defaults to 'readonly' except
                # buffer arguments which default to 'writeonly'
                effective_access = arg.access
                if effective_access is None:
                    if arg.class_name == "buffer":
                        effective_access = "writeonly"
                    else:
                        effective_access = "readonly"
                # Determine accessed_by: value types (data) passed by value
                is_value = False
                for fp in (fallback_projects or []):
                    try:
                        cls = class_ir(fp, arg.class_name)
                        if cls.attrs.get("is_value_type") in {"1", "true"}:
                            is_value = True
                        break
                    except KeyError:
                        pass
                if not is_value:
                    try:
                        cls = class_ir(project_ir, arg.class_name)
                        if cls.attrs.get("is_value_type") in {"1", "true"}:
                            is_value = True
                    except KeyError:
                        pass
                arg_dict["accessed_by"] = "value" if is_value else "pointer"
                # Apply const for non-value readonly args
                if effective_access == "readonly" and not is_value:
                    arg_dict["is_const"] = "1"
            elif arg.interface_name:
                arg_dict["class"] = "impl"
                if arg.access in ("readonly", None):
                    arg_dict["is_const"] = "1"
                arg_dict["accessed_by"] = "pointer"
            elif arg.enum_name:
                arg_dict["enum"] = arg.enum_name
            elif arg.type_name:
                resolved_arg_type, _ = type_map(arg.type_name, getattr(arg, 'type_size', None))
                arg_dict["type"] = resolved_arg_type
                is_pointer = arg.is_reference or arg.is_array
                accessed_by = "pointer" if is_pointer else "value"
                arg_dict["accessed_by"] = accessed_by
                if is_pointer and arg.access in ("readonly", None) and not arg.is_array:
                    arg_dict["is_const"] = "1"
            args.append(arg_dict)

        ret_type = None
        ret_class = None
        ret_is_const = False
        ret_accessed_by = "value"
        attrs_list: tuple[str, ...] = ()
        if method.returns:
            ret = method.returns[0]
            if ret.enum_name:
                ret_type = f"enum:{ret.enum_name}"
            elif ret.interface_name:
                ret_class = "impl"
            elif ret.class_name:
                ret_class = ret.class_name
            elif ret.type_name:
                resolved_ret_type, _ = type_map(ret.type_name, getattr(ret, 'type_size', None))
                ret_type = resolved_ret_type
                if ret.is_reference:
                    ret_accessed_by = "pointer"
                    if ret.access == "readonly":
                        ret_is_const = True

        # Check for NODISCARD / status return
        if method.returns and method.returns[0].enum_name == "status":
            attrs_list = (f"{project_ir.prefix.upper()}_NODISCARD",)
            ret_type = "status"

        _render_impl_method(
            root,
            name=method_name,
            description=method.description or "",
            impl=impl,
            project_ir=project_ir,
            arguments=args if args else None,
            return_type=ret_type,
            return_class=ret_class,
            return_is_const=ret_is_const,
            return_accessed_by=ret_accessed_by,
            code="//  TODO: This is STUB. Implement me.",
            code_type="stub",
            visibility=method_vis,
            declaration=method_decl,
            definition="private",
            attributes=attrs_list,
            fallback_projects=fallback_projects,
        )

    # --- Forward typedefs for interface API types (needed by accessor return types) ---
    for binding in impl.interface_bindings:
        try:
            iface = interface_ir(project_ir, binding.name)
        except KeyError:
            continue
        iface_output = cast(IROutputTarget, iface.output)
        api_type = _interface_api_struct_symbol(iface_output)
        text_element(
            root, "c_alias",
            name=api_type,
            type=f"struct {api_type}",
            declaration="public",
        )

    # --- Interface API accessor declarations (Pattern B) ---
    # e.g. VSCF_PUBLIC const vscf_cipher_info_api_t * vscf_aes256_gcm_cipher_info_api(void);
    for binding in impl.interface_bindings:
        try:
            iface = interface_ir(project_ir, binding.name)
        except KeyError:
            continue
        iface_output = cast(IROutputTarget, iface.output)
        iface_snake = snake_name(binding.name)
        api_type = _interface_api_struct_symbol(iface_output)
        accessor_name = f"{impl_output.c_symbol}_{iface_snake}_api"

        accessor = text_element(
            root,
            "c_method",
            name=accessor_name,
            visibility="public",
            declaration="public",
            definition="external",
            uid=f"c_class_{impl_snake}_method_{iface_snake}_api",
        )
        text_element(
            accessor, "c_return",
            accessed_by="pointer",
            type=api_type, type_is="class",
            is_const_type="1",
        )
        text_element(accessor, "c_modifier", value=f"{prefix_upper}_PUBLIC")
        accessor.text = comment_text(f"Returns instance of the implemented interface '{binding.name}'.")

    root.text = comment_text(f"This module contains '{impl.name}' implementation.")

    return root


def type_map(type_name: str | None, type_size: str | None = None) -> tuple[str, str]:
    # Handle sized integer/unsigned types first
    if type_name == "integer" and type_size is not None:
        sized_map = {"1": "int8_t", "2": "int16_t", "4": "int32_t", "8": "int64_t"}
        if type_size in sized_map:
            return (sized_map[type_size], "primitive")
    if type_name == "unsigned" and type_size is not None:
        sized_map = {"1": "uint8_t", "2": "uint16_t", "4": "uint32_t", "8": "uint64_t"}
        if type_size in sized_map:
            return (sized_map[type_size], "primitive")
    if type_name == "unsigned" and type_size is None:
        return ("unsigned int", "primitive")
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
    lines = ["        //"]
    lines.extend(f"        //  {line}" if line else "        //" for line in desc.splitlines())
    lines.append("        //")
    return "\n" + "\n".join(lines) + "\n    "



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
    if attrs.get("interface") is not None:
        # Interface-typed argument → resolve to {prefix}_impl_t pointer
        prefix = project_ir.prefix if project_ir is not None else "vscf"
        type_name = f"{prefix}_impl_t"
        extra: dict[str, str] = {}
        # Legacy default: interface args without access → readonly (const)
        effective_access = attrs.get("access")
        if effective_access is None:
            effective_access = "readonly"
        if effective_access == "readonly":
            extra["is_const_type"] = "1"
        return text_element(parent, "c_argument", name=arg_name, accessed_by="pointer", type=type_name, type_is="class", **extra)
    if attrs.get("class") is not None:
        resolved_class = owner_class if attrs.get("class") == "self" else attrs.get("class", owner_class)
        # Legacy default: buffer→writeonly, self→keep existing, everything else→readonly
        effective_cls_access = attrs.get("access")
        if effective_cls_access is None and attrs.get("class") != "self":
            effective_cls_access = "writeonly" if attrs.get("class") == "buffer" else "readonly"
        extra = {"is_const_type": "1"} if effective_cls_access == "readonly" else {}
        # Handle const prefix in class name
        resolved_class_str = cast(str, resolved_class)
        if resolved_class_str.startswith("const "):
            resolved_class_str = resolved_class_str[len("const "):]
            extra["is_const_type"] = "1"
        if attrs.get("library") and attrs.get("class") != "self":
            # External or internal library type — use name as-is without IR lookup
            type_name = resolved_class_str
        else:
            type_name = class_type_symbol(project_ir, resolved_class_str) if project_ir is not None else "vsc_data_t"
        accessed_by = "value"
        if attrs.get("class") == "self" and attrs.get("passed_by") == "reference":
            accessed_by = "reference"
        elif attrs.get("class") == "self" and project_ir is not None and class_ir(project_ir, owner_class).attrs.get("is_value_type") not in {"1", "true"}:
            accessed_by = "pointer"
        elif attrs.get("library") and attrs.get("is_reference") not in {"1", "true"} and attrs.get("class") != "self":
            accessed_by = "value"
        elif attrs.get("library") and attrs.get("class") != "self":
            accessed_by = "pointer"
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
    if attrs.get("enum") is not None:
        # Enum-typed argument → resolve to enum type
        enum_name = attrs["enum"]
        if project_ir is not None:
            try:
                enum_out = entity_output(project_ir, entity_kind="enum", entity_name=enum_name)
                rendered_type = f"{enum_out.c_symbol}_t"
            except (KeyError, ValueError):
                rendered_type = f"{project_ir.prefix}_{snake_name(enum_name)}_t"
        else:
            rendered_type = f"vscf_{snake_name(enum_name)}_t"
        return text_element(parent, "c_argument", name=arg_name, accessed_by="value", type=rendered_type, type_is="primitive")
    rendered_type, kind = type_map(attrs.get("type"), attrs.get("size"))
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
    if attrs.get("interface") is not None:
        # Interface return → {prefix}_impl_t pointer
        prefix = project_ir.prefix if project_ir is not None else "vscf"
        return text_element(parent, "c_return", accessed_by="pointer", type=f"{prefix}_impl_t", type_is="class")
    if attrs.get("enum") is not None:
        # Enum return → resolve to enum type
        enum_name = attrs["enum"]
        if project_ir is not None:
            try:
                enum_out = entity_output(project_ir, entity_kind="enum", entity_name=enum_name)
                rendered_type = f"{enum_out.c_symbol}_t"
            except (KeyError, ValueError):
                rendered_type = f"{project_ir.prefix}_{snake_name(enum_name)}_t"
        else:
            rendered_type = f"vscf_{snake_name(enum_name)}_t"
        return text_element(parent, "c_return", accessed_by="value", type=rendered_type, type_is="primitive")
    if attrs.get("class") is not None:
        resolved_class = owner_class if attrs.get("class") == "self" else attrs.get("class", owner_class)
        extra = {}
        # Handle const prefix in class name
        resolved_class_str = cast(str, resolved_class)
        if resolved_class_str.startswith("const "):
            resolved_class_str = resolved_class_str[len("const "):]
            extra["is_const_type"] = "1"
        if attrs.get("library") and attrs.get("class") != "self":
            # External or internal library type — use name as-is without IR lookup
            type_name = resolved_class_str
        else:
            type_name = class_type_symbol(project_ir, resolved_class_str) if project_ir is not None else "vsc_data_t"
        accessed_by = "value"
        if attrs.get("class") == "self" and project_ir is not None and class_ir(project_ir, owner_class).attrs.get("is_value_type") not in {"1", "true"}:
            accessed_by = "pointer"
        elif attrs.get("library") and attrs.get("is_reference") in {"1", "true"} and attrs.get("class") != "self":
            accessed_by = "pointer"
        return text_element(parent, "c_return", accessed_by=accessed_by, type=type_name, type_is="class", **extra)
    if attrs.get("type") == "byte" and attrs.get("is_reference") in {"1", "true"}:
        extra = {"is_const_type": "1"} if attrs.get("access") != "readwrite" else {}
        return text_element(parent, "c_return", accessed_by="pointer", type="byte", type_is="primitive", **extra)
    rendered_type, kind = type_map(attrs.get("type"), attrs.get("size"))
    return text_element(parent, "c_return", accessed_by="value", type=rendered_type, type_is=kind)
