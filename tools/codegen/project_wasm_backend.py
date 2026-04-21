"""WASM wrapper file generation for the project-rooted codegen pipeline.

Generates JavaScript wrapper files and CMakeLists.txt for each project
purely from the IR (IRProject), with no dependency on resolved XML files
in codegen/generated/.

Each entity (enum, class, implementation) becomes a single ``.js`` file.
Per-project infrastructure files (``index.js``, ``precondition.js``,
``{Project}Error.js``, ``{Project}Interface.js``, ``{Project}InterfaceTag.js``,
``{Project}ImplTag.js``) are also generated. Additionally, per-project
``CMakeLists.txt`` files are generated for the Emscripten build.
"""
from __future__ import annotations

from pathlib import Path

from tools.codegen.project_ir import (
    IRCArgument,
    IRCConstant,
    IRCMethod,
    IRClass,
    IRDependency,
    IREnum,
    IRImplementation,
    IRInterface,
    IRProject,
    resolve_constant_value,
)


# ---------------------------------------------------------------------------
# Copyright header
# ---------------------------------------------------------------------------

def _format_license_wasm_block(raw: str) -> str:
    """Format raw license text as /** ... */ block with space-star (JS style)."""
    lines = ["/**"]
    for line in raw.splitlines():
        lines.append(f" * {line}".rstrip() if line.strip() else " *")
    lines.append(" */")
    return "\n".join(lines)


def _format_license_hash(raw: str) -> str:
    """Format raw license text as # comments (CMakeLists style)."""
    lines = []
    for line in raw.splitlines():
        lines.append(f"# {line}".rstrip() if line.strip() else "#")
    return "\n".join(lines)


_LICENSE_HEADER = ""        # populated by generate_wasm_files()
_CMAKE_LICENSE_HEADER = ""  # populated by generate_wasm_files()


# ---------------------------------------------------------------------------
# Name utilities
# ---------------------------------------------------------------------------

def _split_words(name: str) -> list[str]:
    """Split a space-separated / underscore-separated name into words."""
    return [w for w in name.replace("_", " ").split(" ") if w]


def _pascalize_word(word: str) -> str:
    if not word:
        return word
    if len(word) > 1 and word.isupper():
        return word
    if word[:1].isupper():
        return word
    return word[:1].upper() + word[1:]


def _pascal_case(name: str) -> str:
    """Convert entity name to PascalCase.

    ``"alg id"`` -> ``"AlgId"``
    ``"aes256 gcm"`` -> ``"Aes256Gcm"``
    """
    return "".join(_pascalize_word(w) for w in _split_words(name))


def _camel_case(name: str) -> str:
    """Convert to camelCase."""
    words = _split_words(name)
    if not words:
        return name
    return words[0].lower() + "".join(w[:1].upper() + w[1:] for w in words[1:])


def _snake_case(name: str) -> str:
    return name.replace(" ", "_")


def _upper_snake(name: str) -> str:
    return name.replace(" ", "_").upper()


def _c_prefix(project_ir: IRProject) -> str:
    return project_ir.prefix


def _c_entity_prefix(project_ir: IRProject, entity_name: str) -> str:
    """Canonical C function prefix: ``vscf_sha256``."""
    return f"{_c_prefix(project_ir)}_{_snake_case(entity_name)}"


def _module_name(project_ir: IRProject) -> str:
    return _pascal_case(project_ir.name) + "Module"


def _error_class_name(project_ir: IRProject) -> str:
    return _pascal_case(project_ir.name) + "Error"


def _interface_class_name(project_ir: IRProject) -> str:
    return _pascal_case(project_ir.name) + "Interface"


def _interface_tag_class_name(project_ir: IRProject) -> str:
    return _pascal_case(project_ir.name) + "InterfaceTag"


def _impl_tag_class_name(project_ir: IRProject) -> str:
    return _pascal_case(project_ir.name) + "ImplTag"


def _lib_name(project_ir: IRProject) -> str:
    return f"lib{project_ir.name}"


def _cmake_enable_option(project_ir: IRProject) -> str:
    return f"VIRGIL_LIB_{project_ir.name.upper()}"


# ---------------------------------------------------------------------------
# Project prefix fallback for cross-project references
# ---------------------------------------------------------------------------
_PROJECT_PREFIX_FALLBACK: dict[str, str] = {
    "common": "vsc",
    "foundation": "vscf",
    "pythia": "vscp",
    "ratchet": "vscr",
    "phe": "vsce",
}


def _resolve_project_prefix(project_ir: IRProject, project_name: str | None) -> str:
    if not project_name or project_name == project_ir.name:
        return project_ir.prefix
    for fp in getattr(project_ir, "fallback_projects", None) or []:
        if fp.name == project_name:
            return fp.prefix
    return _PROJECT_PREFIX_FALLBACK.get(project_name, project_name)


# ---------------------------------------------------------------------------
# Method filtering (ported from Go backend)
# ---------------------------------------------------------------------------

def _method_should_wrap(method: IRCMethod) -> bool:
    scope = method.attrs.get("scope", "public")
    decl = method.declaration or method.attrs.get("declaration", "public")
    vis = method.visibility or method.attrs.get("visibility", "public")
    return scope == "public" and decl == "public" and vis == "public"


def _arg_should_skip(arg: IRCArgument) -> bool:
    if arg.access == "writeonly":
        return True
    if arg.class_name == "error":
        return True
    return False


def _arg_is_buffer_output(arg: IRCArgument) -> bool:
    return arg.class_name == "buffer"


def _method_has_error_arg(method: IRCMethod) -> bool:
    return any(arg.class_name == "error" for arg in method.arguments)


def _method_has_status_return(method: IRCMethod) -> bool:
    return any(r.enum_name == "status" for r in method.returns)


def _method_has_interface_return(method: IRCMethod) -> bool:
    return any(r.interface_name for r in method.returns)


def _method_has_class_return(method: IRCMethod) -> bool:
    return any(r.class_name and r.class_name not in {"data", "buffer", "error"}
               for r in method.returns)


def _method_has_boolean_return(method: IRCMethod) -> bool:
    return any(r.type_name == "boolean" for r in method.returns)


def _method_has_data_return(method: IRCMethod) -> bool:
    return any(r.class_name == "data" for r in method.returns)


def _is_static_method(method: IRCMethod) -> bool:
    return method.attrs.get("is_static") in {"1", "true"}


def _is_static_class(cls: IRClass) -> bool:
    return cls.attrs.get("context") == "none"


# ---------------------------------------------------------------------------
# Entity scope filtering
# ---------------------------------------------------------------------------

def _is_public(entity) -> bool:
    return entity.attrs.get("scope", "public") == "public"


# ---------------------------------------------------------------------------
# Buffer capacity expression
# ---------------------------------------------------------------------------

def _buffer_capacity_expr(
    project_ir: IRProject,
    entity_name: str,
    arg: IRCArgument,
    method_args: list[IRCArgument],
    is_static: bool,
) -> str:
    """Derive the JS expression for buffer capacity from length_attrs."""
    la = arg.length_attrs
    if not la:
        return "0"

    if "method" in la:
        method_name = la["method"]
        js_method = _camel_case(method_name)
        proxy_args: list[str] = []
        idx = 0
        while f"proxy_{idx}_to" in la:
            cast = la.get(f"proxy_{idx}_cast")
            src_arg = la.get(f"proxy_{idx}_argument")
            src_const = la.get(f"proxy_{idx}_constant")
            if src_const is not None:
                proxy_args.append(src_const)
            elif src_arg is not None:
                local = _camel_case(src_arg)
                if cast == "data_length":
                    proxy_args.append(f"{local}.length")
                else:
                    proxy_args.append(local)
            idx += 1
        args_str = ", ".join(proxy_args)
        if is_static:
            class_name = _pascal_case(entity_name)
            return f"modules.{class_name}.{js_method}({args_str})"
        else:
            return f"this.{js_method}({args_str})"

    if "constant" in la:
        const_name = la["constant"]
        owner_class = la.get("class")
        if owner_class and owner_class != "self":
            return f"modules.{_pascal_case(owner_class)}.{_upper_snake(const_name)}"
        return f"this.{_upper_snake(const_name)}"

    if "argument" in la:
        src = la["argument"]
        local = _camel_case(src)
        if la.get("cast") == "data_length":
            return f"{local}.length"
        return local

    return "0"


# ---------------------------------------------------------------------------
# JS method body generation
# ---------------------------------------------------------------------------

def _gen_precondition_checks(
    project_ir: IRProject,
    method: IRCMethod,
    is_static: bool,
    all_entities: dict[str, str],
) -> list[str]:
    """Generate precondition.ensure* lines for method args."""
    lines: list[str] = []
    if not is_static:
        lines.append("precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);")
    for arg in method.arguments:
        if _arg_should_skip(arg):
            continue
        if _arg_is_buffer_output(arg):
            continue
        local = _camel_case(arg.name)
        if arg.class_name == "data":
            lines.append(f"precondition.ensureByteArray('{local}', {local});")
        elif arg.interface_name:
            iface_project = arg.project or project_ir.name
            iface_pascal = _pascal_case(iface_project) + "." + _pascal_case(arg.interface_name)
            tag_name = _upper_snake(arg.interface_name)
            tag_class = _interface_tag_class_name(project_ir) if not arg.project else _pascal_case(arg.project) + "InterfaceTag"
            iface_class = _interface_class_name(project_ir) if not arg.project else _pascal_case(arg.project) + "Interface"
            lines.append(
                f"precondition.ensureImplementInterface('{local}', {local}, "
                f"'{iface_pascal}', modules.{tag_class}.{tag_name}, modules.{iface_class});"
            )
        elif arg.class_name and arg.class_name not in {"data", "buffer", "error"}:
            class_pascal = _pascal_case(arg.class_name)
            lines.append(f"precondition.ensureClass('{local}', {local}, modules.{class_pascal});")
        elif arg.type_name == "size" or arg.type_name == "integer" or arg.type_name == "unsigned":
            lines.append(f"precondition.ensureNumber('{local}', {local});")
        elif arg.type_name == "boolean":
            lines.append(f"precondition.ensureBoolean('{local}', {local});")
        elif arg.type_name == "string":
            lines.append(f"precondition.ensureString('{local}', {local});")
    return lines


def _gen_data_input_block(arg_name: str) -> list[str]:
    """Generate WASM memory copy block for a vsc_data_t input argument."""
    local = _camel_case(arg_name)
    return [
        f"",
        f"// Copy bytes from JS memory to the WASM memory.",
        f"const {local}Size = {local}.length * {local}.BYTES_PER_ELEMENT;",
        f"const {local}Ptr = Module._malloc({local}Size);",
        f"Module.HEAP8.set({local}, {local}Ptr);",
        f"",
        f"// Create C structure vsc_data_t.",
        f"const {local}CtxSize = Module._vsc_data_ctx_size();",
        f"const {local}CtxPtr = Module._malloc({local}CtxSize);",
        f"",
        f"// Point created vsc_data_t object to the copied bytes.",
        f"Module._vsc_data({local}CtxPtr, {local}Ptr, {local}Size);",
    ]


def _gen_buffer_output_block(arg_name: str, capacity_expr: str) -> list[str]:
    """Generate buffer output allocation block."""
    local = _camel_case(arg_name)
    return [
        f"",
        f"const {local}Capacity = {capacity_expr};",
        f"const {local}CtxPtr = Module._vsc_buffer_new_with_capacity({local}Capacity);",
    ]


def _gen_buffer_extract_lines(arg_name: str) -> list[str]:
    """Generate buffer extraction lines (inside try block)."""
    local = _camel_case(arg_name)
    return [
        f"const {local}Ptr = Module._vsc_buffer_bytes({local}CtxPtr);",
        f"const {local}PtrLen = Module._vsc_buffer_len({local}CtxPtr);",
        f"const {local} = Module.HEAPU8.slice({local}Ptr, {local}Ptr + {local}PtrLen);",
    ]


def _gen_method_body(
    project_ir: IRProject,
    entity_name: str,
    method: IRCMethod,
    is_static: bool,
    all_entities: dict[str, str],
) -> list[str]:
    """Generate the complete method body lines."""
    lines: list[str] = []
    prefix = _c_entity_prefix(project_ir, entity_name)
    c_func = f"Module._{prefix}_{_snake_case(method.name)}"
    error_class = _error_class_name(project_ir)

    # Precondition checks
    checks = _gen_precondition_checks(project_ir, method, is_static, all_entities)
    lines.extend(checks)

    # Collect data inputs and buffer outputs
    data_inputs: list[IRCArgument] = []
    buffer_outputs: list[IRCArgument] = []
    c_call_args: list[str] = []
    free_ptrs: list[str] = []
    free_bufs: list[str] = []

    if not is_static:
        c_call_args.append("this.ctxPtr")

    for arg in method.arguments:
        if arg.class_name == "error":
            # Error struct pattern — handled separately
            continue
        local = _camel_case(arg.name)
        if arg.class_name == "data":
            data_inputs.append(arg)
            c_call_args.append(f"{local}CtxPtr")
        elif _arg_is_buffer_output(arg):
            buffer_outputs.append(arg)
            c_call_args.append(f"{local}CtxPtr")
        elif arg.interface_name or (arg.class_name and arg.class_name not in {"data", "buffer", "error"}):
            c_call_args.append(f"{local}.ctxPtr")
        elif arg.type_name == "self":
            c_call_args.append("this.ctxPtr")
        else:
            c_call_args.append(local)

    # Generate data input blocks
    for arg in data_inputs:
        local = _camel_case(arg.name)
        lines.extend(_gen_data_input_block(arg.name))
        free_ptrs.append(f"{local}Ptr")
        free_ptrs.append(f"{local}CtxPtr")

    # Generate buffer output blocks
    for arg in buffer_outputs:
        local = _camel_case(arg.name)
        cap_expr = _buffer_capacity_expr(project_ir, entity_name, arg, method.arguments, is_static)
        lines.extend(_gen_buffer_output_block(arg.name, cap_expr))
        free_bufs.append(f"{local}CtxPtr")

    # Determine what the method returns
    has_status_return = _method_has_status_return(method)
    has_error_arg = _method_has_error_arg(method)
    # Direct status return: the C function itself returns the status code (no error arg).
    has_status = has_status_return and not has_error_arg
    # Error output parameter pattern: C function returns an object pointer; error is
    # reported via a <prefix>_error_t* output parameter that we allocate and pass.
    has_error_ctx = has_error_arg
    has_iface_return = _method_has_interface_return(method)
    has_class_return = _method_has_class_return(method)
    has_boolean_return = _method_has_boolean_return(method)
    has_data_return = _method_has_data_return(method)
    has_value_return = any(
        r.enum_name != "status" and r.class_name != "error"
        for r in method.returns
    ) and not has_iface_return and not has_class_return and not has_boolean_return and not has_data_return

    error_handler = f"modules.{error_class}"
    proj_prefix = _c_prefix(project_ir)

    # error_ctx methods always need try/finally to free the error context pointer
    needs_try = bool(free_ptrs) or bool(free_bufs) or has_error_ctx

    # Append error context pointer as last C argument for error-output-parameter methods
    if has_error_ctx:
        c_call_args.append("errorCtxPtr")

    # Build the C call and result handling
    call_str = f"{c_func}({', '.join(c_call_args)})"

    if needs_try:
        lines.append("")
        if has_error_ctx:
            lines.append(f"const errorCtxSize = Module._{proj_prefix}_error_ctx_size();")
            lines.append(f"const errorCtxPtr = Module._malloc(errorCtxSize);")
            lines.append(f"Module._{proj_prefix}_error_reset(errorCtxPtr);")
            lines.append("")
        if has_status:
            lines.append("try {")
            lines.append(f"    const proxyResult = {call_str};")
            lines.append(f"    {error_handler}.handleStatusCode(proxyResult);")
        elif has_error_ctx:
            lines.append("let proxyResult;")
            lines.append("")
            lines.append("try {")
            lines.append(f"    proxyResult = {call_str};")
            lines.append("")
            lines.append(f"    const errorStatus = Module._{proj_prefix}_error_status(errorCtxPtr);")
            lines.append(f"    {error_handler}.handleStatusCode(errorStatus);")
        elif has_iface_return or has_class_return or has_boolean_return or has_data_return or has_value_return:
            if has_value_return and not buffer_outputs:
                lines.append("let proxyResult;")
                lines.append("")
                lines.append("try {")
                lines.append(f"    proxyResult = {call_str};")
            else:
                lines.append("try {")
                if has_iface_return or has_class_return or has_boolean_return or has_data_return:
                    lines.append(f"    const proxyResult = {call_str};")
                else:
                    lines.append(f"    {call_str};")
        else:
            lines.append("try {")
            lines.append(f"    {call_str};")

        # Extract buffer outputs inside try
        for arg in buffer_outputs:
            local = _camel_case(arg.name)
            lines.append("")
            for extract_line in _gen_buffer_extract_lines(arg.name):
                lines.append(f"    {extract_line}")

        # Return value
        if has_iface_return:
            for r in method.returns:
                if r.interface_name:
                    iface_class = _interface_class_name(project_ir) if not r.project else _pascal_case(r.project) + "Interface"
                    if r.access == "disown" or r.access is None:
                        lines.append(f"")
                        lines.append(f"    const jsResult = modules.{iface_class}.newAndTakeCContext(proxyResult);")
                    else:
                        lines.append(f"")
                        lines.append(f"    const jsResult = modules.{iface_class}.newAndUseCContext(proxyResult);")
                    lines.append("    return jsResult;")
                    break
        elif has_class_return:
            for r in method.returns:
                if r.class_name and r.class_name not in {"data", "buffer", "error"}:
                    cls_pascal = _pascal_case(r.class_name)
                    if r.access == "disown":
                        lines.append(f"")
                        lines.append(f"    const jsResult = modules.{cls_pascal}.newAndTakeCContext(proxyResult);")
                    else:
                        lines.append(f"")
                        lines.append(f"    const jsResult = modules.{cls_pascal}.newAndUseCContext(proxyResult);")
                    lines.append("    return jsResult;")
                    break
        elif has_boolean_return:
            lines.append("")
            lines.append("    const booleanResult = !!proxyResult;")
            lines.append("    return booleanResult;")
        elif buffer_outputs:
            if len(buffer_outputs) == 1:
                local = _camel_case(buffer_outputs[0].name)
                lines.append(f"    return {local};")
            else:
                props = ", ".join(_camel_case(b.name) for b in buffer_outputs)
                lines.append(f"    return {{ {props} }};")

        # Finally block
        lines.append("} finally {")
        for ptr in free_ptrs:
            lines.append(f"    Module._free({ptr});")
        for buf in free_bufs:
            lines.append(f"    Module._vsc_buffer_delete({buf});")
        if has_error_ctx:
            lines.append(f"    Module._free(errorCtxPtr);")
        lines.append("}")
    else:
        # No try/finally needed
        if has_status:
            lines.append(f"const proxyResult = {call_str};")
            lines.append(f"{error_handler}.handleStatusCode(proxyResult);")
        elif has_iface_return:
            lines.append("")
            lines.append("let proxyResult;")
            lines.append(f"proxyResult = {call_str};")
            for r in method.returns:
                if r.interface_name:
                    iface_class = _interface_class_name(project_ir) if not r.project else _pascal_case(r.project) + "Interface"
                    if r.access == "disown" or r.access is None:
                        lines.append(f"")
                        lines.append(f"const jsResult = modules.{iface_class}.newAndTakeCContext(proxyResult);")
                    else:
                        lines.append(f"")
                        lines.append(f"const jsResult = modules.{iface_class}.newAndUseCContext(proxyResult);")
                    lines.append("return jsResult;")
                    break
        elif has_class_return:
            lines.append("")
            lines.append("let proxyResult;")
            lines.append(f"proxyResult = {call_str};")
            for r in method.returns:
                if r.class_name and r.class_name not in {"data", "buffer", "error"}:
                    cls_pascal = _pascal_case(r.class_name)
                    if r.access == "disown":
                        lines.append(f"")
                        lines.append(f"const jsResult = modules.{cls_pascal}.newAndTakeCContext(proxyResult);")
                    else:
                        lines.append(f"")
                        lines.append(f"const jsResult = modules.{cls_pascal}.newAndUseCContext(proxyResult);")
                    lines.append("return jsResult;")
                    break
        elif has_boolean_return:
            lines.append("")
            lines.append("let proxyResult;")
            lines.append(f"proxyResult = {call_str};")
            lines.append("")
            lines.append("const booleanResult = !!proxyResult;")
            lines.append("return booleanResult;")
        elif has_value_return:
            lines.append("")
            lines.append("let proxyResult;")
            lines.append(f"proxyResult = {call_str};")
            lines.append("return proxyResult;")
        else:
            lines.append(f"{call_str};")

    return lines


def _gen_dependency_setter(
    project_ir: IRProject,
    entity_name: str,
    dep: IRDependency,
) -> list[str]:
    """Generate a dependency setter method body."""
    lines: list[str] = []
    prefix = _c_entity_prefix(project_ir, entity_name)
    local = _camel_case(dep.name)
    dep_snake = _snake_case(dep.name)

    lines.append(f"precondition.ensureNotNull('this.ctxPtr', this.ctxPtr);")

    if dep.type_kind == "interface":
        iface_name = dep.type_name
        iface_project = dep.attrs.get("project", "")
        if iface_project:
            iface_pascal = _pascal_case(iface_project) + "." + _pascal_case(iface_name)
            tag_class = _pascal_case(iface_project) + "InterfaceTag"
            iface_class = _pascal_case(iface_project) + "Interface"
        else:
            iface_pascal = _pascal_case(project_ir.name) + "." + _pascal_case(iface_name)
            tag_class = _interface_tag_class_name(project_ir)
            iface_class = _interface_class_name(project_ir)
        tag_name = _upper_snake(iface_name)
        lines.append(
            f"precondition.ensureImplementInterface('{local}', {local}, "
            f"'{iface_pascal}', modules.{tag_class}.{tag_name}, modules.{iface_class});"
        )
    elif dep.type_kind in ("class", "impl"):
        cls_pascal = _pascal_case(dep.type_name)
        lines.append(f"precondition.ensureClass('{local}', {local}, modules.{cls_pascal});")

    lines.append(f"Module._{prefix}_release_{dep_snake}(this.ctxPtr)")
    lines.append(f"Module._{prefix}_use_{dep_snake}(this.ctxPtr, {local}.ctxPtr)")
    return lines


# ---------------------------------------------------------------------------
# Source output paths
# ---------------------------------------------------------------------------

def _source_dir(project_ir: IRProject) -> str:
    return f"wrappers/wasm/{project_ir.name}/src/"


def _cmake_dir(project_ir: IRProject) -> str:
    return f"wrappers/wasm/{project_ir.name}/"


# ---------------------------------------------------------------------------
# Enum JS file generator
# ---------------------------------------------------------------------------

def _generate_enum_js(project_ir: IRProject, enum: IREnum) -> str:
    """Generate a JS file for a plain enum (Object.freeze pattern)."""
    name = _pascal_case(enum.name)
    lines: list[str] = [_LICENSE_HEADER, ""]

    lines.append(f"const init{name} = (Module, modules) => {{")
    lines.append(f"    const {name} = Object.freeze({{")

    for const in enum.constants:
        cname = _upper_snake(const.name)
        raw_value = const.attrs.get("value")
        if raw_value is not None and raw_value != "":
            cvalue = raw_value.strip()
        else:
            # Derive integer value from position (C enum semantics)
            cvalue = str(_enum_constant_value(enum, const))
        lines.append(f"        {cname}: {cvalue},")

    lines.append("    });")
    lines.append("")
    lines.append(f"    return {name};")
    lines.append("};")
    lines.append("")
    lines.append(f"module.exports = init{name};")
    lines.append("")
    return "\n".join(lines)


def _enum_constant_value(enum: IREnum, target_const: IRCConstant) -> int:
    """Calculate the integer value for an enum constant."""
    next_val = 0
    for const in enum.constants:
        raw = const.attrs.get("value")
        if raw is not None and raw.strip() != "":
            try:
                next_val = int(raw.strip(), 0)
            except ValueError:
                pass
        if const is target_const:
            return next_val
        next_val += 1
    return 0


# ---------------------------------------------------------------------------
# Interface Tag JS file generator
# ---------------------------------------------------------------------------

def _generate_interface_tag_js(project_ir: IRProject) -> str:
    """Generate {Project}InterfaceTag.js — frozen enum of interface tags."""
    tag_name = _interface_tag_class_name(project_ir)
    public_interfaces = [
        i for i in project_ir.interfaces if _is_public(i)
    ]
    # Sort alphabetically by uppercased name for stable output
    sorted_ifaces = sorted(public_interfaces, key=lambda i: _upper_snake(i.name))

    lines: list[str] = [_LICENSE_HEADER, ""]
    lines.append(f"const init{tag_name} = (Module, modules) => {{")
    lines.append(f"    const {tag_name} = Object.freeze({{")
    for idx, iface in enumerate(sorted_ifaces, start=1):
        lines.append(f"        {_upper_snake(iface.name)}: {idx},")
    lines.append("    });")
    lines.append("")
    lines.append(f"    return {tag_name};")
    lines.append("};")
    lines.append("")
    lines.append(f"module.exports = init{tag_name};")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Impl Tag JS file generator
# ---------------------------------------------------------------------------

def _generate_impl_tag_js(project_ir: IRProject) -> str:
    """Generate {Project}ImplTag.js — frozen enum of implementation tags."""
    tag_name = _impl_tag_class_name(project_ir)
    # Sort implementations alphabetically
    sorted_impls = sorted(project_ir.implementations, key=lambda i: _upper_snake(i.name))

    lines: list[str] = [_LICENSE_HEADER, ""]
    lines.append(f"const init{tag_name} = (Module, modules) => {{")
    lines.append(f"    const {tag_name} = Object.freeze({{")
    for idx, impl in enumerate(sorted_impls, start=1):
        lines.append(f"        {_upper_snake(impl.name)}: {idx},")
    lines.append("    });")
    lines.append("")
    lines.append(f"    return {tag_name};")
    lines.append("};")
    lines.append("")
    lines.append(f"module.exports = init{tag_name};")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Error JS file generator
# ---------------------------------------------------------------------------

def _generate_error_js(project_ir: IRProject) -> str:
    """Generate {Project}Error.js — error class with handleStatusCode."""
    error_name = _error_class_name(project_ir)
    status_enum = _find_status_enum(project_ir)
    if status_enum is None:
        return ""

    lines: list[str] = [_LICENSE_HEADER, ""]
    lines.append(f"const init{error_name} = (Module, modules) => {{")
    lines.append(f"    class {error_name} extends Error {{")
    lines.append("")
    lines.append("        constructor(message) {")
    lines.append("            super(message);")
    lines.append(f"            this.name = '{error_name}';")
    lines.append("            this.message = message;")
    lines.append("        }")
    lines.append("")
    lines.append("        static handleStatusCode(statusCode) {")
    lines.append("            if (statusCode == 0) {")
    lines.append("                return;")
    lines.append("            }")

    # Generate one if-block per non-success status constant
    non_success = [c for c in status_enum.constants if c.name != "success"]
    for const in non_success:
        raw_value = const.attrs.get("value", "0").strip()
        description = _flatten_description(const.description)
        lines.append("")
        lines.append(f"            if (statusCode == {raw_value}) {{")
        lines.append(f'                throw new {error_name}("{description}");')
        lines.append("            }")

    lines.append("")
    lines.append(f'            throw new {error_name}("Unexpected status code:" + statusCode);')
    lines.append("        }")
    lines.append("")
    lines.append("    }")
    lines.append("")
    lines.append(f"    return {error_name};")
    lines.append("};")
    lines.append("")
    lines.append(f"module.exports = init{error_name};")
    lines.append("")
    return "\n".join(lines)


def _find_status_enum(project_ir: IRProject) -> IREnum | None:
    for enum in project_ir.enums:
        if enum.name == "status":
            return enum
    return None


def _flatten_description(description: str) -> str:
    if not description:
        return ""
    lines = [line.strip() for line in description.strip().splitlines()]
    return " ".join(line for line in lines if line)


# ---------------------------------------------------------------------------
# Interface dispatch JS file generator
# ---------------------------------------------------------------------------

def _generate_interface_js(project_ir: IRProject) -> str:
    """Generate {Project}Interface.js — impl-tag dispatch class."""
    iface_name = _interface_class_name(project_ir)
    impl_tag_name = _impl_tag_class_name(project_ir)
    prefix = _c_prefix(project_ir)

    # Sort implementations alphabetically for stable output
    sorted_impls = sorted(project_ir.implementations, key=lambda i: _upper_snake(i.name))

    lines: list[str] = [_LICENSE_HEADER, ""]
    lines.append(f"const init{iface_name} = (Module, modules) => {{")
    lines.append(f"    class {iface_name} {{")
    lines.append("")
    lines.append("        static newAndTakeCContext(ctxPtr) {")
    lines.append(f"            const implTag = Module._{prefix}_impl_tag(ctxPtr);")
    lines.append("            switch(implTag) {")

    for impl in sorted_impls:
        tag_const = _upper_snake(impl.name)
        class_name = _pascal_case(impl.name)
        lines.append("")
        lines.append(f"                case modules.{impl_tag_name}.{tag_const}:")
        lines.append(f"                    return modules.{class_name}.newAndTakeCContext(ctxPtr);")

    lines.append("")
    lines.append("                default:")
    lines.append("                    throw new Error('Unexpected implementation tag found: ' + implTag);")
    lines.append("            }")
    lines.append("        }")
    lines.append("")
    lines.append("        static newAndUseCContext(ctxPtr) {")
    lines.append(f"            return new modules.{iface_name}.newAndTakeCContext(Module._{prefix}_impl_shallow_copy(ctxPtr));")
    lines.append("        }")
    lines.append("")
    lines.append("        static isImplemented(ctxPtr, interfaceTag) {")
    lines.append(f"            return Module._{prefix}_impl_api(ctxPtr, interfaceTag) != 0;")
    lines.append("        }")
    lines.append("")
    lines.append("    }")
    lines.append("")
    lines.append(f"    return {iface_name};")
    lines.append("};")
    lines.append("")
    lines.append(f"module.exports = init{iface_name};")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# precondition.js generator (static content)
# ---------------------------------------------------------------------------

_PRECONDITION_JS_BODY = """\

function ensureNumber(arg, value) {
    if (!(typeof value === 'number' || value instanceof Number)) {
        throw new TypeError(`'${arg}' is not a number`);
    }
    if (Number.isNaN(value)) {
        throw new TypeError(`'${arg}' is NaN`);
    }
    if (value === Infinity) {
        throw new TypeError(`'${arg}' is Infinity`);
    }
    if (value === -Infinity) {
        throw new TypeError(`'${arg}' is -Infinity`);
    }
}

function ensureNotNull(arg, value) {
    ensureNumber(arg, value);

    if (value == 0) {
        throw new TypeError(`'${arg}' is NULL`);
    }
}

function ensureString(arg, value) {
    if (!(typeof value === 'string' || value instanceof String)) {
        throw new TypeError(`'${arg}' is not a string`);
    }
}

function ensureBoolean(arg, value) {
    if (typeof value !== 'boolean') {
        throw new TypeError(`'${arg}' is not a boolean`);
    }
}

function ensureByteArray(arg, value) {
    if (!(value instanceof Uint8Array)) {
        throw new TypeError(`'${arg}' is not an Uint8Array`);
    }
}

function ensureClass(arg, value, cls) {
    if (!(value instanceof cls)) {
        throw new TypeError(`'${arg}' is not an instance of the class ${cls.name}`);
    }
    ensureNotNull(arg, value.ctxPtr);
}

function ensureImplementInterface(arg, value, interfaceName, interfaceTag, interfaceChecker) {
    ensureNotNull(arg, value.ctxPtr);
    if (!interfaceChecker.isImplemented(value.ctxPtr, interfaceTag)) {
        throw new TypeError(`'${arg}' does not implement interface '${interfaceName}'`);
    }
}

module.exports.ensureNumber = ensureNumber;
module.exports.ensureString = ensureString;
module.exports.ensureBoolean = ensureBoolean;
module.exports.ensureByteArray = ensureByteArray;
module.exports.ensureClass = ensureClass;
module.exports.ensureNotNull = ensureNotNull;
module.exports.ensureImplementInterface = ensureImplementInterface;
"""


# ---------------------------------------------------------------------------
# Class / implementation JS file generator
# ---------------------------------------------------------------------------

def _generate_class_js(
    project_ir: IRProject,
    entity_name: str,
    methods: list[IRCMethod],
    dependencies: list[IRDependency],
    constants: list[IRCConstant],
    is_static: bool,
    all_entities: dict[str, str],
    constructors: list[IRCMethod] | None = None,
) -> str:
    """Generate a JS file for a class or implementation."""
    class_name = _pascal_case(entity_name)
    prefix = _c_entity_prefix(project_ir, entity_name)

    lines: list[str] = [_LICENSE_HEADER, ""]
    lines.append("")
    lines.append("const precondition = require('./precondition');")
    lines.append("")
    lines.append(f"const init{class_name} = (Module, modules) => {{")
    lines.append(f"    class {class_name} {{")
    lines.append("")

    if not is_static:
        # Constructor
        lines.append(f"        constructor(ctxPtr) {{")
        lines.append(f"            this.name = '{class_name}';")
        lines.append(f"")
        lines.append(f"            if (typeof ctxPtr === 'undefined') {{")
        lines.append(f"                this.ctxPtr = Module._{prefix}_new();")
        lines.append(f"            }} else {{")
        lines.append(f"                this.ctxPtr = ctxPtr;")
        lines.append(f"            }}")
        lines.append(f"        }}")
        lines.append("")

        # Static factory methods
        lines.append(f"        static newAndUseCContext(ctxPtr) {{")
        lines.append(f"            // assert(typeof ctxPtr === 'number');")
        lines.append(f"            return new {class_name}(Module._{prefix}_shallow_copy(ctxPtr));")
        lines.append(f"        }}")
        lines.append("")
        lines.append(f"        static newAndTakeCContext(ctxPtr) {{")
        lines.append(f"            // assert(typeof ctxPtr === 'number');")
        lines.append(f"            return new {class_name}(ctxPtr);")
        lines.append(f"        }}")
        lines.append("")

        # delete()
        lines.append(f"        delete() {{")
        lines.append(f"            if (typeof this.ctxPtr !== 'undefined' && this.ctxPtr !== null) {{")
        lines.append(f"                Module._{prefix}_delete(this.ctxPtr);")
        lines.append(f"                this.ctxPtr = null;")
        lines.append(f"            }}")
        lines.append(f"        }}")
        lines.append("")

    # Dependency setters
    for dep in dependencies:
        dep_local = _camel_case(dep.name)
        dep_body = _gen_dependency_setter(project_ir, entity_name, dep)
        lines.append(f"        set {dep_local}({dep_local}) {{")
        for bl in dep_body:
            lines.append(f"            {bl}")
        lines.append(f"        }}")
        lines.append("")

    # Constants as static+instance getters
    # Look up entity for constant expression resolution
    _entity_ref = None
    for _ent in list(project_ir.classes) + list(project_ir.implementations):
        if _ent.name == entity_name:
            _entity_ref = _ent
            break
    for const in constants:
        cname = _upper_snake(const.name)
        raw_value = resolve_constant_value(
            const.attrs.get("value", "0").strip(), _entity_ref, project_ir
        )
        lines.append(f"        static get {cname}() {{")
        lines.append(f"            return {raw_value};")
        lines.append(f"        }}")
        lines.append("")
        lines.append(f"        get {cname}() {{")
        lines.append(f"            return {raw_value};")
        lines.append(f"        }}")
        lines.append("")

    # Methods
    for method in methods:
        if not _method_should_wrap(method):
            continue
        method_name = _camel_case(method.name)
        is_method_static = _is_static_method(method) or is_static

        # Build argument list for JS signature
        js_args: list[str] = []
        for arg in method.arguments:
            if _arg_should_skip(arg):
                continue
            if _arg_is_buffer_output(arg):
                continue
            js_args.append(_camel_case(arg.name))

        args_str = ", ".join(js_args)
        if is_method_static and not is_static:
            # Emit static method first, then an instance wrapper that delegates to it.
            lines.append(f"        static {method_name}({args_str}) {{")
            body = _gen_method_body(
                project_ir, entity_name, method, True,
                all_entities,
            )
            for bl in body:
                lines.append(f"            {bl}")
            lines.append(f"        }}")
            lines.append("")
            lines.append(f"        {method_name}({args_str}) {{")
            lines.append(f"            return {class_name}.{method_name}({args_str});")
            lines.append(f"        }}")
        else:
            static_kw = "static " if is_method_static else ""
            lines.append(f"        {static_kw}{method_name}({args_str}) {{")
            body = _gen_method_body(
                project_ir, entity_name, method, is_method_static or not not is_static,
                all_entities,
            )
            for bl in body:
                lines.append(f"            {bl}")
            lines.append(f"        }}")
        lines.append("")

    lines.append("    }")
    lines.append("")
    lines.append(f"    return {class_name};")
    lines.append("};")
    lines.append("")
    lines.append(f"module.exports = init{class_name};")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# index.js generator
# ---------------------------------------------------------------------------

# Cross-project foundation modules that phe/ratchet require in their index.js.
# These are the foundation infrastructure + specific implementations that
# the legacy codegen always includes for projects depending on foundation.
_FOUNDATION_CROSS_PROJECT_INFRA = [
    "FoundationError",
    "FoundationInterface",
    "FoundationInterfaceTag",
    "FoundationImplTag",
]

_FOUNDATION_CROSS_PROJECT_IMPLS = [
    "CtrDrbg",
    "Hmac",
    "Hkdf",
    "Sha512",
]


def _generate_index_js(
    project_ir: IRProject,
    entity_entries: list[tuple[str, str]],
) -> str:
    """Generate index.js — module aggregator.

    entity_entries: list of (js_class_name, js_file_name) for all entities
    in this project (excluding precondition.js and index.js themselves).
    """
    mod_name = _module_name(project_ir)
    project_var = project_ir.name + "Module"
    has_foundation_dep = any(
        lr.name == "foundation" and lr.kind == "project"
        for lr in project_ir.library_requires
    )
    has_interfaces = bool(project_ir.interfaces)

    lines: list[str] = [_LICENSE_HEADER, ""]

    # Module require
    lines.append(f"const {mod_name} = require(process.env.PROJECT_MODULE);")
    lines.append("")

    # Cross-project foundation imports (for non-foundation projects)
    cross_project_entries: list[tuple[str, str]] = []
    if has_foundation_dep and project_ir.name != "foundation":
        # Always import foundation infra if the project requires foundation
        for infra_name in _FOUNDATION_CROSS_PROJECT_INFRA:
            rel_path = f"../foundation/{infra_name}"
            lines.append(f"const init{infra_name} = require('{rel_path}');")
            cross_project_entries.append((infra_name, rel_path))
        for impl_name in _FOUNDATION_CROSS_PROJECT_IMPLS:
            rel_path = f"../foundation/{impl_name}"
            lines.append(f"const init{impl_name} = require('{rel_path}');")
            cross_project_entries.append((impl_name, rel_path))

    # Local entity requires
    for class_name, file_name in entity_entries:
        lines.append(f"const init{class_name} = require('./{file_name}');")

    lines.append("")
    lines.append("const initProject = options => {")
    lines.append("    return new Promise((resolve, reject) => {")
    lines.append("")
    lines.append(f"        {mod_name}(options).then({project_var} => {{")
    lines.append("            const modules = {};")
    lines.append("")

    # Initialize cross-project modules
    for class_name, _ in cross_project_entries:
        lines.append(f"            modules.{class_name} = init{class_name}({project_var}, modules);")

    # Initialize local modules
    for class_name, _ in entity_entries:
        lines.append(f"            modules.{class_name} = init{class_name}({project_var}, modules);")

    lines.append("            resolve(modules);")
    lines.append("        }).catch(error => {")
    lines.append("            reject(error);")
    lines.append("        });")
    lines.append("")
    lines.append("    });")
    lines.append("};")
    lines.append("module.exports = initProject;")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CMakeLists.txt generator
# ---------------------------------------------------------------------------

def _generate_cmake(project_ir: IRProject) -> str:
    """Generate per-project CMakeLists.txt for Emscripten build."""
    name = project_ir.name
    pascal = _pascal_case(name)
    mod_name = _module_name(project_ir)
    lib_name = _lib_name(project_ir)
    enable_opt = _cmake_enable_option(project_ir)

    lines: list[str] = [_CMAKE_LICENSE_HEADER, ""]
    lines.append(f"cmake_minimum_required(VERSION 3.12 FATAL_ERROR)")
    lines.append("")
    lines.append(f"project(virgil_crypto_{name}_wasm VERSION ${{virgil_crypto_VERSION}} LANGUAGES C)")
    lines.append("")
    lines.append("# ---------------------------------------------------------------------------")
    lines.append("# Check dependencies")
    lines.append("# ---------------------------------------------------------------------------")
    lines.append(f"if(NOT {enable_opt})")
    lines.append(f'    message(STATUS "Skip building the WebAssembly wrapper for library {name}, which is not built.")')
    lines.append("    return()")
    lines.append("endif()")
    lines.append("")
    lines.append("# ---------------------------------------------------------------------------")
    lines.append("# Find utils")
    lines.append("# ---------------------------------------------------------------------------")
    lines.append("find_host_program(WASM2WAT wasm2wat)")
    lines.append("")
    lines.append("# ---------------------------------------------------------------------------")
    lines.append("# Common steps for all WebAssembly libraries.")
    lines.append("# ---------------------------------------------------------------------------")
    lines.append('file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/fake.c" "")')
    lines.append("")
    lines.append("function(wasm_add_common_wasm_options target)")
    lines.append('    target_sources(${target} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/fake.c")')
    lines.append('    target_sources(${target} PRIVATE "${CMAKE_CURRENT_LIST_DIR}/exported_functions.json")')
    lines.append("    target_link_libraries(${target}")
    lines.append('            "-s WASM=1"')
    lines.append('            "-s ALLOW_MEMORY_GROWTH=1"')
    lines.append('            "-s EXPORTED_FUNCTIONS=\\"@${CMAKE_CURRENT_LIST_DIR}/exported_functions.json\\""')
    lines.append('            "-s EXPORTED_RUNTIME_METHODS=[\\"HEAP8\\",\\"HEAPU8\\",\\"HEAP16\\",\\"HEAPU16\\",\\"HEAP32\\",\\"HEAPU32\\",\\"HEAPF32\\",\\"HEAPF64\\"]"')
    lines.append('            "-s MODULARIZE=1"')
    lines.append(f'            "-s EXPORT_NAME={mod_name}"')
    lines.append('            "$<$<CONFIG:Release>:--llvm-lto 1 -Os --closure 1>"')
    lines.append('            "$<$<CONFIG:Debug>:--emrun>"')
    lines.append(f"            vsc::{name}")
    lines.append("            )")
    lines.append("endfunction()")
    lines.append("")
    lines.append("# ---------------------------------------------------------------------------")
    lines.append("# Create WebAssembly library")
    lines.append("# ---------------------------------------------------------------------------")
    lines.append(f"add_executable({lib_name})")
    lines.append(f"wasm_add_common_wasm_options({lib_name})")
    lines.append(f"target_link_libraries({lib_name}")
    lines.append('        "-s ENVIRONMENT=node"')
    lines.append("        )")
    lines.append("")
    lines.append(f"add_executable({lib_name}.browser)")
    lines.append(f"wasm_add_common_wasm_options({lib_name}.browser)")
    lines.append(f"target_link_libraries({lib_name}.browser")
    lines.append('        "-s ENVIRONMENT=web"')
    lines.append("        )")
    lines.append("")
    lines.append(f"add_executable({lib_name}.worker)")
    lines.append(f"wasm_add_common_wasm_options({lib_name}.worker)")
    lines.append(f"target_link_libraries({lib_name}.worker")
    lines.append('        "-s ENVIRONMENT=worker"')
    lines.append("        )")
    lines.append("")
    lines.append(f"add_custom_command(TARGET {lib_name} POST_BUILD")
    lines.append("        COMMAND ${CMAKE_COMMAND} -E copy_directory")
    lines.append('                "${CMAKE_CURRENT_LIST_DIR}/src" "${CMAKE_CURRENT_BINARY_DIR}"')
    lines.append("        )")
    lines.append("")
    lines.append("if(WASM2WAT)")
    lines.append(f"    add_custom_command(TARGET {lib_name} POST_BUILD")
    lines.append('            COMMAND "${WASM2WAT}"')
    lines.append(f"                    {lib_name}.wasm")
    lines.append(f"                    -o {lib_name}.wat")
    lines.append(f'            COMMENT "Create WAT from {lib_name}.wasm"')
    lines.append("            )")
    lines.append("endif()")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def generate_wasm_files(
    project_ir: IRProject, license_text: str = "",
    repo_root: str | Path = ".",
) -> list[tuple[str, str]]:
    """Generate all WASM wrapper files for a project.

    Returns a list of ``(repo_relative_path, file_content)`` tuples.
    Pure IR-driven — no filesystem reads.
    """
    global _LICENSE_HEADER, _CMAKE_LICENSE_HEADER
    if license_text:
        _LICENSE_HEADER = _format_license_wasm_block(license_text)
        _CMAKE_LICENSE_HEADER = _format_license_hash(license_text)
    del repo_root

    files: list[tuple[str, str]] = []
    src_dir = _source_dir(project_ir)
    cmake_dir = _cmake_dir(project_ir)

    # Build entity lookup for cross-references
    all_entities: dict[str, str] = {}
    for cls in project_ir.classes:
        all_entities[cls.name] = "class"
    for impl in project_ir.implementations:
        all_entities[impl.name] = "implementation"
    for enum in project_ir.enums:
        all_entities[enum.name] = "enum"

    has_interfaces = bool(project_ir.interfaces)
    has_implementations = bool(project_ir.implementations)

    # Track entity entries for index.js (class_name, file_name_without_ext)
    index_entries: list[tuple[str, str]] = []

    # --- Infrastructure files ---
    # Interface infrastructure (only for projects with interfaces/implementations)
    if has_interfaces:
        tag_name = _interface_tag_class_name(project_ir)
        content = _generate_interface_tag_js(project_ir)
        files.append((f"{src_dir}{tag_name}.js", content))
        index_entries.append((tag_name, tag_name))

    if has_interfaces:
        iface_name = _interface_class_name(project_ir)
        content = _generate_interface_js(project_ir)
        files.append((f"{src_dir}{iface_name}.js", content))
        index_entries.append((iface_name, iface_name))

    if has_implementations:
        impl_tag_name = _impl_tag_class_name(project_ir)
        content = _generate_impl_tag_js(project_ir)
        files.append((f"{src_dir}{impl_tag_name}.js", content))
        index_entries.append((impl_tag_name, impl_tag_name))

    # Error class
    error_name = _error_class_name(project_ir)
    error_content = _generate_error_js(project_ir)
    if error_content:
        files.append((f"{src_dir}{error_name}.js", error_content))
        index_entries.append((error_name, error_name))

    # --- Enums (excluding status and impl/tag) ---
    for enum in project_ir.enums:
        if enum.name == "status":
            continue
        if enum.name == "impl/tag":
            continue
        if not _is_public(enum):
            continue
        enum_pascal = _pascal_case(enum.name)
        content = _generate_enum_js(project_ir, enum)
        files.append((f"{src_dir}{enum_pascal}.js", content))
        index_entries.append((enum_pascal, enum_pascal))

    # --- Public classes (excluding error) ---
    for cls in project_ir.classes:
        if not _is_public(cls):
            continue
        if cls.name == "error":
            continue
        class_name = _pascal_case(cls.name)
        is_static = _is_static_class(cls)

        # Collect methods: own methods + methods from constructors
        all_methods = list(cls.methods)

        content = _generate_class_js(
            project_ir,
            cls.name,
            all_methods,
            cls.dependencies,
            cls.constants,
            is_static,
            all_entities,
            constructors=cls.constructors,
        )
        files.append((f"{src_dir}{class_name}.js", content))
        index_entries.append((class_name, class_name))

    # --- Implementations ---
    for impl in project_ir.implementations:
        impl_pascal = _pascal_case(impl.name)

        # Collect methods: own methods + inherited interface methods
        all_methods: list[IRCMethod] = []
        iface_by_name = {i.name: i for i in project_ir.interfaces}
        for binding in impl.interface_bindings:
            iface = iface_by_name.get(binding.name)
            if iface is not None:
                for m in iface.methods:
                    all_methods.append(m)
        all_methods.extend(impl.methods)

        # Collect constants: own + binding constants from interfaces
        all_constants: list[IRCConstant] = list(impl.constants)
        for binding in impl.interface_bindings:
            for bc in binding.constants:
                all_constants.append(IRCConstant(
                    name=bc.name,
                    attrs={"value": bc.value, **bc.attrs},
                    description=bc.description,
                ))

        content = _generate_class_js(
            project_ir,
            impl.name,
            all_methods,
            impl.dependencies,
            all_constants,
            False,  # implementations always have context
            all_entities,
            constructors=impl.constructors,
        )
        files.append((f"{src_dir}{impl_pascal}.js", content))
        index_entries.append((impl_pascal, impl_pascal))

    # --- precondition.js ---
    precondition_content = (_LICENSE_HEADER + "\n" if _LICENSE_HEADER else "") + _PRECONDITION_JS_BODY
    files.append((f"{src_dir}precondition.js", precondition_content))

    # --- index.js ---
    index_content = _generate_index_js(project_ir, index_entries)
    files.append((f"{src_dir}index.js", index_content))

    # --- CMakeLists.txt ---
    cmake_content = _generate_cmake(project_ir)
    files.append((f"{cmake_dir}CMakeLists.txt", cmake_content))

    return files
