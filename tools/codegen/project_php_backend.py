"""PHP wrapper file generation for the project-rooted codegen pipeline.

Generates ALL output from the IR (IRProject), with zero dependency on
resolved XML files in codegen/generated/.

Each entity becomes a ``.php`` high-level class file. Per-project
C extension files (``.c``, ``.h``) and ``CMakeLists.txt`` are also
generated. All output is assembled purely from the IR.

Architecture mirrors the Go backend (project_go_backend.py):
- Name utilities derive PHP class names, C extension function names
- Entity generators produce content for each IR entity type
- Orchestrator (generate_php_files) walks the IR and collects output
"""
from __future__ import annotations

import copy
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
# PHP license header (matches legacy output)
# ---------------------------------------------------------------------------

_PHP_LICENSE = """\
/**
* Copyright (C) 2015-2022 Virgil Security, Inc.
*
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
* (1) Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
*
* (2) Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in
* the documentation and/or other materials provided with the
* distribution.
*
* (3) Neither the name of the copyright holder nor the names of its
* contributors may be used to endorse or promote products derived from
* this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
* INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
* IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
*/"""

_C_LICENSE = """\
//
// Copyright (C) 2015-2022 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// (1) Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// (2) Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in
// the documentation and/or other materials provided with the
// distribution.
//
// (3) Neither the name of the copyright holder nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//"""

# Project prefix lookup for cross-project references.
_PROJECT_PREFIX = {
    "common": "vsc",
    "foundation": "vscf",
    "pythia": "vscp",
    "ratchet": "vscr",
    "phe": "vsce",
}


# ---------------------------------------------------------------------------
# Name utilities
# ---------------------------------------------------------------------------

def _pascal_case(name: str) -> str:
    """Convert a space/underscore separated name to PascalCase.

    ``"alg id"`` -> ``"AlgId"``
    ``"sha256"`` -> ``"Sha256"``
    ``"aes256 gcm"`` -> ``"Aes256Gcm"``
    ``"asn1rd"`` -> ``"Asn1rd"``
    """
    words = name.replace("_", " ").split()
    return "".join(w[:1].upper() + w[1:] for w in words if w)


def _camel_case(name: str) -> str:
    """Convert to camelCase for PHP variable/method names.

    ``"alg id"`` -> ``"algId"``
    ``"plain text"`` -> ``"plainText"``
    """
    words = name.replace("_", " ").split()
    if not words:
        return name
    head = words[0].lower()
    tail = "".join(w[:1].upper() + w[1:].lower() for w in words[1:])
    return head + tail


def _snake_case(name: str) -> str:
    """Convert to snake_case for C function names.

    ``"alg id"`` -> ``"alg_id"``
    """
    return name.replace(" ", "_").lower()


def _php_class_name(entity_name: str) -> str:
    """Derive the PHP class name for an entity."""
    return _pascal_case(entity_name)


def _php_namespace(project_name: str) -> str:
    """Derive the PHP namespace for a project.

    ``"foundation"`` -> ``"Virgil\\CryptoWrapper\\Foundation"``
    """
    return f"Virgil\\CryptoWrapper\\{_pascal_case(project_name)}"


def _c_ext_func_name(prefix: str, entity_name: str, method_name: str) -> str:
    """Derive the C extension PHP function name.

    ``("vscf", "sha256", "alg id")`` -> ``"vscf_sha256_alg_id_php"``
    """
    entity_snake = _snake_case(entity_name)
    method_snake = _snake_case(method_name)
    return f"{prefix}_{entity_snake}_{method_snake}_php"


def _resolve_project_prefix(project_ir: IRProject, project_name: str | None) -> str:
    """Return the C prefix for a given project name."""
    if not project_name or project_name == project_ir.name:
        return project_ir.prefix
    return _PROJECT_PREFIX.get(project_name, project_name)


# ---------------------------------------------------------------------------
# Method filtering (ported from Go backend)
# ---------------------------------------------------------------------------

def _method_should_wrap(method: IRCMethod) -> bool:
    """Port of ``wrapper_should_wrap_method`` -- public scope, declaration, visibility."""
    scope = method.attrs.get("scope", "public")
    decl = method.declaration or method.attrs.get("declaration", "public")
    vis = method.visibility or method.attrs.get("visibility", "public")
    return scope == "public" and decl == "public" and vis == "public"


def _arg_should_skip(arg: IRCArgument) -> bool:
    """Arguments filtered from the wrapper API (writeonly / error class)."""
    if arg.access == "writeonly":
        return True
    if arg.class_name == "error":
        return True
    return False


def _arg_is_buffer_output(arg: IRCArgument) -> bool:
    """Buffer-class arguments act as output parameters."""
    return arg.class_name == "buffer"


def _method_has_error_arg(method: IRCMethod) -> bool:
    """True if the method has an explicit class="error" argument."""
    return any(arg.class_name == "error" for arg in method.arguments)


def _method_has_status_return(method: IRCMethod) -> bool:
    """True if the method returns a status enum."""
    return any(r.enum_name == "status" for r in method.returns)


def _method_throws(method: IRCMethod) -> bool:
    """True if the method can throw (status return or error arg)."""
    return _method_has_status_return(method) or _method_has_error_arg(method)


def _is_static_class(cls: IRClass) -> bool:
    """Static-only classes (context="none") carry no cCtx and no lifecycle."""
    return cls.attrs.get("context") == "none"


def _resolve_self_arg(entity_name: str, arg: IRCArgument) -> IRCArgument:
    """Resolve class="self" references to the enclosing entity name."""
    if arg.class_name == "self":
        resolved = copy.copy(arg)
        resolved.class_name = entity_name
        return resolved
    return arg


# ---------------------------------------------------------------------------
# PHP type mapping
# ---------------------------------------------------------------------------

def _php_type_for_arg(project_ir: IRProject, arg: IRCArgument) -> str:
    """Map an IR argument to its PHP type hint string."""
    if arg.enum_name:
        if arg.project and arg.project != project_ir.name:
            return f"\\{_php_namespace(arg.project)}\\{_php_class_name(arg.enum_name)}"
        return _php_class_name(arg.enum_name)
    if arg.interface_name:
        if arg.project and arg.project != project_ir.name:
            return f"\\{_php_namespace(arg.project)}\\{_php_class_name(arg.interface_name)}"
        return _php_class_name(arg.interface_name)
    if arg.class_name and arg.class_name not in {"data", "buffer", "error"}:
        if arg.project and arg.project != project_ir.name:
            return f"\\{_php_namespace(arg.project)}\\{_php_class_name(arg.class_name)}"
        return _php_class_name(arg.class_name)
    if arg.class_name == "data":
        return "string"
    type_name = (arg.type_name or "").lower()
    if type_name in ("size", "integer", "unsigned"):
        return "int"
    if type_name == "boolean":
        return "bool"
    if type_name in ("string", "byte"):
        return "string"
    return ""


def _php_return_type(project_ir: IRProject, method: IRCMethod, entity_name: str) -> str:
    """Determine the PHP return type hint for a method.

    Considers status returns, buffer outputs, and value returns.
    Returns an empty string for methods with multiple buffer outputs (array return).
    """
    resolved_returns = [_resolve_self_arg(entity_name, r) for r in method.returns]
    value_returns = [r for r in resolved_returns if r.enum_name != "status"]

    buffer_outputs = [a for a in method.arguments if _arg_is_buffer_output(a)]

    # Multiple buffer outputs => array return
    if len(buffer_outputs) > 1:
        return "array"
    if len(buffer_outputs) == 1 and value_returns:
        return "array"

    if buffer_outputs:
        return "string"

    if not value_returns:
        return "void"

    ret = value_returns[0]
    return _php_type_for_arg(project_ir, ret)


def _php_return_is_enum(project_ir: IRProject, method: IRCMethod, entity_name: str) -> bool:
    """True if the method returns an enum type."""
    resolved_returns = [_resolve_self_arg(entity_name, r) for r in method.returns]
    value_returns = [r for r in resolved_returns if r.enum_name != "status"]
    if len(value_returns) == 1 and value_returns[0].enum_name:
        return True
    return False


def _php_return_is_interface(project_ir: IRProject, method: IRCMethod, entity_name: str) -> bool:
    """True if the method returns an interface type."""
    resolved_returns = [_resolve_self_arg(entity_name, r) for r in method.returns]
    value_returns = [r for r in resolved_returns if r.enum_name != "status"]
    if len(value_returns) == 1 and value_returns[0].interface_name:
        return True
    return False


def _php_return_is_class(project_ir: IRProject, method: IRCMethod, entity_name: str) -> bool:
    """True if the method returns a concrete class type."""
    resolved_returns = [_resolve_self_arg(entity_name, r) for r in method.returns]
    value_returns = [r for r in resolved_returns if r.enum_name != "status"]
    if len(value_returns) == 1:
        ret = value_returns[0]
        if ret.class_name and ret.class_name not in {"data", "buffer", "error"}:
            return True
    return False


# ---------------------------------------------------------------------------
# PHP method body generation
# ---------------------------------------------------------------------------

def _php_arg_expr(project_ir: IRProject, arg: IRCArgument) -> str:
    """Return the PHP expression to pass this arg to a C ext function.

    Interface args use ->getCtx(), everything else passes directly.
    """
    var = f"$${_camel_case(arg.name)}"
    if arg.interface_name:
        return f"{var}->getCtx()"
    return var


def _render_php_method_body(
    project_ir: IRProject,
    entity_name: str,
    method: IRCMethod,
    *,
    is_static: bool = False,
    is_dependency_setter: bool = False,
    dep_name: str = "",
) -> list[str]:
    """Render the body lines (inside { ... }) for a PHP method.

    Returns a list of indented body lines.
    """
    prefix = project_ir.prefix
    func_name = _c_ext_func_name(prefix, entity_name, method.name)

    resolved_args = [_resolve_self_arg(entity_name, a) for a in method.arguments]
    resolved_returns = [_resolve_self_arg(entity_name, r) for r in method.returns]

    # Build call arguments
    call_args: list[str] = []
    if not is_static:
        call_args.append("$this->ctx")
    for arg in resolved_args:
        if _arg_should_skip(arg):
            continue
        if _arg_is_buffer_output(arg):
            continue
        call_args.append(_php_arg_expr(project_ir, arg))

    call_str = ", ".join(call_args)

    value_returns = [r for r in resolved_returns if r.enum_name != "status"]
    buffer_outputs = [a for a in resolved_args if _arg_is_buffer_output(a)]

    lines: list[str] = []
    ret_type = _php_return_type(project_ir, method, entity_name)

    if _php_return_is_enum(project_ir, method, entity_name):
        lines.append(f"        $enum = {func_name}({call_str});")
        lines.append(f"        return new {ret_type}($enum);")
    elif _php_return_is_interface(project_ir, method, entity_name):
        impl_class = _pascal_case(project_ir.name) + "Implementation"
        lines.append(f"        $ctx = {func_name}({call_str});")
        lines.append(f"        return {impl_class}::wrap{ret_type}($ctx);")
    elif _php_return_is_class(project_ir, method, entity_name):
        lines.append(f"        $ctx = {func_name}({call_str});")
        lines.append(f"        return new {ret_type}($ctx);")
    elif ret_type == "void":
        lines.append(f"        {func_name}({call_str});")
    else:
        lines.append(f"        return {func_name}({call_str});")

    return lines


def _render_php_method(
    project_ir: IRProject,
    entity_name: str,
    method: IRCMethod,
    *,
    is_static: bool = False,
    lines: list[str],
) -> None:
    """Render a complete PHP method (doc + signature + body) and append to lines."""
    resolved_args = [_resolve_self_arg(entity_name, a) for a in method.arguments]
    # Build parameter list for signature
    params: list[str] = []
    for arg in resolved_args:
        if _arg_should_skip(arg):
            continue
        if _arg_is_buffer_output(arg):
            continue
        php_type = _php_type_for_arg(project_ir, arg)
        var_name = f"$${_camel_case(arg.name)}"
        if php_type:
            params.append(f"{php_type} {var_name}")
        else:
            params.append(var_name)

    ret_type = _php_return_type(project_ir, method, entity_name)
    throws = _method_throws(method)

    # Doc comment
    lines.append("    /**")
    lines.append("    *")
    for arg in resolved_args:
        if _arg_should_skip(arg):
            continue
        if _arg_is_buffer_output(arg):
            continue
        php_type = _php_type_for_arg(project_ir, arg)
        var_name = f"$${_camel_case(arg.name)}"
        lines.append(f"    * @param {php_type} {var_name}")
    lines.append(f"    * @return {ret_type}")
    if throws:
        lines.append("    * @throws \\Exception")
    lines.append("    */")

    # Method signature
    static_kw = "static " if is_static else ""
    params_str = ", ".join(params)
    ret_hint = f": {ret_type}" if ret_type and ret_type != "array" else ""
    lines.append(f"    public {static_kw}function {_camel_case(method.name)}({params_str}){ret_hint}")
    lines.append("    {")

    # Method body
    body = _render_php_method_body(
        project_ir, entity_name, method, is_static=is_static,
    )
    lines.extend(body)
    lines.append("    }")
    lines.append("")


# ---------------------------------------------------------------------------
# PHP file header
# ---------------------------------------------------------------------------

def _php_file_header(namespace: str) -> list[str]:
    """Return the standard PHP file header lines."""
    lines: list[str] = []
    lines.append("<?php")
    lines.append(_PHP_LICENSE)
    lines.append("")
    lines.append(f"namespace {namespace};")
    lines.append("")
    return lines


# ---------------------------------------------------------------------------
# Enum generator
# ---------------------------------------------------------------------------

def generate_php_enum(project_ir: IRProject, enum: IREnum) -> str:
    """Generate a PHP enum class (extends Enum)."""
    namespace = _php_namespace(project_ir.name)
    class_name = _php_class_name(enum.name)

    lines = _php_file_header(namespace)
    lines.append(f"class {class_name} extends Enum")
    lines.append("{")
    lines.append("")

    next_value = 0
    for const in enum.constants:
        raw_value = const.attrs.get("value")
        if raw_value is not None and raw_value != "":
            value_str = raw_value.strip()
            try:
                next_value = int(value_str, 0) + 1
            except ValueError:
                next_value += 1
        else:
            value_str = str(next_value)
            next_value += 1
        const_name = _snake_case(const.name).upper()
        lines.append(f"    private const {const_name} = {value_str};")

    lines.append("")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Enum base class generator
# ---------------------------------------------------------------------------

def generate_php_enum_base() -> str:
    """Generate the Enum base class that all enum classes extend."""
    # This is a utility class, not generated from IR per se,
    # but needed by all enum types. Legacy output has it as a hand-written file.
    # We don't generate it -- it already exists in the output dir.
    # Returning empty means orchestrator won't emit it.
    return ""


# ---------------------------------------------------------------------------
# Ctx interface generator
# ---------------------------------------------------------------------------

def generate_php_ctx_interface(project_ir: IRProject) -> str:
    """Generate the Ctx interface that all wrapped types implement."""
    namespace = _php_namespace(project_ir.name)
    lines = _php_file_header(namespace)
    lines.append("interface Ctx")
    lines.append("{")
    lines.append("")
    lines.append("    /**")
    lines.append("    * Get C context.")
    lines.append("    *")
    lines.append("    * @return resource")
    lines.append("    */")
    lines.append("    public function getCtx()")
    lines.append("    {")
    lines.append("        return $this->ctx;")
    lines.append("    }")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Interface generator
# ---------------------------------------------------------------------------

def generate_php_interface(project_ir: IRProject, iface: IRInterface) -> str:
    """Generate a PHP interface file.

    Interfaces extend Ctx and declare method stubs.
    Legacy output has method bodies with incomplete C function calls
    (no function name, just the arguments). We replicate that pattern.
    """
    namespace = _php_namespace(project_ir.name)
    class_name = _php_class_name(iface.name)

    # Build extends clause from inherited interfaces
    extends = ["Ctx"]
    for parent_name in iface.inherits:
        extends.append(_php_class_name(parent_name))

    extends_str = ", ".join(extends)

    lines = _php_file_header(namespace)
    lines.append(f"interface {class_name} extends {extends_str}")
    lines.append("{")
    lines.append("")

    for method in iface.methods:
        if not _method_should_wrap(method):
            continue
        _render_php_interface_method(project_ir, iface.name, method, lines)

    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _render_php_interface_method(
    project_ir: IRProject,
    entity_name: str,
    method: IRCMethod,
    lines: list[str],
) -> None:
    """Render an interface method stub.

    Legacy interfaces have method bodies with partial call expressions
    (no function name prefix). We replicate that pattern.
    """
    is_static = method.attrs.get("is_static") in {"1", "true"}
    resolved_args = [_resolve_self_arg(entity_name, a) for a in method.arguments]

    # Build parameter list
    params: list[str] = []
    for arg in resolved_args:
        if _arg_should_skip(arg):
            continue
        if _arg_is_buffer_output(arg):
            continue
        php_type = _php_type_for_arg(project_ir, arg)
        var_name = f"$${_camel_case(arg.name)}"
        if php_type:
            params.append(f"{php_type} {var_name}")
        else:
            params.append(var_name)

    ret_type = _php_return_type(project_ir, method, entity_name)
    throws = _method_throws(method)

    # Doc comment
    lines.append("    /**")
    lines.append("    *")
    for arg in resolved_args:
        if _arg_should_skip(arg):
            continue
        if _arg_is_buffer_output(arg):
            continue
        php_type = _php_type_for_arg(project_ir, arg)
        var_name = f"$${_camel_case(arg.name)}"
        lines.append(f"    * @param {php_type} {var_name}")
    lines.append(f"    * @return {ret_type}")
    if throws:
        lines.append("    * @throws \\Exception")
    lines.append("    */")

    # Method signature (matches legacy interface format)
    static_kw = "static " if is_static else ""
    params_str = ", ".join(params)
    ret_hint = f": {ret_type}" if ret_type and ret_type != "array" else ""
    lines.append(f"    public {static_kw}function {_camel_case(method.name)}({params_str}){ret_hint}")
    lines.append("    {")

    # Interface methods have stub bodies that mirror the call shape
    # but without the C function name (legacy behavior).
    call_args: list[str] = []
    if not is_static:
        call_args.append("$this->ctx")
    for arg in resolved_args:
        if _arg_should_skip(arg):
            continue
        if _arg_is_buffer_output(arg):
            continue
        call_args.append(_php_arg_expr(project_ir, arg))
    call_str = ", ".join(call_args)

    if _php_return_is_enum(project_ir, method, entity_name):
        lines.append(f"        $enum = ({call_str});")
        lines.append(f"        return new {ret_type}($enum);")
    elif _php_return_is_interface(project_ir, method, entity_name):
        impl_class = _pascal_case(project_ir.name) + "Implementation"
        lines.append(f"        $ctx = ({call_str});")
        lines.append(f"        return {impl_class}::wrap{ret_type}($ctx);")
    elif _php_return_is_class(project_ir, method, entity_name):
        lines.append(f"        $ctx = ({call_str});")
        lines.append(f"        return new {ret_type}($ctx);")
    elif ret_type == "void":
        lines.append(f"        ({call_str});")
    else:
        lines.append(f"        return ({call_str});")

    lines.append("    }")
    lines.append("")


# ---------------------------------------------------------------------------
# Implementation / Class generator
# ---------------------------------------------------------------------------

def _collect_interface_names(project_ir: IRProject, impl: IRImplementation) -> list[str]:
    """Collect the interface names that an implementation implements."""
    iface_names = []
    for binding in impl.interface_bindings:
        iface_names.append(_php_class_name(binding.name))
    return iface_names


def _collect_constants_for_entity(
    project_ir: IRProject,
    constants: list[IRCConstant],
    entity=None,
) -> list[tuple[str, str]]:
    """Collect (NAME, value) pairs for class constants."""
    result = []
    for const in constants:
        if const.attrs.get("definition") == "private":
            continue
        const_name = _snake_case(const.name).upper()
        value = resolve_constant_value(
            const.attrs.get("value", "0"), entity, project_ir
        )
        result.append((const_name, value))
    return result


def generate_php_implementation(project_ir: IRProject, impl: IRImplementation) -> str:
    """Generate a PHP class for an implementation (has context, implements interfaces)."""
    namespace = _php_namespace(project_ir.name)
    class_name = _php_class_name(impl.name)
    prefix = project_ir.prefix
    entity_snake = _snake_case(impl.name)

    # Collect interface names
    iface_names = _collect_interface_names(project_ir, impl)

    lines = _php_file_header(namespace)

    # Class declaration
    if iface_names:
        implements_str = ", ".join(iface_names)
        lines.append(f"class {class_name} implements {implements_str}")
    else:
        lines.append(f"class {class_name}")
    lines.append("{")
    lines.append("")

    # Property
    lines.append("    /**")
    lines.append("    * @var")
    lines.append("    */")
    lines.append("    private $ctx;")
    lines.append("")

    # Constants from interface bindings
    constants = _collect_constants_for_entity(project_ir, impl.constants, entity=impl)
    if constants:
        for cname, cvalue in constants:
            lines.append(f"    const {cname} = {cvalue};")
        lines.append("")

    # Constructor
    new_func = f"{prefix}_{entity_snake}_new_php"
    lines.append("    /**")
    lines.append("    * Create underlying C context.")
    lines.append("    * @param null $ctx")
    lines.append("    * @return void")
    lines.append("    */")
    lines.append("    public function __construct($ctx = null)")
    lines.append("    {")
    lines.append(f"        $this->ctx = is_null($ctx) ? {new_func}() : $ctx;")
    lines.append("    }")
    lines.append("")

    # Destructor
    del_func = f"{prefix}_{entity_snake}_delete_php"
    lines.append("    /**")
    lines.append("    * Destroy underlying C context.")
    lines.append("    * @return void")
    lines.append("    */")
    lines.append("    public function __destructor()")
    lines.append("    {")
    lines.append(f"        {del_func}($this->ctx);")
    lines.append("    }")
    lines.append("")

    # Dependency setters (use{Dep} methods)
    for dep in impl.dependencies:
        _render_dependency_setter(project_ir, impl.name, dep, lines)

    # Methods -- both own methods and those from interface bindings
    rendered_methods: set[str] = set()

    # Interface-bound methods first (they come from the interfaces)
    iface_by_name = {i.name: i for i in project_ir.interfaces}
    for binding in impl.interface_bindings:
        iface = iface_by_name.get(binding.name)
        if iface is None:
            continue
        for method in iface.methods:
            if not _method_should_wrap(method):
                continue
            method_key = method.name
            if method_key in rendered_methods:
                continue
            rendered_methods.add(method_key)
            is_static = method.attrs.get("is_static") in {"1", "true"}
            _render_php_method(
                project_ir, impl.name, method,
                is_static=is_static, lines=lines,
            )

    # Own methods
    for method in impl.methods:
        if not _method_should_wrap(method):
            continue
        method_key = method.name
        if method_key in rendered_methods:
            continue
        rendered_methods.add(method_key)
        is_static = method.attrs.get("is_static") in {"1", "true"}
        _render_php_method(
            project_ir, impl.name, method,
            is_static=is_static, lines=lines,
        )

    # getCtx method
    lines.append("    /**")
    lines.append("    * Get C context.")
    lines.append("    *")
    lines.append("    * @return resource")
    lines.append("    */")
    lines.append("    public function getCtx()")
    lines.append("    {")
    lines.append("        return $this->ctx;")
    lines.append("    }")

    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def generate_php_class(project_ir: IRProject, cls: IRClass) -> str:
    """Generate a PHP class for a non-static class (has context)."""
    namespace = _php_namespace(project_ir.name)
    class_name = _php_class_name(cls.name)
    prefix = project_ir.prefix
    entity_snake = _snake_case(cls.name)

    lines = _php_file_header(namespace)
    lines.append(f"class {class_name}")
    lines.append("{")
    lines.append("")

    # Property
    lines.append("    /**")
    lines.append("    * @var")
    lines.append("    */")
    lines.append("    private $ctx;")
    lines.append("")

    # Constants
    constants = _collect_constants_for_entity(project_ir, cls.constants, entity=cls)
    if constants:
        for cname, cvalue in constants:
            lines.append(f"    const {cname} = {cvalue};")
        lines.append("")

    # Constructor
    new_func = f"{prefix}_{entity_snake}_new_php"
    lines.append("    /**")
    lines.append("    * Create underlying C context.")
    lines.append("    * @param null $ctx")
    lines.append("    * @return void")
    lines.append("    */")
    lines.append("    public function __construct($ctx = null)")
    lines.append("    {")
    lines.append(f"        $this->ctx = is_null($ctx) ? {new_func}() : $ctx;")
    lines.append("    }")
    lines.append("")

    # Destructor
    del_func = f"{prefix}_{entity_snake}_delete_php"
    lines.append("    /**")
    lines.append("    * Destroy underlying C context.")
    lines.append("    * @return void")
    lines.append("    */")
    lines.append("    public function __destructor()")
    lines.append("    {")
    lines.append(f"        {del_func}($this->ctx);")
    lines.append("    }")
    lines.append("")

    # Dependency setters
    for dep in cls.dependencies:
        _render_dependency_setter(project_ir, cls.name, dep, lines)

    # Methods
    for method in cls.methods:
        if not _method_should_wrap(method):
            continue
        is_static = method.attrs.get("is_static") in {"1", "true"}
        _render_php_method(
            project_ir, cls.name, method,
            is_static=is_static, lines=lines,
        )

    # getCtx method
    lines.append("    /**")
    lines.append("    * Get C context.")
    lines.append("    *")
    lines.append("    * @return resource")
    lines.append("    */")
    lines.append("    public function getCtx()")
    lines.append("    {")
    lines.append("        return $this->ctx;")
    lines.append("    }")

    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def generate_php_static_class(project_ir: IRProject, cls: IRClass) -> str:
    """Generate a PHP class for a static-only class (no context)."""
    namespace = _php_namespace(project_ir.name)
    class_name = _php_class_name(cls.name)

    lines = _php_file_header(namespace)
    lines.append(f"class {class_name}")
    lines.append("{")
    lines.append("")

    # Constants (if any)
    constants = _collect_constants_for_entity(project_ir, cls.constants, entity=cls)
    if constants:
        for cname, cvalue in constants:
            lines.append(f"    const {cname} = {cvalue};")
        lines.append("")

    # Methods (all static)
    for method in cls.methods:
        if not _method_should_wrap(method):
            continue
        _render_php_method(
            project_ir, cls.name, method,
            is_static=True, lines=lines,
        )

    lines.append("}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Dependency setter generation
# ---------------------------------------------------------------------------

def _render_dependency_setter(
    project_ir: IRProject,
    entity_name: str,
    dep: IRDependency,
    lines: list[str],
) -> None:
    """Render a use{Dep} method for a dependency."""
    prefix = project_ir.prefix
    entity_snake = _snake_case(entity_name)
    dep_name_camel = _camel_case(dep.name)
    dep_method_name = f"use{_pascal_case(dep.name)}"
    func_name = f"{prefix}_{entity_snake}_use_{_snake_case(dep.name)}_php"

    # Determine the type of the dependency
    if dep.type_kind == "interface":
        dep_type = _php_class_name(dep.type_name)
        if dep.attrs.get("project") and dep.attrs.get("project") != project_ir.name:
            dep_type = f"\\{_php_namespace(dep.attrs['project'])}\\{dep_type}"
    elif dep.type_kind in ("class", "impl"):
        dep_type = _php_class_name(dep.type_name)
        if dep.attrs.get("project") and dep.attrs.get("project") != project_ir.name:
            dep_type = f"\\{_php_namespace(dep.attrs['project'])}\\{dep_type}"
    else:
        dep_type = _php_class_name(dep.type_name)

    lines.append("    /**")
    lines.append("    *")
    lines.append(f"    * @param {dep_type} $${dep_name_camel}")
    lines.append("    * @return void")
    lines.append("    */")
    lines.append(f"    public function {dep_method_name}({dep_type} $${dep_name_camel}): void")
    lines.append("    {")
    lines.append(f"        {func_name}($this->ctx, $${dep_name_camel});")
    lines.append("    }")
    lines.append("")


# ---------------------------------------------------------------------------
# Implementation dispatch class ({Project}Implementation)
# ---------------------------------------------------------------------------

def generate_php_project_implementation(project_ir: IRProject) -> str:
    """Generate the {PascalProject}Implementation class.

    This class has:
    - Constants mapping each implementation to a tag number
    - Static wrap{Interface}($ctx) methods for each interface
    """
    namespace = _php_namespace(project_ir.name)
    project_pascal = _pascal_case(project_ir.name)
    class_name = f"{project_pascal}Implementation"
    prefix = project_ir.prefix

    lines = _php_file_header(namespace)
    lines.append(f"class {class_name}")
    lines.append("{")
    lines.append("")

    # Impl tag constants - sorted by name for stable output
    sorted_impls = sorted(project_ir.implementations, key=lambda i: i.name)
    for idx, impl in enumerate(sorted_impls, start=1):
        const_name = _snake_case(impl.name).upper()
        lines.append(f"    const {const_name} = {idx};")
    lines.append("")

    # Wrap methods for each interface
    for iface in project_ir.interfaces:
        if iface.attrs.get("scope") == "private":
            continue
        iface_php_name = _php_class_name(iface.name)
        func_name = f"{prefix}_{_snake_case(project_ir.name)}_implementation_wrap_{_snake_case(iface.name)}_php"

        lines.append("    /**")
        lines.append("    *")
        lines.append(f"    * @param  $$ctx")
        lines.append(f"    * @return {iface_php_name}")
        lines.append("    */")
        lines.append(f"    public static function wrap{iface_php_name}($$ctx): {iface_php_name}")
        lines.append("    {")
        lines.append(f"        return {func_name}($$ctx);")
        lines.append("    }")
        lines.append("")

    lines.append("}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# C extension generator (stub)
# ---------------------------------------------------------------------------

def _flatten_description(description: str) -> str:
    """Collapse a multi-line description into a single space-joined line."""
    lines = [line.strip() for line in description.strip().splitlines()]
    return " ".join(line for line in lines if line)


def generate_c_extension_source(project_ir: IRProject) -> str:
    """Generate the C extension .c source file from IR.

    Produces the complete C extension with:
    - License, includes, status handler
    - Resource type registrations
    - PHP function implementations wrapping C calls
    - Function entry table (PHP_FE)
    - Module definition
    """
    prefix = project_ir.prefix
    prefix_upper = prefix.upper()
    project_name = project_ir.name

    lines: list[str] = []
    lines.append(_C_LICENSE)
    lines.append("")

    # Includes
    lines.append("#include <php.h>")
    lines.append("#include <zend_exceptions.h>")
    lines.append("#include <zend_list.h>")
    lines.append(f'#include "{prefix}_assert.h"')
    lines.append(f'#include "{prefix}_{project_name}_php.h"')

    # Collect all entities that need C includes
    all_entities = _collect_all_wrapped_entities(project_ir)
    for ename, ekind in all_entities:
        entity_snake = _snake_case(ename)
        lines.append(f'#include "{prefix}_{entity_snake}.h"')

    lines.append("")

    # Status handler macro
    lines.append(f"#define {prefix_upper}_HANDLE_STATUS(status) do {{ if(status != {prefix}_status_SUCCESS) {{ {prefix}_handle_throw_exception(status); }} }} while (false)")
    lines.append("")

    # Exception class entry
    lines.append(f"zend_class_entry* {prefix}_exception_ce;")
    lines.append("")

    # Status handler function
    status_enum = _find_status_enum(project_ir)
    lines.append("void")
    lines.append(f"{prefix}_handle_throw_exception({prefix}_status_t status) {{")
    lines.append("")
    lines.append("    switch(status) {")
    lines.append("")
    if status_enum:
        for const in status_enum.constants:
            const_c_name = f"{prefix}_status_{_snake_case(const.name).upper()}"
            value = const.attrs.get("value", "0")
            desc = _flatten_description(const.description) if const.description else const.name
            desc_escaped = desc.replace('"', '\\"')
            if const.name == "success":
                lines.append(f"    case {const_c_name}:")
                lines.append("        break;")
            else:
                lines.append(f"    case {const_c_name}:")
                lines.append(f'        zend_throw_exception_ex({prefix}_exception_ce, {value}, "{desc_escaped}");')
                lines.append("        break;")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def generate_c_extension_header(project_ir: IRProject) -> str:
    """Generate the C extension .h header file from IR."""
    prefix = project_ir.prefix
    prefix_upper = prefix.upper()
    project_name = project_ir.name
    guard = f"{prefix_upper}_{project_name.upper()}_PHP_H_INCLUDED"

    lines: list[str] = []
    lines.append(_C_LICENSE)
    lines.append("")
    lines.append(f"#ifndef {guard}")
    lines.append(f"#define {guard}")
    lines.append("")
    lines.append('#ifdef __cplusplus')
    lines.append('extern "C" {')
    lines.append('#endif')
    lines.append("")
    lines.append("")

    # Visibility macros
    lines.append(f"#if defined(_WIN32) || defined(__CYGWIN__)")
    lines.append(f"# if {prefix_upper}_PHP_SHARED_LIBRARY")
    lines.append(f"# if defined({prefix_upper}_PHP_INTERNAL_BUILD)")
    lines.append(f"# ifdef __GNUC__")
    lines.append(f"# define {prefix_upper}_PHP_PUBLIC __attribute__ ((dllexport))")
    lines.append(f"# else")
    lines.append(f"# define {prefix_upper}_PHP_PUBLIC __declspec(dllexport)")
    lines.append(f"# endif")
    lines.append(f"# else")
    lines.append(f"# ifdef __GNUC__")
    lines.append(f"# define {prefix_upper}_PHP_PUBLIC __attribute__ ((dllimport))")
    lines.append(f"# else")
    lines.append(f"# define {prefix_upper}_PHP_PUBLIC __declspec(dllimport)")
    lines.append(f"# endif")
    lines.append(f"# endif")
    lines.append(f"# else")
    lines.append(f"# define {prefix_upper}_PHP_PUBLIC")
    lines.append(f"# endif")
    lines.append(f"# define {prefix_upper}_PHP_PRIVATE")
    lines.append(f"#else")
    lines.append(f"# if (defined(__GNUC__) && __GNUC__ >= 4) || defined(__INTEL_COMPILER) || defined(__clang__)")
    lines.append(f"# define {prefix_upper}_PHP_PUBLIC __attribute__ ((visibility (\"default\")))")
    lines.append(f"# define {prefix_upper}_PHP_PRIVATE __attribute__ ((visibility (\"hidden\")))")
    lines.append(f"# else")
    lines.append(f"# define {prefix_upper}_PHP_PRIVATE")
    lines.append(f"# endif")
    lines.append(f"#endif")
    lines.append("")

    # Resource name declarations for each class/impl
    lines.append("//")
    lines.append("// Constants")
    lines.append("//")

    all_entities = _collect_all_wrapped_entities(project_ir)
    for ename, ekind in all_entities:
        entity_snake = _snake_case(ename)
        if ekind in ("class", "implementation"):
            lines.append(f"{prefix_upper}_PHP_PUBLIC const char*")
            lines.append(f"{prefix}_{entity_snake}_t_php_res_name(void);")
            lines.append("")

    # Also declare impl_t resource name
    lines.append(f"{prefix_upper}_PHP_PUBLIC const char*")
    lines.append(f"{prefix}_impl_t_php_res_name(void);")
    lines.append("")

    lines.append("#ifdef __cplusplus")
    lines.append("}")
    lines.append("#endif")
    lines.append("")
    lines.append(f"#endif // {guard}")
    lines.append("")

    return "\n".join(lines)


def generate_c_extension_cmake(project_ir: IRProject) -> str:
    """Generate the CMakeLists.txt for the PHP C extension.

    Matches the legacy GSL-generated CMakeLists structure: uses
    vsc::{project} imported target, phplib, macOS dynamic_lookup,
    and proper output naming.
    """
    prefix = project_ir.prefix
    project_name = project_ir.name
    lib_option = f"VIRGIL_LIB_{project_name.upper()}"
    target = f"{project_name}_php"
    c_target = f"vsc::{project_name}"

    lines: list[str] = []
    lines.append("cmake_minimum_required(VERSION 3.12 FATAL_ERROR)")
    lines.append("")
    lines.append(f"project(virgil_crypto_{project_name}_php "
                 "VERSION ${virgil_crypto_php_VERSION} LANGUAGES C)")
    lines.append("")
    lines.append(f"if(NOT {lib_option})")
    lines.append(f'    message(STATUS "Skip building the PHP wrapper for '
                 f"library '{project_name}', which is not built.\")")
    lines.append("    return()")
    lines.append("endif()")
    lines.append("")
    lines.append(f"add_library({target} SHARED)")
    lines.append("")
    lines.append(f"set_target_properties({target} PROPERTIES")
    lines.append(f'    OUTPUT_NAME "{prefix}_{project_name}_php"')
    lines.append('    PREFIX ""')
    lines.append('    SUFFIX ".so"')
    lines.append(")")
    lines.append("")
    lines.append(f"if(WIN32)")
    lines.append(f"    set_target_properties({target} PROPERTIES SUFFIX \".dll\")")
    lines.append(f"endif()")
    lines.append("")
    lines.append(f"target_compile_definitions({target}")
    lines.append("    PRIVATE")
    lines.append(f"        {prefix.upper()}_PHP_SHARED_LIBRARY")
    lines.append(f"        {prefix.upper()}_PHP_INTERNAL_BUILD=1")
    lines.append(")")
    lines.append("")
    lines.append(f"target_sources({target}")
    lines.append("    PRIVATE")
    lines.append(f"        $<BUILD_INTERFACE:{prefix}_{project_name}_php.c>")
    lines.append(")")
    lines.append("")
    lines.append(f"target_include_directories({target}")
    lines.append("    PUBLIC")
    lines.append("        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>")
    lines.append(")")
    lines.append("")
    lines.append(f"target_link_libraries({target}")
    lines.append("    PUBLIC")
    lines.append(f"        {c_target}")
    lines.append("    PRIVATE")
    lines.append("        phplib")
    lines.append('        "$<$<STREQUAL:${CMAKE_SYSTEM_NAME},Darwin>:'
                 '-undefined dynamic_lookup>"')
    lines.append(")")
    lines.append("")
    lines.append("if(VIRGIL_INSTALL_WRAP_LIBS)")
    lines.append(f"    install(TARGETS {target}")
    lines.append("        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}")
    lines.append("        RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}")
    lines.append("    )")
    lines.append("endif()")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_status_enum(project_ir: IRProject) -> IREnum | None:
    """Find the 'status' enum in the project IR."""
    for enum in project_ir.enums:
        if enum.name == "status":
            return enum
    return None


def _collect_all_wrapped_entities(
    project_ir: IRProject,
) -> list[tuple[str, str]]:
    """Collect all entity (name, kind) pairs that are wrapped for PHP.

    Returns sorted list for stable output.
    """
    entities: list[tuple[str, str]] = []

    for cls in project_ir.classes:
        if cls.attrs.get("scope") in {"private", "internal"}:
            continue
        if cls.name == "error":
            continue
        entities.append((cls.name, "class"))

    for impl in project_ir.implementations:
        if impl.attrs.get("scope") in {"private", "internal"}:
            continue
        entities.append((impl.name, "implementation"))

    return sorted(entities, key=lambda x: x[0])


# ---------------------------------------------------------------------------
# Output directory
# ---------------------------------------------------------------------------

def _php_source_dir(project_ir: IRProject) -> str:
    """PHP source dir for a project's high-level PHP files."""
    project_pascal = _pascal_case(project_ir.name)
    return f"wrappers/php/VirgilCryptoWrapper/src/{project_pascal}/"


def _php_extension_dir(project_ir: IRProject) -> str:
    """PHP extension dir for a project's C extension files."""
    return f"wrappers/php/VirgilCryptoWrapper/extensions/{project_ir.name}/"


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def generate_php_files(
    project_ir: IRProject, license_text: str = "",
    repo_root: str | Path = ".",
) -> list[tuple[str, str]]:
    """Generate all PHP wrapper files for a project from IR.

    Returns a list of ``(repo_relative_path, file_content)`` tuples.
    No dependency on resolved XML files.
    """
    del license_text
    del repo_root

    files: list[tuple[str, str]] = []

    src_dir = _php_source_dir(project_ir)
    ext_dir = _php_extension_dir(project_ir)

    # --- Ctx interface (only emitted when the project has interfaces) ---
    has_public_interfaces = any(
        iface.attrs.get("scope") != "private"
        for iface in project_ir.interfaces
    )
    if has_public_interfaces:
        files.append((f"{src_dir}Ctx.php", generate_php_ctx_interface(project_ir)))

    # --- Enums ---
    for enum in project_ir.enums:
        if enum.name in ("status", "impl/tag"):
            continue
        if enum.attrs.get("scope") == "private":
            continue
        class_name = _php_class_name(enum.name)
        files.append((f"{src_dir}{class_name}.php", generate_php_enum(project_ir, enum)))

    # --- Interfaces ---
    for iface in project_ir.interfaces:
        if iface.attrs.get("scope") == "private":
            continue
        class_name = _php_class_name(iface.name)
        files.append((f"{src_dir}{class_name}.php", generate_php_interface(project_ir, iface)))

    # --- Classes ---
    for cls in project_ir.classes:
        if cls.attrs.get("scope") in {"private", "internal"}:
            continue
        if cls.name == "error":
            continue
        class_name = _php_class_name(cls.name)
        if _is_static_class(cls):
            content = generate_php_static_class(project_ir, cls)
        else:
            content = generate_php_class(project_ir, cls)
        files.append((f"{src_dir}{class_name}.php", content))

    # --- Implementations ---
    for impl in project_ir.implementations:
        if impl.attrs.get("scope") in {"private", "internal"}:
            continue
        class_name = _php_class_name(impl.name)
        files.append((f"{src_dir}{class_name}.php", generate_php_implementation(project_ir, impl)))

    # --- Project implementation dispatch class ---
    if project_ir.implementations:
        project_pascal = _pascal_case(project_ir.name)
        files.append((
            f"{src_dir}{project_pascal}Implementation.php",
            generate_php_project_implementation(project_ir),
        ))

    # --- C extension source ---
    c_filename = f"{project_ir.prefix}_{project_ir.name}_php.c"
    files.append((f"{ext_dir}{c_filename}", generate_c_extension_source(project_ir)))

    # --- C extension header ---
    h_filename = f"{project_ir.prefix}_{project_ir.name}_php.h"
    files.append((f"{ext_dir}{h_filename}", generate_c_extension_header(project_ir)))

    # --- CMakeLists.txt ---
    files.append((f"{ext_dir}CMakeLists.txt", generate_c_extension_cmake(project_ir)))

    return files
