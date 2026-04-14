"""Swift wrapper file generation for the project-rooted codegen pipeline.

Ports the legacy ``codegen/swift.gsl`` / ``codegen/swift_codegen.gsl``
templates to Python, consuming the shared :class:`IRProject` already
used by the C, CMake, and Go backends.

Each entity (enum, interface, class, implementation) becomes a single
``.swift`` file.  Per-project infrastructure files (``CContext.swift``,
``{Project}Error.swift``, ``{Project}Implementation.swift``) are also
generated.

ALL output is generated from the IR — no resolved XML dependency.
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
)


# ---------------------------------------------------------------------------
# Per-project configuration derived from IRProject
# ---------------------------------------------------------------------------

def _framework(project_ir: IRProject) -> str:
    """The C framework name to import (e.g., ``VSCFoundation``)."""
    return project_ir.framework or f"VSC{project_ir.name.capitalize()}"


def _objc_prefix(project_ir: IRProject) -> str:
    """ObjC bridging prefix (e.g., ``VSCF`` for foundation)."""
    return project_ir.prefix.upper()


def _c_prefix(project_ir: IRProject) -> str:
    """C symbol prefix (e.g., ``vscf_``)."""
    return f"{project_ir.prefix}_"


def _namespace(project_ir: IRProject) -> str:
    """Swift namespace / module directory (e.g., ``VirgilCryptoFoundation``)."""
    if project_ir.namespace:
        return "".join(_pascalize_word(w) for w in project_ir.namespace.split())
    return f"VirgilCrypto{project_ir.name.capitalize()}"


def _source_dir(project_ir: IRProject) -> str:
    """Repo-relative output directory for this project's Swift files."""
    ns = _namespace(project_ir)
    return f"wrappers/swift/VirgilCrypto/{ns}/"


def _project_name_pascal(project_ir: IRProject) -> str:
    """PascalCase project name (e.g., ``Foundation``)."""
    return swift_type_name(project_ir.name)


# ---------------------------------------------------------------------------
# Name utilities
# ---------------------------------------------------------------------------

def _split_words(name: str) -> list[str]:
    """Split a space/underscore-separated entity name into words."""
    return [w for w in name.replace("_", " ").split(" ") if w]


def swift_type_name(entity_name: str) -> str:
    """Derive the exported Swift type name for an entity.

    ``"alg id"`` -> ``"AlgId"``
    ``"sha256"`` -> ``"Sha256"``
    ``"aes256 gcm"`` -> ``"Aes256Gcm"``
    ``"asn1 reader"`` -> ``"Asn1Reader"``
    """
    return "".join(_pascalize_word(w) for w in _split_words(entity_name))


def _pascalize_word(word: str) -> str:
    """Convert a single word to PascalCase.

    Lowercase words are title-cased; already-capitalized words keep case.
    """
    if not word:
        return word
    if len(word) > 1 and word.isupper():
        return word
    if word[:1].isupper():
        return word
    return word[:1].upper() + word[1:]


def swift_case_name(constant_name: str) -> str:
    """Derive a Swift enum case name (camelCase).

    ``"sha256"``        -> ``"sha256"``
    ``"aes256 gcm"``    -> ``"aes256Gcm"``
    ``"round5 nd 1cca 5d"`` -> ``"round5Nd1cca5d"``
    ``"none"``          -> ``"none"``
    """
    words = _split_words(constant_name)
    if not words:
        return constant_name
    head = words[0].lower()
    tail = [_pascalize_word(w) for w in words[1:]]
    return head + "".join(tail)


def swift_method_name(method_name: str) -> str:
    """Derive a Swift method name (camelCase).

    ``"alg id"`` -> ``"algId"``
    ``"encrypt data"`` -> ``"encryptData"``
    """
    return swift_case_name(method_name)


def _c_enum_type(project_ir: IRProject, enum: IREnum) -> str:
    """C type name for an enum (e.g., ``vscf_alg_id_t``)."""
    stem = enum.name.replace(" ", "_").lower()
    return f"{_c_prefix(project_ir)}{stem}_t"


def _c_enum_type_by_name(project_ir: IRProject, enum_name: str) -> str:
    """C type name for an enum by name (e.g., ``vscf_alg_id_t``)."""
    stem = enum_name.replace(" ", "_").lower()
    return f"{_c_prefix(project_ir)}{stem}_t"


def _from_c_param_name(enum: IREnum) -> str:
    """The ``fromC`` initializer parameter name (camelCase of enum name)."""
    return swift_case_name(enum.name)


def _entity_snake(name: str) -> str:
    """Convert entity name to snake_case (``"sha256"`` -> ``"sha256"``,
    ``"brainkey client"`` -> ``"brainkey_client"``)."""
    return name.replace(" ", "_").lower()


def _c_func_name(project_ir: IRProject, entity_name: str, method_name: str) -> str:
    """Build a C function name like ``vscf_sha256_hash``."""
    prefix = project_ir.prefix
    entity = _entity_snake(entity_name)
    method = _entity_snake(method_name)
    return f"{prefix}_{entity}_{method}"


# ---------------------------------------------------------------------------
# License header
# ---------------------------------------------------------------------------

def _emit_doc(lines: list[str], description: str, indent: str = "    ") -> None:
    """Append ``/// ...`` doc-comment lines for a description.

    Multi-line descriptions produce one ``///`` line per source line,
    matching the legacy GSL output.
    """
    doc = description.strip() if description else ""
    if not doc:
        return
    for doc_line in doc.splitlines():
        stripped = doc_line.strip()
        if stripped:
            lines.append(f"{indent}/// {stripped}")
        else:
            lines.append(f"{indent}///")


_SWIFT_LICENSE = """\
// Copyright (C) 2015-2022 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
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
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>"""


def _file_header(project_ir: IRProject, *, import_framework: bool = True) -> str:
    """Standard file header: license + imports."""
    lines: list[str] = []
    lines.append(_SWIFT_LICENSE)
    lines.append("")
    lines.append("")
    lines.append("import Foundation")
    if import_framework:
        lines.append(f"import {_framework(project_ir)}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Enum generator
# ---------------------------------------------------------------------------

# Enums that are NOT emitted as standalone .swift enum files:
# - "status" -> becomes {Project}Error.swift (infrastructure, handled separately)
# - "impl/tag" -> C-internal dispatch enum, part of {Project}Implementation.swift
_INFRASTRUCTURE_ENUMS = frozenset({"status", "impl/tag"})


def generate_swift_enum(project_ir: IRProject, enum: IREnum) -> str:
    """Generate the ``.swift`` file content for a single enum."""
    type_name = swift_type_name(enum.name)
    objc_name = f"{_objc_prefix(project_ir)}{type_name}"
    framework = _framework(project_ir)
    c_type = _c_enum_type(project_ir, enum)
    param_name = _from_c_param_name(enum)

    lines: list[str] = []
    lines.append(_SWIFT_LICENSE)
    lines.append("")
    lines.append("import Foundation")
    lines.append(f"import {framework}")
    lines.append("")

    # Enum doc comment
    doc = enum.description.strip() if enum.description else ""
    if doc:
        lines.append(f"/// {doc}")

    lines.append(f"@objc({objc_name}) public enum {type_name}: Int {{")

    # Enum cases
    next_default = 0
    for const in enum.constants:
        case_name = swift_case_name(const.name)

        # Doc comment for this case
        const_doc = const.description.strip() if const.description else ""
        if const_doc:
            for doc_line in const_doc.splitlines():
                lines.append(f"    /// {doc_line.strip()}")

        raw_value = const.attrs.get("value")
        if raw_value is None or raw_value == "":
            lines.append(f"    case {case_name}")
            next_default += 1
        else:
            value_str = raw_value.strip()
            lines.append(f"    case {case_name} = {value_str}")
            try:
                next_default = int(value_str, 0) + 1
            except ValueError:
                next_default += 1

        lines.append("")

    # fromC initializer
    lines.append("    /// Create enumeration value from the correspond C enumeration value.")
    lines.append(f"    init(fromC {param_name}: {c_type}) {{")
    lines.append(f"        self.init(rawValue: Int({param_name}.rawValue))!")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Arg / return type classification helpers
# ---------------------------------------------------------------------------

def _arg_is_buffer_output(arg: IRCArgument) -> bool:
    """Buffer-class arguments act as output parameters -- pushed to returns."""
    return arg.class_name == "buffer"


def _arg_should_skip(arg: IRCArgument) -> bool:
    """Arguments filtered from the wrapper API (writeonly, error-class)."""
    if arg.access == "writeonly":
        return True
    if arg.class_name == "error":
        return True
    return False


def _method_has_error_arg(method: IRCMethod) -> bool:
    """True if the method has an explicit ``class="error"`` argument."""
    return any(arg.class_name == "error" for arg in method.arguments)


def _method_has_status_return(method: IRCMethod) -> bool:
    """True if the method returns a status enum."""
    return any(r.enum_name == "status" for r in method.returns)


def _method_throws(method: IRCMethod) -> bool:
    """True if the method should be marked ``throws`` in Swift."""
    return _method_has_status_return(method) or _method_has_error_arg(method)


def _method_should_wrap(method: IRCMethod) -> bool:
    """Port of ``wrapper_should_wrap_method``."""
    scope = method.attrs.get("scope", "public")
    decl = method.declaration or method.attrs.get("declaration", "public")
    vis = method.visibility or method.attrs.get("visibility", "public")
    return scope == "public" and decl == "public" and vis == "public"


def _is_static_class(cls: IRClass) -> bool:
    """Static-only classes (``context="none"``) carry no c_ctx."""
    return cls.attrs.get("context") == "none"


def _resolve_self_class(cls_name: str, arg: IRCArgument) -> IRCArgument:
    """Resolve ``class="self"`` to the enclosing class name."""
    if arg.class_name == "self":
        resolved = copy.copy(arg)
        resolved.class_name = cls_name
        return resolved
    return arg


# ---------------------------------------------------------------------------
# Swift type mapping
# ---------------------------------------------------------------------------

def _swift_type_for_arg(project_ir: IRProject, arg: IRCArgument) -> str:
    """Map an IR argument to its Swift type name."""
    if arg.enum_name:
        return swift_type_name(arg.enum_name)
    if arg.interface_name:
        return swift_type_name(arg.interface_name)
    if arg.class_name == "data":
        return "Data"
    if arg.class_name == "buffer":
        return "Data"
    if arg.class_name and arg.class_name not in {"data", "buffer"}:
        return swift_type_name(arg.class_name)
    type_name = (arg.type_name or "").lower()
    if type_name == "size":
        return "Int"
    if type_name == "boolean":
        return "Bool"
    if type_name == "integer":
        return "Int"  # Swift maps to Int for all integer sizes
    if type_name == "unsigned":
        return "Int"  # Swift wraps unsigned as Int for ObjC compat
    if type_name == "byte" and arg.is_reference:
        return "UnsafeMutableRawPointer"
    return "Void"


def _swift_return_type(project_ir: IRProject, method: IRCMethod, entity_name: str) -> str:
    """Determine the Swift return type for a method.

    Handles single returns, buffer outputs (Data), and multi-return
    (result struct).
    """
    value_returns: list[IRCArgument] = []
    buffer_outputs: list[IRCArgument] = []

    for ret in method.returns:
        if ret.enum_name == "status":
            continue
        value_returns.append(ret)

    for arg in method.arguments:
        if _arg_is_buffer_output(arg):
            buffer_outputs.append(arg)

    total = len(value_returns) + len(buffer_outputs)

    if total == 0:
        return "Void"
    elif total == 1:
        if value_returns:
            return _swift_type_for_arg(project_ir, value_returns[0])
        else:
            return "Data"
    else:
        # Multi-return: generate a result struct name
        # Format: {InterfaceName}{MethodName}Result or {ClassName}{MethodName}Result
        return _result_struct_name(entity_name, method.name)


def _result_struct_name(entity_name: str, method_name: str) -> str:
    """Build a result struct name like ``AuthEncryptAuthEncryptResult``."""
    return swift_type_name(entity_name) + swift_type_name(method_name) + "Result"


# ---------------------------------------------------------------------------
# Buffer capacity expression
# ---------------------------------------------------------------------------

def _buffer_capacity_expr(
    project_ir: IRProject,
    entity_name: str,
    arg: IRCArgument,
    method_arg_locals: dict[str, str],
    *,
    is_static: bool = False,
) -> str:
    """Resolve the Swift expression for buffer capacity.

    Returns a Swift expression string.
    """
    la = arg.length_attrs
    if not la:
        return "0"

    if "method" in la:
        method_name = la["method"]
        swift_meth = swift_method_name(method_name)

        # Build the proxy arguments
        proxy_args: list[str] = []
        idx = 0
        while f"proxy_{idx}_to" in la:
            cast = la.get(f"proxy_{idx}_cast")
            src_arg = la.get(f"proxy_{idx}_argument")
            src_const = la.get(f"proxy_{idx}_constant")
            target_arg = la.get(f"proxy_{idx}_to")
            target_swift = swift_method_name(target_arg) if target_arg else ""

            if src_const is not None:
                proxy_args.append(f"{target_swift}: {src_const}")
            elif src_arg is not None:
                local = method_arg_locals.get(src_arg, swift_method_name(src_arg))
                if cast == "data_length":
                    proxy_args.append(f"{target_swift}: {local}.count")
                else:
                    proxy_args.append(f"{target_swift}: {local}")
            idx += 1

        if is_static:
            caller = swift_type_name(entity_name)
        else:
            caller = "self"
        return f"{caller}.{swift_meth}({', '.join(proxy_args)})"

    if "constant" in la:
        const_name = la["constant"]
        swift_const = swift_method_name(const_name)
        owner_class = la.get("class")
        if owner_class and owner_class != "self":
            return f"{swift_type_name(owner_class)}.{swift_const}"
        if is_static:
            return f"{swift_type_name(entity_name)}.{swift_const}"
        return f"self.{swift_const}"

    if "argument" in la:
        src = la["argument"]
        local = method_arg_locals.get(src, swift_method_name(src))
        if la.get("cast") == "data_length":
            return f"{local}.count"
        return local

    return "0"


# ---------------------------------------------------------------------------
# Method body generation
# ---------------------------------------------------------------------------

def _swift_method_body(
    project_ir: IRProject,
    entity_name: str,
    method: IRCMethod,
    *,
    is_static: bool = False,
    is_interface_method: bool = False,
) -> list[str]:
    """Generate the body lines for a Swift method.

    Returns a list of lines (without the method signature or closing brace).
    """
    prefix = project_ir.prefix
    c_func = _c_func_name(project_ir, entity_name, method.name)
    error_type_name = f"{_project_name_pascal(project_ir)}Error"
    status_type = f"{prefix}_status_t"
    impl_class_name = f"{_project_name_pascal(project_ir)}Implementation"

    resolved_args = [_resolve_self_class(entity_name, a) for a in method.arguments]
    resolved_returns = [_resolve_self_class(entity_name, r) for r in method.returns]

    # Classify arguments
    input_args: list[IRCArgument] = []
    buffer_outputs: list[IRCArgument] = []
    data_inputs: list[IRCArgument] = []
    error_arg: IRCArgument | None = None

    method_arg_locals: dict[str, str] = {}
    for arg in resolved_args:
        local = swift_method_name(arg.name)
        method_arg_locals[arg.name] = local
        if _arg_is_buffer_output(arg):
            buffer_outputs.append(arg)
        elif arg.class_name == "error":
            error_arg = arg
        elif _arg_should_skip(arg):
            continue
        else:
            input_args.append(arg)
            if arg.class_name == "data":
                data_inputs.append(arg)

    # Classify returns
    value_returns: list[IRCArgument] = []
    has_status_return = False
    for ret in resolved_returns:
        if ret.enum_name == "status":
            has_status_return = True
            continue
        value_returns.append(ret)

    has_error = has_status_return or error_arg is not None

    lines: list[str] = []

    # Error arg setup (for methods using error struct pattern)
    if error_arg is not None:
        lines.append(f"        var error: {prefix}_error_t = {prefix}_error_t()")
        lines.append(f"        {prefix}_error_reset(&error)")
        lines.append("")

    # Buffer output setup
    for buf_arg in buffer_outputs:
        buf_local = swift_method_name(buf_arg.name)
        cap_expr = _buffer_capacity_expr(
            project_ir, entity_name, buf_arg, method_arg_locals,
            is_static=is_static,
        )
        buf_count_var = f"{buf_local}Count"
        lines.append(f"        let {buf_count_var} = {cap_expr}")
        lines.append(f"        var {buf_local} = Data(count: {buf_count_var})")
        lines.append(f"        let {buf_local}Buf = vsc_buffer_new()")
        lines.append("        defer {")
        lines.append(f"            vsc_buffer_delete({buf_local}Buf)")
        lines.append("        }")
        lines.append("")

    # Build the C call and the wrapping closures
    # Determine if we need withUnsafeBytes / withUnsafeMutableBytes closures
    needs_data_closures = [a for a in input_args if a.class_name == "data"]
    needs_buf_closures = buffer_outputs

    # Determine the innermost return type for the closure chain
    has_proxy_result = has_status_return or has_error or bool(value_returns)

    # Build the C call argument list
    # Methods marked ``is_static="1"`` on the source interface bypass the
    # instance pointer (e.g., ``Hash.hash`` is a stateless helper).
    is_static_method = is_static or method.attrs.get("is_static") == "1"
    c_call_parts: list[str] = []
    if not is_static_method:
        c_call_parts.append("self.c_ctx")

    for arg in resolved_args:
        if arg.class_name == "error":
            c_call_parts.append("&error")
            continue
        if _arg_should_skip(arg) and not _arg_is_buffer_output(arg):
            continue
        if _arg_is_buffer_output(arg):
            buf_local = swift_method_name(arg.name)
            c_call_parts.append(f"{buf_local}Buf")
        elif arg.class_name == "data":
            local = method_arg_locals[arg.name]
            ptr_name = f"{local}Pointer"
            c_call_parts.append(
                f"vsc_data({ptr_name}.bindMemory(to: byte.self).baseAddress, {local}.count)"
            )
        elif arg.interface_name:
            local = method_arg_locals[arg.name]
            c_call_parts.append(f"{local}.c_ctx")
        elif arg.class_name and arg.class_name not in {"data", "buffer"}:
            local = method_arg_locals[arg.name]
            c_call_parts.append(f"{local}.c_ctx")
        elif arg.enum_name:
            local = method_arg_locals[arg.name]
            c_type = _c_enum_type_by_name(project_ir, arg.enum_name)
            c_call_parts.append(f"{c_type}(rawValue: UInt32({local}.rawValue))")
        elif (arg.type_name or "").lower() in {"size", "integer", "unsigned"}:
            local = method_arg_locals[arg.name]
            c_call_parts.append(local)
        elif (arg.type_name or "").lower() == "boolean":
            local = method_arg_locals[arg.name]
            c_call_parts.append(local)
        else:
            local = method_arg_locals[arg.name]
            c_call_parts.append(local)

    c_call = f"{c_func}({', '.join(c_call_parts)})"

    # Determine the closure return type
    if has_status_return:
        closure_return_type = status_type
    elif value_returns and not buffer_outputs:
        # Single value return with no buffers
        ret = value_returns[0]
        if ret.class_name == "data":
            closure_return_type = "vsc_data_t"
        elif ret.enum_name:
            closure_return_type = _c_enum_type_by_name(project_ir, ret.enum_name)
        elif ret.interface_name or (ret.class_name and ret.class_name not in {"data", "buffer"}):
            closure_return_type = "OpaquePointer?"
        elif (ret.type_name or "").lower() in {"size", "integer", "unsigned"}:
            closure_return_type = None  # Direct Int return
        elif (ret.type_name or "").lower() == "boolean":
            closure_return_type = None
        else:
            closure_return_type = None
    else:
        closure_return_type = None

    # Decide whether to use closures or direct call
    if not needs_data_closures and not needs_buf_closures:
        # Direct call -- no closures needed
        if has_proxy_result or value_returns:
            lines.append(f"        let proxyResult = {c_call}")
        else:
            lines.append(f"        {c_call}")
    else:
        # Need closures for data/buffer args
        # Build nested closure structure
        _emit_closure_chain(
            lines, needs_data_closures, needs_buf_closures,
            c_call, method_arg_locals, has_status_return, closure_return_type,
            has_proxy_result or bool(value_returns), status_type,
        )

    # After closures: update buffer counts
    for buf_arg in buffer_outputs:
        buf_local = swift_method_name(buf_arg.name)
        lines.append(f"        {buf_local}.count = vsc_buffer_len({buf_local}Buf)")

    # Status handling
    if has_status_return:
        lines.append("")
        lines.append(f"        try {error_type_name}.handleStatus(fromC: proxyResult)")
    elif error_arg is not None:
        lines.append("")
        lines.append(f"        try {error_type_name}.handleStatus(fromC: error.status)")

    # Return statement
    total_returns = len(value_returns) + len(buffer_outputs)
    if total_returns == 0:
        pass  # No return
    elif total_returns == 1 and not buffer_outputs:
        # Single value return
        ret = value_returns[0]
        lines.append("")
        lines.append(f"        return {_swift_return_expr(project_ir, ret, 'proxyResult')}")
    elif total_returns == 1 and buffer_outputs:
        # Single buffer return
        buf_local = swift_method_name(buffer_outputs[0].name)
        lines.append("")
        lines.append(f"        return {buf_local}")
    else:
        # Multi-return: result struct
        result_parts: list[str] = []
        for ret in value_returns:
            result_parts.append(
                f"{swift_method_name(ret.name)}: "
                f"{_swift_return_expr(project_ir, ret, 'proxyResult')}"
            )
        for buf_arg in buffer_outputs:
            buf_local = swift_method_name(buf_arg.name)
            result_parts.append(f"{buf_local}: {buf_local}")
        result_type = _result_struct_name(entity_name, method.name)
        lines.append("")
        lines.append(f"        return {result_type}({', '.join(result_parts)})")

    return lines


def _emit_closure_chain(
    lines: list[str],
    data_inputs: list[IRCArgument],
    buffer_outputs: list[IRCArgument],
    c_call: str,
    method_arg_locals: dict[str, str],
    has_status_return: bool,
    closure_return_type: str | None,
    assign_result: bool,
    status_type: str,
) -> None:
    """Emit the nested withUnsafeBytes / withUnsafeMutableBytes closure chain."""
    # Determine the outermost return type annotation
    all_closures: list[tuple[str, str, str]] = []  # (kind, local, ptrName)
    for arg in data_inputs:
        local = method_arg_locals[arg.name]
        ptr_name = f"{local}Pointer"
        all_closures.append(("data", local, ptr_name))
    for arg in buffer_outputs:
        local = swift_method_name(arg.name)
        ptr_name = f"{local}Pointer"
        all_closures.append(("buffer", local, ptr_name))

    if not all_closures:
        if assign_result:
            lines.append(f"        let proxyResult = {c_call}")
        else:
            lines.append(f"        {c_call}")
        return

    # Determine the type of the return value through the closure chain
    if has_status_return:
        ret_type = status_type
    elif closure_return_type:
        ret_type = closure_return_type
    else:
        ret_type = "Void"

    # Build the nested closures
    indent = "        "
    prefix = "let proxyResult = " if assign_result else ""

    for i, (kind, local, ptr_name) in enumerate(all_closures):
        closer_ret = f" -> {ret_type}" if ret_type != "Void" else ""
        if kind == "data":
            type_annot = "UnsafeRawBufferPointer"
            lines.append(
                f"{indent}{prefix}{local}.withUnsafeBytes({{ ({ptr_name}: {type_annot}){closer_ret} in"
            )
        else:
            type_annot = "UnsafeMutableRawBufferPointer"
            lines.append(
                f"{indent}{prefix}{local}.withUnsafeMutableBytes({{ ({ptr_name}: {type_annot}){closer_ret} in"
            )

        indent += "    "
        prefix = ""

        # For buffer outputs, emit vsc_buffer_use
        if kind == "buffer":
            buf_count = f"{local}Count"
            lines.append(
                f"{indent}vsc_buffer_use({local}Buf, "
                f"{ptr_name}.bindMemory(to: byte.self).baseAddress, {buf_count})"
            )
            lines.append("")

    # Emit the C call at the deepest level
    if assign_result and ret_type != "Void":
        lines.append(f"{indent}return {c_call}")
    elif assign_result:
        lines.append(f"{indent}{c_call}")
    else:
        lines.append(f"{indent}{c_call}")

    # Close all closures
    for i in range(len(all_closures) - 1, -1, -1):
        indent = "        " + "    " * i
        lines.append(f"{indent}}})")


def _swift_return_expr(project_ir: IRProject, ret: IRCArgument, c_expr: str) -> str:
    """Convert a C return expression to Swift."""
    impl_class_name = f"{_project_name_pascal(project_ir)}Implementation"

    if ret.class_name == "data":
        return f"Data.init(bytes: {c_expr}.bytes, count: {c_expr}.len)"

    if ret.interface_name:
        iface_name = swift_type_name(ret.interface_name)
        if ret.access == "disown":
            return f"{impl_class_name}.wrap{iface_name}(take: {c_expr}!)"
        else:
            return f"{impl_class_name}.wrap{iface_name}(use: {c_expr}!)"

    if ret.class_name and ret.class_name not in {"data", "buffer"}:
        cls_name = swift_type_name(ret.class_name)
        if ret.access == "disown":
            return f"{cls_name}.init(take: {c_expr}!)"
        else:
            return f"{cls_name}.init(use: {c_expr}!)"

    if ret.enum_name:
        enum_name = swift_type_name(ret.enum_name)
        return f"{enum_name}.init(fromC: {c_expr})"

    type_name = (ret.type_name or "").lower()
    if type_name in {"size", "integer", "unsigned"}:
        return c_expr  # Direct Int-compatible
    if type_name == "boolean":
        return c_expr

    return c_expr


# ---------------------------------------------------------------------------
# Swift method signature
# ---------------------------------------------------------------------------

def _swift_method_signature_parts(
    project_ir: IRProject,
    method: IRCMethod,
    entity_name: str,
    *,
    is_static: bool = False,
    is_protocol: bool = False,
) -> tuple[str, str, bool, str]:
    """Return (args_str, return_type, throws, modifier).

    ``modifier`` is ``"static "`` for static methods, ``""`` otherwise.
    """
    resolved_args = [_resolve_self_class(entity_name, a) for a in method.arguments]
    resolved_returns = [_resolve_self_class(entity_name, r) for r in method.returns]

    # Build argument list
    arg_parts: list[str] = []
    for arg in resolved_args:
        if _arg_is_buffer_output(arg) or _arg_should_skip(arg):
            continue
        local = swift_method_name(arg.name)
        swift_type = _swift_type_for_arg(project_ir, arg)
        arg_parts.append(f"{local}: {swift_type}")

    # Determine return type
    ret_type = _swift_return_type(project_ir, method, entity_name)

    throws = _method_throws(method)
    modifier = "static " if is_static else ""

    return ", ".join(arg_parts), ret_type, throws, modifier


# ---------------------------------------------------------------------------
# Protocol (interface) generator
# ---------------------------------------------------------------------------

def generate_swift_protocol(project_ir: IRProject, iface: IRInterface) -> str:
    """Generate a protocol .swift file from an IRInterface."""
    type_name = swift_type_name(iface.name)
    objc_name = f"{_objc_prefix(project_ir)}{type_name}"

    lines: list[str] = []
    lines.append(_file_header(project_ir))

    # Inheritance
    inherits = ["CContext"]
    for parent in iface.inherits:
        inherits.append(swift_type_name(parent))

    lines.append(f"@objc({objc_name}) public protocol {type_name} : {', '.join(inherits)} {{")

    # Constants as properties
    for const in iface.constants:
        _emit_doc(lines, const.description)
        prop_name = swift_method_name(const.name)
        # Determine type from attrs
        const_type = _swift_constant_type(const)
        lines.append(f"    @objc var {prop_name}: {const_type} {{ get }}")

    # Methods
    for method in iface.methods:
        if not _method_should_wrap(method):
            continue
        lines.append("")
        _emit_doc(lines, method.description)

        args_str, ret_type, throws, _ = _swift_method_signature_parts(
            project_ir, method, iface.name, is_protocol=True,
        )
        throws_str = " throws" if throws else ""
        ret_str = f" -> {ret_type}" if ret_type != "Void" else ""
        meth_name = swift_method_name(method.name)
        lines.append(f"    @objc func {meth_name}({args_str}){throws_str}{ret_str}")

    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def _swift_constant_type(const: IRCConstant) -> str:
    """Map a constant's type attrs to a Swift type."""
    type_attr = (const.attrs.get("type") or "size").lower()
    if type_attr == "size":
        return "Int"
    if type_attr == "boolean":
        return "Bool"
    if type_attr == "integer":
        return "Int"
    if type_attr == "unsigned":
        return "Int"
    return "Int"


# ---------------------------------------------------------------------------
# Class generator
# ---------------------------------------------------------------------------

def generate_swift_class(project_ir: IRProject, cls: IRClass) -> str:
    """Generate a class .swift file from an IRClass."""
    type_name = swift_type_name(cls.name)
    objc_name = f"{_objc_prefix(project_ir)}{type_name}"
    entity_snake = _entity_snake(cls.name)
    prefix = project_ir.prefix
    is_static = _is_static_class(cls)

    lines: list[str] = []
    lines.append(_file_header(project_ir))

    if is_static:
        lines.append(f"@objc({objc_name}) public class {type_name}: NSObject {{")
        lines.append("")
    else:
        lines.append(f"@objc({objc_name}) public class {type_name}: NSObject {{")
        lines.append("")
        # c_ctx property
        lines.append("    /// Handle underlying C context.")
        lines.append("    @objc public let c_ctx: OpaquePointer")
        lines.append("")

        # Constants as let properties
        for const in cls.constants:
            if const.attrs.get("definition") == "private":
                continue
            prop_name = swift_method_name(const.name)
            const_type = _swift_constant_type(const)
            value = const.attrs.get("value", "0")
            _emit_doc(lines, const.description)
            lines.append(f"    @objc public let {prop_name}: {const_type} = {value}")
            lines.append("")

        # Lifecycle: init(), init(take:), init(use:), deinit
        lines.append(f"    public override init() {{")
        lines.append(f"        self.c_ctx = {prefix}_{entity_snake}_new()")
        lines.append(f"        super.init()")
        lines.append("    }")
        lines.append("")
        lines.append(f"    public init(take c_ctx: OpaquePointer) {{")
        lines.append(f"        self.c_ctx = c_ctx")
        lines.append(f"        super.init()")
        lines.append("    }")
        lines.append("")
        lines.append(f"    public init(use c_ctx: OpaquePointer) {{")
        lines.append(f"        self.c_ctx = {prefix}_{entity_snake}_shallow_copy(c_ctx)")
        lines.append(f"        super.init()")
        lines.append("    }")
        lines.append("")
        lines.append("    /// Release underlying C context.")
        lines.append("    deinit {")
        lines.append(f"        {prefix}_{entity_snake}_delete(self.c_ctx)")
        lines.append("    }")
        lines.append("")

    # Dependency setters (for non-static classes)
    if not is_static:
        for dep in cls.dependencies:
            _emit_dependency_setter(lines, project_ir, cls.name, dep)

    # Static constants for static classes
    if is_static:
        for const in cls.constants:
            if const.attrs.get("definition") == "private":
                continue
            prop_name = swift_method_name(const.name)
            const_type = _swift_constant_type(const)
            value = const.attrs.get("value", "0")
            _emit_doc(lines, const.description)
            lines.append(f"    @objc public static let {prop_name}: {const_type} = {value}")
            lines.append("")

    # Methods
    for method in cls.methods:
        if not _method_should_wrap(method):
            continue

        is_method_static = is_static or method.attrs.get("is_static") == "1"

        args_str, ret_type, throws, modifier = _swift_method_signature_parts(
            project_ir, method, cls.name, is_static=is_method_static,
        )
        if is_method_static:
            modifier = "static "

        throws_str = " throws" if throws else ""
        ret_str = f" -> {ret_type}" if ret_type != "Void" else ""
        meth_name = swift_method_name(method.name)

        _emit_doc(lines, method.description)
        lines.append(
            f"    @objc public {modifier}func {meth_name}"
            f"({args_str}){throws_str}{ret_str} {{"
        )

        body = _swift_method_body(
            project_ir, cls.name, method, is_static=is_method_static,
        )
        lines.extend(body)
        lines.append("    }")
        lines.append("")

    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def _emit_dependency_setter(
    lines: list[str],
    project_ir: IRProject,
    entity_name: str,
    dep: IRDependency,
) -> None:
    """Emit a dependency setter method."""
    prefix = project_ir.prefix
    entity_snake = _entity_snake(entity_name)
    dep_snake = _entity_snake(dep.name)
    setter_name = "set" + swift_type_name(dep.name)
    dep_type = swift_type_name(dep.type_name)
    local = swift_method_name(dep.name)

    lines.append(f"    @objc public func {setter_name}({local}: {dep_type}) {{")
    lines.append(f"        {prefix}_{entity_snake}_release_{dep_snake}(self.c_ctx)")
    lines.append(f"        {prefix}_{entity_snake}_use_{dep_snake}(self.c_ctx, {local}.c_ctx)")
    lines.append("    }")
    lines.append("")


# ---------------------------------------------------------------------------
# Implementation generator
# ---------------------------------------------------------------------------

def generate_swift_implementation(project_ir: IRProject, impl: IRImplementation) -> str:
    """Generate an implementation .swift file from an IRImplementation."""
    type_name = swift_type_name(impl.name)
    objc_name = f"{_objc_prefix(project_ir)}{type_name}"
    entity_snake = _entity_snake(impl.name)
    prefix = project_ir.prefix

    # Determine interface conformance
    iface_names: list[str] = []
    for binding in impl.interface_bindings:
        iface_names.append(swift_type_name(binding.name))

    lines: list[str] = []
    lines.append(_file_header(project_ir))

    # Class declaration with interface conformance
    if iface_names:
        inherit_str = f": NSObject, {', '.join(iface_names)}"
    else:
        inherit_str = ": NSObject"

    lines.append(f"@objc({objc_name}) public class {type_name}{inherit_str} {{")
    lines.append("")

    # c_ctx property
    lines.append("    /// Handle underlying C context.")
    lines.append("    @objc public let c_ctx: OpaquePointer")
    lines.append("")

    # Binding constants as let properties
    iface_by_name = {i.name: i for i in project_ir.interfaces}
    for binding in impl.interface_bindings:
        iface = iface_by_name.get(binding.name)
        if iface is None:
            continue
        iface_const_by_name = {c.name: c for c in iface.constants}
        for bconst in binding.constants:
            iface_const = iface_const_by_name.get(bconst.name)
            if iface_const is None:
                continue
            prop_name = swift_method_name(bconst.name)
            const_type = _swift_constant_type(iface_const)
            value = bconst.value or bconst.attrs.get("value", "0")
            _emit_doc(lines, iface_const.description)
            lines.append(f"    @objc public let {prop_name}: {const_type} = {value}")
            lines.append("")

    # Impl-specific constants
    for const in impl.constants:
        if const.attrs.get("definition") == "private":
            continue
        prop_name = swift_method_name(const.name)
        const_type = _swift_constant_type(const)
        value = const.attrs.get("value", "0")
        _emit_doc(lines, const.description)
        lines.append(f"    @objc public let {prop_name}: {const_type} = {value}")
        lines.append("")

    # Lifecycle
    lines.append(f"    public override init() {{")
    lines.append(f"        self.c_ctx = {prefix}_{entity_snake}_new()")
    lines.append(f"        super.init()")
    lines.append("    }")
    lines.append("")
    lines.append(f"    public init(take c_ctx: OpaquePointer) {{")
    lines.append(f"        self.c_ctx = c_ctx")
    lines.append(f"        super.init()")
    lines.append("    }")
    lines.append("")
    lines.append(f"    public init(use c_ctx: OpaquePointer) {{")
    lines.append(f"        self.c_ctx = {prefix}_{entity_snake}_shallow_copy(c_ctx)")
    lines.append(f"        super.init()")
    lines.append("    }")
    lines.append("")
    lines.append("    /// Release underlying C context.")
    lines.append("    deinit {")
    lines.append(f"        {prefix}_{entity_snake}_delete(self.c_ctx)")
    lines.append("    }")
    lines.append("")

    # Dependency setters
    for dep in impl.dependencies:
        _emit_dependency_setter(lines, project_ir, impl.name, dep)

    # Impl-specific methods
    for method in impl.methods:
        if method.attrs.get("declaration") != "public":
            continue
        if not _method_should_wrap(method):
            continue
        _emit_method(lines, project_ir, impl.name, method, is_static=False)

    # Interface methods (from bindings)
    for binding in impl.interface_bindings:
        iface = iface_by_name.get(binding.name)
        if iface is None:
            continue
        for method in iface.methods:
            if not _method_should_wrap(method):
                continue
            _emit_method(lines, project_ir, impl.name, method, is_static=False)

    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def _emit_method(
    lines: list[str],
    project_ir: IRProject,
    entity_name: str,
    method: IRCMethod,
    *,
    is_static: bool = False,
) -> None:
    """Emit a complete method (signature + body + closing brace)."""
    args_str, ret_type, throws, modifier = _swift_method_signature_parts(
        project_ir, method, entity_name, is_static=is_static,
    )
    if is_static:
        modifier = "static "

    throws_str = " throws" if throws else ""
    ret_str = f" -> {ret_type}" if ret_type != "Void" else ""
    meth_name = swift_method_name(method.name)

    _emit_doc(lines, method.description)
    lines.append(
        f"    @objc public {modifier}func {meth_name}"
        f"({args_str}){throws_str}{ret_str} {{"
    )
    body = _swift_method_body(
        project_ir, entity_name, method, is_static=is_static,
    )
    lines.extend(body)
    lines.append("    }")
    lines.append("")


# ---------------------------------------------------------------------------
# CContext.swift generator
# ---------------------------------------------------------------------------

def generate_swift_ccontext(project_ir: IRProject) -> str:
    """Generate the CContext.swift protocol file."""
    lines: list[str] = []
    lines.append(_SWIFT_LICENSE)
    lines.append("")
    lines.append("")
    lines.append("import Foundation")
    lines.append("")

    objc_name = f"{_objc_prefix(project_ir)}CContext"
    lines.append(f"@objc({objc_name}) public protocol CContext {{")
    lines.append("    /// Handle underlying C context.")
    lines.append("    @objc var c_ctx: OpaquePointer { get }")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# {Project}Error.swift generator
# ---------------------------------------------------------------------------

def _find_status_enum(project_ir: IRProject) -> IREnum | None:
    for enum in project_ir.enums:
        if enum.name == "status":
            return enum
    return None


def generate_swift_error(project_ir: IRProject) -> str:
    """Generate the {Project}Error.swift file from the status enum."""
    status = _find_status_enum(project_ir)
    if status is None:
        raise ValueError(
            f"project {project_ir.name!r} has no 'status' enum"
        )

    proj_name = _project_name_pascal(project_ir)
    type_name = f"{proj_name}Error"
    objc_name = f"{_objc_prefix(project_ir)}{type_name}"
    prefix = project_ir.prefix
    status_c_type = f"{prefix}_status_t"

    # Non-success constants
    body_constants = [c for c in status.constants if c.name != "success"]

    lines: list[str] = []
    lines.append(_file_header(project_ir))

    lines.append(f"@objc({objc_name}) public enum {type_name}: Int, Error {{")
    lines.append("")

    for const in body_constants:
        _emit_doc(lines, const.description)
        case_name = swift_case_name(const.name)
        value = const.attrs.get("value", "0").strip()
        # Error values are negative
        lines.append(f"    case {case_name} = {value}")
        lines.append("")

    # fromC initializer
    lines.append(f"    internal init(fromC status: {status_c_type}) {{")
    lines.append(f"        self.init(rawValue: Int(status.rawValue))!")
    lines.append("    }")

    # handleStatus method
    lines.append(f"    @objc public static func handleStatus(fromC code: {status_c_type}) throws {{")
    lines.append(f"        if code != {prefix}_status_SUCCESS {{")
    lines.append(f"            throw {type_name}(fromC: code)")
    lines.append("        }")
    lines.append("    }")
    lines.append("")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# {Project}Implementation.swift generator
# ---------------------------------------------------------------------------

def _find_impl_tag_enum(project_ir: IRProject) -> IREnum | None:
    for enum in project_ir.enums:
        if enum.name == "impl/tag":
            return enum
    return None


def generate_swift_project_implementation(project_ir: IRProject) -> str:
    """Generate the {Project}Implementation.swift dispatch file."""
    proj_name = _project_name_pascal(project_ir)
    type_name = f"{proj_name}Implementation"
    objc_name = f"{_objc_prefix(project_ir)}{type_name}"
    prefix = project_ir.prefix

    # Build interface -> implementations mapping
    iface_by_name = {i.name: i for i in project_ir.interfaces}
    impls_per_iface: dict[str, list[str]] = {}
    iface_order: list[str] = []
    for impl in project_ir.implementations:
        for binding in impl.interface_bindings:
            if binding.name not in impls_per_iface:
                iface_order.append(binding.name)
            impls_per_iface.setdefault(binding.name, []).append(impl.name)

    lines: list[str] = []
    lines.append(_file_header(project_ir))
    lines.append(f"@objc({objc_name}) public class {type_name}: NSObject {{")
    lines.append("")

    for iface_name in iface_order:
        iface = iface_by_name.get(iface_name)
        if iface is None:
            continue
        impls = impls_per_iface[iface_name]
        iface_pascal = swift_type_name(iface.name)
        iface_snake = _entity_snake(iface.name)

        # wrapXxx(take:) method
        lines.append(f"    @objc public static func wrap{iface_pascal}(take c_ctx: OpaquePointer) -> {iface_pascal} {{")
        lines.append(f"        if (!{prefix}_{iface_snake}_is_implemented(c_ctx)) {{")
        lines.append(f'            fatalError("Given C implementation does not implement interface {iface_pascal}.")')
        lines.append("        }")
        lines.append("")
        lines.append(f"        let implTag = {prefix}_impl_tag(c_ctx)")
        lines.append("        switch(implTag) {")

        for impl_name in impls:
            impl_tag = f"{prefix}_impl_tag_{impl_name.replace(' ', '_').upper()}"
            impl_swift = swift_type_name(impl_name)
            lines.append(f"        case {impl_tag}:")
            lines.append(f"            return {impl_swift}(take: c_ctx)")

        lines.append("        default:")
        lines.append('            fatalError("Unexpected C implementation cast to the Swift implementation.")')
        lines.append("        }")
        lines.append("    }")
        lines.append("")

        # wrapXxx(use:) method
        lines.append(f"    @objc public static func wrap{iface_pascal}(use c_ctx: OpaquePointer) -> {iface_pascal} {{")
        lines.append(f"        let shallowCopy = {prefix}_impl_shallow_copy(c_ctx)!")
        lines.append(f"        return {type_name}.wrap{iface_pascal}(take:shallowCopy)")
        lines.append("    }")
        lines.append("")

    lines.append("}")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Result struct generator
# ---------------------------------------------------------------------------

def _collect_result_structs(
    project_ir: IRProject,
) -> dict[str, list[tuple[str, str]]]:
    """Collect all multi-return result struct definitions.

    Returns a dict of {struct_name: [(field_name, field_type), ...]}.
    """
    result_structs: dict[str, list[tuple[str, str]]] = {}

    def _check_method(method: IRCMethod, entity_name: str) -> None:
        resolved_returns = [_resolve_self_class(entity_name, r) for r in method.returns]
        value_returns = [r for r in resolved_returns if r.enum_name != "status"]
        buffer_outputs = [a for a in method.arguments if _arg_is_buffer_output(a)]

        total = len(value_returns) + len(buffer_outputs)
        if total <= 1:
            return

        struct_name = _result_struct_name(entity_name, method.name)
        if struct_name in result_structs:
            return

        fields: list[tuple[str, str]] = []
        for ret in value_returns:
            fields.append((
                swift_method_name(ret.name),
                _swift_type_for_arg(project_ir, ret),
            ))
        for buf_arg in buffer_outputs:
            fields.append((
                swift_method_name(buf_arg.name),
                "Data",
            ))
        result_structs[struct_name] = fields

    # Check interface methods
    for iface in project_ir.interfaces:
        for method in iface.methods:
            if not _method_should_wrap(method):
                continue
            _check_method(method, iface.name)

    # Check class methods
    for cls in project_ir.classes:
        for method in cls.methods:
            if not _method_should_wrap(method):
                continue
            _check_method(method, cls.name)

    # Check implementation methods
    iface_by_name = {i.name: i for i in project_ir.interfaces}
    for impl in project_ir.implementations:
        for method in impl.methods:
            if not _method_should_wrap(method):
                continue
            _check_method(method, impl.name)
        for binding in impl.interface_bindings:
            iface = iface_by_name.get(binding.name)
            if iface is None:
                continue
            for method in iface.methods:
                if not _method_should_wrap(method):
                    continue
                _check_method(method, iface.name)

    return result_structs


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def generate_swift_files(
    project_ir: IRProject, license_text: str = "",
    repo_root: str | Path = ".",
) -> list[tuple[str, str]]:
    """Generate all Swift wrapper files for a project.

    Returns a list of ``(repo_relative_path, file_content)`` tuples.
    The caller writes these to disk.

    ALL output is generated from the IR.
    """
    del license_text  # Accepted for API parity; Swift files use _SWIFT_LICENSE

    output_dir = _source_dir(project_ir)
    files: list[tuple[str, str]] = []

    # --- CContext.swift ---
    files.append((f"{output_dir}CContext.swift", generate_swift_ccontext(project_ir)))

    # --- {Project}Error.swift ---
    if _find_status_enum(project_ir) is not None:
        proj_name = _project_name_pascal(project_ir)
        files.append((
            f"{output_dir}{proj_name}Error.swift",
            generate_swift_error(project_ir),
        ))

    # --- Enums ---
    for enum in project_ir.enums:
        if enum.name in _INFRASTRUCTURE_ENUMS:
            continue
        if enum.attrs.get("scope") == "private":
            continue
        stem = swift_type_name(enum.name)
        files.append((f"{output_dir}{stem}.swift", generate_swift_enum(project_ir, enum)))

    # --- Interfaces (protocols) ---
    for iface in project_ir.interfaces:
        if iface.attrs.get("scope") == "private":
            continue
        stem = swift_type_name(iface.name)
        files.append((f"{output_dir}{stem}.swift", generate_swift_protocol(project_ir, iface)))

    # --- Classes ---
    for cls in project_ir.classes:
        if cls.attrs.get("scope") in {"private", "internal"}:
            continue
        if cls.name == "error":
            continue
        stem = swift_type_name(cls.name)
        files.append((f"{output_dir}{stem}.swift", generate_swift_class(project_ir, cls)))

    # --- Implementations ---
    for impl in project_ir.implementations:
        if impl.attrs.get("scope") in {"private", "internal"}:
            continue
        stem = swift_type_name(impl.name)
        files.append((f"{output_dir}{stem}.swift", generate_swift_implementation(project_ir, impl)))

    # --- {Project}Implementation.swift ---
    files.append((
        f"{output_dir}{_project_name_pascal(project_ir)}Implementation.swift",
        generate_swift_project_implementation(project_ir),
    ))

    return files
