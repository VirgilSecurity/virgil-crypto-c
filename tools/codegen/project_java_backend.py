"""Java/JNI wrapper file generation for the project-rooted codegen pipeline.

Generates all Java wrapper files purely from the IR (``IRProject``),
with **no dependency on resolved XML files** in ``codegen/generated/``.

Each entity (enum, interface, class, implementation) becomes a ``.java``
class file.  Per-project infrastructure files are also generated:

- ``{Project}JNI.java`` -- singleton with native method declarations
- ``{Project}Exception.java`` -- error class from the ``status`` enum
- ``{Project}ContextHolder.java`` -- package-private context carrier

For implementations and classes with methods that have multiple buffer
outputs, a ``{Entity}{Method}Result.java`` carrier class is emitted.

JNI C and H files (``{Project}JNI.c``, ``{Project}JNI.h``) are generated
with the C-side native implementations for marshalling.
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
# Name utilities
# ---------------------------------------------------------------------------

def _split_words(name: str) -> list[str]:
    return [w for w in name.replace("_", " ").split(" ") if w]


def _pascal(name: str) -> str:
    """PascalCase from space/underscore-separated name."""
    return "".join(w[:1].upper() + w[1:] for w in _split_words(name))


def _camel(name: str) -> str:
    """camelCase from space/underscore-separated name."""
    words = _split_words(name)
    if not words:
        return name
    return words[0].lower() + "".join(w[:1].upper() + w[1:] for w in words[1:])


def _snake(name: str) -> str:
    return name.replace(" ", "_")


def _upper_snake(name: str) -> str:
    return name.replace(" ", "_").upper()


def _project_pascal(project_name: str) -> str:
    """PascalCase project name (``foundation`` -> ``Foundation``)."""
    return _pascal(project_name)


def _jni_class(project_name: str) -> str:
    return f"{_project_pascal(project_name)}JNI"


def _exception_class(project_name: str) -> str:
    return f"{_project_pascal(project_name)}Exception"


def _context_holder_class(project_name: str) -> str:
    return f"{_project_pascal(project_name)}ContextHolder"


def _java_package(project_name: str) -> str:
    return f"com.virgilsecurity.crypto.{project_name}"


def _java_package_dir(project_name: str) -> str:
    return _java_package(project_name).replace(".", "/")


def _jni_package_path(project_name: str) -> str:
    """JNI path component (slashes, for FindClass)."""
    return _java_package(project_name).replace(".", "/")


# ---------------------------------------------------------------------------
# License header
# ---------------------------------------------------------------------------

_LICENSE = """\
/*
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
/*
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


# ---------------------------------------------------------------------------
# IR query helpers
# ---------------------------------------------------------------------------

def _method_should_wrap(method: IRCMethod) -> bool:
    """Return True if method should appear in the wrapper API."""
    scope = method.attrs.get("scope", "public")
    decl = method.declaration or method.attrs.get("declaration", "public")
    vis = method.visibility or method.attrs.get("visibility", "public")
    return scope == "public" and decl == "public" and vis == "public"


def _is_static_class(cls: IRClass) -> bool:
    return cls.attrs.get("context") == "none"


def _is_static_method(method: IRCMethod) -> bool:
    return method.attrs.get("is_static") in {"1", "true"}


def _method_has_error(method: IRCMethod) -> bool:
    """True if method returns status or has an error-class argument."""
    for ret in method.returns:
        if ret.enum_name == "status":
            return True
    return any(arg.class_name == "error" for arg in method.arguments)


def _buffer_output_args(method: IRCMethod) -> list[IRCArgument]:
    """Buffer-class arguments that are writeonly outputs."""
    return [a for a in method.arguments if a.class_name == "buffer"]


def _method_needs_result_class(method: IRCMethod) -> bool:
    return len(_buffer_output_args(method)) >= 2


def _find_status_enum(project_ir: IRProject) -> IREnum | None:
    for enum in project_ir.enums:
        if enum.name == "status":
            return enum
    return None


# ---------------------------------------------------------------------------
# Java type mapping
# ---------------------------------------------------------------------------

_INT_SIZE_MAP = {"1": "byte", "2": "short", "4": "int", "8": "long"}


def _java_type_for_arg(arg: IRCArgument, project_name: str) -> str:
    """Map an IR argument to its Java type name."""
    if arg.enum_name:
        if arg.enum_name == "status":
            return "void"
        return _pascal(arg.enum_name)
    if arg.interface_name:
        return _pascal(arg.interface_name)
    if arg.class_name == "data":
        return "byte[]"
    if arg.class_name == "buffer":
        return "byte[]"
    if arg.class_name == "error":
        return "void"
    if arg.class_name and arg.class_name not in ("data", "buffer", "error"):
        return _pascal(arg.class_name)
    type_name = (arg.type_name or "").lower()
    if type_name == "size":
        return "int"
    if type_name == "boolean":
        return "boolean"
    if type_name == "integer":
        return _INT_SIZE_MAP.get(arg.type_size or "4", "int")
    if type_name == "unsigned":
        size = arg.type_size or "4"
        # Java has no unsigned -- use next-size-up signed type
        unsigned_map = {"1": "int", "2": "int", "4": "int", "8": "long"}
        return unsigned_map.get(size, "int")
    if type_name == "byte":
        if arg.is_array:
            return "byte[]"
        return "byte"
    if type_name == "string":
        return "String"
    if type_name == "nothing":
        return "void"
    return type_name or "void"


def _java_return_type(method: IRCMethod, project_name: str,
                      entity_name: str) -> str:
    """Determine the Java return type for a wrapped method."""
    buf_outs = _buffer_output_args(method)
    if len(buf_outs) >= 2:
        return f"{_pascal(entity_name)}{_pascal(method.name)}Result"

    # Single buffer output -> byte[]
    if len(buf_outs) == 1:
        return "byte[]"

    # Check explicit returns (excluding status)
    value_returns = [r for r in method.returns if r.enum_name != "status"]
    if not value_returns:
        return "void"

    ret = value_returns[0]
    return _java_type_for_arg(ret, project_name)


def _java_param_list(method: IRCMethod, project_name: str,
                     *, include_ctx: bool = False) -> list[tuple[str, str]]:
    """Return list of (type, name) for Java method parameters.

    Filters out buffer outputs, error args, and writeonly args.
    """
    params: list[tuple[str, str]] = []
    if include_ctx:
        params.append(("long", "cCtx"))
    for arg in method.arguments:
        if arg.class_name == "buffer":
            continue
        if arg.class_name == "error":
            continue
        if arg.access == "writeonly":
            continue
        if arg.type_name == "self":
            continue
        jtype = _java_type_for_arg(arg, project_name)
        jname = _camel(arg.name)
        params.append((jtype, jname))
    return params


# ---------------------------------------------------------------------------
# Entity snake name for JNI method dispatch
# ---------------------------------------------------------------------------

def _entity_camel(name: str) -> str:
    """Entity name in camelCase for JNI dispatch: ``recipient cipher`` -> ``recipientCipher``."""
    return _camel(name)


def _method_camel(name: str) -> str:
    """Method name in camelCase: ``alg id`` -> ``algId``."""
    return _camel(name)


# ---------------------------------------------------------------------------
# Enum generator
# ---------------------------------------------------------------------------

def _generate_enum(project_ir: IRProject, enum: IREnum) -> str:
    """Generate a Java file for an enum entity."""
    enum_name = _pascal(enum.name)
    lines: list[str] = []
    lines.append(_LICENSE)
    lines.append("")
    lines.append(f"package {_java_package(project_ir.name)};")
    lines.append("")

    lines.append(f"public class {enum_name} {{")
    lines.append("")

    # Enum constants
    next_val = 0
    for const in enum.constants:
        value = const.attrs.get("value")
        if value is not None and value != "":
            val_str = resolve_constant_value(value, None, project_ir)
        else:
            val_str = str(next_val)
        lines.append(f"    public static final int {_upper_snake(const.name)} = {val_str};")
        try:
            next_val = int(val_str, 0) + 1
        except ValueError:
            next_val += 1
    lines.append("")

    # fromCode / getCode
    lines.append("    private final int code;")
    lines.append("")
    lines.append(f"    public {enum_name}(int code) {{")
    lines.append("        this.code = code;")
    lines.append("    }")
    lines.append("")
    lines.append("    public int getCode() {")
    lines.append("        return this.code;")
    lines.append("    }")

    lines.append("}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Interface generator
# ---------------------------------------------------------------------------

def _generate_interface(project_ir: IRProject, iface: IRInterface) -> str:
    """Generate a Java file for an interface entity."""
    iface_name = _pascal(iface.name)
    lines: list[str] = []
    lines.append(_LICENSE)
    lines.append("")
    lines.append(f"package {_java_package(project_ir.name)};")
    lines.append("")

    # Inheritance
    inherits = [_pascal(p) for p in iface.inherits if p]
    extends_str = f" extends {', '.join(inherits)}" if inherits else ""

    lines.append(f"public interface {iface_name}{extends_str} {{")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Implementation / Class generator
# ---------------------------------------------------------------------------

def _collect_all_methods(
    project_ir: IRProject,
    impl: IRImplementation,
) -> list[tuple[IRCMethod, str]]:
    """Collect all methods for an implementation: own + inherited from interfaces.

    Returns list of (method, origin_entity_name) tuples.
    ``origin_entity_name`` is the implementation name for own methods,
    or the interface name for inherited methods.
    """
    iface_index = {i.name: i for i in project_ir.interfaces}
    methods: list[tuple[IRCMethod, str]] = []

    for binding in impl.interface_bindings:
        iface = iface_index.get(binding.name)
        if iface is None:
            continue
        for m in iface.methods:
            if not _method_should_wrap(m):
                continue
            methods.append((m, impl.name))

    for m in impl.methods:
        if not _method_should_wrap(m):
            continue
        methods.append((m, impl.name))

    return methods


def _collect_constant_getters(
    project_ir: IRProject,
    impl: IRImplementation,
) -> list[tuple[str, str, str]]:
    """Collect interface binding constants as (getter_name, java_type, value)."""
    iface_index = {i.name: i for i in project_ir.interfaces}
    getters: list[tuple[str, str, str]] = []
    for binding in impl.interface_bindings:
        iface = iface_index.get(binding.name)
        if iface is None:
            continue
        # Build a lookup from constant name -> value from the binding
        binding_values = {c.name: c.value for c in binding.constants}
        for const in iface.constants:
            value = binding_values.get(const.name)
            if value is None:
                continue
            type_name = (const.attrs.get("type") or "size").lower()
            if type_name == "size":
                jtype = "int"
            elif type_name == "boolean":
                jtype = "boolean"
            elif type_name == "integer":
                jtype = _INT_SIZE_MAP.get(const.attrs.get("size") or "4", "int")
            elif type_name == "unsigned":
                jtype = "int"
            else:
                jtype = "int"
            getter_name = "get" + _pascal(const.name)
            # Convert value expression: could be numeric or expression
            # Legacy uses raw value like "32", "64", "1024 * 1024 - 64"
            getters.append((getter_name, jtype, value))
    return getters


def _get_impl_interfaces(
    project_ir: IRProject, impl: IRImplementation
) -> list[str]:
    """Get list of Java interface names implemented by this impl."""
    iface_index = {i.name: i for i in project_ir.interfaces}
    result: list[str] = ["AutoCloseable"]
    for binding in impl.interface_bindings:
        iface = iface_index.get(binding.name)
        if iface is not None:
            result.append(_pascal(binding.name))
    return result


def _generate_method_body(
    project_ir: IRProject,
    method: IRCMethod,
    entity_name: str,
    is_static: bool,
) -> list[str]:
    """Generate method delegation body lines for a single method."""
    pname = project_ir.name
    jni = _jni_class(pname)
    entity_camel = _entity_camel(entity_name)
    method_camel = _method_camel(method.name)
    exception = _exception_class(pname)

    ret_type = _java_return_type(method, pname, entity_name)
    has_error = _method_has_error(method)
    params = _java_param_list(method, pname)

    throws = f" throws {exception}" if has_error else ""
    params_str = ", ".join(f"{t} {n}" for t, n in params)

    # Build JNI call arguments
    jni_args: list[str] = []
    if not is_static:
        jni_args.append("this.cCtx")
    for t, n in params:
        jni_args.append(n)
    jni_args_str = ", ".join(jni_args)

    jni_call = f"{jni}.INSTANCE.{entity_camel}_{method_camel}({jni_args_str})"

    lines: list[str] = []
    sig = f"    public {ret_type} {method_camel}({params_str}){throws} {{"
    lines.append(sig)
    if ret_type == "void":
        lines.append(f"        {jni_call};")
    else:
        lines.append(f"        return {jni_call};")
    lines.append("    }")
    return lines


def _generate_class_file(
    project_ir: IRProject,
    entity_name: str,
    is_static: bool,
    interfaces: list[str],
    dependencies: list[IRDependency],
    methods: list[tuple[IRCMethod, str]],
    constant_getters: list[tuple[str, str, str]],
    class_constants: list[IRCConstant] | None = None,
) -> str:
    """Generate a complete Java class file for an implementation or class entity."""
    pname = project_ir.name
    class_name = _pascal(entity_name)
    jni = _jni_class(pname)
    exception = _exception_class(pname)
    ctx_holder = _context_holder_class(pname)
    entity_camel = _entity_camel(entity_name)

    lines: list[str] = []
    lines.append(_LICENSE)
    lines.append("")
    lines.append(f"package {_java_package(pname)};")
    lines.append("")

    # Class declaration
    impl_str = ""
    if interfaces:
        impl_str = f" implements {', '.join(interfaces)}"
    lines.append(f"public class {class_name}{impl_str} {{")
    lines.append("")

    # For non-static classes: cCtx field + constructors + lifecycle
    if not is_static:
        lines.append("    public long cCtx;")
        lines.append("")

        # Public constructor
        lines.append(f"    public {class_name}() {{")
        lines.append("        super();")
        lines.append(f"        this.cCtx = {jni}.INSTANCE.{entity_camel}_new();")
        lines.append("    }")
        lines.append("")

        # Package-private constructor from context holder (no modifier = package-private)
        lines.append(f"    {class_name}({ctx_holder} contextHolder) {{")
        lines.append("        this.cCtx = contextHolder.cCtx;")
        lines.append("    }")
        lines.append("")

        # getInstance static factory
        lines.append(f"    public {class_name} getInstance(long cCtx) {{")
        lines.append(f"        {ctx_holder} ctxHolder = new {ctx_holder}(cCtx);")
        lines.append(f"        return new {class_name}(ctxHolder);")
        lines.append("    }")
        lines.append("")

        # clearResources
        lines.append("    private void clearResources() {")
        lines.append("        long ctx = this.cCtx;")
        lines.append("        if (this.cCtx > 0) {")
        lines.append("            this.cCtx = 0;")
        lines.append(f"            {jni}.INSTANCE.{entity_camel}_close(ctx);")
        lines.append("        }")
        lines.append("    }")
        lines.append("")

        # close
        lines.append("    public void close() {")
        lines.append("        clearResources();")
        lines.append("    }")
        lines.append("")

        # finalize
        lines.append("    protected void finalize() throws Throwable {")
        lines.append("        clearResources();")
        lines.append("    }")
        lines.append("")

    # Dependency setters
    for dep in dependencies:
        dep_type = _pascal(dep.type_name)
        dep_setter = "set" + _pascal(dep.name)
        dep_param = _camel(dep.name)
        lines.append(f"    public void {dep_setter}({dep_type} {dep_param}) {{")
        lines.append(
            f"        {jni}.INSTANCE.{entity_camel}_{dep_setter}(this.cCtx, {dep_param});"
        )
        lines.append("    }")
        lines.append("")

    # Constant getters (from interface bindings)
    for getter_name, jtype, value in constant_getters:
        lines.append(f"    public {jtype} {getter_name}() {{")
        lines.append(f"        return {value};")
        lines.append("    }")
        lines.append("")

    # Class-level constants as getters
    if class_constants:
        for const in class_constants:
            if const.attrs.get("scope", "public") != "public":
                continue
            ctype = (const.attrs.get("type") or "size").lower()
            if ctype == "size":
                jtype = "int"
            elif ctype == "boolean":
                jtype = "boolean"
            elif ctype == "integer":
                jtype = _INT_SIZE_MAP.get(const.attrs.get("size") or "4", "int")
            else:
                jtype = "int"
            getter_name = "get" + _pascal(const.name)
            # Look up entity for constant expression resolution
            _ent = None
            for _e in list(project_ir.classes) + list(project_ir.implementations):
                if _e.name == entity_name:
                    _ent = _e
                    break
            value = resolve_constant_value(
                const.attrs.get("value", "0"), _ent, project_ir
            )
            lines.append(f"    public {jtype} {getter_name}() {{")
            lines.append(f"        return {value};")
            lines.append("    }")
            lines.append("")

    # Methods
    for method, origin in methods:
        method_lines = _generate_method_body(
            project_ir, method, entity_name,
            is_static=is_static or _is_static_method(method),
        )
        lines.extend(method_lines)
        lines.append("")

    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _generate_impl_file(project_ir: IRProject, impl: IRImplementation) -> str:
    interfaces = _get_impl_interfaces(project_ir, impl)
    methods = _collect_all_methods(project_ir, impl)
    constant_getters = _collect_constant_getters(project_ir, impl)
    return _generate_class_file(
        project_ir,
        entity_name=impl.name,
        is_static=False,
        interfaces=interfaces,
        dependencies=impl.dependencies,
        methods=methods,
        constant_getters=constant_getters,
    )


def _generate_class_entity_file(project_ir: IRProject, cls: IRClass) -> str:
    is_static = _is_static_class(cls)
    interfaces = ["AutoCloseable"] if not is_static else []
    methods = [
        (m, cls.name)
        for m in cls.methods
        if _method_should_wrap(m)
    ]
    return _generate_class_file(
        project_ir,
        entity_name=cls.name,
        is_static=is_static,
        interfaces=interfaces,
        dependencies=cls.dependencies,
        methods=methods,
        constant_getters=[],
        class_constants=cls.constants,
    )


# ---------------------------------------------------------------------------
# Result class generator
# ---------------------------------------------------------------------------

def _generate_result_class(
    project_ir: IRProject,
    entity_name: str,
    method: IRCMethod,
) -> str:
    """Generate a {Entity}{Method}Result carrier class for multi-buffer returns."""
    pname = project_ir.name
    class_name = f"{_pascal(entity_name)}{_pascal(method.name)}Result"
    buf_outs = _buffer_output_args(method)

    lines: list[str] = []
    lines.append(_LICENSE)
    lines.append("")
    lines.append(f"package {_java_package(pname)};")
    lines.append("")
    lines.append("")
    lines.append(f"public class {class_name} {{")
    lines.append("")

    # Fields with getters and setters
    for buf in buf_outs:
        field_name = _camel(buf.name)
        lines.append(f"    private byte[] {field_name};")
        lines.append("")
        getter = "get" + _pascal(buf.name)
        lines.append(f"    public byte[] {getter}() {{")
        lines.append(f"        return this.{field_name};")
        lines.append("    }")
        lines.append("")
        setter = "set" + _pascal(buf.name)
        lines.append(f"    public void {setter}(byte[] {field_name}) {{")
        lines.append(f"        this.{field_name} = {field_name};")
        lines.append("    }")
        lines.append("")

    # Package-private no-arg constructor (no modifier = package-private)
    lines.append(f"    {class_name}() {{")
    lines.append("        super();")
    lines.append("    }")
    lines.append("")

    # Package-private all-args constructor (no modifier = package-private)
    ctor_params = ", ".join(f"byte[] {_camel(b.name)}" for b in buf_outs)
    lines.append(f"    {class_name}({ctor_params}) {{")
    lines.append("        super();")
    for buf in buf_outs:
        field_name = _camel(buf.name)
        lines.append(f"        this.{field_name} = {field_name};")
    lines.append("    }")
    lines.append("")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Infrastructure file generators
# ---------------------------------------------------------------------------

def _generate_jni_java(project_ir: IRProject) -> str:
    """Generate {Project}JNI.java -- singleton with native method declarations."""
    pname = project_ir.name
    jni_class = _jni_class(pname)

    lines: list[str] = []
    lines.append(_LICENSE)
    lines.append("")
    lines.append(f"package {_java_package(pname)};")
    lines.append("")
    lines.append("")
    lines.append(f"public class {jni_class} {{")
    lines.append("")
    lines.append(f"    public static final {jni_class} INSTANCE = new {jni_class}();")
    lines.append("")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _generate_exception(project_ir: IRProject) -> str:
    """Generate {Project}Exception.java from the status enum."""
    pname = project_ir.name
    exception_class = _exception_class(pname)
    status = _find_status_enum(project_ir)

    lines: list[str] = []
    lines.append(_LICENSE)
    lines.append("")
    lines.append(f"package {_java_package(pname)};")
    lines.append("")
    lines.append(f"public class {exception_class} {{")
    lines.append("")

    if status is not None:
        # Error code constants
        for const in status.constants:
            field_name = _upper_snake(const.name)
            lines.append(f"    public int {field_name};")
            lines.append("")

    # statusCode field
    lines.append("    private int statusCode;")
    lines.append("")

    # Constructor
    lines.append(f"    public {exception_class}(int statusCode) {{")
    lines.append("        super();")
    lines.append("        this.statusCode = statusCode;")
    lines.append("    }")
    lines.append("")

    # getStatusCode
    lines.append("    public int getStatusCode() {")
    lines.append("        return this.statusCode;")
    lines.append("    }")
    lines.append("")

    # getMessage with switch
    lines.append("    public String getMessage() {")
    lines.append("        switch (this.statusCode) {")
    if status is not None:
        for const in status.constants:
            field_name = _upper_snake(const.name)
            desc = const.description.strip() if const.description else "Unknown error"
            # Single-line the description
            desc = " ".join(desc.split())
            lines.append(f"        case {field_name}:")
            lines.append(f'            return "{desc}";')
    lines.append("        default:")
    lines.append('            return "Unknown error";')
    lines.append("        }")
    lines.append("    }")
    lines.append("")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _generate_context_holder(project_ir: IRProject) -> str:
    """Generate {Project}ContextHolder.java."""
    pname = project_ir.name
    class_name = _context_holder_class(pname)

    lines: list[str] = []
    lines.append(_LICENSE)
    lines.append("")
    lines.append(f"package {_java_package(pname)};")
    lines.append("")
    lines.append(f"class {class_name} {{")
    lines.append("")
    lines.append("    long cCtx;")
    lines.append("")
    lines.append(f"    {class_name}(long cCtx) {{")
    lines.append("        this.cCtx = cCtx;")
    lines.append("    }")
    lines.append("")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JNI C file generator
# ---------------------------------------------------------------------------

def _c_prefix(project_ir: IRProject) -> str:
    return project_ir.prefix


def _c_type_for_arg(project_ir: IRProject, arg: IRCArgument) -> str:
    """Map IR argument to C type name for JNI marshalling."""
    if arg.enum_name:
        return f"{_c_prefix(project_ir)}_{_snake(arg.enum_name)}_t"
    if arg.interface_name:
        return f"{_c_prefix(project_ir)}_impl_t"
    if arg.class_name == "data":
        return "vsc_data_t"
    if arg.class_name == "buffer":
        return "vsc_buffer_t"
    if arg.class_name == "error":
        return f"{_c_prefix(project_ir)}_error_t"
    if arg.class_name:
        return f"{_c_prefix(project_ir)}_{_snake(arg.class_name)}_t"
    type_name = (arg.type_name or "").lower()
    if type_name == "size":
        return "size_t"
    if type_name == "boolean":
        return "bool"
    if type_name == "integer":
        return "int"
    if type_name == "unsigned":
        return "unsigned"
    if type_name == "byte":
        return "byte"
    if type_name == "string":
        return "const char *"
    return "void"


def _jni_type_for_arg(arg: IRCArgument) -> str:
    """Map IR argument to JNI type."""
    if arg.enum_name:
        return "jobject"
    if arg.interface_name:
        return "jobject"
    if arg.class_name == "data":
        return "jbyteArray"
    if arg.class_name == "buffer":
        return "jbyteArray"
    if arg.class_name and arg.class_name not in ("data", "buffer", "error"):
        return "jobject"
    type_name = (arg.type_name or "").lower()
    if type_name == "size":
        return "jint"
    if type_name == "boolean":
        return "jboolean"
    if type_name == "integer":
        return "jint"
    if type_name == "unsigned":
        return "jint"
    if type_name == "byte":
        return "jbyte"
    if type_name == "string":
        return "jstring"
    return "void"


def _jni_return_type(method: IRCMethod) -> str:
    """JNI return type for a method."""
    buf_outs = _buffer_output_args(method)
    if len(buf_outs) >= 2:
        return "jobject"
    if len(buf_outs) == 1:
        return "jbyteArray"
    value_returns = [r for r in method.returns if r.enum_name != "status"]
    if not value_returns:
        return "void"
    ret = value_returns[0]
    return _jni_type_for_arg(ret)


def _jni_func_name(project_ir: IRProject, entity_name: str, method_name: str) -> str:
    """JNI C function name.

    ``Java_com_virgilsecurity_crypto_{project}_{Project}JNI_{entity}_{method}``
    Underscores in entity/method names become ``_1``.
    """
    pkg_path = _jni_package_path(project_ir.name).replace("/", "_")
    jni_class = _jni_class(project_ir.name)
    entity_escaped = _entity_camel(entity_name).replace("_", "_1")
    method_escaped = _method_camel(method_name).replace("_", "_1")
    return f"Java_{pkg_path}_{jni_class}_{entity_escaped}_1{method_escaped}"


def _generate_jni_c_method(
    project_ir: IRProject,
    method: IRCMethod,
    entity_name: str,
    is_static: bool,
) -> list[str]:
    """Generate JNI C code for a single method implementation."""
    pname = project_ir.name
    prefix = _c_prefix(project_ir)
    entity_snake = _snake(entity_name)
    method_snake = _snake(method.name)
    c_func = f"{prefix}_{entity_snake}_{method_snake}"
    exception_class = _exception_class(pname)
    pkg_path = _jni_package_path(pname)

    lines: list[str] = []
    buf_outs = _buffer_output_args(method)
    has_error = _method_has_error(method)

    # Unwrap enum arguments
    for arg in method.arguments:
        if arg.class_name == "buffer" or arg.class_name == "error":
            continue
        if arg.type_name == "self":
            continue
        if arg.access == "writeonly":
            continue
        if arg.enum_name:
            arg_camel = _camel(arg.name)
            enum_snake = _snake(arg.enum_name)
            enum_c_type = f"{prefix}_{enum_snake}_t"
            lines.append(f"// Wrap enums")
            lines.append(
                f"jclass {arg_camel}_cls = (*jenv)->GetObjectClass(jenv, j{arg_camel});"
            )
            lines.append(
                f'jmethodID {arg_camel}_methodID = '
                f'(*jenv)->GetMethodID(jenv, {arg_camel}_cls, "getCode", "()I");'
            )
            lines.append(
                f"{enum_c_type} /*8*/ {_snake(arg.name)} = "
                f"({enum_c_type} /*8*/) (*jenv)->CallIntMethod(jenv, j{arg_camel}, {arg_camel}_methodID);"
            )
            lines.append("")
        elif arg.class_name == "data":
            arg_camel = _camel(arg.name)
            arg_snake = _snake(arg.name)
            lines.append("// Wrap input data")
            lines.append(
                f"byte* {arg_snake}_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, j{arg_camel}, NULL);"
            )
            lines.append(
                f"vsc_data_t {arg_snake} = vsc_data({arg_snake}_arr, "
                f"(*jenv)->GetArrayLength(jenv, j{arg_camel}));"
            )
            lines.append("")
        elif arg.type_name == "string":
            arg_camel = _camel(arg.name)
            arg_snake = _snake(arg.name)
            lines.append("// Wrap Java strings")
            lines.append(
                f'const char *{arg_snake} = (*jenv)->GetStringUTFChars(jenv, j{arg_camel}, NULL);'
            )
            lines.append("")

    # Allocate output buffers
    for buf in buf_outs:
        buf_snake = _snake(buf.name)
        # Use length_attrs to determine capacity expression
        length = buf.length_attrs
        if length.get("method"):
            cap_method = f"{prefix}_{entity_snake}_{_snake(length['method'])}"
            # Build cap call args from proxy attrs
            cap_call_args = []
            if not is_static:
                cap_call_args.append(f"{entity_snake}_ctx")
            # Check for proxy arguments
            i = 0
            while True:
                proxy_key = f"proxy_{i}_argument"
                if proxy_key in length:
                    proxy_arg = _snake(length[proxy_key])
                    cap_call_args.append(f"{proxy_arg}.len/*a*/")
                else:
                    break
                i += 1
            if not cap_call_args:
                cap_call_args_str = ""
            else:
                cap_call_args_str = ", ".join(cap_call_args)
            lines.append(
                f"vsc_buffer_t *{buf_snake} = "
                f"vsc_buffer_new_with_capacity({cap_method}({cap_call_args_str}));"
            )
        elif length.get("constant"):
            lines.append(
                f"vsc_buffer_t *{buf_snake} = "
                f"vsc_buffer_new_with_capacity({length['constant']});"
            )
        else:
            lines.append(
                f"vsc_buffer_t *{buf_snake} = "
                f"vsc_buffer_new_with_capacity(/* TODO: determine capacity */);"
            )
        lines.append("")

    # Cast class context for non-static
    if not is_static:
        c_type = f"{prefix}_{entity_snake}_t"
        lines.append(f"// Cast class context")
        lines.append(
            f"{c_type} /*2*/* {entity_snake}_ctx = *({c_type} /*2*/**) &c_ctx;"
        )
        lines.append("")

    # Build C function call
    c_args: list[str] = []
    if not is_static:
        c_args.append(f"{entity_snake}_ctx /*a1*/")
    for arg in method.arguments:
        if arg.type_name == "self":
            continue
        if arg.class_name == "error":
            continue
        arg_snake = _snake(arg.name)
        if arg.class_name == "data":
            c_args.append(f"{arg_snake} /*a3*/")
        elif arg.class_name == "buffer":
            c_args.append(f"{arg_snake} /*a3*/")
        elif arg.enum_name:
            c_args.append(f"{arg_snake} /*a7*/")
        elif arg.interface_name:
            c_args.append(f"j{_camel(arg.name)} /*TODO*/")
        elif arg.type_name == "string":
            c_args.append(f"{arg_snake} /*a8*/")
        elif arg.access != "writeonly":
            c_args.append(f"j{_camel(arg.name)} /*a9*/")

    c_args_str = ", ".join(c_args)

    value_returns = [r for r in method.returns if r.enum_name != "status"]
    has_status_return = any(r.enum_name == "status" for r in method.returns)

    if has_status_return:
        lines.append(f"{prefix}_status_t status = {c_func}({c_args_str});")
        lines.append(f"if (status != {prefix}_status_SUCCESS) {{")
        lines.append(f"    throw{_project_pascal(pname)}Exception(jenv, jobj, status);")
        lines.append("    return NULL;")
        lines.append("}")
    elif value_returns:
        ret = value_returns[0]
        if ret.class_name == "data":
            lines.append(
                f"const vsc_data_t /*3*/ proxyResult = {c_func}({c_args_str});"
            )
        elif ret.enum_name:
            enum_c = f"{prefix}_{_snake(ret.enum_name)}_t"
            lines.append(
                f"const {enum_c} proxyResult = {c_func}({c_args_str});"
            )
        elif ret.interface_name:
            lines.append(
                f"const {prefix}_impl_t */*6*/ proxyResult = {c_func}({c_args_str});"
            )
        elif ret.class_name:
            class_c = f"{prefix}_{_snake(ret.class_name)}_t"
            lines.append(
                f"const {class_c} */*5*/ proxyResult = {c_func}({c_args_str});"
            )
        elif ret.type_name in ("size", "integer", "unsigned"):
            lines.append(f"jint ret = (jint) {c_func}({c_args_str});")
        elif ret.type_name == "boolean":
            lines.append(f"jboolean ret = (jboolean) {c_func}({c_args_str});")
        else:
            lines.append(f"{c_func}({c_args_str});")
    elif not buf_outs:
        lines.append(f"{c_func}({c_args_str});")
    else:
        if has_status_return:
            pass  # already handled
        else:
            lines.append(f"{c_func}({c_args_str});")

    # Marshal return values
    if buf_outs and len(buf_outs) == 1:
        buf_snake = _snake(buf_outs[0].name)
        lines.append(
            f"jbyteArray ret = (*jenv)->NewByteArray(jenv, vsc_buffer_len({buf_snake}));"
        )
        lines.append(
            f"(*jenv)->SetByteArrayRegion (jenv, ret, 0, "
            f"vsc_buffer_len({buf_snake}), (jbyte*) vsc_buffer_bytes({buf_snake}));"
        )
    elif buf_outs and len(buf_outs) >= 2:
        result_class = f"{_pascal(entity_name)}{_pascal(method.name)}Result"
        lines.append(
            f'jclass result_cls = (*jenv)->FindClass(jenv, '
            f'"{pkg_path}/{result_class}");'
        )
    elif value_returns:
        ret = value_returns[0]
        if ret.class_name == "data":
            lines.append("jbyteArray ret = NULL;")
            lines.append("if (proxyResult.len > 0) {")
            lines.append(
                "    ret = (*jenv)->NewByteArray(jenv, proxyResult.len);"
            )
            lines.append(
                "    (*jenv)->SetByteArrayRegion (jenv, ret, 0, proxyResult.len, "
                "(jbyte*) proxyResult.bytes);"
            )
            lines.append("}")
        elif ret.enum_name:
            enum_pascal = _pascal(ret.enum_name)
            lines.append(
                f'jclass cls = (*jenv)->FindClass(jenv, '
                f'"{pkg_path}/{enum_pascal}");'
            )
            lines.append("if (NULL == cls) {")
            lines.append(f'    VSCF_ASSERT("Enum {enum_pascal} not found.");')
            lines.append("}")
            lines.append("")
            lines.append(
                f'jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, '
                f'"fromCode", "(I)L{pkg_path}/{enum_pascal};");'
            )
            lines.append("if (NULL == methodID) {")
            lines.append(
                f"""    VSCF_ASSERT("Enum {enum_pascal} has no method 'fromCode'.");"""
            )
            lines.append("}")
            lines.append(
                "jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);"
            )
        elif ret.class_name:
            class_pascal = _pascal(ret.class_name)
            lines.append(
                f'jclass result_cls = (*jenv)->FindClass(jenv, '
                f'"{pkg_path}/{class_pascal}");'
            )
            lines.append("if (NULL == result_cls) {")
            lines.append(f'    VSCF_ASSERT("Class {class_pascal} not found.");')
            lines.append("}")
            lines.append(
                f'jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, '
                f'"getInstance", "(J)L{pkg_path}/{class_pascal};");'
            )
            lines.append("if (NULL == result_methodID) {")
            lines.append(
                f"""    VSCF_ASSERT("Class {class_pascal} has no 'getInstance' method.");"""
            )
            lines.append("}")
            # shallow_copy for readonly access
            if ret.access in ("readonly", None):
                class_c = f"{prefix}_{_snake(ret.class_name)}_t"
                lines.append(
                    f"{prefix}_{_snake(ret.class_name)}_shallow_copy("
                    f"({class_c} */*5*/) proxyResult);"
                )
            lines.append(
                f"jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, "
                f"result_methodID, (jlong) proxyResult);"
            )
        elif ret.interface_name:
            iface_pascal = _pascal(ret.interface_name)
            lines.append(
                f"{prefix}_impl_shallow_copy(({prefix}_impl_t */*6*/) proxyResult);"
            )
            lines.append(
                f"jobject ret = wrap{iface_pascal}(jenv, jobj, proxyResult);"
            )

    # Free resources
    for arg in method.arguments:
        if arg.class_name == "data":
            arg_camel = _camel(arg.name)
            arg_snake = _snake(arg.name)
            lines.append("// Free resources")
            lines.append(
                f"(*jenv)->ReleaseByteArrayElements(jenv, j{arg_camel}, "
                f"(jbyte*) {arg_snake}_arr, 0);"
            )
            lines.append("")

    for buf in buf_outs:
        buf_snake = _snake(buf.name)
        lines.append(f"vsc_buffer_delete({buf_snake});")
        lines.append("")

    # Return statement
    if buf_outs or value_returns:
        lines.append("return ret;")
    elif not (value_returns or buf_outs):
        pass  # void method

    return lines


def _generate_jni_c_entity_lifecycle(
    project_ir: IRProject,
    entity_name: str,
) -> list[str]:
    """Generate new/close JNI C methods for a non-static entity."""
    prefix = _c_prefix(project_ir)
    entity_snake = _snake(entity_name)
    c_type = f"{prefix}_{entity_snake}_t"

    lines: list[str] = []
    # new
    lines.append("jlong c_ctx = 0;")
    lines.append(f"*({c_type} **)&c_ctx = {prefix}_{entity_snake}_new();")
    lines.append("return c_ctx;")
    lines.append("")

    # close
    lines.append(
        f"{prefix}_{entity_snake}_delete(*({c_type} /*2*/ **) &c_ctx /*5*/);"
    )
    lines.append("")
    return lines


def _generate_jni_c(project_ir: IRProject) -> str:
    """Generate the complete {Project}JNI.c file."""
    pname = project_ir.name
    prefix = _c_prefix(project_ir)
    exception_class = _exception_class(pname)
    pkg_path = _jni_package_path(pname)

    lines: list[str] = []
    lines.append(_C_LICENSE)
    lines.append("")

    # throwException helper
    lines.append(
        f'jclass cls = (*jenv)->FindClass(jenv, '
        f'"{pkg_path}/{exception_class}");'
    )
    lines.append("if (NULL == cls) {")
    lines.append(f'    VSCF_ASSERT("Class PheException not found.");')
    lines.append("    return 0;")
    lines.append("}")
    lines.append("")
    lines.append(
        'jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(I)V");'
    )
    lines.append("if (NULL == methodID) {")
    lines.append(
        f'    VSCF_ASSERT("Class {pkg_path.replace("/", ".")}.{exception_class} '
        f'has no constructor.");'
    )
    lines.append("    return 0;")
    lines.append("}")
    lines.append(
        "jthrowable obj = (*jenv)->NewObject(jenv, cls, methodID, statusCode);"
    )
    lines.append("if (NULL == obj) {")
    lines.append(
        f'    VSCF_ASSERT("Can\'t instantiate {pkg_path.replace("/", ".")}.{exception_class}.");'
    )
    lines.append("    return 0;")
    lines.append("}")
    lines.append("return (*jenv)->Throw(jenv, obj);")
    lines.append("")

    iface_index = {i.name: i for i in project_ir.interfaces}

    # Static classes
    for cls in project_ir.classes:
        if cls.attrs.get("scope") in ("private", "internal"):
            continue
        if cls.name == "error":
            continue
        is_static = _is_static_class(cls)

        if not is_static:
            # Lifecycle
            lifecycle = _generate_jni_c_entity_lifecycle(project_ir, cls.name)
            lines.extend(lifecycle)

        for m in cls.methods:
            if not _method_should_wrap(m):
                continue
            method_lines = _generate_jni_c_method(
                project_ir, m, cls.name,
                is_static=is_static or _is_static_method(m),
            )
            lines.extend(method_lines)
            lines.append("")

    # Implementations
    for impl in project_ir.implementations:
        if impl.attrs.get("scope") in ("private", "internal"):
            continue

        # Lifecycle
        lifecycle = _generate_jni_c_entity_lifecycle(project_ir, impl.name)
        lines.extend(lifecycle)

        # Dependency setters
        for dep in impl.dependencies:
            entity_snake = _snake(impl.name)
            dep_snake = _snake(dep.name)
            lines.append(
                f"// Dependency setter: {_pascal(dep.name)}"
            )
            lines.append("")

        # Interface methods
        for binding in impl.interface_bindings:
            iface = iface_index.get(binding.name)
            if iface is None:
                continue
            for m in iface.methods:
                if not _method_should_wrap(m):
                    continue
                method_lines = _generate_jni_c_method(
                    project_ir, m, impl.name, is_static=_is_static_method(m),
                )
                lines.extend(method_lines)
                lines.append("")

        # Own methods
        for m in impl.methods:
            if not _method_should_wrap(m):
                continue
            method_lines = _generate_jni_c_method(
                project_ir, m, impl.name, is_static=_is_static_method(m),
            )
            lines.extend(method_lines)
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JNI H file generator
# ---------------------------------------------------------------------------

def _generate_jni_h_method_decl(
    project_ir: IRProject,
    method: IRCMethod,
    entity_name: str,
    is_static: bool,
) -> list[str]:
    """Generate a JNI header declaration for a single method."""
    jni_ret = _jni_return_type(method)
    func_name = _jni_func_name(project_ir, entity_name, method.name)

    # Build parameter list
    params: list[str] = []
    if not is_static:
        params.append("jlong c_ctx")
    for arg in method.arguments:
        if arg.class_name == "buffer" or arg.class_name == "error":
            continue
        if arg.type_name == "self":
            continue
        if arg.access == "writeonly":
            continue
        jtype = _jni_type_for_arg(arg)
        params.append(f"{jtype} j{_camel(arg.name)}")

    params_str = ", ".join(params) if params else "void"

    lines: list[str] = []
    lines.append(f"JNIEXPORT {jni_ret} JNICALL")
    lines.append(f"{func_name}({params_str});")
    lines.append("")
    return lines


def _generate_jni_h(project_ir: IRProject) -> str:
    """Generate the complete {Project}JNI.h file."""
    iface_index = {i.name: i for i in project_ir.interfaces}

    lines: list[str] = []
    lines.append(_C_LICENSE)
    lines.append("")

    # Static classes
    for cls in project_ir.classes:
        if cls.attrs.get("scope") in ("private", "internal"):
            continue
        if cls.name == "error":
            continue
        is_static = _is_static_class(cls)

        if not is_static:
            # new declaration
            jni_class = _jni_class(project_ir.name)
            pkg_path = _jni_package_path(project_ir.name).replace("/", "_")
            entity_escaped = _entity_camel(cls.name).replace("_", "_1")
            lines.append(f"JNIEXPORT jlong JNICALL")
            lines.append(
                f"Java_{pkg_path}_{jni_class}_{entity_escaped}_1new__(void);"
            )
            lines.append("")
            # close declaration
            lines.append(f"JNIEXPORT void JNICALL")
            lines.append(
                f"Java_{pkg_path}_{jni_class}_{entity_escaped}_1close(jlong );"
            )
            lines.append("")

        for m in cls.methods:
            if not _method_should_wrap(m):
                continue
            decl = _generate_jni_h_method_decl(
                project_ir, m, cls.name,
                is_static=is_static or _is_static_method(m),
            )
            lines.extend(decl)

    # Implementations
    for impl in project_ir.implementations:
        if impl.attrs.get("scope") in ("private", "internal"):
            continue

        jni_class = _jni_class(project_ir.name)
        pkg_path = _jni_package_path(project_ir.name).replace("/", "_")
        entity_escaped = _entity_camel(impl.name).replace("_", "_1")
        # new
        lines.append(f"JNIEXPORT jlong JNICALL")
        lines.append(
            f"Java_{pkg_path}_{jni_class}_{entity_escaped}_1new__(void);"
        )
        lines.append("")
        # close
        lines.append(f"JNIEXPORT void JNICALL")
        lines.append(
            f"Java_{pkg_path}_{jni_class}_{entity_escaped}_1close(jlong );"
        )
        lines.append("")

        # Interface methods
        for binding in impl.interface_bindings:
            iface = iface_index.get(binding.name)
            if iface is None:
                continue
            for m in iface.methods:
                if not _method_should_wrap(m):
                    continue
                decl = _generate_jni_h_method_decl(
                    project_ir, m, impl.name,
                    is_static=_is_static_method(m),
                )
                lines.extend(decl)

        # Own methods
        for m in impl.methods:
            if not _method_should_wrap(m):
                continue
            decl = _generate_jni_h_method_decl(
                project_ir, m, impl.name,
                is_static=_is_static_method(m),
            )
            lines.extend(decl)

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def generate_java_files(
    project_ir: IRProject, license_text: str = "",
    repo_root: str | Path = ".",
) -> list[tuple[str, str]]:
    """Generate all Java wrapper files for a project from IR.

    Returns a list of ``(repo_relative_path, file_content)`` tuples.
    No dependency on resolved XML files -- pure IR only.
    """
    del license_text
    del repo_root

    pname = project_ir.name
    java_base = (
        f"wrappers/java/{pname}/src/main/java/"
        f"{_java_package_dir(pname)}/"
    )
    jni_base = f"wrappers/java/{pname}/jni/"

    files: list[tuple[str, str]] = []
    iface_index = {i.name: i for i in project_ir.interfaces}

    # Track emitted result classes to allow duplicates matching legacy XML behavior
    # (one per interface, plus one per implementation binding that uses it)

    # --- Enums (excluding status and impl/tag) ---
    for enum in project_ir.enums:
        if enum.attrs.get("scope") == "private":
            continue
        if enum.name in ("status", "impl/tag"):
            continue
        files.append((
            f"{java_base}{_pascal(enum.name)}.java",
            _generate_enum(project_ir, enum),
        ))

    # --- Interfaces ---
    for iface in project_ir.interfaces:
        if iface.attrs.get("scope") == "private":
            continue
        files.append((
            f"{java_base}{_pascal(iface.name)}.java",
            _generate_interface(project_ir, iface),
        ))

        # Result classes for interface multi-buffer methods
        for m in iface.methods:
            if not _method_should_wrap(m):
                continue
            if _method_needs_result_class(m):
                result_name = f"{_pascal(iface.name)}{_pascal(m.name)}Result"
                files.append((
                    f"{java_base}{result_name}.java",
                    _generate_result_class(project_ir, iface.name, m),
                ))

    # --- Classes ---
    for cls in project_ir.classes:
        if cls.attrs.get("scope") in ("private", "internal"):
            continue
        if cls.name == "error":
            continue
        files.append((
            f"{java_base}{_pascal(cls.name)}.java",
            _generate_class_entity_file(project_ir, cls),
        ))

        # Result classes for class multi-buffer methods
        for m in cls.methods:
            if not _method_should_wrap(m):
                continue
            if _method_needs_result_class(m):
                result_name = f"{_pascal(cls.name)}{_pascal(m.name)}Result"
                files.append((
                    f"{java_base}{result_name}.java",
                    _generate_result_class(project_ir, cls.name, m),
                ))

    # --- Implementations ---
    for impl in project_ir.implementations:
        if impl.attrs.get("scope") in ("private", "internal"):
            continue
        files.append((
            f"{java_base}{_pascal(impl.name)}.java",
            _generate_impl_file(project_ir, impl),
        ))

        # Result classes for implementation interface bindings (duplicates per-impl)
        for binding in impl.interface_bindings:
            iface = iface_index.get(binding.name)
            if iface is None:
                continue
            for m in iface.methods:
                if not _method_should_wrap(m):
                    continue
                if _method_needs_result_class(m):
                    result_name = f"{_pascal(iface.name)}{_pascal(m.name)}Result"
                    files.append((
                        f"{java_base}{result_name}.java",
                        _generate_result_class(project_ir, iface.name, m),
                    ))

    # --- Infrastructure ---
    files.append((
        f"{java_base}{_jni_class(pname)}.java",
        _generate_jni_java(project_ir),
    ))
    files.append((
        f"{java_base}{_exception_class(pname)}.java",
        _generate_exception(project_ir),
    ))
    files.append((
        f"{java_base}{_context_holder_class(pname)}.java",
        _generate_context_holder(project_ir),
    ))

    # --- JNI C/H ---
    files.append((
        f"{jni_base}{_jni_class(pname)}.h",
        _generate_jni_h(project_ir),
    ))
    files.append((
        f"{jni_base}{_jni_class(pname)}.c",
        _generate_jni_c(project_ir),
    ))

    return files
