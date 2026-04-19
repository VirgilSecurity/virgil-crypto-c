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

def _method_should_wrap(method: IRCMethod, project_ir: IRProject | None = None) -> bool:
    """Return True if method should appear in the wrapper API."""
    scope = method.attrs.get("scope", "public")
    decl = method.declaration or method.attrs.get("declaration", "public")
    vis = method.visibility or method.attrs.get("visibility", "public")
    defn = method.definition or method.attrs.get("definition", "public")
    if not (scope == "public" and decl == "public" and vis == "public"):
        return False
    # Also check definition -- some methods have public scope but private definition
    if defn == "private":
        return False
    # Skip methods that reference private/internal class types
    if project_ir is not None and _method_has_internal_types(method, project_ir):
        return False
    # Skip methods with raw byte pointer arguments (not wrappable in JNI)
    for arg in method.arguments:
        if (arg.type_name or "").lower() == "byte" and arg.is_reference:
            return False
    return True


def _is_internal_own_method(method: IRCMethod) -> bool:
    """Return True if this is a private C helper on an implementation.

    Implementation own methods that have no declaration/visibility attrs are
    private C-level helpers not present in public headers. Class methods also
    have no attrs by default but should never be passed to this function.
    """
    return (method.declaration is None
            and method.visibility is None
            and method.attrs.get("declaration") is None
            and method.attrs.get("visibility") is None)


def _method_has_internal_types(method: IRCMethod, project_ir: IRProject) -> bool:
    """Return True if any argument or return references a private/internal class."""
    # Build set of public class names
    public_classes: set[str] = set()
    private_classes: set[str] = set()
    for cls in project_ir.classes:
        scope = cls.attrs.get("scope", "public")
        if scope in ("private", "internal"):
            private_classes.add(cls.name)
        else:
            public_classes.add(cls.name)
    # Also include impl names as public
    for impl in project_ir.implementations:
        if impl.attrs.get("scope") not in ("private", "internal"):
            public_classes.add(impl.name)

    for arg in method.arguments + method.returns:
        cn = arg.class_name
        if cn and cn not in ("data", "buffer", "error", "self"):
            if cn in private_classes or cn not in public_classes:
                return True
    return False


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
    if arg.class_name and arg.class_name not in ("data", "buffer", "error", "self"):
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
    # Resolve class_name="self" to the entity's own type
    if ret.class_name == "self":
        return _pascal(entity_name)
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

    # Build constant name → integer value mapping
    constants: list[tuple[str, str]] = []
    next_val = 0
    for const in enum.constants:
        value = const.attrs.get("value")
        if value is not None and value != "":
            val_str = resolve_constant_value(value, None, project_ir)
        else:
            val_str = str(next_val)
        constants.append((_upper_snake(const.name), val_str))
        try:
            next_val = int(val_str, 0) + 1
        except ValueError:
            next_val += 1

    lines.append(f"public enum {enum_name} {{")
    lines.append("")
    # Enum values with code
    for i, (cname, cval) in enumerate(constants):
        sep = ";" if i == len(constants) - 1 else ","
        lines.append(f"    {cname}({cval}){sep}")
    lines.append("")
    lines.append("    private final int code;")
    lines.append("")
    lines.append(f"    private {enum_name}(int code) {{")
    lines.append("        this.code = code;")
    lines.append("    }")
    lines.append("")
    lines.append("    public int getCode() {")
    lines.append("        return code;")
    lines.append("    }")
    lines.append("")
    lines.append(f"    public static {enum_name} fromCode(int code) {{")
    lines.append(f"        for ({enum_name} a : {enum_name}.values()) {{")
    lines.append("            if (a.code == code) {")
    lines.append("                return a;")
    lines.append("            }")
    lines.append("        }")
    lines.append("        return null;")
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

    pname = project_ir.name
    exception_class = _exception_class(pname)
    lines.append(f"public interface {iface_name}{extends_str} {{")
    for method in iface.methods:
        if not _method_should_wrap(method):
            continue
        method_camel = _method_camel(method.name)
        ret_type = _java_return_type(method, pname, iface_name)
        params = _java_param_list(method, pname, include_ctx=False)
        params_str = ", ".join(f"{t} {n}" for t, n in params)
        throws = f" throws {exception_class}" if _method_has_error(method) else ""
        lines.append(f"    {ret_type} {method_camel}({params_str}){throws};")
        lines.append("")
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
            if not _method_should_wrap(m, project_ir):
                continue
            methods.append((m, iface.name))

    for m in impl.methods:
        if not _method_should_wrap(m, project_ir):
            continue
        if _is_internal_own_method(m):
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
    *,
    java_is_static: bool | None = None,
    return_entity_name: str | None = None,
) -> list[str]:
    """Generate method delegation body lines for a single method.

    ``is_static`` controls whether ``this.cCtx`` is omitted from the JNI call
    (i.e. whether the underlying C function is context-free).
    ``java_is_static`` overrides the Java ``static`` keyword independently —
    used for interface-inherited C-static methods that must be instance methods
    in Java to satisfy the interface contract.
    ``return_entity_name`` overrides the entity name used for result-class
    naming (e.g. the interface name instead of the implementation name).
    """
    pname = project_ir.name
    jni = _jni_class(pname)
    entity_camel = _entity_camel(entity_name)
    method_camel = _method_camel(method.name)
    exception = _exception_class(pname)

    _ret_entity = return_entity_name if return_entity_name is not None else entity_name
    ret_type = _java_return_type(method, pname, _ret_entity)
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

    _java_static = java_is_static if java_is_static is not None else is_static
    lines: list[str] = []
    static_kw = "static " if _java_static else ""
    sig = f"    public {static_kw}{ret_type} {method_camel}({params_str}){throws} {{"
    lines.append(sig)
    if ret_type == "void":
        lines.append(f"        {jni_call};")
    else:
        lines.append(f"        return {jni_call};")
    lines.append("    }")
    return lines


_JAVA_WRAPPER_PROJECTS = {"common", "foundation", "phe", "pythia", "ratchet"}


def _collect_cross_project_imports(
    project_ir: IRProject,
    dependencies: list[IRDependency],
    methods: list[tuple[IRCMethod, str]],
) -> list[str]:
    """Collect import statements for types from other projects.

    Uses wildcard imports for external projects when cross-project
    types are detected (matching the original GSL-generated style).
    Only includes imports for known Java wrapper projects.
    """
    project_name = project_ir.name
    # Build set of locally-defined type names
    local_types: set[str] = set()
    for iface in project_ir.interfaces:
        local_types.add(iface.name)
    for cls in project_ir.classes:
        local_types.add(cls.name)
    for enum in project_ir.enums:
        local_types.add(enum.name)
    for impl in project_ir.implementations:
        local_types.add(impl.name)

    external_projects: set[str] = set()

    for dep in dependencies:
        dep_project = dep.attrs.get("project", "")
        if dep_project and dep_project != project_name and dep_project in _JAVA_WRAPPER_PROJECTS:
            external_projects.add(dep_project)

    for method, _ in methods:
        for arg in method.arguments + method.returns:
            lib = arg.library
            if lib and lib != project_name and lib in _JAVA_WRAPPER_PROJECTS:
                external_projects.add(lib)
                continue
            # If no library set, check if type is locally defined
            type_ref = arg.interface_name or arg.class_name or arg.enum_name
            if type_ref and type_ref not in ("data", "buffer", "error", "self"):
                if type_ref not in local_types:
                    # Assume foundation for unattributed external types
                    if "foundation" in _JAVA_WRAPPER_PROJECTS and project_name != "foundation":
                        external_projects.add("foundation")

    return sorted(
        f"import {_java_package(proj)}.*;"
        for proj in external_projects
    )


def _generate_class_file(
    project_ir: IRProject,
    entity_name: str,
    is_static: bool,
    interfaces: list[str],
    dependencies: list[IRDependency],
    methods: list[tuple[IRCMethod, str]],
    constant_getters: list[tuple[str, str, str]],
    class_constants: list[IRCConstant] | None = None,
    constructors: list[IRCMethod] | None = None,
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

    # Cross-project imports
    cross_imports = _collect_cross_project_imports(project_ir, dependencies, methods)
    if cross_imports:
        for imp in cross_imports:
            lines.append(imp)
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

        # Named constructors from impl/class constructors list
        for ctor in (constructors or []):
            if not _method_should_wrap(ctor):
                continue
            ctor_params = _java_param_list(ctor, pname, include_ctx=False)
            if not ctor_params:
                continue
            ctor_params_str = ", ".join(f"{t} {n}" for t, n in ctor_params)
            ctor_args_str = ", ".join(n for _, n in ctor_params)
            lines.append(f"    public {class_name}({ctor_params_str}) {{")
            lines.append("        super();")
            lines.append(f"        this.cCtx = {jni}.INSTANCE.{entity_camel}_new({ctor_args_str});")
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
        from_iface = (origin != entity_name)
        # jni_static: whether to omit this.cCtx (C function is context-free)
        jni_static = is_static or _is_static_method(method)
        # java_static: whether to put `static` in the Java signature.
        # Interface-inherited methods must be non-static (instance) in Java
        # even when the underlying C function is context-free.
        java_static = is_static if from_iface else jni_static
        method_lines = _generate_method_body(
            project_ir, method, entity_name,
            is_static=jni_static,
            java_is_static=java_static,
            return_entity_name=origin,
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
        constructors=impl.constructors,
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
        constructors=cls.constructors,
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
    """Generate {Project}JNI.java -- singleton with ALL native method declarations."""
    pname = project_ir.name
    jni_class = _jni_class(pname)
    exception_class = _exception_class(pname)

    # Collect cross-project imports from all entities
    all_jni_imports: set[str] = set()
    for cls in project_ir.classes:
        if cls.attrs.get("scope") in ("private", "internal"):
            continue
        if cls.name == "error":
            continue
        cls_methods = [(m, cls.name) for m in cls.methods if _method_should_wrap(m)]
        for imp in _collect_cross_project_imports(project_ir, cls.dependencies, cls_methods):
            all_jni_imports.add(imp)
    for impl in project_ir.implementations:
        if impl.attrs.get("scope") in ("private", "internal"):
            continue
        impl_methods = _collect_all_methods(project_ir, impl)
        for imp in _collect_cross_project_imports(project_ir, impl.dependencies, impl_methods):
            all_jni_imports.add(imp)

    lines: list[str] = []
    lines.append(_LICENSE)
    lines.append("")
    lines.append(f"package {_java_package(pname)};")
    lines.append("")
    lines.append("import com.virgilsecurity.crypto.common.utils.NativeUtils;")
    if all_jni_imports:
        for imp in sorted(all_jni_imports):
            lines.append(imp)
    lines.append("")
    lines.append(f"public class {jni_class} {{")
    lines.append("")
    lines.append(f"    public static final {jni_class} INSTANCE;")
    lines.append("")
    lines.append("    static {")
    lines.append(f'        NativeUtils.load("{project_ir.prefix}_{pname}");')
    lines.append(f"        INSTANCE = new {jni_class}();")
    lines.append("    }")
    lines.append("")
    lines.append(f"    private {jni_class}() {{")
    lines.append("    }")
    lines.append("")

    def _emit_native_methods(
        entity_name: str,
        methods: list,
        dependencies: list,
        is_static: bool,
        interface_bindings: list | None = None,
        is_implementation: bool = False,
        constructors: list | None = None,
    ) -> None:
        entity_camel = _entity_camel(entity_name)
        iface_by_name = {i.name: i for i in project_ir.interfaces}

        # new / close for non-static entities
        if not is_static:
            lines.append(f"    public native long {entity_camel}_new();")
            lines.append("")
            lines.append(f"    public native void {entity_camel}_close(long cCtx);")
            lines.append("")

            # Named constructor overloads
            for ctor in (constructors or []):
                if not _method_should_wrap(ctor):
                    continue
                ctor_params = _java_param_list(ctor, pname, include_ctx=False)
                if not ctor_params:
                    continue
                ctor_params_str = ", ".join(f"{t} {n}" for t, n in ctor_params)
                lines.append(f"    public native long {entity_camel}_new({ctor_params_str});")
                lines.append("")

        # Dependency setters
        for dep in dependencies:
            dep_type = _pascal(dep.type_name)
            dep_setter = "set" + _pascal(dep.name)
            lines.append(
                f"    public native void {entity_camel}_{dep_setter}"
                f"(long cCtx, {dep_type} {_camel(dep.name)});"
            )
            lines.append("")

        # Collect all methods (own + inherited from interface bindings)
        all_methods = list(methods)
        if interface_bindings:
            for binding in interface_bindings:
                iface = iface_by_name.get(binding.name)
                if iface is None:
                    continue
                existing_names = {m.name for m in all_methods}
                for m in iface.methods:
                    if m.name not in existing_names:
                        all_methods.append(m)

        # Method declarations: use iface.name as origin for interface-inherited
        # methods so result-class names match the interface (e.g. KemKemEncapsulateResult,
        # not Ed25519KemEncapsulateResult), matching the main-branch GSL codegen output.
        method_origins: list[tuple[IRCMethod, str]] = []
        for m in methods:
            if is_implementation and _is_internal_own_method(m):
                continue
            method_origins.append((m, entity_name))
        if interface_bindings:
            for binding in interface_bindings:
                iface = iface_by_name.get(binding.name)
                if iface is None:
                    continue
                existing_names = {m.name for m, _ in method_origins}
                for m in iface.methods:
                    if m.name not in existing_names:
                        method_origins.append((m, iface.name))

        for method, origin_name in method_origins:
            if not _method_should_wrap(method):
                continue
            # Skip methods that reference external library types
            has_ext_lib = False
            for a in method.arguments + method.returns:
                if a.library and a.library not in ("common", "foundation", "phe", "pythia", "ratchet"):
                    has_ext_lib = True
                    break
            if has_ext_lib:
                continue
            method_camel = _camel(method.name)
            # Use the origin entity name for result class naming
            ret_type = _java_return_type(method, pname, origin_name)
            # Match class file logic: include cCtx unless entity or method is static
            method_is_static = is_static or _is_static_method(method)
            include_ctx = not method_is_static
            params = _java_param_list(method, pname, include_ctx=include_ctx)
            params_str = ", ".join(f"{t} {n}" for t, n in params)
            throws = _method_has_error(method)
            throws_str = f" throws {exception_class}" if throws else ""
            lines.append(
                f"    public native {ret_type} {entity_camel}_{method_camel}"
                f"({params_str}){throws_str};"
            )
            lines.append("")

    # Iterate ALL entities: classes, then implementations
    for cls in project_ir.classes:
        if cls.attrs.get("scope") in ("private", "internal"):
            continue
        if cls.name == "error":
            continue
        _emit_native_methods(
            cls.name, cls.methods, cls.dependencies,
            _is_static_class(cls),
            constructors=cls.constructors,
        )

    for impl in project_ir.implementations:
        if impl.attrs.get("scope") in ("private", "internal"):
            continue
        _emit_native_methods(
            impl.name, impl.methods, impl.dependencies,
            False,
            interface_bindings=impl.interface_bindings,
            is_implementation=True,
            constructors=impl.constructors,
        )

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
    lines.append(f"public class {exception_class} extends RuntimeException {{")
    lines.append("")

    if status is not None:
        # Error code constants -- must be static final for use in switch cases
        next_val = 0
        for const in status.constants:
            field_name = _upper_snake(const.name)
            value = const.attrs.get("value")
            if value is not None and value != "":
                val_str = resolve_constant_value(value, None, project_ir)
            else:
                val_str = str(next_val)
            lines.append(f"    public static final int {field_name} = {val_str};")
            lines.append("")
            try:
                next_val = int(val_str, 0) + 1
            except ValueError:
                next_val += 1

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

_PROJECT_PREFIX_MAP = {
    "common": "vsc",
    "foundation": "vscf",
    "phe": "vsce",
    "pythia": "vscp",
    "ratchet": "vscr",
}


def _c_prefix(project_ir: IRProject) -> str:
    return project_ir.prefix


def _resolve_project_prefix(project_ir: IRProject, project_name: str | None) -> str:
    """Resolve the C prefix for a cross-project reference."""
    if not project_name or project_name == project_ir.name:
        return project_ir.prefix
    return _PROJECT_PREFIX_MAP.get(project_name, project_name)


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
        # Raw byte pointer (is_reference or readwrite) -> jbyteArray or jlong
        if arg.is_reference:
            return "jlong"
        if arg.access == "readwrite":
            return "jbyteArray"
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


def _jni_ctor_arg_descriptor(arg: IRCArgument, pname: str) -> str:
    """JNI type descriptor for one constructor arg (for overloaded C function name suffix)."""
    if arg.enum_name:
        pkg = _java_package(pname).replace(".", "_")
        return f"L{pkg}_{_pascal(arg.enum_name)}_2"
    if arg.interface_name:
        pkg = _java_package(pname).replace(".", "_")
        return f"L{pkg}_{_pascal(arg.interface_name)}_2"
    if arg.class_name == "data":
        return "_3B"
    type_name = (arg.type_name or "").lower()
    if type_name in ("size", "integer", "unsigned"):
        return "I"
    if type_name == "boolean":
        return "Z"
    if type_name == "byte":
        return "B"
    return ""


def _jni_ctor_overload_suffix(ctor: IRCMethod, pname: str) -> str:
    """JNI overloaded function name suffix for a named constructor.

    E.g. for AlgId arg: ``__Lcom_virgilsecurity_crypto_foundation_AlgId_2``
    """
    parts: list[str] = []
    for arg in ctor.arguments:
        if arg.class_name in ("buffer", "error") or arg.type_name == "self":
            continue
        desc = _jni_ctor_arg_descriptor(arg, pname)
        if desc:
            parts.append(desc)
    return "__" + "".join(parts)


def _generate_jni_c_named_constructor(
    project_ir: IRProject,
    entity_name: str,
    ctor: IRCMethod,
) -> list[str]:
    """Generate JNI C wrapper for a named constructor (e.g. new_with_alg_id)."""
    prefix = _c_prefix(project_ir)
    prefix_upper = project_ir.prefix.upper()
    pname = project_ir.name
    entity_snake = _snake(entity_name)
    c_func = f"{prefix}_{entity_snake}_new_{_snake(ctor.name)}"
    c_type = f"{prefix}_{entity_snake}_t"

    pkg_path = _jni_package_path(pname).replace("/", "_")
    jni_class = _jni_class(pname)
    entity_escaped = _entity_camel(entity_name).replace("_", "_1")
    overload_suffix = _jni_ctor_overload_suffix(ctor, pname)
    func_name = f"Java_{pkg_path}_{jni_class}_{entity_escaped}_1new{overload_suffix}"

    # Build JNI parameter list
    params: list[str] = ["JNIEnv *jenv", "jobject jobj"]
    for arg in ctor.arguments:
        if arg.class_name in ("buffer", "error") or arg.type_name == "self":
            continue
        jtype = _jni_type_for_arg(arg)
        params.append(f"{jtype} j{_camel(arg.name)}")

    lines: list[str] = []
    lines.append(f"JNIEXPORT jlong JNICALL {func_name} ({', '.join(params)}) {{")

    # Track data args for cleanup
    data_args: list[str] = []

    # Unwrap arguments
    for arg in ctor.arguments:
        if arg.class_name in ("buffer", "error") or arg.type_name == "self":
            continue
        arg_camel = _camel(arg.name)
        arg_snake = _snake(arg.name)
        if arg.enum_name:
            enum_c_type = f"{prefix}_{_snake(arg.enum_name)}_t"
            lines.append(f"    // Wrap enums")
            lines.append(f"    jclass {arg_camel}_cls = (*jenv)->GetObjectClass(jenv, j{arg_camel});")
            lines.append(f"    jmethodID {arg_camel}_methodID = (*jenv)->GetMethodID(jenv, {arg_camel}_cls, \"getCode\", \"()I\");")
            lines.append(f"    {enum_c_type} /*8*/ {arg_snake} = ({enum_c_type} /*8*/) (*jenv)->CallIntMethod(jenv, j{arg_camel}, {arg_camel}_methodID);")
            lines.append(f"    ")
        elif arg.class_name == "data":
            lines.append(f"    // Wrap input data")
            lines.append(f"    byte* {arg_snake}_arr = (byte*) (*jenv)->GetByteArrayElements(jenv, j{arg_camel}, NULL);")
            lines.append(f"    vsc_data_t {arg_snake} = vsc_data({arg_snake}_arr, (*jenv)->GetArrayLength(jenv, j{arg_camel}));")
            lines.append(f"    ")
            data_args.append((arg_camel, arg_snake))
        elif arg.interface_name:
            iface_pascal = _pascal(arg.interface_name)
            impl_prefix = _resolve_project_prefix(project_ir, arg.project)
            lines.append(f"    // Wrap Java interfaces")
            lines.append(f"    jclass {arg_snake}_cls = (*jenv)->GetObjectClass(jenv, j{arg_camel});")
            lines.append(f"    if (NULL == {arg_snake}_cls) {{")
            lines.append(f"        {prefix_upper}_ASSERT(\"Class {iface_pascal} not found.\");")
            lines.append(f"    }}")
            lines.append(f"    jfieldID {arg_snake}_fidCtx = (*jenv)->GetFieldID(jenv, {arg_snake}_cls, \"cCtx\", \"J\");")
            lines.append(f"    if (NULL == {arg_snake}_fidCtx) {{")
            lines.append(f"        {prefix_upper}_ASSERT(\"Class '{iface_pascal}' has no field 'cCtx'.\");")
            lines.append(f"    }}")
            lines.append(f"    jlong {arg_snake}_c_ctx = (*jenv)->GetLongField(jenv, j{arg_camel}, {arg_snake}_fidCtx);")
            lines.append(f"    {impl_prefix}_impl_t */*6*/ {arg_snake} = *({impl_prefix}_impl_t */*6*/*)&{arg_snake}_c_ctx;")
            lines.append(f"    ")

    # Build C call args
    call_args: list[str] = []
    for arg in ctor.arguments:
        if arg.type_name == "self" or arg.class_name in ("buffer", "error"):
            continue
        type_name = (arg.type_name or "").lower()
        if type_name in ("size", "integer", "unsigned", "boolean"):
            call_args.append(f"j{_camel(arg.name)}")
        else:
            call_args.append(_snake(arg.name))

    lines.append(f"    jlong proxyResult = (jlong) {c_func}({', '.join(call_args)});")

    # Release data arrays
    for arg_camel, arg_snake in data_args:
        lines.append(f"    // Free resources")
        lines.append(f"    (*jenv)->ReleaseByteArrayElements(jenv, j{arg_camel}, (jbyte*) {arg_snake}_arr, 0);")
        lines.append(f"    ")

    lines.append(f"    return proxyResult;")
    lines.append(f"}}")
    lines.append(f"")
    return lines


def _generate_jni_c_method(
    project_ir: IRProject,
    method: IRCMethod,
    entity_name: str,
    is_static: bool,
) -> list[str]:
    """Generate JNI C code for a single method implementation."""
    pname = project_ir.name
    prefix = _c_prefix(project_ir)
    prefix_upper = project_ir.prefix.upper()
    entity_snake = _snake(entity_name)
    method_snake = _snake(method.name)
    c_func = f"{prefix}_{entity_snake}_{method_snake}"
    exception_class = _exception_class(pname)
    pkg_path = _jni_package_path(pname)

    lines: list[str] = []
    buf_outs = _buffer_output_args(method)
    has_error = _method_has_error(method)
    has_error_arg = any(arg.class_name == "error" for arg in method.arguments)

    # Declare error struct if method has an error argument
    if has_error_arg:
        lines.append("// Wrap errors")
        lines.append(f"struct {prefix}_error_t /*4*/ error;")
        lines.append(f"{prefix}_error_reset(&error);")

    # Unwrap arguments (enums, data, interfaces, strings)
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
        elif arg.interface_name:
            arg_camel = _camel(arg.name)
            arg_snake = _snake(arg.name)
            iface_pascal = _pascal(arg.interface_name)
            lines.append("// Wrap Java interfaces")
            lines.append(
                f"jclass {arg_snake}_cls = (*jenv)->GetObjectClass(jenv, j{arg_camel});"
            )
            lines.append(f"if (NULL == {arg_snake}_cls) {{")
            lines.append(f'    {prefix_upper}_ASSERT("Class {iface_pascal} not found.");')
            lines.append(f"}}")
            lines.append(
                f'jfieldID {arg_snake}_fidCtx = (*jenv)->GetFieldID(jenv, {arg_snake}_cls, "cCtx", "J");'
            )
            lines.append(f"if (NULL == {arg_snake}_fidCtx) {{")
            lines.append(f"    {prefix_upper}_ASSERT(\"Class '{iface_pascal}' has no field 'cCtx'.\");")
            lines.append(f"}}")
            lines.append(
                f"jlong {arg_snake}_c_ctx = (*jenv)->GetLongField(jenv, j{arg_camel}, {arg_snake}_fidCtx);"
            )
            # Use the defining project's prefix for impl_t (cross-project refs)
            impl_prefix = _resolve_project_prefix(project_ir, arg.project)
            lines.append(
                f"{impl_prefix}_impl_t */*6*/ {arg_snake} = *({impl_prefix}_impl_t */*6*/*)&{arg_snake}_c_ctx;"
            )
            lines.append("")
        elif arg.class_name and arg.class_name not in ("data", "buffer", "error", "self"):
            # Non-interface object arg: unwrap cCtx from Java object
            arg_camel = _camel(arg.name)
            arg_snake = _snake(arg.name)
            class_pascal = _pascal(arg.class_name)
            class_c = f"{prefix}_{_snake(arg.class_name)}_t"
            lines.append("// Wrap Java objects")
            lines.append(
                f"jclass {arg_snake}_cls = (*jenv)->GetObjectClass(jenv, j{arg_camel});"
            )
            lines.append(f"if (NULL == {arg_snake}_cls) {{")
            lines.append(f'    {prefix_upper}_ASSERT("Class {class_pascal} not found.");')
            lines.append(f"}}")
            lines.append(
                f'jfieldID {arg_snake}_fidCtx = (*jenv)->GetFieldID(jenv, {arg_snake}_cls, "cCtx", "J");'
            )
            lines.append(f"if (NULL == {arg_snake}_fidCtx) {{")
            lines.append(f"    {prefix_upper}_ASSERT(\"Class '{class_pascal}' has no field 'cCtx'.\");")
            lines.append(f"}}")
            lines.append(
                f"jlong {arg_snake}_c_ctx = (*jenv)->GetLongField(jenv, j{arg_camel}, {arg_snake}_fidCtx);"
            )
            lines.append(
                f"{class_c} */*5*/ {arg_snake} = *({class_c} */*5*/*)&{arg_snake}_c_ctx;"
            )
            lines.append("")
        elif (arg.type_name or "").lower() == "byte" and arg.access == "readwrite":
            arg_camel = _camel(arg.name)
            arg_snake = _snake(arg.name)
            lines.append("// Wrap arrays")
            lines.append(
                f"byte * {arg_snake} = (byte *) (*jenv)->GetByteArrayElements(jenv, j{arg_camel}, NULL);"
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

    # Cast class context for non-static (before buffer allocation since capacity
    # expressions may reference the ctx)
    if not is_static:
        c_type = f"{prefix}_{entity_snake}_t"
        lines.append(f"// Cast class context")
        lines.append(
            f"{c_type} /*9*/* {entity_snake}_ctx = *({c_type} /*9*/**) &c_ctx;"
        )
        lines.append("")

    # Allocate output buffers
    arg_by_name = {a.name: a for a in method.arguments}
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
            # Check for proxy arguments -- can be proxy_N_argument (pass method arg)
            # or proxy_N_constant (pass a literal value like 0)
            i = 0
            while True:
                arg_key = f"proxy_{i}_argument"
                const_key = f"proxy_{i}_constant"
                if arg_key in length:
                    proxy_arg_name = length[arg_key]
                    proxy_arg_snake = _snake(proxy_arg_name)
                    proxy_ir = arg_by_name.get(proxy_arg_name)
                    if proxy_ir and proxy_ir.class_name == "data":
                        cap_call_args.append(f"{proxy_arg_snake}.len/*a*/")
                    elif proxy_ir and proxy_ir.type_name == "string":
                        cap_call_args.append(f"{proxy_arg_snake}/*a*/")
                    elif proxy_ir and (proxy_ir.interface_name or (proxy_ir.class_name and proxy_ir.class_name not in ("data", "buffer", "error", "self"))):
                        cap_call_args.append(f"{proxy_arg_snake}/*a*/")
                    elif proxy_ir and proxy_ir.type_name in ("size", "integer", "unsigned"):
                        cap_call_args.append(f"j{_camel(proxy_arg_name)}")
                    else:
                        cap_call_args.append(f"{proxy_arg_snake}.len/*a*/")
                elif const_key in length:
                    cap_call_args.append(length[const_key])
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
            const_val = length["constant"]
            const_class = length.get("class", "")
            # Resolve constants to C constant names.
            # "self" means entity-scoped; empty means interface constant
            # resolved against the current entity (implementation).
            if const_class == "self" or not const_class:
                c_const = f"{prefix}_{entity_snake}_{_upper_snake(const_val)}"
            else:
                c_const = f"{prefix}_{_snake(const_class)}_{_upper_snake(const_val)}"
            lines.append(
                f"vsc_buffer_t *{buf_snake} = "
                f"vsc_buffer_new_with_capacity({c_const});"
            )
        elif length.get("argument"):
            # Buffer capacity comes from a named method argument.
            # For data-typed args use the vsc_data_t .len; for size args use the JNI var.
            cap_arg_name = length["argument"]
            cap_arg_ir = arg_by_name.get(cap_arg_name)
            if cap_arg_ir and cap_arg_ir.class_name == "data":
                cap_expr = f"{_snake(cap_arg_name)}.len"
            else:
                cap_expr = f"j{_camel(cap_arg_name)}"
            lines.append(
                f"vsc_buffer_t *{buf_snake} = "
                f"vsc_buffer_new_with_capacity({cap_expr});"
            )
        else:
            lines.append(
                f"vsc_buffer_t *{buf_snake} = "
                f"vsc_buffer_new_with_capacity(/* TODO: determine capacity */);"
            )
        lines.append("")

    # Build C function call
    c_args: list[str] = []
    if not is_static:
        c_args.append(f"{entity_snake}_ctx /*a1*/")
    for arg in method.arguments:
        if arg.type_name == "self":
            continue
        arg_snake = _snake(arg.name)
        if arg.class_name == "error":
            c_args.append("&error /*a4*/")
        elif arg.class_name == "data":
            c_args.append(f"{arg_snake} /*a3*/")
        elif arg.class_name == "buffer":
            c_args.append(f"{arg_snake} /*a3*/")
        elif arg.enum_name:
            c_args.append(f"{arg_snake} /*a7*/")
        elif arg.interface_name:
            c_args.append(f"{arg_snake} /*a6*/")
        elif arg.class_name and arg.class_name not in ("data", "buffer", "error", "self"):
            c_args.append(f"{arg_snake} /*a5*/")
        elif (arg.type_name or "").lower() == "byte" and arg.access == "readwrite":
            c_args.append(f"{arg_snake} /*a3*/")
        elif arg.type_name == "string":
            c_args.append(f"{arg_snake} /*a8*/")
        elif arg.access != "writeonly":
            c_args.append(f"j{_camel(arg.name)} /*a9*/")

    c_args_str = ", ".join(c_args)

    value_returns = [r for r in method.returns if r.enum_name != "status"]
    has_status_return = any(r.enum_name == "status" for r in method.returns)

    def _error_return_stmt() -> str:
        """Return the right error-return statement for this method."""
        jni_ret = _jni_return_type(method)
        if jni_ret == "void":
            return "    return;"
        elif jni_ret in ("jint", "jlong", "jbyte", "jshort"):
            return "    return 0;"
        elif jni_ret == "jboolean":
            return "    return JNI_FALSE;"
        else:
            return "    return NULL;"

    if has_status_return:
        lines.append(f"{prefix}_status_t status = {c_func}({c_args_str});")
        lines.append(f"if (status != {prefix}_status_SUCCESS) {{")
        lines.append(f"    throw{_project_pascal(pname)}Exception(jenv, jobj, status);")
        lines.append(_error_return_stmt())
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
            ret_impl_prefix = _resolve_project_prefix(project_ir, ret.project) if ret.project else prefix
            lines.append(
                f"const {ret_impl_prefix}_impl_t */*6*/ proxyResult = {c_func}({c_args_str});"
            )
        elif ret.class_name:
            # Resolve "self" to the entity's own type
            resolved_class = entity_name if ret.class_name == "self" else ret.class_name
            # data/buffer are from common project, not local prefix
            if resolved_class == "buffer":
                class_c = "vsc_buffer_t"
            elif resolved_class == "data":
                class_c = "vsc_data_t"
            else:
                ret_prefix = _resolve_project_prefix(project_ir, ret.project) if ret.project else prefix
                class_c = f"{ret_prefix}_{_snake(resolved_class)}_t"
            lines.append(
                f"const {class_c} */*5*/ proxyResult = {c_func}({c_args_str});"
            )
        elif ret.type_name in ("size", "integer", "unsigned"):
            lines.append(f"jint ret = (jint) {c_func}({c_args_str});")
        elif ret.type_name == "boolean":
            lines.append(f"jboolean ret = (jboolean) {c_func}({c_args_str});")
        elif (ret.type_name or "").lower() == "byte" and ret.is_reference:
            lines.append(f"jlong ret = (jlong) {c_func}({c_args_str});")
        else:
            lines.append(f"{c_func}({c_args_str});")
    elif not buf_outs:
        lines.append(f"{c_func}({c_args_str});")
    else:
        if has_status_return:
            pass  # already handled
        else:
            lines.append(f"{c_func}({c_args_str});")

    # Check error struct (for methods with error arg, no status return)
    if has_error_arg and not has_status_return:
        lines.append("")
        lines.append(f"if (error.status != {prefix}_status_SUCCESS) {{")
        lines.append(f"    throw{_project_pascal(pname)}Exception(jenv, jobj, error.status);")
        lines.append(_error_return_stmt())
        lines.append("}")

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
        lines.append("if (NULL == result_cls) {")
        lines.append(f'    {prefix_upper}_ASSERT("Class {result_class} not found.");')
        lines.append("}")
        lines.append(
            'jmethodID result_methodID = (*jenv)->GetMethodID(jenv, result_cls, "<init>", "()V");'
        )
        lines.append(
            "jobject newObj = (*jenv)->NewObject(jenv, result_cls, result_methodID);"
        )
        for buf in buf_outs:
            buf_snake = _snake(buf.name)
            buf_camel = _camel(buf.name)
            lines.append(
                f'jfieldID fid{_pascal(buf.name)} = '
                f'(*jenv)->GetFieldID(jenv, result_cls, "{buf_camel}", "[B");'
            )
            lines.append(
                f"jbyteArray j{_pascal(buf.name)}Arr = "
                f"(*jenv)->NewByteArray(jenv, vsc_buffer_len({buf_snake}));"
            )
            lines.append(
                f"(*jenv)->SetByteArrayRegion (jenv, j{_pascal(buf.name)}Arr, 0, "
                f"vsc_buffer_len({buf_snake}), (jbyte*) vsc_buffer_bytes({buf_snake}));"
            )
            lines.append(
                f"(*jenv)->SetObjectField(jenv, newObj, fid{_pascal(buf.name)}, j{_pascal(buf.name)}Arr);"
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
            lines.append(f'    {prefix_upper}_ASSERT("Enum {enum_pascal} not found.");')
            lines.append("}")
            lines.append("")
            lines.append(
                f'jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, '
                f'"fromCode", "(I)L{pkg_path}/{enum_pascal};");'
            )
            lines.append("if (NULL == methodID) {")
            lines.append(
                f"""    {prefix_upper}_ASSERT("Enum {enum_pascal} has no method 'fromCode'.");"""
            )
            lines.append("}")
            lines.append(
                "jobject ret = (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, proxyResult);"
            )
        elif ret.class_name:
            resolved_class = entity_name if ret.class_name == "self" else ret.class_name
            class_pascal = _pascal(resolved_class)
            lines.append(
                f'jclass result_cls = (*jenv)->FindClass(jenv, '
                f'"{pkg_path}/{class_pascal}");'
            )
            lines.append("if (NULL == result_cls) {")
            lines.append(f'    {prefix_upper}_ASSERT("Class {class_pascal} not found.");')
            lines.append("}")
            lines.append(
                f'jmethodID result_methodID = (*jenv)->GetStaticMethodID(jenv, result_cls, '
                f'"getInstance", "(J)L{pkg_path}/{class_pascal};");'
            )
            lines.append("if (NULL == result_methodID) {")
            lines.append(
                f"""    {prefix_upper}_ASSERT("Class {class_pascal} has no 'getInstance' method.");"""
            )
            lines.append("}")
            # shallow_copy for readonly access
            if ret.access in ("readonly", None):
                class_c = f"{prefix}_{_snake(resolved_class)}_t"
                lines.append(
                    f"{prefix}_{_snake(resolved_class)}_shallow_copy("
                    f"({class_c} */*5*/) proxyResult);"
                )
            lines.append(
                f"jobject ret = (*jenv)->CallStaticObjectMethod(jenv, result_cls, "
                f"result_methodID, (jlong) proxyResult);"
            )
        elif ret.interface_name:
            iface_pascal = _pascal(ret.interface_name)
            ret_impl_prefix = _resolve_project_prefix(project_ir, ret.project) if ret.project else prefix
            lines.append(
                f"{ret_impl_prefix}_impl_shallow_copy(({ret_impl_prefix}_impl_t */*6*/) proxyResult);"
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
    if buf_outs and len(buf_outs) >= 2:
        lines.append("return newObj;")
    elif buf_outs or value_returns:
        lines.append("return ret;")
    elif not (value_returns or buf_outs):
        pass  # void method

    return lines


def _generate_jni_c_entity_lifecycle(
    project_ir: IRProject,
    entity_name: str,
) -> list[str]:
    """Generate new/close JNI C functions for a non-static entity."""
    prefix = _c_prefix(project_ir)
    entity_snake = _snake(entity_name)
    c_type = f"{prefix}_{entity_snake}_t"
    func_name_base = _jni_func_name(project_ir, entity_name, "new")
    # The legacy uses __  suffix for new (overloaded)
    # We build the function name manually for new/close
    pkg_path = _jni_package_path(project_ir.name).replace("/", "_")
    jni_class = _jni_class(project_ir.name)
    entity_escaped = _entity_camel(entity_name).replace("_", "_1")

    lines: list[str] = []
    # new
    new_func = f"Java_{pkg_path}_{jni_class}_{entity_escaped}_1new__"
    lines.append(
        f"JNIEXPORT jlong JNICALL {new_func} (JNIEnv *jenv, jobject jobj) {{"
    )
    lines.append("    jlong c_ctx = 0;")
    lines.append(f"    *({c_type} **)&c_ctx = {prefix}_{entity_snake}_new();")
    lines.append("    return c_ctx;")
    lines.append("}")
    lines.append("")

    # close
    close_func = f"Java_{pkg_path}_{jni_class}_{entity_escaped}_1close"
    lines.append(
        f"JNIEXPORT void JNICALL {close_func} (JNIEnv *jenv, jobject jobj, jlong c_ctx) {{"
    )
    lines.append(
        f"    {prefix}_{entity_snake}_delete(*({c_type} /*9*/ **) &c_ctx /*5*/);"
    )
    lines.append("}")
    lines.append("")
    return lines


def _generate_jni_c_dep_setter(
    project_ir: IRProject,
    entity_name: str,
    dep: IRDependency,
) -> list[str]:
    """Generate a JNI C dependency setter function."""
    prefix = _c_prefix(project_ir)
    prefix_upper = project_ir.prefix.upper()
    entity_snake = _snake(entity_name)
    c_type = f"{prefix}_{entity_snake}_t"
    dep_snake = _snake(dep.name)
    dep_pascal = _pascal(dep.name)
    dep_setter_java = "set" + dep_pascal

    pkg_path = _jni_package_path(project_ir.name).replace("/", "_")
    jni_class = _jni_class(project_ir.name)
    entity_escaped = _entity_camel(entity_name).replace("_", "_1")
    setter_escaped = dep_setter_java.replace("_", "_1")
    func_name = f"Java_{pkg_path}_{jni_class}_{entity_escaped}_1{setter_escaped}"

    lines: list[str] = []
    lines.append(
        f"JNIEXPORT void JNICALL {func_name} "
        f"(JNIEnv *jenv, jobject jobj, jlong c_ctx, jobject j{_camel(dep.name)}) {{"
    )
    dep_camel = _camel(dep.name)
    lines.append(f"    jclass {dep_camel}_cls = (*jenv)->GetObjectClass(jenv, j{dep_camel});")
    lines.append(f"    if (NULL == {dep_camel}_cls) {{")
    lines.append(f'        {prefix_upper}_ASSERT("Class {dep_pascal} not found.");')
    lines.append(f"    }}")
    lines.append(f'    jfieldID {dep_camel}_fidCtx = (*jenv)->GetFieldID(jenv, {dep_camel}_cls, "cCtx", "J");')
    lines.append(f"    if (NULL == {dep_camel}_fidCtx) {{")
    lines.append(f"        {prefix_upper}_ASSERT(\"Class '{dep_pascal}' has no field 'cCtx'.\");")
    lines.append(f"    }}")
    lines.append(f"    jlong {dep_camel}_c_ctx = (*jenv)->GetLongField(jenv, j{dep_camel}, {dep_camel}_fidCtx);")
    # Use the correct C type based on type_kind
    if dep.type_kind == "class":
        dep_c_type = f"{prefix}_{dep_snake}_t"
        lines.append(f"    {dep_c_type} */*5*/ {dep_snake} = *({dep_c_type} */*5*/*)&{dep_camel}_c_ctx;")
    else:
        lines.append(f"    vscf_impl_t */*6*/ {dep_snake} = *(vscf_impl_t */*6*/*)&{dep_camel}_c_ctx;")
    lines.append("")
    lines.append(f"    {prefix}_{entity_snake}_release_{dep_snake}(({c_type} /*2*/ *) c_ctx);")
    lines.append(f"    {prefix}_{entity_snake}_use_{dep_snake}(({c_type} /*2*/ *) c_ctx, {dep_snake});")
    lines.append("}")
    lines.append("")
    return lines


def _collect_interface_implementors(
    project_ir: IRProject,
) -> dict[str, list[str]]:
    """Build map: interface_name -> list of implementation names that bind it."""
    result: dict[str, list[str]] = {}
    for impl in project_ir.implementations:
        if impl.attrs.get("scope") in ("private", "internal"):
            continue
        for binding in impl.interface_bindings:
            result.setdefault(binding.name, []).append(impl.name)
    return result


def _generate_interface_wrap_helpers(project_ir: IRProject) -> list[str]:
    """Generate getXxxClassName / wrapXxx C helper functions for each interface."""
    prefix = _c_prefix(project_ir)
    prefix_upper = project_ir.prefix.upper()
    pkg_path = _jni_package_path(project_ir.name)
    iface_impls = _collect_interface_implementors(project_ir)
    # Find the impl/tag enum for tag constant names
    tag_enum = None
    for e in project_ir.enums:
        if e.name == "impl/tag":
            tag_enum = e
            break
    tag_names = {c.name for c in tag_enum.constants} if tag_enum else set()

    lines: list[str] = []
    for iface in project_ir.interfaces:
        if iface.attrs.get("scope") == "private":
            continue
        iface_pascal = _pascal(iface.name)
        iface_snake = _snake(iface.name)
        implementors = iface_impls.get(iface.name, [])
        if not implementors:
            continue

        # getXxxClassName
        lines.append(
            f"char* get{iface_pascal}ClassName "
            f"(JNIEnv *jenv, jobject jobj, const {prefix}_impl_t /*1*/* c_obj) {{"
        )
        lines.append(f"    if (!{prefix}_{iface_snake}_is_implemented(c_obj)) {{")
        lines.append(
            f'        {prefix_upper}_ASSERT("Given C implementation does not implement interface {iface_pascal}.");'
        )
        lines.append(f"    }}")
        lines.append(f"    char *classFullName = malloc(200);")
        lines.append(f'    strcpy (classFullName, "{pkg_path}/");')
        lines.append(f"    {prefix}_impl_tag_t implTag = {prefix}_impl_tag(c_obj);")
        lines.append(f"    switch(implTag) {{")
        for impl_name in implementors:
            impl_tag = impl_name.upper().replace(" ", "_")
            lines.append(f"    case {prefix}_impl_tag_{impl_tag}:")
            lines.append(f'        strcat (classFullName, "{_pascal(impl_name)}");')
            lines.append(f"        break;")
        lines.append(f"    default:")
        lines.append(f"        free(classFullName);")
        lines.append(
            f'        {prefix_upper}_ASSERT("Unexpected C implementation cast to the Java implementation.");'
        )
        lines.append(f"    }}")
        lines.append(f"    return classFullName;")
        lines.append(f"}}")
        lines.append("")

        # wrapXxx
        lines.append(
            f"jobject wrap{iface_pascal} "
            f"(JNIEnv *jenv, jobject jobj, const {prefix}_impl_t /*1*/* c_obj) {{"
        )
        lines.append(f"    char *classFullName = get{iface_pascal}ClassName(jenv, jobj, c_obj);")
        lines.append(f"    jclass cls = (*jenv)->FindClass(jenv, classFullName);")
        lines.append(f"    if (NULL == cls) {{")
        lines.append(f"        free(classFullName);")
        lines.append(f'        {prefix_upper}_ASSERT("Class not found.");')
        lines.append(f"    }}")
        lines.append(f"")
        lines.append(f'    char *methodSig = malloc(200);')
        lines.append(f'    strcpy (methodSig, "(J)L");')
        lines.append(f'    strcat (methodSig, classFullName);')
        lines.append(f'    strcat (methodSig, ";");')
        lines.append(f'    jmethodID methodID = (*jenv)->GetStaticMethodID(jenv, cls, "getInstance", methodSig);')
        lines.append(f"    free(classFullName);")
        lines.append(f"    free (methodSig);")
        lines.append(f"    if (NULL == methodID) {{")
        lines.append(f"        {prefix_upper}_ASSERT(\"Class has no 'getInstance' method.\");")
        lines.append(f"    }}")
        lines.append(f"")
        lines.append(f"    jlong c_ctx = 0;")
        lines.append(f"    *(const {prefix}_impl_t /*1*/**) &c_ctx = c_obj;")
        lines.append(f"    return (*jenv)->CallStaticObjectMethod(jenv, cls, methodID, c_ctx);")
        lines.append(f"}}")
        lines.append("")

    return lines


def _generate_jni_c_wrapped_method(
    project_ir: IRProject,
    method: IRCMethod,
    entity_name: str,
    is_static: bool,
) -> list[str]:
    """Generate a complete JNIEXPORT function wrapping a method body."""
    jni_ret = _jni_return_type(method)
    func_name = _jni_func_name(project_ir, entity_name, method.name)

    # Build JNI parameter list
    params: list[str] = ["JNIEnv *jenv", "jobject jobj"]
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

    params_str = ", ".join(params)

    lines: list[str] = []
    lines.append(
        f"JNIEXPORT {jni_ret} JNICALL {func_name} ({params_str}) {{"
    )

    # Get method body lines
    body = _generate_jni_c_method(
        project_ir, method, entity_name, is_static=is_static,
    )
    for bline in body:
        lines.append(f"    {bline}")

    lines.append("}")
    lines.append("")
    return lines


def _generate_jni_c(project_ir: IRProject) -> str:
    """Generate the complete {Project}JNI.c file."""
    pname = project_ir.name
    prefix = _c_prefix(project_ir)
    prefix_upper = project_ir.prefix.upper()
    project_pascal = _project_pascal(pname)
    exception_class = _exception_class(pname)
    jni_class_name = _jni_class(pname)
    pkg_path = _jni_package_path(pname)

    lines: list[str] = []
    lines.append(_C_LICENSE)
    lines.append("")

    # Includes
    lines.append(f'#include "{jni_class_name}.h"')
    lines.append("")
    lines.append(f'#include "{prefix}_{pname}_public.h"')
    lines.append("")
    lines.append("#include <string.h>")
    lines.append("")

    # throwException helper function
    lines.append(
        f"jint throw{project_pascal}Exception "
        f"(JNIEnv *jenv, jobject jobj, jint statusCode) {{"
    )
    lines.append(
        f'    jclass cls = (*jenv)->FindClass(jenv, '
        f'"{pkg_path}/{exception_class}");'
    )
    lines.append("    if (NULL == cls) {")
    lines.append(f'        {prefix_upper}_ASSERT("Class PheException not found.");')
    lines.append("        return 0;")
    lines.append("    }")
    lines.append("")
    lines.append(
        '    jmethodID methodID = (*jenv)->GetMethodID(jenv, cls, "<init>", "(I)V");'
    )
    lines.append("    if (NULL == methodID) {")
    lines.append(
        f'        {prefix_upper}_ASSERT("Class {pkg_path.replace("/", ".")}.{exception_class} '
        f'has no constructor.");'
    )
    lines.append("        return 0;")
    lines.append("    }")
    lines.append(
        "    jthrowable obj = (*jenv)->NewObject(jenv, cls, methodID, statusCode);"
    )
    lines.append("    if (NULL == obj) {")
    lines.append(
        f'        {prefix_upper}_ASSERT("Can\'t instantiate {pkg_path.replace("/", ".")}.{exception_class}.");'
    )
    lines.append("        return 0;")
    lines.append("    }")
    lines.append("    return (*jenv)->Throw(jenv, obj);")
    lines.append("}")
    lines.append("")

    # Interface wrap helpers
    iface_helpers = _generate_interface_wrap_helpers(project_ir)
    lines.extend(iface_helpers)

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

            # Named constructors
            for ctor in cls.constructors:
                if not _method_should_wrap(ctor):
                    continue
                ctor_params = _java_param_list(ctor, pname, include_ctx=False)
                if not ctor_params:
                    continue
                ctor_lines = _generate_jni_c_named_constructor(project_ir, cls.name, ctor)
                lines.extend(ctor_lines)

        for m in cls.methods:
            if not _method_should_wrap(m, project_ir):
                continue
            method_lines = _generate_jni_c_wrapped_method(
                project_ir, m, cls.name,
                is_static=is_static or _is_static_method(m),
            )
            lines.extend(method_lines)

    # Implementations
    for impl in project_ir.implementations:
        if impl.attrs.get("scope") in ("private", "internal"):
            continue

        # Lifecycle
        lifecycle = _generate_jni_c_entity_lifecycle(project_ir, impl.name)
        lines.extend(lifecycle)

        # Named constructors
        for ctor in impl.constructors:
            if not _method_should_wrap(ctor):
                continue
            ctor_params = _java_param_list(ctor, pname, include_ctx=False)
            if not ctor_params:
                continue
            ctor_lines = _generate_jni_c_named_constructor(project_ir, impl.name, ctor)
            lines.extend(ctor_lines)

        # Dependency setters
        for dep in impl.dependencies:
            dep_lines = _generate_jni_c_dep_setter(project_ir, impl.name, dep)
            lines.extend(dep_lines)

        # Interface methods
        for binding in impl.interface_bindings:
            iface = iface_index.get(binding.name)
            if iface is None:
                continue
            for m in iface.methods:
                if not _method_should_wrap(m, project_ir):
                    continue
                method_lines = _generate_jni_c_wrapped_method(
                    project_ir, m, impl.name, is_static=_is_static_method(m),
                )
                lines.extend(method_lines)

        # Own methods (skip internal implementation methods)
        for m in impl.methods:
            if not _method_should_wrap(m, project_ir):
                continue
            if _is_internal_own_method(m):
                continue
            method_lines = _generate_jni_c_wrapped_method(
                project_ir, m, impl.name, is_static=_is_static_method(m),
            )
            lines.extend(method_lines)

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

    # Build parameter list -- always starts with JNIEnv *, jobject
    params: list[str] = ["JNIEnv *", "jobject"]
    if not is_static:
        params.append("jlong")
    for arg in method.arguments:
        if arg.class_name == "buffer" or arg.class_name == "error":
            continue
        if arg.type_name == "self":
            continue
        if arg.access == "writeonly":
            continue
        jtype = _jni_type_for_arg(arg)
        params.append(jtype)

    params_str = ", ".join(params)

    lines: list[str] = []
    lines.append(
        f"JNIEXPORT {jni_ret} JNICALL {func_name} ({params_str});"
    )
    lines.append("")
    return lines


def _generate_jni_h(project_ir: IRProject) -> str:
    """Generate the complete {Project}JNI.h file."""
    pname = project_ir.name
    jni_class = _jni_class(pname)
    pkg_path = _jni_package_path(pname).replace("/", "_")
    guard = f"_Included_{jni_class}_h"
    iface_index = {i.name: i for i in project_ir.interfaces}

    lines: list[str] = []
    lines.append(_C_LICENSE)
    lines.append("")
    lines.append("#include <jni.h>")
    lines.append("")
    lines.append(f"#ifndef {guard}")
    lines.append(f"#define {guard}")
    lines.append("#ifdef __cplusplus")
    lines.append('extern "C" {')
    lines.append("#endif")

    # Static classes
    for cls in project_ir.classes:
        if cls.attrs.get("scope") in ("private", "internal"):
            continue
        if cls.name == "error":
            continue
        is_static = _is_static_class(cls)

        if not is_static:
            entity_escaped = _entity_camel(cls.name).replace("_", "_1")
            # new declaration
            lines.append(
                f"JNIEXPORT jlong JNICALL "
                f"Java_{pkg_path}_{jni_class}_{entity_escaped}_1new__ "
                f"(JNIEnv *, jobject);"
            )
            lines.append("")
            # Named constructor overload declarations
            for ctor in cls.constructors:
                if not _method_should_wrap(ctor):
                    continue
                ctor_params = _java_param_list(ctor, pname, include_ctx=False)
                if not ctor_params:
                    continue
                overload_suffix = _jni_ctor_overload_suffix(ctor, pname)
                h_params = ["JNIEnv *", "jobject"] + [_jni_type_for_arg(a) for a in ctor.arguments if a.class_name not in ("buffer", "error") and a.type_name != "self"]
                lines.append(
                    f"JNIEXPORT jlong JNICALL "
                    f"Java_{pkg_path}_{jni_class}_{entity_escaped}_1new{overload_suffix} "
                    f"({', '.join(h_params)});"
                )
                lines.append("")
            # close declaration
            lines.append(
                f"JNIEXPORT void JNICALL "
                f"Java_{pkg_path}_{jni_class}_{entity_escaped}_1close "
                f"(JNIEnv *, jobject, jlong);"
            )
            lines.append("")

        for m in cls.methods:
            if not _method_should_wrap(m, project_ir):
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

        entity_escaped = _entity_camel(impl.name).replace("_", "_1")
        # new
        lines.append(
            f"JNIEXPORT jlong JNICALL "
            f"Java_{pkg_path}_{jni_class}_{entity_escaped}_1new__ "
            f"(JNIEnv *, jobject);"
        )
        lines.append("")
        # Named constructor overload declarations
        for ctor in impl.constructors:
            if not _method_should_wrap(ctor):
                continue
            ctor_params = _java_param_list(ctor, pname, include_ctx=False)
            if not ctor_params:
                continue
            overload_suffix = _jni_ctor_overload_suffix(ctor, pname)
            h_params = ["JNIEnv *", "jobject"] + [_jni_type_for_arg(a) for a in ctor.arguments if a.class_name not in ("buffer", "error") and a.type_name != "self"]
            lines.append(
                f"JNIEXPORT jlong JNICALL "
                f"Java_{pkg_path}_{jni_class}_{entity_escaped}_1new{overload_suffix} "
                f"({', '.join(h_params)});"
            )
            lines.append("")
        # close
        lines.append(
            f"JNIEXPORT void JNICALL "
            f"Java_{pkg_path}_{jni_class}_{entity_escaped}_1close "
            f"(JNIEnv *, jobject, jlong);"
        )
        lines.append("")

        # Dependency setter declarations
        for dep in impl.dependencies:
            dep_setter = "set" + _pascal(dep.name)
            dep_setter_escaped = dep_setter.replace("_", "_1")
            lines.append(
                f"JNIEXPORT void JNICALL "
                f"Java_{pkg_path}_{jni_class}_{entity_escaped}_1{dep_setter_escaped} "
                f"(JNIEnv *, jobject, jlong, jobject);"
            )
            lines.append("")

        # Interface methods
        for binding in impl.interface_bindings:
            iface = iface_index.get(binding.name)
            if iface is None:
                continue
            for m in iface.methods:
                if not _method_should_wrap(m, project_ir):
                    continue
                decl = _generate_jni_h_method_decl(
                    project_ir, m, impl.name,
                    is_static=_is_static_method(m),
                )
                lines.extend(decl)

        # Own methods (skip internal implementation methods)
        for m in impl.methods:
            if not _method_should_wrap(m, project_ir):
                continue
            if _is_internal_own_method(m):
                continue
            decl = _generate_jni_h_method_decl(
                project_ir, m, impl.name,
                is_static=_is_static_method(m),
            )
            lines.extend(decl)

    lines.append("")
    lines.append("#ifdef __cplusplus")
    lines.append("}")
    lines.append("#endif")
    lines.append(f"#endif")
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
            if not _method_should_wrap(m, project_ir):
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
            if not _method_should_wrap(m, project_ir):
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

        # Result classes for implementation interface bindings
        # Use impl.name (not iface.name) to match class file and JNI naming
        for binding in impl.interface_bindings:
            iface = iface_index.get(binding.name)
            if iface is None:
                continue
            for m in iface.methods:
                if not _method_should_wrap(m, project_ir):
                    continue
                if _method_needs_result_class(m):
                    result_name = f"{_pascal(impl.name)}{_pascal(m.name)}Result"
                    files.append((
                        f"{java_base}{result_name}.java",
                        _generate_result_class(project_ir, impl.name, m),
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
