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
# PHP license header
# ---------------------------------------------------------------------------

def _format_license_php_block(raw: str) -> str:
    """Format raw license text as /** ... */ block (PHP style)."""
    lines = ["/**"]
    for line in raw.splitlines():
        lines.append(f"* {line}".rstrip() if line.strip() else "*")
    lines.append("*/")
    return "\n".join(lines)


def _format_license_slash_bordered(raw: str) -> str:
    """Format raw license text as // comments with border lines (C extension style)."""
    lines = ["//"]
    for line in raw.splitlines():
        lines.append(f"// {line}".rstrip() if line.strip() else "//")
    lines.append("//")
    return "\n".join(lines)


_PHP_LICENSE = ""    # populated by generate_php_files()
_C_LICENSE = ""      # populated by generate_php_files()

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
    defn = method.definition or method.attrs.get("definition")
    # Methods with explicit private/internal definition are not wrapped.
    if defn in ("private", "internal"):
        return False
    return scope == "public" and decl == "public" and vis == "public"


def _impl_own_method_should_wrap(method: IRCMethod) -> bool:
    """Check if an implementation's own method (not from interface) should be wrapped.

    Implementation-specific methods that lack explicit definition/declaration
    are considered internal helpers and should not be wrapped.
    """
    # If method has no definition and no declaration explicitly set,
    # and has no scope explicitly set, treat as internal.
    has_explicit_decl = method.declaration is not None or "declaration" in method.attrs
    has_explicit_def = method.definition is not None or "definition" in method.attrs
    has_explicit_scope = "scope" in method.attrs
    # Must have at least one explicit public marker to be wrapped
    if not has_explicit_decl and not has_explicit_def and not has_explicit_scope:
        return False
    return _method_should_wrap(method)


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
# C extension generator
# ---------------------------------------------------------------------------

def _flatten_description(description: str) -> str:
    """Collapse a multi-line description into a single space-joined line."""
    lines = [line.strip() for line in description.strip().splitlines()]
    return " ".join(line for line in lines if line)


def _is_impl_type(project_ir: IRProject, entity_name: str) -> bool:
    """True if entity_name corresponds to an implementation (uses impl_t resource)."""
    for impl in project_ir.implementations:
        if impl.name == entity_name:
            return True
    return False


def _entity_res_name_func(prefix: str, entity_name: str, project_ir: IRProject) -> str:
    """Return the C function name that retrieves the resource name string."""
    if _is_impl_type(project_ir, entity_name):
        return f"{prefix}_impl_t_php_res_name()"
    entity_snake = _snake_case(entity_name)
    return f"{prefix}_{entity_snake}_t_php_res_name()"


def _entity_le_func(prefix: str, entity_name: str, project_ir: IRProject) -> str:
    """Return the C function name that retrieves the resource list entry id."""
    if _is_impl_type(project_ir, entity_name):
        return f"le_{prefix}_impl_t()"
    entity_snake = _snake_case(entity_name)
    return f"le_{prefix}_{entity_snake}_t()"


def _entity_c_type(prefix: str, entity_name: str, project_ir: IRProject) -> str:
    """Return the C type for an entity's context pointer."""
    if _is_impl_type(project_ir, entity_name):
        return f"{prefix}_impl_t"
    entity_snake = _snake_case(entity_name)
    return f"{prefix}_{entity_snake}_t"


def _zend_arg_type_for_c_arg(arg: IRCArgument) -> str:
    """Map an IR argument to its ZEND_ARG_TYPE_INFO type constant."""
    if arg.class_name == "data":
        return "IS_STRING"
    if arg.class_name in ("buffer",):
        return "IS_STRING"  # buffer outputs become string returns
    if arg.interface_name or arg.class_name:
        return "IS_RESOURCE"
    if arg.enum_name:
        return "IS_LONG"
    type_name = (arg.type_name or "").lower()
    if type_name in ("size", "integer", "unsigned"):
        return "IS_LONG"
    if type_name == "boolean":
        return "_IS_BOOL"
    if type_name in ("string", "byte"):
        return "IS_STRING"
    return "IS_STRING"


def _zend_return_type_for_method(
    project_ir: IRProject,
    method: IRCMethod,
    entity_name: str,
) -> str:
    """Determine the ZEND return type constant for a method."""
    resolved_returns = [_resolve_self_arg(entity_name, r) for r in method.returns]
    value_returns = [r for r in resolved_returns if r.enum_name != "status"]
    buffer_outputs = [a for a in method.arguments if _arg_is_buffer_output(a)]

    if buffer_outputs:
        return "IS_STRING"

    if not value_returns:
        return "IS_VOID"

    ret = value_returns[0]
    if ret.enum_name:
        return "IS_LONG"
    if ret.interface_name:
        return "IS_RESOURCE"
    if ret.class_name and ret.class_name not in ("data", "buffer", "error"):
        return "IS_RESOURCE"
    if ret.class_name == "data":
        return "IS_STRING"
    type_name = (ret.type_name or "").lower()
    if type_name in ("size", "integer", "unsigned"):
        return "IS_LONG"
    if type_name == "boolean":
        return "_IS_BOOL"
    if type_name in ("string", "byte"):
        return "IS_STRING"
    return "IS_VOID"


def _c_func_name(prefix: str, entity_name: str, method_name: str) -> str:
    """C library function name: {prefix}_{entity_snake}_{method_snake}."""
    return f"{prefix}_{_snake_case(entity_name)}_{_snake_case(method_name)}"


def _buffer_capacity_expr(
    project_ir: IRProject,
    entity_name: str,
    method: IRCMethod,
    buf_arg: IRCArgument,
    entity=None,
    *,
    instance_var: str = "",
) -> str:
    """Build a C expression for the capacity of a buffer output argument.

    Uses the length_attrs metadata from the IR to build the correct
    capacity computation expression (method call, constant, or argument).

    ``instance_var`` is the C variable name for the entity instance
    (e.g., ``"sha256"``). When set, it's prepended as the first argument
    to instance method length calls.
    """
    prefix = project_ir.prefix
    entity_snake = _snake_case(entity_name)
    la = buf_arg.length_attrs
    if not la:
        return "0"

    if "method" in la:
        method_name = la["method"]
        len_func = f"{prefix}_{entity_snake}_{_snake_case(method_name)}"
        # Build proxy arguments
        proxy_args: list[str] = []
        # If this is an instance method, self goes first
        if instance_var:
            proxy_args.append(instance_var)
        idx = 0
        while f"proxy_{idx}_to" in la:
            cast = la.get(f"proxy_{idx}_cast")
            src_arg = la.get(f"proxy_{idx}_argument")
            src_const = la.get(f"proxy_{idx}_constant")
            if src_const is not None:
                proxy_args.append(src_const)
            elif src_arg is not None:
                if cast == "data_length":
                    # data.len — the proxy passes the length of a data argument
                    proxy_args.append(f"{_snake_case(src_arg)}.len")
                else:
                    proxy_args.append(_snake_case(src_arg))
            idx += 1
        return f"{len_func}({', '.join(proxy_args)})"

    if "constant" in la:
        const_name = la["constant"]
        owner_class = la.get("class")
        if owner_class and owner_class != "self":
            return f"{prefix}_{_snake_case(owner_class)}_{_snake_case(const_name).upper()}"
        return f"{prefix}_{entity_snake}_{_snake_case(const_name).upper()}"

    if "argument" in la:
        arg_name = _snake_case(la["argument"])
        cast = la.get("cast")
        if cast == "data_length":
            return f"{arg_name}.len"
        return arg_name

    return "0"


def _collect_methods_for_entity(
    project_ir: IRProject,
    entity_name: str,
    entity,
    is_implementation: bool = False,
) -> list[tuple[IRCMethod, bool]]:
    """Collect (method, is_static) pairs for an entity, including interface methods.

    For implementations, includes methods from bound interfaces.
    Returns deduplicated list preserving order.
    """
    result: list[tuple[IRCMethod, bool]] = []
    seen: set[str] = set()

    if is_implementation:
        iface_by_name = {i.name: i for i in project_ir.interfaces}
        for binding in entity.interface_bindings:
            iface = iface_by_name.get(binding.name)
            if iface is None:
                continue
            for method in iface.methods:
                if not _method_should_wrap(method):
                    continue
                if method.name in seen:
                    continue
                seen.add(method.name)
                is_static = method.attrs.get("is_static") in {"1", "true"}
                result.append((method, is_static))

    for method in entity.methods:
        checker = _impl_own_method_should_wrap if is_implementation else _method_should_wrap
        if not checker(method):
            continue
        if method.name in seen:
            continue
        seen.add(method.name)
        is_static = method.attrs.get("is_static") in {"1", "true"}
        result.append((method, is_static))

    return result


def _emit_arginfo(
    lines: list[str],
    php_func_name: str,
    method: IRCMethod,
    entity_name: str,
    project_ir: IRProject,
    *,
    is_static: bool = False,
    is_instance: bool = False,
) -> None:
    """Emit ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX block for a method."""
    resolved_args = [_resolve_self_arg(entity_name, a) for a in method.arguments]
    # Count required args: ctx + non-skipped, non-buffer args
    req_count = 0
    if is_instance and not is_static:
        req_count += 1  # ctx
    for arg in resolved_args:
        if _arg_should_skip(arg):
            continue
        if _arg_is_buffer_output(arg):
            continue
        req_count += 1

    ret_type = _zend_return_type_for_method(project_ir, method, entity_name)

    lines.append("ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(")
    lines.append(f"    arginfo_{php_func_name},")
    lines.append(f"    0 /*return_reference*/,")
    lines.append(f"    {req_count} /*required_num_args*/,")
    lines.append(f"    {ret_type} /*type*/,")
    lines.append(f"    0 /*allow_null*/)")
    lines.append("")

    # Self/ctx argument
    if is_instance and not is_static:
        lines.append("    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)")

    # Regular arguments
    for arg in resolved_args:
        if _arg_should_skip(arg):
            continue
        if _arg_is_buffer_output(arg):
            continue
        arg_type = _zend_arg_type_for_c_arg(arg)
        in_name = f"in_{_snake_case(arg.name)}"
        lines.append(f"    ZEND_ARG_TYPE_INFO(0, {in_name}, {arg_type}, 0)")

    lines.append("ZEND_END_ARG_INFO()")
    lines.append("")


def _ret_local_name(ret: IRCArgument, entity_snake: str = "") -> str:
    """Derive a safe C local variable name for a return argument.

    Uses the interface/class name when available (matching legacy),
    falls back to ret.name but avoids C keywords like "return".
    ``entity_snake`` is the entity's snake_case name to avoid conflicts.
    """
    candidate = ""
    if ret.interface_name:
        candidate = _snake_case(ret.interface_name)
    elif ret.class_name and ret.class_name not in ("data", "buffer", "error"):
        candidate = _snake_case(ret.class_name)
    elif ret.class_name == "data":
        candidate = "res"
    else:
        raw = _snake_case(ret.name)
        if raw in ("return", "class", "int", "void", "char", "if", "else", "switch",
                    "case", "break", "default", "for", "while", "do", "struct"):
            candidate = "res"
        else:
            candidate = raw

    # Avoid collision with the entity ctx variable
    if entity_snake and candidate == entity_snake:
        candidate = f"proxy_{candidate}"
    return candidate


def _emit_php_function(
    lines: list[str],
    php_func_name: str,
    c_func_name: str,
    method: IRCMethod,
    entity_name: str,
    project_ir: IRProject,
    *,
    is_static: bool = False,
    is_instance: bool = False,
    entity=None,
) -> None:
    """Emit a PHP_FUNCTION implementation for a method."""
    prefix = project_ir.prefix
    prefix_upper = prefix.upper()
    resolved_args = [_resolve_self_arg(entity_name, a) for a in method.arguments]
    resolved_returns = [_resolve_self_arg(entity_name, r) for r in method.returns]
    value_returns = [r for r in resolved_returns if r.enum_name != "status"]
    has_status = _method_has_status_return(method)
    has_error_arg = _method_has_error_arg(method)
    buffer_outputs = [a for a in resolved_args if _arg_is_buffer_output(a)]

    lines.append(f"PHP_FUNCTION({php_func_name}) {{")
    lines.append("")

    # Declare input variables
    lines.append("    //")
    lines.append("    // Declare input argument")
    lines.append("    //")

    if is_instance and not is_static:
        lines.append("    zval *in_ctx = NULL;")

    for arg in resolved_args:
        if _arg_should_skip(arg):
            continue
        if _arg_is_buffer_output(arg):
            continue
        in_name = f"in_{_snake_case(arg.name)}"
        if arg.interface_name or (arg.class_name and arg.class_name not in ("data", "buffer", "error")):
            lines.append(f"    zval *{in_name} = NULL;")
        elif arg.class_name == "data":
            lines.append(f"    char *{in_name} = NULL;")
            lines.append(f"    size_t {in_name}_blen = 0;")
        elif arg.enum_name:
            lines.append(f"    zend_long {in_name} = 0;")
        else:
            type_name = (arg.type_name or "").lower()
            if type_name in ("size", "integer", "unsigned"):
                lines.append(f"    zend_long {in_name} = 0;")
            elif type_name == "boolean":
                lines.append(f"    zend_bool {in_name} = 0;")
            elif type_name == "byte" and not arg.is_string:
                # Raw byte pointer — passed as integer
                lines.append(f"    zend_long {in_name} = 0;")
            elif type_name == "string" or arg.is_string:
                lines.append(f"    char *{in_name} = NULL;")
                lines.append(f"    size_t {in_name}_blen = 0;")
            else:
                lines.append(f"    zend_long {in_name} = 0;")

    lines.append("")

    # Parse parameters
    req_count = 0
    if is_instance and not is_static:
        req_count += 1
    for arg in resolved_args:
        if _arg_should_skip(arg):
            continue
        if _arg_is_buffer_output(arg):
            continue
        req_count += 1

    lines.append("    //")
    lines.append("    // Parse arguments")
    lines.append("    //")
    lines.append(f"    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, {req_count}, {req_count})")

    if is_instance and not is_static:
        lines.append("        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)")

    for arg in resolved_args:
        if _arg_should_skip(arg):
            continue
        if _arg_is_buffer_output(arg):
            continue
        in_name = f"in_{_snake_case(arg.name)}"
        if arg.interface_name or (arg.class_name and arg.class_name not in ("data", "buffer", "error")):
            lines.append(f"        Z_PARAM_RESOURCE_EX({in_name}, 1 /*check_null*/, 0 /*separate*/)")
        elif arg.class_name == "data":
            lines.append(f"        Z_PARAM_STRING_EX({in_name}, {in_name}_blen, 1 /*check_null*/, 0 /*separate*/)")
        elif arg.enum_name:
            lines.append(f"        Z_PARAM_LONG({in_name})")
        else:
            type_name = (arg.type_name or "").lower()
            if type_name in ("size", "integer", "unsigned"):
                lines.append(f"        Z_PARAM_LONG({in_name})")
            elif type_name == "boolean":
                lines.append(f"        Z_PARAM_BOOL({in_name})")
            elif type_name == "byte" and not arg.is_string:
                lines.append(f"        Z_PARAM_LONG({in_name})")
            elif type_name == "string" or arg.is_string:
                lines.append(f"        Z_PARAM_STRING_EX({in_name}, {in_name}_blen, 1 /*check_null*/, 0 /*separate*/)")
            else:
                lines.append(f"        Z_PARAM_LONG({in_name})")

    lines.append("    ZEND_PARSE_PARAMETERS_END();")
    lines.append("")

    # Proxy call: fetch resources and convert data
    lines.append("    //")
    lines.append("    // Proxy call")
    lines.append("    //")

    entity_c_type = _entity_c_type(prefix, entity_name, project_ir)
    entity_snake = _snake_case(entity_name)

    if is_instance and not is_static:
        res_name = _entity_res_name_func(prefix, entity_name, project_ir)
        le_name = _entity_le_func(prefix, entity_name, project_ir)
        lines.append(f"    {entity_c_type} *{entity_snake} = zend_fetch_resource_ex(in_ctx, {res_name}, {le_name});")

    for arg in resolved_args:
        if _arg_should_skip(arg):
            continue
        if _arg_is_buffer_output(arg):
            continue
        in_name = f"in_{_snake_case(arg.name)}"
        local_name = _snake_case(arg.name)
        if arg.interface_name:
            iface_prefix = _resolve_project_prefix(project_ir, arg.project)
            lines.append(f"    {iface_prefix}_impl_t *{local_name} = zend_fetch_resource_ex({in_name}, {iface_prefix}_impl_t_php_res_name(), le_{iface_prefix}_impl_t());")
        elif arg.class_name and arg.class_name not in ("data", "buffer", "error"):
            cls_prefix = _resolve_project_prefix(project_ir, arg.project)
            if _is_impl_type(project_ir, arg.class_name):
                lines.append(f"    {cls_prefix}_impl_t *{local_name} = zend_fetch_resource_ex({in_name}, {cls_prefix}_impl_t_php_res_name(), le_{cls_prefix}_impl_t());")
            else:
                cls_snake = _snake_case(arg.class_name)
                lines.append(f"    {cls_prefix}_{cls_snake}_t *{local_name} = zend_fetch_resource_ex({in_name}, {cls_prefix}_{cls_snake}_t_php_res_name(), le_{cls_prefix}_{cls_snake}_t());")
        elif arg.class_name == "data":
            lines.append(f"    vsc_data_t {local_name} = vsc_data((const byte*){in_name}, {in_name}_blen);")
        elif arg.enum_name:
            lines.append(f"    int {local_name} = {in_name};")
        elif arg.type_name and arg.type_name.lower() == "byte" and not arg.is_string:
            # Raw byte — value or pointer based on access/is_reference
            if arg.is_reference or arg.access in ("writeonly", "readwrite"):
                lines.append(f"    byte *{local_name} = (byte *){in_name};")
            else:
                lines.append(f"    byte {local_name} = (byte){in_name};")
        elif arg.is_string or (arg.type_name and arg.type_name.lower() == "string"):
            lines.append(f"    char *{local_name} = {in_name};")
        else:
            type_name = (arg.type_name or "").lower()
            if type_name in ("size", "integer", "unsigned"):
                lines.append(f"    size_t {local_name} = {in_name};")
            elif type_name == "boolean":
                lines.append(f"    bool {local_name} = {in_name};")

    # Error arg setup
    if has_error_arg:
        lines.append(f"    {prefix}_error_t error;")
        lines.append(f"    {prefix}_error_reset(&error);")

    lines.append("")

    # Allocate output buffers
    for buf_arg in buffer_outputs:
        buf_name = _snake_case(buf_arg.name)
        inst_var = entity_snake if (is_instance and not is_static) else ""
        cap_expr = _buffer_capacity_expr(
            project_ir, entity_name, method, buf_arg, entity=entity,
            instance_var=inst_var,
        )
        lines.append("    //")
        lines.append(f"    // Allocate output buffer for output '{buf_name}'")
        lines.append("    //")
        lines.append(f"    zend_string *out_{buf_name} = zend_string_alloc({cap_expr}, 0);")
        lines.append(f"    vsc_buffer_t *{buf_name} = vsc_buffer_new();")
        lines.append(f"    vsc_buffer_use({buf_name}, (byte *)ZSTR_VAL(out_{buf_name}), ZSTR_LEN(out_{buf_name}));")
        lines.append("")

    # Build the C function call
    lines.append("    //")
    lines.append("    // Call main function")
    lines.append("    //")

    call_args: list[str] = []
    if is_instance and not is_static:
        call_args.append(entity_snake)
    for arg in resolved_args:
        if arg.class_name == "error":
            call_args.append("&error")
            continue
        if _arg_is_buffer_output(arg):
            call_args.append(_snake_case(arg.name))
            continue
        if _arg_should_skip(arg):
            continue
        local_name = _snake_case(arg.name)
        call_args.append(local_name)

    call_str = ", ".join(call_args)

    # Determine how to capture the return
    if has_status and not has_error_arg:
        lines.append(f"    {prefix}_status_t status ={c_func_name}({call_str});")
    elif has_error_arg:
        if value_returns:
            ret = value_returns[0]
            if ret.interface_name:
                ret_prefix = _resolve_project_prefix(project_ir, ret.project)
                lines.append(f"    {ret_prefix}_impl_t *{_ret_local_name(ret, entity_snake)} ={c_func_name}({call_str});")
            elif ret.class_name and ret.class_name not in ("data", "buffer", "error"):
                ret_prefix = _resolve_project_prefix(project_ir, ret.project)
                if _is_impl_type(project_ir, ret.class_name):
                    lines.append(f"    {ret_prefix}_impl_t *{_ret_local_name(ret, entity_snake)} ={c_func_name}({call_str});")
                else:
                    ret_snake = _snake_case(ret.class_name)
                    lines.append(f"    {ret_prefix}_{ret_snake}_t *{_ret_local_name(ret, entity_snake)} ={c_func_name}({call_str});")
            elif ret.class_name == "data":
                lines.append(f"    vsc_data_t {_ret_local_name(ret, entity_snake)} ={c_func_name}({call_str});")
            elif ret.enum_name:
                lines.append(f"    int {_ret_local_name(ret, entity_snake)} ={c_func_name}({call_str});")
            else:
                type_name = (ret.type_name or "").lower()
                if type_name in ("size", "integer", "unsigned"):
                    lines.append(f"    size_t res ={c_func_name}({call_str});")
                elif type_name == "boolean":
                    lines.append(f"    bool res ={c_func_name}({call_str});")
                else:
                    lines.append(f"    {c_func_name}({call_str});")
        else:
            lines.append(f"    {c_func_name}({call_str});")
    elif value_returns and not buffer_outputs:
        ret = value_returns[0]
        if ret.interface_name:
            ret_prefix = _resolve_project_prefix(project_ir, ret.project)
            ret_name = _ret_local_name(ret, entity_snake)
            # Cast away const for readonly returns (C function returns const ptr)
            if ret.access == "readonly":
                lines.append(f"    {ret_prefix}_impl_t *{ret_name} =({ret_prefix}_impl_t *){c_func_name}({call_str});")
            else:
                lines.append(f"    {ret_prefix}_impl_t *{ret_name} ={c_func_name}({call_str});")
        elif ret.class_name and ret.class_name not in ("data", "buffer", "error"):
            ret_prefix = _resolve_project_prefix(project_ir, ret.project)
            ret_name = _ret_local_name(ret, entity_snake)
            if _is_impl_type(project_ir, ret.class_name):
                if ret.access == "readonly":
                    lines.append(f"    {ret_prefix}_impl_t *{ret_name} =({ret_prefix}_impl_t *){c_func_name}({call_str});")
                else:
                    lines.append(f"    {ret_prefix}_impl_t *{ret_name} ={c_func_name}({call_str});")
            else:
                ret_snake = _snake_case(ret.class_name)
                if ret.access == "readonly":
                    lines.append(f"    {ret_prefix}_{ret_snake}_t *{ret_name} =({ret_prefix}_{ret_snake}_t *){c_func_name}({call_str});")
                else:
                    lines.append(f"    {ret_prefix}_{ret_snake}_t *{ret_name} ={c_func_name}({call_str});")
        elif ret.class_name == "data":
            lines.append(f"    vsc_data_t {_ret_local_name(ret, entity_snake)} ={c_func_name}({call_str});")
        elif ret.enum_name:
            lines.append(f"    int {_ret_local_name(ret, entity_snake)} ={c_func_name}({call_str});")
        else:
            type_name = (ret.type_name or "").lower()
            if type_name in ("size", "integer", "unsigned"):
                lines.append(f"    size_t res ={c_func_name}({call_str});")
            elif type_name == "boolean":
                lines.append(f"    bool res ={c_func_name}({call_str});")
            else:
                lines.append(f"    {c_func_name}({call_str});")
    else:
        lines.append(f"    {c_func_name}({call_str});")

    lines.append("")

    # Handle error
    if has_status and not has_error_arg:
        lines.append("    //")
        lines.append("    // Handle error")
        lines.append("    //")
        lines.append(f"    {prefix_upper}_HANDLE_STATUS(status);")
        lines.append("")

    if has_error_arg:
        lines.append("    //")
        lines.append("    // Handle error")
        lines.append("    //")
        lines.append(f"    {prefix}_status_t status = {prefix}_error_status(&error);")
        lines.append(f"    {prefix_upper}_HANDLE_STATUS(status);")
        lines.append("")

    # Write returned result
    if buffer_outputs:
        buf_arg = buffer_outputs[0]
        buf_name = _snake_case(buf_arg.name)
        lines.append("    //")
        lines.append("    // Correct string length to the actual")
        lines.append("    //")
        lines.append(f"    ZSTR_LEN(out_{buf_name}) = vsc_buffer_len({buf_name});")
        lines.append("")
        lines.append("    //")
        lines.append("    // Write returned result")
        lines.append("    //")
        if has_status or has_error_arg:
            lines.append(f"    if (status == {prefix}_status_SUCCESS) {{")
            lines.append(f"        RETVAL_STR(out_{buf_name});")
            lines.append(f"        vsc_buffer_destroy(&{buf_name});")
            lines.append("    }")
            lines.append("    else {")
            lines.append(f"        zend_string_free(out_{buf_name});")
            lines.append("    }")
        else:
            lines.append(f"    RETVAL_STR(out_{buf_name});")
    elif value_returns:
        ret = value_returns[0]
        lines.append("    //")
        lines.append("    // Write returned result")
        lines.append("    //")
        if ret.interface_name:
            ret_name = _ret_local_name(ret, entity_snake)
            ret_prefix = _resolve_project_prefix(project_ir, ret.project)
            # Shallow copy only for readonly/borrowed returns (not disown/transfer)
            needs_shallow_copy = ret.access == "readonly"
            if needs_shallow_copy:
                lines.append(f"    {ret_name} = {ret_prefix}_impl_shallow_copy({ret_name});")
            if has_error_arg:
                lines.append(f"    if (status == {prefix}_status_SUCCESS) {{")
                lines.append(f"        zend_resource *{ret_name}_res = zend_register_resource({ret_name}, le_{ret_prefix}_impl_t());")
                lines.append(f"        RETVAL_RES({ret_name}_res);")
                lines.append("    }")
            else:
                lines.append(f"    zend_resource *{ret_name}_res = zend_register_resource({ret_name}, le_{ret_prefix}_impl_t());")
                lines.append(f"    RETVAL_RES({ret_name}_res);")
        elif ret.class_name and ret.class_name not in ("data", "buffer", "error"):
            ret_name = _ret_local_name(ret, entity_snake)
            ret_prefix = _resolve_project_prefix(project_ir, ret.project)
            needs_shallow_copy = ret.access == "readonly"
            if _is_impl_type(project_ir, ret.class_name):
                if needs_shallow_copy:
                    lines.append(f"    {ret_name} = {ret_prefix}_impl_shallow_copy({ret_name});")
                if has_error_arg:
                    lines.append(f"    if (status == {prefix}_status_SUCCESS) {{")
                    lines.append(f"        zend_resource *{ret_name}_res = zend_register_resource({ret_name}, le_{ret_prefix}_impl_t());")
                    lines.append(f"        RETVAL_RES({ret_name}_res);")
                    lines.append("    }")
                else:
                    lines.append(f"    zend_resource *{ret_name}_res = zend_register_resource({ret_name}, le_{ret_prefix}_impl_t());")
                    lines.append(f"    RETVAL_RES({ret_name}_res);")
            else:
                ret_snake = _snake_case(ret.class_name)
                if needs_shallow_copy:
                    lines.append(f"    {ret_name} = {ret_prefix}_{ret_snake}_shallow_copy({ret_name});")

                if has_error_arg:
                    lines.append(f"    if (status == {prefix}_status_SUCCESS) {{")
                    lines.append(f"        zend_resource *{ret_name}_res = zend_register_resource({ret_name}, le_{ret_prefix}_{ret_snake}_t());")
                    lines.append(f"        RETVAL_RES({ret_name}_res);")
                    lines.append("    }")
                else:
                    lines.append(f"    zend_resource *{ret_name}_res = zend_register_resource({ret_name}, le_{ret_prefix}_{ret_snake}_t());")
                    lines.append(f"    RETVAL_RES({ret_name}_res);")
        elif ret.class_name == "data":
            ret_name = _ret_local_name(ret, entity_snake)
            lines.append(f"    RETVAL_STRINGL((const char *){ret_name}.bytes, {ret_name}.len);")
        elif ret.enum_name:
            ret_name = _ret_local_name(ret, entity_snake)
            lines.append(f"    RETVAL_LONG({ret_name});")
        else:
            type_name = (ret.type_name or "").lower()
            if type_name in ("size", "integer", "unsigned"):
                lines.append("    RETVAL_LONG(res);")
            elif type_name == "boolean":
                lines.append("    RETVAL_BOOL(res);")

    lines.append("}")
    lines.append("")


def _emit_new_function(
    lines: list[str],
    prefix: str,
    entity_name: str,
    project_ir: IRProject,
) -> str:
    """Emit new/delete PHP functions for an entity. Returns list of PHP_FE names."""
    prefix_upper = prefix.upper()
    entity_snake = _snake_case(entity_name)
    is_impl = _is_impl_type(project_ir, entity_name)
    c_type = _entity_c_type(prefix, entity_name, project_ir)
    le_func = _entity_le_func(prefix, entity_name, project_ir)
    new_php = f"{prefix}_{entity_snake}_new_php"
    del_php = f"{prefix}_{entity_snake}_delete_php"

    # new arginfo
    lines.append("ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(")
    lines.append(f"        arginfo_{new_php},")
    lines.append("        0 /*return_reference*/,")
    lines.append("        0 /*required_num_args*/,")
    lines.append("        IS_RESOURCE /*type*/,")
    lines.append("        0 /*allow_null*/)")
    lines.append("ZEND_END_ARG_INFO()")
    lines.append("")

    # new function
    lines.append(f"PHP_FUNCTION({new_php}) {{")
    lines.append(f"    {c_type} *{entity_snake} = {prefix}_{entity_snake}_new();")
    lines.append(f"    zend_resource *{entity_snake}_res = zend_register_resource({entity_snake}, {le_func});")
    lines.append(f"    RETVAL_RES({entity_snake}_res);")
    lines.append("}")
    lines.append("")

    # delete arginfo
    lines.append("//")
    lines.append(f"// Wrap method: {prefix}_{entity_snake}_delete")
    lines.append("//")
    lines.append("ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(")
    lines.append(f"        arginfo_{del_php},")
    lines.append("        0 /*return_reference*/,")
    lines.append("        1 /*required_num_args*/,")
    lines.append("        IS_VOID /*type*/,")
    lines.append("        0 /*allow_null*/)")
    lines.append("")
    lines.append("        ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)")
    lines.append("ZEND_END_ARG_INFO()")
    lines.append("")

    # delete function
    res_name = _entity_res_name_func(prefix, entity_name, project_ir)
    lines.append(f"PHP_FUNCTION({del_php}) {{")
    lines.append("    //")
    lines.append("    // Declare input arguments")
    lines.append("    //")
    lines.append("    zval *in_ctx = NULL;")
    lines.append("")
    lines.append("    //")
    lines.append("    // Parse arguments")
    lines.append("    //")
    lines.append("    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)")
    lines.append("        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)")
    lines.append("    ZEND_PARSE_PARAMETERS_END();")
    lines.append("")
    lines.append("    //")
    lines.append("    // Fetch for type checking and then release")
    lines.append("    //")
    lines.append(f"    {c_type} *{entity_snake} = zend_fetch_resource_ex(in_ctx, {res_name}, {le_func});")
    lines.append("    zend_list_close(Z_RES_P(in_ctx));")
    lines.append("    RETURN_TRUE;")
    lines.append("}")
    lines.append("")

    return (new_php, del_php)


def _emit_dependency_setter_c(
    lines: list[str],
    prefix: str,
    entity_name: str,
    dep: IRDependency,
    project_ir: IRProject,
) -> str:
    """Emit a use_{dep} PHP function. Returns the PHP function name."""
    prefix_upper = prefix.upper()
    entity_snake = _snake_case(entity_name)
    dep_snake = _snake_case(dep.name)
    php_func = f"{prefix}_{entity_snake}_use_{dep_snake}_php"
    c_func = f"{prefix}_{entity_snake}_use_{dep_snake}"

    c_type = _entity_c_type(prefix, entity_name, project_ir)
    res_name = _entity_res_name_func(prefix, entity_name, project_ir)
    le_func = _entity_le_func(prefix, entity_name, project_ir)

    lines.append("//")
    lines.append(f"// Wrap method: {c_func}")
    lines.append("//")
    lines.append("ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(")
    lines.append(f"    arginfo_{php_func},")
    lines.append("    0 /*return_reference*/,")
    lines.append("    2 /*required_num_args*/,")
    lines.append("    IS_VOID /*type*/,")
    lines.append("    0 /*allow_null*/)")
    lines.append("")
    lines.append("")
    lines.append("    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)")
    lines.append(f"    ZEND_ARG_TYPE_INFO(0, in_{dep_snake}, IS_RESOURCE, 0)")
    lines.append("ZEND_END_ARG_INFO()")
    lines.append("")
    lines.append(f"PHP_FUNCTION({php_func}) {{")
    lines.append("")
    lines.append("    //")
    lines.append("    // Declare input argument")
    lines.append("    //")
    lines.append("    zval *in_ctx = NULL;")
    lines.append(f"    zval *in_{dep_snake} = NULL;")
    lines.append("")
    lines.append("    //")
    lines.append("    // Parse arguments")
    lines.append("    //")
    lines.append("    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 2, 2)")
    lines.append("        Z_PARAM_RESOURCE_EX(in_ctx, 1, 0)")
    lines.append(f"        Z_PARAM_RESOURCE_EX(in_{dep_snake}, 1 /*check_null*/, 0 /*separate*/)")
    lines.append("    ZEND_PARSE_PARAMETERS_END();")
    lines.append("")
    lines.append("    //")
    lines.append("    // Proxy call")
    lines.append("    //")
    lines.append(f"    {c_type} *{entity_snake} = zend_fetch_resource_ex(in_ctx, {res_name}, {le_func});")

    # Determine dependency type
    dep_prefix = _resolve_project_prefix(project_ir, dep.attrs.get("project"))
    if dep.type_kind == "interface":
        lines.append(f"    {dep_prefix}_impl_t *{dep_snake} = zend_fetch_resource_ex(in_{dep_snake}, {dep_prefix}_impl_t_php_res_name(), le_{dep_prefix}_impl_t());")
    elif dep.type_kind in ("class", "impl"):
        if _is_impl_type(project_ir, dep.type_name):
            lines.append(f"    {dep_prefix}_impl_t *{dep_snake} = zend_fetch_resource_ex(in_{dep_snake}, {dep_prefix}_impl_t_php_res_name(), le_{dep_prefix}_impl_t());")
        else:
            dep_type_snake = _snake_case(dep.type_name)
            lines.append(f"    {dep_prefix}_{dep_type_snake}_t *{dep_snake} = zend_fetch_resource_ex(in_{dep_snake}, {dep_prefix}_{dep_type_snake}_t_php_res_name(), le_{dep_prefix}_{dep_type_snake}_t());")
    else:
        lines.append(f"    {dep_prefix}_impl_t *{dep_snake} = zend_fetch_resource_ex(in_{dep_snake}, {dep_prefix}_impl_t_php_res_name(), le_{dep_prefix}_impl_t());")

    lines.append("")
    lines.append("    //")
    lines.append("    // Call main function")
    lines.append("    //")
    lines.append(f"    {c_func}({entity_snake}, {dep_snake});")
    lines.append("}")
    lines.append("")

    return php_func


def generate_c_extension_source(project_ir: IRProject) -> str:
    """Generate the C extension .c source file from IR.

    Produces the complete C extension with:
    - License, includes, status handler
    - Resource name constants and accessor functions
    - Resource type variables and accessor functions
    - MINIT/MSHUTDOWN declarations
    - PHP function implementations (new, delete, use_*, methods)
    - Function entry table (PHP_FE)
    - Module definition
    - Resource destructors
    - MINIT function (register resources + exception class)
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

    # Collect all entities that need C includes (including static classes)
    all_included_entities = _collect_all_included_entities(project_ir)
    for ename, ekind in all_included_entities:
        entity_snake = _snake_case(ename)
        lines.append(f'#include "{prefix}_{entity_snake}.h"')

    # Cross-project PHP extension headers for symbol declarations.
    # On Windows, __declspec(dllimport) decoration requires the header;
    # on all platforms, the declaration prevents implicit-function warnings.
    for dep_project in sorted(_collect_cross_project_php_deps(project_ir)):
        dep_prefix = _PROJECT_PREFIX.get(dep_project, dep_project)
        lines.append(f'#include "{dep_prefix}_{dep_project}_php.h"')

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

    # --- Constants: resource name strings ---
    lines.append("//")
    lines.append("// Constants")
    lines.append("//")
    ver = project_ir.version or {}
    ver_str = f"{ver.get('major', '0')}.{ver.get('minor', '0')}.{ver.get('patch', '0')}"
    lines.append(f'const char {prefix_upper}_{project_name.upper()}_PHP_VERSION[] = "{ver_str}";')
    lines.append(f'const char {prefix_upper}_{project_name.upper()}_PHP_EXTNAME[] = "{prefix}_{project_name}_php";')
    lines.append("")

    # Resource-type entities (non-static classes + implementations)
    all_entities = _collect_all_wrapped_entities(project_ir)

    # impl_t resource name (only when project has interface implementations)
    if project_ir.implementations:
        lines.append(f'static const char {prefix_upper}_IMPL_T_PHP_RES_NAME[] = "{prefix}_impl_t";')

    for ename, ekind in all_entities:
        entity_snake = _snake_case(ename)
        entity_upper = entity_snake.upper()
        lines.append(f'static const char {prefix_upper}_{entity_upper}_T_PHP_RES_NAME[] = "{prefix}_{entity_snake}_t";')

    lines.append("")

    # Resource name accessor functions
    lines.append("//")
    lines.append("// Constants func wrapping")
    lines.append("//")
    if project_ir.implementations:
        lines.append(f"{prefix_upper}_PHP_PUBLIC const char* {prefix}_impl_t_php_res_name(void) {{")
        lines.append(f"    return {prefix_upper}_IMPL_T_PHP_RES_NAME;")
        lines.append("}")
        lines.append("")

    for ename, ekind in all_entities:
        entity_snake = _snake_case(ename)
        entity_upper = entity_snake.upper()
        lines.append(f"{prefix_upper}_PHP_PUBLIC const char* {prefix}_{entity_snake}_t_php_res_name(void) {{")
        lines.append(f"    return {prefix_upper}_{entity_upper}_T_PHP_RES_NAME;")
        lines.append("}")
        lines.append("")

    # --- Registered resources (int variables) ---
    lines.append("//")
    lines.append("// Registered resources")
    lines.append("//")
    if project_ir.implementations:
        lines.append(f"int LE_{prefix_upper}_IMPL_T;")
    for ename, ekind in all_entities:
        entity_snake = _snake_case(ename)
        entity_upper = entity_snake.upper()
        lines.append(f"int LE_{prefix_upper}_{entity_upper}_T;")
    lines.append("")

    # Resource accessor functions
    lines.append("//")
    lines.append("// Registered resources func wrapping")
    lines.append("//")
    if project_ir.implementations:
        lines.append(f"{prefix_upper}_PHP_PUBLIC int le_{prefix}_impl_t(void) {{")
        lines.append(f"    return LE_{prefix_upper}_IMPL_T;")
        lines.append("}")
    lines.append("")

    for ename, ekind in all_entities:
        entity_snake = _snake_case(ename)
        entity_upper = entity_snake.upper()
        lines.append(f"{prefix_upper}_PHP_PUBLIC int le_{prefix}_{entity_snake}_t(void) {{")
        lines.append(f"    return LE_{prefix_upper}_{entity_upper}_T;")
        lines.append("}")
        lines.append("")

    # MINIT/MSHUTDOWN declarations
    lines.append("//")
    lines.append("// Extension init functions declaration")
    lines.append("//")
    lines.append(f"PHP_MINIT_FUNCTION({prefix}_{project_name}_php);")
    lines.append(f"PHP_MSHUTDOWN_FUNCTION({prefix}_{project_name}_php);")
    lines.append("")

    # --- Function implementations ---
    lines.append("//")
    lines.append("// Functions wrapping")
    lines.append("//")

    # Track all php function names for the function table
    all_php_funcs: list[str] = []

    # 1. vscf_impl_tag function (only for projects that have implementations)
    if project_ir.implementations:
        impl_tag_php = f"{prefix}_impl_tag_php"
        all_php_funcs.append(impl_tag_php)

        lines.append("//")
        lines.append(f"// Wrap method: {prefix}_impl_tag")
        lines.append("//")
        lines.append("ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(")
        lines.append(f"    arginfo_{impl_tag_php},")
        lines.append("    0 /*return_reference*/,")
        lines.append("    1 /*required_num_args*/,")
        lines.append("    IS_LONG /*type*/,")
        lines.append("    0 /*allow_null*/)")
        lines.append("")
        lines.append("")
        lines.append("    ZEND_ARG_TYPE_INFO(0, in_ctx, IS_RESOURCE, 0)")
        lines.append("ZEND_END_ARG_INFO()")
        lines.append("")
        lines.append(f"PHP_FUNCTION({impl_tag_php}) {{")
        lines.append("")
        lines.append("    //")
        lines.append("    // Declare input argument")
        lines.append("    //")
        lines.append("    zval *in_ctx = NULL;")
        lines.append("")
        lines.append("    //")
        lines.append("    // Parse arguments")
        lines.append("    //")
        lines.append("    ZEND_PARSE_PARAMETERS_START_EX(ZEND_PARSE_PARAMS_THROW, 1, 1)")
        lines.append("        Z_PARAM_RESOURCE_EX(in_ctx, 1 /*check_null*/, 0 /*separate*/)")
        lines.append("    ZEND_PARSE_PARAMETERS_END();")
        lines.append("")
        lines.append("    //")
        lines.append("    // Proxy call")
        lines.append("    //")
        lines.append(f"    {prefix}_impl_t *ctx = zend_fetch_resource_ex(in_ctx, {prefix}_impl_t_php_res_name(), le_{prefix}_impl_t());")
        lines.append("")
        lines.append("    //")
        lines.append("    // Call main function")
        lines.append("    //")
        lines.append(f"    int tag ={prefix}_impl_tag(ctx);")
        lines.append("")
        lines.append("    //")
        lines.append("    // Write returned result")
        lines.append("    //")
        lines.append("    RETVAL_LONG(tag);")
        lines.append("}")
        lines.append("")

    # 2. Static class methods (classes with context="none")
    for cls in project_ir.classes:
        if cls.attrs.get("scope") in {"private", "internal"}:
            continue
        if cls.name == "error":
            continue
        if not _is_static_class(cls):
            continue

        for method in cls.methods:
            if not _method_should_wrap(method):
                continue
            entity_snake = _snake_case(cls.name)
            php_func = f"{prefix}_{entity_snake}_{_snake_case(method.name)}_php"
            c_func = _c_func_name(prefix, cls.name, method.name)
            all_php_funcs.append(php_func)

            lines.append("//")
            lines.append(f"// Wrap method: {c_func}")
            lines.append("//")
            _emit_arginfo(lines, php_func, method, cls.name, project_ir,
                         is_static=True, is_instance=False)
            _emit_php_function(lines, php_func, c_func, method, cls.name,
                              project_ir, is_static=True, is_instance=False,
                              entity=cls)

    # 3. Non-static classes (with context)
    for cls in project_ir.classes:
        if cls.attrs.get("scope") in {"private", "internal"}:
            continue
        if cls.name == "error":
            continue
        if _is_static_class(cls):
            continue

        entity_snake = _snake_case(cls.name)

        # new/delete
        lines.append("//")
        lines.append(f"// Wrap method: {prefix}_{entity_snake}_new")
        lines.append("//")
        new_php, del_php = _emit_new_function(lines, prefix, cls.name, project_ir)
        all_php_funcs.extend([new_php, del_php])

        # methods
        for method in cls.methods:
            if not _method_should_wrap(method):
                continue
            is_static = method.attrs.get("is_static") in {"1", "true"}
            php_func = f"{prefix}_{entity_snake}_{_snake_case(method.name)}_php"
            c_func = _c_func_name(prefix, cls.name, method.name)
            all_php_funcs.append(php_func)

            lines.append("//")
            lines.append(f"// Wrap method: {c_func}")
            lines.append("//")
            _emit_arginfo(lines, php_func, method, cls.name, project_ir,
                         is_static=is_static, is_instance=True)
            _emit_php_function(lines, php_func, c_func, method, cls.name,
                              project_ir, is_static=is_static, is_instance=True,
                              entity=cls)

        # dependency setters
        for dep in cls.dependencies:
            dep_func = _emit_dependency_setter_c(lines, prefix, cls.name, dep, project_ir)
            all_php_funcs.append(dep_func)

    # 4. Implementations
    for impl in project_ir.implementations:
        if impl.attrs.get("scope") in {"private", "internal"}:
            continue

        entity_snake = _snake_case(impl.name)

        # new/delete
        lines.append("//")
        lines.append(f"// Wrap method: {prefix}_{entity_snake}_new")
        lines.append("//")
        new_php, del_php = _emit_new_function(lines, prefix, impl.name, project_ir)
        all_php_funcs.extend([new_php, del_php])

        # Collect all methods (interface + own)
        method_pairs = _collect_methods_for_entity(
            project_ir, impl.name, impl, is_implementation=True,
        )
        for method, is_static in method_pairs:
            php_func = f"{prefix}_{entity_snake}_{_snake_case(method.name)}_php"
            c_func = _c_func_name(prefix, impl.name, method.name)
            all_php_funcs.append(php_func)

            lines.append("//")
            lines.append(f"// Wrap method: {c_func}")
            lines.append("//")
            _emit_arginfo(lines, php_func, method, impl.name, project_ir,
                         is_static=is_static, is_instance=True)
            _emit_php_function(lines, php_func, c_func, method, impl.name,
                              project_ir, is_static=is_static, is_instance=True,
                              entity=impl)

        # dependency setters
        for dep in impl.dependencies:
            dep_func = _emit_dependency_setter_c(lines, prefix, impl.name, dep, project_ir)
            all_php_funcs.append(dep_func)

    # --- Function entry table ---
    lines.append(f"static zend_function_entry {prefix}_{project_name}_php_functions[] = {{")
    for func_name in all_php_funcs:
        lines.append(f"    PHP_FE({func_name}, arginfo_{func_name})")
    lines.append("    PHP_FE_END")
    lines.append("};")
    lines.append("")

    # --- Module entry ---
    lines.append("//")
    lines.append("// Extension module definition")
    lines.append("//")
    lines.append(f"zend_module_entry {prefix}_{project_name}_php_module_entry = {{")
    lines.append("#if ZEND_MODULE_API_NO >= 20010901")
    lines.append("    STANDARD_MODULE_HEADER,")
    lines.append("#endif")
    lines.append(f"    {prefix_upper}_{project_name.upper()}_PHP_EXTNAME,")
    lines.append(f"    {prefix}_{project_name}_php_functions,")
    lines.append(f"    PHP_MINIT({prefix}_{project_name}_php),")
    lines.append(f"    PHP_MSHUTDOWN({prefix}_{project_name}_php),")
    lines.append("    NULL,")
    lines.append("    NULL,")
    lines.append("    NULL,")
    lines.append("#if ZEND_MODULE_API_NO >= 20010901")
    lines.append(f"    {prefix_upper}_{project_name.upper()}_PHP_VERSION,")
    lines.append("#endif")
    lines.append("    STANDARD_MODULE_PROPERTIES")
    lines.append("};")
    lines.append("")
    lines.append(f"ZEND_GET_MODULE({prefix}_{project_name}_php)")
    lines.append("")

    # --- Resource destructors ---
    lines.append("//")
    lines.append("// Extension init functions definition")
    lines.append("//")

    # impl_t destructor (only when project has interface implementations)
    if project_ir.implementations:
        lines.append(f"static void {prefix}_impl_dtor_php(zend_resource *rsrc) {{")
        lines.append(f"    {prefix}_impl_delete(({prefix}_impl_t *)rsrc->ptr);")
        lines.append("}")

    for ename, ekind in all_entities:
        if _is_impl_type(project_ir, ename):
            continue  # implementations use impl_t destructor
        entity_snake = _snake_case(ename)
        lines.append(f"static void {prefix}_{entity_snake}_dtor_php(zend_resource *rsrc) {{")
        lines.append(f"    {prefix}_{entity_snake}_delete(({prefix}_{entity_snake}_t *)rsrc->ptr);")
        lines.append("}")

    # MINIT function
    lines.append(f"PHP_MINIT_FUNCTION({prefix}_{project_name}_php) {{")

    # Register exception class
    project_pascal = _pascal_case(project_name)
    lines.append(f"    zend_class_entry {prefix}_ce;")
    lines.append(f'    INIT_CLASS_ENTRY({prefix}_ce, "{project_pascal}Exception", NULL);')
    lines.append(f"    {prefix}_exception_ce = zend_register_internal_class_ex(&{prefix}_ce, zend_ce_exception);")

    # Register resource types (impl_t only when project has interface implementations)
    if project_ir.implementations:
        lines.append(f"    LE_{prefix_upper}_IMPL_T = zend_register_list_destructors_ex({prefix}_impl_dtor_php, NULL, {prefix}_impl_t_php_res_name(), module_number);")

    for ename, ekind in all_entities:
        entity_snake = _snake_case(ename)
        entity_upper = entity_snake.upper()
        if _is_impl_type(project_ir, ename):
            # Implementations share the impl_t destructor but get their own resource slot
            # Actually, looking at legacy, implementations don't get separate resource types --
            # they all use LE_VSCF_IMPL_T. Only classes get their own.
            continue
        lines.append(f"    LE_{prefix_upper}_{entity_upper}_T = zend_register_list_destructors_ex({prefix}_{entity_snake}_dtor_php, NULL, {prefix}_{entity_snake}_t_php_res_name(), module_number);")

    lines.append("    return SUCCESS;")
    lines.append("}")

    # MSHUTDOWN function
    lines.append(f"PHP_MSHUTDOWN_FUNCTION({prefix}_{project_name}_php) {{")
    lines.append("    return SUCCESS;")
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
    lines.append(f"#   if VSCF_PHP_SHARED_LIBRARY")
    lines.append(f"#       if defined({prefix_upper}_PHP_INTERNAL_BUILD)")
    lines.append(f"#           ifdef __GNUC__")
    lines.append(f"#               define {prefix_upper}_PHP_PUBLIC __attribute__ ((dllexport))")
    lines.append(f"#           else")
    lines.append(f"#               define {prefix_upper}_PHP_PUBLIC __declspec(dllexport)")
    lines.append(f"#           endif")
    lines.append(f"#       else")
    lines.append(f"#           ifdef __GNUC__")
    lines.append(f"#               define {prefix_upper}_PHP_PUBLIC __attribute__ ((dllimport))")
    lines.append(f"#           else")
    lines.append(f"#               define {prefix_upper}_PHP_PUBLIC __declspec(dllimport)")
    lines.append(f"#           endif")
    lines.append(f"#       endif")
    lines.append(f"#   else")
    lines.append(f"#       define {prefix_upper}_PHP_PUBLIC")
    lines.append(f"#   endif")
    lines.append(f"#   define {prefix_upper}_PHP_PRIVATE")
    lines.append(f"#else")
    lines.append(f"#   if (defined(__GNUC__) && __GNUC__ >= 4) || defined(__INTEL_COMPILER) || defined(__clang__)")
    lines.append(f"#       define {prefix_upper}_PHP_PUBLIC __attribute__ ((visibility (\"default\")))")
    lines.append(f"#       define {prefix_upper}_PHP_PRIVATE __attribute__ ((visibility (\"hidden\")))")
    lines.append(f"#   else")
    lines.append(f"#       define {prefix_upper}_PHP_PRIVATE")
    lines.append(f"#   endif")
    lines.append(f"#endif")
    lines.append("")

    # Resource name function declarations
    lines.append("//")
    lines.append("// Constants")
    lines.append("//")

    # impl_t first (only when project has interface implementations)
    if project_ir.implementations:
        lines.append(f"{prefix_upper}_PHP_PUBLIC const char*")
        lines.append(f"{prefix}_impl_t_php_res_name(void);")
        lines.append("")

    all_entities = _collect_all_wrapped_entities(project_ir)
    for ename, ekind in all_entities:
        entity_snake = _snake_case(ename)
        lines.append(f"{prefix_upper}_PHP_PUBLIC const char*")
        lines.append(f"{prefix}_{entity_snake}_t_php_res_name(void);")
        lines.append("")

    # Registered resources function declarations
    lines.append("//")
    lines.append("// Registered resources")
    lines.append("//")

    if project_ir.implementations:
        lines.append(f"{prefix_upper}_PHP_PUBLIC int")
        lines.append(f"le_{prefix}_impl_t(void);")
        lines.append("")

    for ename, ekind in all_entities:
        entity_snake = _snake_case(ename)
        lines.append(f"{prefix_upper}_PHP_PUBLIC int")
        lines.append(f"le_{prefix}_{entity_snake}_t(void);")
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
    cross_project_deps = sorted(_collect_cross_project_php_deps(project_ir))

    lines.append(f"target_include_directories({target}")
    lines.append("    PUBLIC")
    lines.append("        $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>")
    if cross_project_deps:
        lines.append("    PRIVATE")
        for dep_project in cross_project_deps:
            lines.append(f"        $<BUILD_INTERFACE:${{CMAKE_CURRENT_LIST_DIR}}/../{dep_project}>")
    lines.append(")")
    lines.append("")
    lines.append(f"target_link_libraries({target}")
    lines.append("    PUBLIC")
    lines.append(f"        {c_target}")
    lines.append("    PRIVATE")
    lines.append("        phplib")
    lines.append('        "$<$<STREQUAL:${CMAKE_SYSTEM_NAME},Darwin>:'
                 '-undefined dynamic_lookup>"')
    for dep_project in cross_project_deps:
        lines.append(f"        $<$<BOOL:${{WIN32}}>:{dep_project}_php>")
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


def _collect_cross_project_php_deps(project_ir: IRProject) -> set[str]:
    """Return set of project names whose PHP symbols this project references.

    Scans class/implementation dependencies and method arguments for
    cross-project interface or class references. On Windows, the returned
    projects must be linked as import libraries. On all platforms, their
    PHP headers must be included for proper symbol declarations.
    """
    deps: set[str] = set()
    current = project_ir.name

    def _check(project_name: str | None) -> None:
        if project_name and project_name != current:
            deps.add(project_name)

    for cls in project_ir.classes:
        for dep in cls.dependencies:
            _check(dep.attrs.get("project"))
        for method in cls.methods:
            for arg in method.arguments + method.returns:
                _check(arg.project)

    for impl in project_ir.implementations:
        for dep in impl.dependencies:
            _check(dep.attrs.get("project"))
        for method in impl.methods:
            for arg in method.arguments + method.returns:
                _check(arg.project)

    return deps


def _collect_all_included_entities(
    project_ir: IRProject,
) -> list[tuple[str, str]]:
    """Collect all entity (name, kind) pairs that need C #include directives.

    Unlike ``_collect_all_wrapped_entities``, this includes static classes
    (which have functions but no resource types).
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


def _collect_all_wrapped_entities(
    project_ir: IRProject,
) -> list[tuple[str, str]]:
    """Collect all entity (name, kind) pairs that are wrapped for PHP.

    Returns sorted list for stable output. Only includes entities that
    have a context (non-static classes and implementations).
    Static classes (context="none") are excluded since they don't have
    resource types -- they only have static functions.
    """
    entities: list[tuple[str, str]] = []

    for cls in project_ir.classes:
        if cls.attrs.get("scope") in {"private", "internal"}:
            continue
        if cls.name == "error":
            continue
        if _is_static_class(cls):
            continue  # Static classes have no context/resource
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
    global _PHP_LICENSE, _C_LICENSE
    if license_text:
        _PHP_LICENSE = _format_license_php_block(license_text)
        _C_LICENSE = _format_license_slash_bordered(license_text)
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
