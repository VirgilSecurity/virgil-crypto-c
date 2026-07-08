"""C++ (C++20) wrapper backend.

Generates an idiomatic, header-based C++20 SDK from the IR models, mirroring the
structure of :mod:`project_swift_backend` (the closest object-oriented analog).

Public entry point: :func:`generate_cpp_files`.

Design (see docs/plans/2026-07-07-001-feat-cpp-wrapper-plan.md):
  * Namespaces ``virgil::crypto::<project>`` (foundation / ratchet / phe).
  * Types PascalCase (``Aes256Gcm``); enum-class members PascalCase; methods
    snake_case (matching the C surface); C reserved words get a trailing ``_``.
  * Enums become ``enum class`` with the same integer values as the C enum, so
    conversion to/from the C type is a plain ``static_cast`` (no lookup table).
  * The C ``status`` enum becomes a per-project ``Error`` enum class; runtime
    failures are reported via ``expected<T, Error>`` (Units 2+). C asserts abort
    and are never surfaced as recoverable errors.

Unit 1 scope: name/type utilities, enum generation, and the ``Error`` type.
Classes, interfaces, implementations and impl-tag dispatch follow in later units.
"""

from __future__ import annotations

from pathlib import Path

from tools.codegen.project_ir import (
    IRProject, IREnum, IRClass, IRCMethod, IRCArgument, IRDependency,
)


# ---------------------------------------------------------------------------
# C++ reserved words (identifiers that must be escaped in generated code)
# ---------------------------------------------------------------------------

_CPP_KEYWORDS = frozenset({
    "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor",
    "bool", "break", "case", "catch", "char", "char8_t", "char16_t",
    "char32_t", "class", "compl", "concept", "const", "consteval", "constexpr",
    "constinit", "const_cast", "continue", "co_await", "co_return", "co_yield",
    "decltype", "default", "delete", "do", "double", "dynamic_cast", "else",
    "enum", "explicit", "export", "extern", "false", "float", "for", "friend",
    "goto", "if", "inline", "int", "long", "mutable", "namespace", "new",
    "noexcept", "not", "not_eq", "nullptr", "operator", "or", "or_eq",
    "private", "protected", "public", "register", "reinterpret_cast",
    "requires", "return", "short", "signed", "sizeof", "static",
    "static_assert", "static_cast", "struct", "switch", "template", "this",
    "thread_local", "throw", "true", "try", "typedef", "typeid", "typename",
    "union", "unsigned", "using", "virtual", "void", "volatile", "wchar_t",
    "while", "xor", "xor_eq",
})


def _escape_cpp_keyword(name: str) -> str:
    """Append a trailing underscore to a C++ reserved word (C++ has no backtick escape)."""
    return f"{name}_" if name in _CPP_KEYWORDS else name


# ---------------------------------------------------------------------------
# Infrastructure enums handled specially (not emitted as plain enums)
# ---------------------------------------------------------------------------

_INFRASTRUCTURE_ENUMS = frozenset({"status", "impl/tag"})

_CPP_LICENSE = ""  # populated by generate_cpp_files()


# ---------------------------------------------------------------------------
# Per-project configuration derived from IRProject
# ---------------------------------------------------------------------------

def _c_prefix(project_ir: IRProject) -> str:
    """C symbol prefix (e.g., ``vscf_``)."""
    return f"{project_ir.prefix}_"


def _ns_leaf(project_ir: IRProject) -> str:
    """Leaf C++ namespace / directory for the project (e.g., ``foundation``)."""
    return project_ir.name.replace(" ", "_").lower()


def _cpp_namespace(project_ir: IRProject) -> str:
    """Full C++ namespace, e.g. ``virgil::crypto::foundation``."""
    return f"virgil::crypto::{_ns_leaf(project_ir)}"


def _output_dir(project_ir: IRProject) -> str:
    """Repo-relative output directory for this project's public C++ headers."""
    return f"wrappers/cpp/include/virgil/crypto/{_ns_leaf(project_ir)}/"


# ---------------------------------------------------------------------------
# Name utilities (pure, unit-tested)
# ---------------------------------------------------------------------------

def _split_words(name: str) -> list[str]:
    """Split a space/underscore-separated entity name into words."""
    return [w for w in name.replace("_", " ").split(" ") if w]


def _pascalize_word(word: str) -> str:
    """Convert a single word to PascalCase, preserving already-capitalized words."""
    if not word:
        return word
    if len(word) > 1 and word.isupper():
        return word
    if word[:1].isupper():
        return word
    return word[:1].upper() + word[1:]


def cpp_type_name(entity_name: str) -> str:
    """Derive the exported C++ type name (PascalCase).

    ``"alg id"`` -> ``"AlgId"``; ``"aes256 gcm"`` -> ``"Aes256Gcm"``;
    ``"status"`` -> ``"Status"``.
    """
    return "".join(_pascalize_word(w) for w in _split_words(entity_name))


def cpp_enum_case(constant_name: str) -> str:
    """Derive a C++ ``enum class`` member name (PascalCase).

    Members are scoped by the enum, so keyword collisions are impossible
    (``Error::Delete`` is fine). ``"bad arguments"`` -> ``"BadArguments"``;
    ``"none"`` -> ``"None"``; ``"aes256 gcm"`` -> ``"Aes256Gcm"``.
    """
    return "".join(_pascalize_word(w) for w in _split_words(constant_name))


def cpp_method_name(method_name: str) -> str:
    """Derive a C++ method name (snake_case), escaping reserved words.

    ``"encrypt data"`` -> ``"encrypt_data"``; ``"delete"`` -> ``"delete_"``.
    """
    snake = "_".join(w.lower() for w in _split_words(method_name))
    return _escape_cpp_keyword(snake)


def cpp_constant_name(constant_name: str) -> str:
    """Derive a C++ constant name (SCREAMING_SNAKE_CASE).

    ``"signature len"`` -> ``"SIGNATURE_LEN"``. Constants use a case distinct from
    methods so a class can expose both ``vscf_ml_dsa_SIGNATURE_LEN`` (the constant) and
    ``vscf_ml_dsa_signature_len`` (a method) without the two colliding in C++."""
    return "_".join(w.upper() for w in _split_words(constant_name))


# ---------------------------------------------------------------------------
# Enum type helpers
# ---------------------------------------------------------------------------

def _c_enum_type(project_ir: IRProject, enum: IREnum) -> str:
    """C type name for an enum (e.g., ``vscf_alg_id_t``)."""
    stem = enum.name.replace(" ", "_").lower()
    return f"{_c_prefix(project_ir)}{stem}_t"


def _header_stem(name: str) -> str:
    """snake_case header stem for an entity (``"aes256 gcm"`` -> ``"aes256_gcm"``)."""
    return name.replace(" ", "_").lower()


def _strip_error_prefix(name: str) -> str:
    """Drop a leading ``error`` word from a status-constant name.

    ``"error bad arguments"`` -> ``"bad arguments"``. Non-``error`` names are
    returned unchanged.
    """
    words = _split_words(name)
    if words and words[0].lower() == "error" and len(words) > 1:
        return " ".join(words[1:])
    return name


def _find_status_enum(project_ir: IRProject) -> IREnum | None:
    for enum in project_ir.enums:
        if enum.name == "status":
            return enum
    return None


# ---------------------------------------------------------------------------
# Emission helpers
# ---------------------------------------------------------------------------

def _format_license(raw: str) -> str:
    """Format raw license text as ``//`` comments."""
    out = []
    for line in raw.splitlines():
        out.append(f"// {line}".rstrip() if line.strip() else "//")
    return "\n".join(out)


def _emit_doc(lines: list[str], description: str, indent: str = "") -> None:
    """Append ``///`` doc-comment lines for a description."""
    doc = description.strip() if description else ""
    if not doc:
        return
    for doc_line in doc.splitlines():
        stripped = doc_line.strip()
        lines.append(f"{indent}/// {stripped}" if stripped else f"{indent}///")


def _header_open(lines: list[str], project_ir: IRProject, includes: list[str],
                 c_forward_decls: list[str] | None = None) -> None:
    """Common header preamble: license, pragma once, includes, optional global-scope
    C forward declarations, namespace open."""
    if _CPP_LICENSE:
        lines.append(_CPP_LICENSE)
        lines.append("")
    lines.append("#pragma once")
    lines.append("")
    for inc in includes:
        lines.append(f"#include {inc}")
    if includes:
        lines.append("")
    if c_forward_decls:
        # C handle types are global; forward-declare them here so the public header
        # need not pull the C library headers (leaner include surface for consumers).
        for fd in c_forward_decls:
            lines.append(f"{fd};")
        lines.append("")
    lines.append(f"namespace {_cpp_namespace(project_ir)} {{")
    lines.append("")


def _header_close(lines: list[str], project_ir: IRProject) -> None:
    lines.append(f"}}  // namespace {_cpp_namespace(project_ir)}")
    lines.append("")


def _source_open(lines: list[str], project_ir: IRProject, includes: list[str]) -> None:
    """.cpp preamble: license, includes, namespace open (no ``#pragma once``)."""
    if _CPP_LICENSE:
        lines.append(_CPP_LICENSE)
        lines.append("")
    for inc in includes:
        lines.append(f"#include {inc}")
    if includes:
        lines.append("")
    lines.append(f"namespace {_cpp_namespace(project_ir)} {{")
    lines.append("")


def _enum_body(lines: list[str], enum: IREnum, type_name: str, underlying: str) -> None:
    """Emit ``enum class <type_name> : <underlying> { ... };`` from the IR constants,
    preserving the C integer values (explicit or auto-incremented)."""
    _emit_doc(lines, enum.description)
    lines.append(f"enum class {type_name} : {underlying} {{")
    next_default = 0
    for const in enum.constants:
        _emit_doc(lines, const.description, indent="    ")
        case = cpp_enum_case(const.name)
        raw_value = const.attrs.get("value")
        if raw_value is None or raw_value == "":
            lines.append(f"    {case} = {next_default},")
            next_default += 1
        else:
            value_str = raw_value.strip()
            lines.append(f"    {case} = {value_str},")
            try:
                next_default = int(value_str, 0) + 1
            except ValueError:
                next_default += 1
    lines.append("};")
    lines.append("")


# ---------------------------------------------------------------------------
# Per-entity generators
# ---------------------------------------------------------------------------

def generate_cpp_enum(project_ir: IRProject, enum: IREnum) -> str:
    """Generate the ``.hpp`` content for a single (non-infrastructure) enum.

    The C header for the corresponding ``vscf_<enum>_t`` type is included so that
    consumers casting between the C++ enum and the C enum (``static_cast<vscf_oid_id_t>``)
    see the C type without depending on it being pulled transitively. Every wrapped
    enum is public-scope (private-scope enums are skipped in generate_cpp_files) and so
    has a dedicated ``vscf_<enum>.h`` header."""
    type_name = cpp_type_name(enum.name)
    ns_path = f"virgil/crypto/{_ns_leaf(project_ir)}"
    c_header = f"<{ns_path}/{project_ir.prefix}_{_entity_snake(enum.name)}.h>"
    lines: list[str] = []
    _header_open(lines, project_ir, ["<cstdint>", c_header])
    _enum_body(lines, enum, type_name, "int")
    _header_close(lines, project_ir)
    return "\n".join(lines)


def generate_cpp_error(project_ir: IRProject) -> str:
    """Generate ``error.hpp``: the per-project ``Error`` enum class derived from
    the C ``status`` enum (non-success values, which are negative)."""
    status = _find_status_enum(project_ir)
    if status is None:
        raise ValueError(f"project {project_ir.name!r} has no 'status' enum")

    lines: list[str] = []
    _header_open(lines, project_ir, ["<cstdint>"])
    lines.append("/// Runtime error reported by the C++ SDK (maps the C status codes).")
    lines.append("/// Only recoverable C status codes appear here; C assertions abort and")
    lines.append("/// are never surfaced as an Error.")
    lines.append("enum class Error : int {")
    for const in status.constants:
        if const.name == "success":
            continue
        _emit_doc(lines, const.description, indent="    ")
        # The C status constants are prefixed "error ..."; the enum-class scope
        # already conveys that (Error::BadArguments), so drop the redundant word.
        case = cpp_enum_case(_strip_error_prefix(const.name))
        value = const.attrs.get("value", "0").strip()
        lines.append(f"    {case} = {value},")
    lines.append("};")
    lines.append("")
    _header_close(lines, project_ir)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Class generation (RAII wrappers)
# ---------------------------------------------------------------------------

def _entity_snake(name: str) -> str:
    return name.replace(" ", "_").lower()


def _c_func_name(project_ir: IRProject, entity_name: str, method_name: str) -> str:
    return f"{project_ir.prefix}_{_entity_snake(entity_name)}_{_entity_snake(method_name)}"


def _c_type(project_ir: IRProject, entity_name: str) -> str:
    return f"{project_ir.prefix}_{_entity_snake(entity_name)}_t"


def _c_enum_type_by_name(project_ir: IRProject, enum_name: str) -> str:
    return f"{project_ir.prefix}_{_entity_snake(enum_name)}_t"


def _is_static_class(cls: IRClass) -> bool:
    """Static-only classes (``context="none"``) carry no C handle."""
    return cls.attrs.get("context") == "none"


def _method_should_wrap(method: IRCMethod) -> bool:
    scope = method.attrs.get("scope", "public")
    decl = method.declaration or method.attrs.get("declaration", "public")
    vis = method.visibility or method.attrs.get("visibility", "public")
    return scope == "public" and decl == "public" and vis == "public"


def _impl_own_method_is_public(method: IRCMethod) -> bool:
    """Implementation-specific methods are private by default; only those explicitly
    marked ``declaration="public"`` belong to the public C API. (Interface-bound
    methods reach the public API through their interface, not here.) Unmarked impl
    methods — e.g. ``vscf_alg_info_der_deserializer_deserialize_simple_alg_info`` — are
    internal helpers that live only in the ``.c`` and are absent from the public
    header, so wrapping them produces calls to undeclared C functions. This differs
    from ``<class>`` methods, which default to public and opt out via
    ``declaration="private"`` (handled by _method_should_wrap)."""
    if not _method_should_wrap(method):
        return False
    return (method.declaration or method.attrs.get("declaration")) == "public"


def _method_is_static(method: IRCMethod) -> bool:
    return method.attrs.get("is_static") == "1"


def _method_is_const(method: IRCMethod) -> bool:
    """Whether the method reads but does not mutate the object (IR ``is_const``),
    so it can be a C++ ``const`` member function. Static methods are never const."""
    return method.attrs.get("is_const") in {"1", "true"} and not _method_is_static(method)


def _arg_is_buffer_output(arg: IRCArgument) -> bool:
    return arg.class_name == "buffer"


def _arg_should_skip(arg: IRCArgument) -> bool:
    return arg.access == "writeonly" or arg.class_name == "error"


def _method_has_status_return(method: IRCMethod) -> bool:
    return any(r.enum_name == "status" for r in method.returns)


def _method_has_error_arg(method: IRCMethod) -> bool:
    return any(a.class_name == "error" for a in method.arguments)


def _resolve_self(entity_name: str, arg: IRCArgument) -> IRCArgument:
    """Return a shallow copy of ``arg`` with ``class="self"`` resolved to the
    enclosing class name."""
    if arg.class_name == "self":
        import copy as _copy
        clone = _copy.copy(arg)
        clone.class_name = entity_name
        return clone
    return arg


_INT_MAP = {"1": "int8_t", "2": "int16_t", "4": "int32_t", "8": "int64_t"}
_UINT_MAP = {"1": "uint8_t", "2": "uint16_t", "4": "uint32_t", "8": "uint64_t"}


def _cpp_scalar_type(arg: IRCArgument) -> str:
    tn = (arg.type_name or "").lower()
    if tn == "size":
        return "std::size_t"
    if tn == "boolean":
        return "bool"
    if tn == "integer":
        return _INT_MAP.get(arg.type_size or "4", "int32_t")
    if tn == "unsigned":
        return _UINT_MAP.get(arg.type_size or "4", "uint32_t")
    if tn in ("string", "char") or arg.is_string:
        # Input strings are non-owning views (cheap, accept literals/std::string).
        # Owning returns override this in _cpp_value_type (a view would dangle).
        return "std::string_view"
    if tn == "byte":
        return "uint8_t*" if (arg.is_array or arg.is_reference) else "uint8_t"
    return "void"


def _project_impl_type(project_ir: IRProject) -> str:
    return f"{cpp_type_name(project_ir.name)}Implementation"


# project name -> (C++ namespace leaf, C symbol prefix). Used to resolve
# cross-project references (e.g. a phe/ratchet class depending on a foundation
# interface) to the right namespace and header path.
_CPP_PROJECT_NS = {
    "common": ("common", "vsc"),
    "foundation": ("foundation", "vscf"),
    "ratchet": ("ratchet", "vscr"),
    "phe": ("phe", "vsce"),
}


def _ref_leaf(project_ir: IRProject, ref_project: str | None) -> str | None:
    """Namespace leaf for a referenced type's project, or ``None`` when the
    reference is local (same project / unset)."""
    if ref_project and ref_project != project_ir.name:
        entry = _CPP_PROJECT_NS.get(ref_project)
        if entry:
            return entry[0]
    return None


def _qual_type_name(project_ir: IRProject, type_name: str, ref_project: str | None) -> str:
    """PascalCase C++ type name, namespace-qualified when it lives in another
    project (``virgil::crypto::foundation::PrivateKey``)."""
    tn = cpp_type_name(type_name)
    leaf = _ref_leaf(project_ir, ref_project)
    return f"virgil::crypto::{leaf}::{tn}" if leaf else tn


def _ref_include(project_ir: IRProject, type_name: str, ref_project: str | None) -> str:
    """Wrapper-header include path for a referenced type, in its owning project's
    directory (cross-project references point at e.g. ``foundation/``)."""
    leaf = _ref_leaf(project_ir, ref_project) or _ns_leaf(project_ir)
    return f"virgil/crypto/{leaf}/{_entity_snake(type_name)}.hpp"


def _ref_prefix(project_ir: IRProject, ref_project: str | None) -> str:
    """C symbol prefix for a referenced type's project (``vscf`` for a foundation
    type referenced from phe/ratchet), defaulting to the current project's."""
    if ref_project and ref_project != project_ir.name:
        entry = _CPP_PROJECT_NS.get(ref_project)
        if entry:
            return entry[1]
    return project_ir.prefix


def _ref_project_impl_type(project_ir: IRProject, ref_project: str | None) -> str:
    """Namespace-qualified ``<Project>Implementation`` dispatcher for a referenced
    interface's owning project (cross-project returns dispatch via that project)."""
    leaf = _ref_leaf(project_ir, ref_project)
    if leaf:
        return f"virgil::crypto::{leaf}::{cpp_type_name(ref_project)}Implementation"
    return _project_impl_type(project_ir)


def _cpp_value_type(project_ir: IRProject, arg: IRCArgument) -> str:
    """C++ type for a value argument or return (not a buffer output)."""
    if arg.enum_name:
        return _qual_type_name(project_ir, arg.enum_name, arg.project)
    if arg.interface_name:
        # Interfaces are abstract; a returned impl is owned polymorphically.
        return f"std::unique_ptr<{_qual_type_name(project_ir, arg.interface_name, arg.project)}>"
    if arg.class_name in {"data", "buffer"}:
        # returned data / an owned vsc_buffer_t* both surface as an owned vector
        return "std::vector<uint8_t>"
    if arg.class_name:
        return _qual_type_name(project_ir, arg.class_name, arg.project)
    if arg.is_string or (arg.type_name or "").lower() in {"string", "char"}:
        return "std::string"  # a returned std::string_view would dangle
    return _cpp_scalar_type(arg)


def _cpp_param_type(project_ir: IRProject, arg: IRCArgument) -> str:
    """C++ parameter type for an input argument."""
    if arg.enum_name:
        return _qual_type_name(project_ir, arg.enum_name, arg.project)
    if arg.interface_name:
        return f"const {_qual_type_name(project_ir, arg.interface_name, arg.project)}&"
    if arg.class_name == "data":
        return "std::span<const uint8_t>"
    if arg.class_name and arg.class_name not in {"data", "buffer"}:
        return f"const {_qual_type_name(project_ir, arg.class_name, arg.project)}&"
    # std::string_view and the numeric scalars are all cheap to pass by value.
    return _cpp_scalar_type(arg)


def _method_inputs(entity_name: str, method: IRCMethod) -> list[IRCArgument]:
    out = []
    for a in (_resolve_self(entity_name, a) for a in method.arguments):
        if _arg_is_buffer_output(a) or _arg_should_skip(a):
            continue
        out.append(a)
    return out


def _method_value_returns(entity_name: str, method: IRCMethod) -> list[IRCArgument]:
    return [
        _resolve_self(entity_name, r)
        for r in method.returns
        if r.enum_name != "status"
    ]


def _result_struct_name(entity_name: str, method_name: str) -> str:
    return cpp_type_name(entity_name) + cpp_type_name(method_name) + "Result"


def _cpp_inner_return_type(project_ir: IRProject, entity_name: str, method: IRCMethod) -> str:
    values = _method_value_returns(entity_name, method)
    buffers = [a for a in method.arguments if _arg_is_buffer_output(a)]
    total = len(values) + len(buffers)
    if total == 0:
        return "void"
    if total == 1:
        if values:
            return _cpp_value_type(project_ir, values[0])
        return "std::vector<uint8_t>"
    return _result_struct_name(entity_name, method.name)


def _cpp_signature_return(project_ir: IRProject, entity_name: str, method: IRCMethod) -> str:
    inner = _cpp_inner_return_type(project_ir, entity_name, method)
    if _method_has_status_return(method) or _method_has_error_arg(method):
        return f"tl::expected<{inner}, Error>"
    return inner


def _buffer_capacity_expr(project_ir, entity_name, arg, is_static, call_entity=None):
    """C++ expression for a buffer output's capacity, from ``length_attrs``.

    ``call_entity`` (defaults to ``entity_name``) owns any ``self``-referenced
    constants/methods. On an interface override it differs from ``entity_name``:
    the signature belongs to the abstract interface, but a length constant like
    ``DIGEST_LEN`` lives on the concrete implementation (e.g. ``Sha256::digest_len``),
    not on the interface (``Hash`` has no such member)."""
    la = arg.length_attrs
    if not la:
        return "0"
    call_entity = call_entity or entity_name
    caller = f"{cpp_type_name(call_entity)}::" if is_static else "this->"
    if "method" in la:
        meth = cpp_method_name(la["method"])
        parts = []
        idx = 0
        while f"proxy_{idx}_to" in la:
            cast = la.get(f"proxy_{idx}_cast")
            src_arg = la.get(f"proxy_{idx}_argument")
            src_const = la.get(f"proxy_{idx}_constant")
            if src_const is not None:
                parts.append(src_const)
            elif src_arg is not None:
                local = cpp_method_name(src_arg)
                parts.append(f"{local}.size()" if cast == "data_length" else local)
            idx += 1
        return f"{caller}{meth}({', '.join(parts)})"
    if "constant" in la:
        const_name = cpp_constant_name(la["constant"])
        owner = la.get("class")
        if owner and owner != "self":
            return f"{cpp_type_name(owner)}::{const_name}"
        return f"{caller}{const_name}"
    if "argument" in la:
        local = cpp_method_name(la["argument"])
        return f"{local}.size()" if la.get("cast") == "data_length" else local
    return "0"


def _c_call_args(project_ir, entity_name, method, is_static):
    """Build the C call argument expressions (excluding the leading self handle)."""
    parts: list[str] = []
    for arg in (_resolve_self(entity_name, a) for a in method.arguments):
        if arg.class_name == "error":
            parts.append("&error")
            continue
        if _arg_should_skip(arg) and not _arg_is_buffer_output(arg):
            continue
        local = cpp_method_name(arg.name)
        if _arg_is_buffer_output(arg):
            parts.append(f"&{local}_buf")
        elif arg.class_name == "data":
            parts.append(f"vsc_data({local}.data(), {local}.size())")
        elif arg.interface_name:
            # A ``disown`` object argument transfers ownership: the C signature is
            # ``vscf_impl_t **`` and the callee steals + nulls the handle. Pass the
            # address of a shallow-copied temp (built in _cpp_method_body) so the
            # caller's wrapper keeps owning its own object.
            parts.append(f"&{local}_ref" if arg.access == "disown" else f"{local}.impl()")
        elif arg.class_name and arg.class_name not in {"data", "buffer"}:
            parts.append(f"&{local}_ref" if arg.access == "disown" else f"{local}.c_ctx()")
        elif arg.enum_name:
            c_enum = _c_enum_type_by_name(project_ir, arg.enum_name)
            parts.append(f"static_cast<{c_enum}>({local})")
        elif arg.is_string or (arg.type_name or "").lower() in {"string", "char"}:
            # C takes a null-terminated ``const char *``; the parameter is a
            # (non-null-terminated) std::string_view, so materialise a std::string.
            parts.append(f"std::string({local}).c_str()")
        else:
            parts.append(local)
    return parts


def _cpp_return_expr(project_ir, ret: IRCArgument, c_expr: str) -> str:
    if ret.class_name == "data":
        return f"std::vector<uint8_t>({c_expr}.bytes, {c_expr}.bytes + {c_expr}.len)"
    if ret.enum_name:
        return f"static_cast<{_qual_type_name(project_ir, ret.enum_name, ret.project)}>({c_expr})"
    # A returned handle may belong to another project (e.g. a phe method returning a
    # foundation type): the shallow_copy, C type, wrapper type, and dispatcher must all
    # use that project's prefix/namespace, not the current one.
    prefix = _ref_prefix(project_ir, ret.project)
    # Ownership of a returned C handle is encoded in ``access``: ``disown`` transfers
    # ownership to the caller (adopt directly), while ``readonly``/``readwrite`` return
    # a borrowed reference the callee still owns — the C signature is then ``const T*``.
    # A RAII wrapper always deletes what it holds, so a borrowed handle must be
    # shallow-copied first, otherwise the wrapper double-frees the callee's object.
    # ``const_cast`` is a no-op for the ``readwrite`` (non-const) case and legalises the
    # ``readonly`` (``const T*``) case for the non-const ``_shallow_copy``.
    owned = ret.access == "disown"
    if ret.interface_name:
        adopt = (c_expr if owned
                 else f"{prefix}_impl_shallow_copy(const_cast<{prefix}_impl_t*>({c_expr}))")
        dispatcher = _ref_project_impl_type(project_ir, ret.project)
        return f"{dispatcher}::wrap_{_entity_snake(ret.interface_name)}({adopt})"
    if ret.class_name and ret.class_name not in {"data", "buffer"}:
        c_t = f"{prefix}_{_entity_snake(ret.class_name)}_t"
        adopt = (c_expr if owned
                 else f"{prefix}_{_entity_snake(ret.class_name)}_shallow_copy(const_cast<{c_t}*>({c_expr}))")
        return f"{_qual_type_name(project_ir, ret.class_name, ret.project)}({adopt})"
    return c_expr


def _cpp_method_body(project_ir: IRProject, entity_name: str, method: IRCMethod,
                     call_entity: str | None = None) -> list[str]:
    # ``entity_name`` drives signature/arg/return resolution (matches the
    # declaration); ``call_entity`` names the C functions to call. They differ
    # for interface methods on an implementation: the signature is the
    # interface's, but the body calls ``vscf_<impl>_<method>``.
    call_entity = call_entity or entity_name
    prefix = project_ir.prefix
    is_static = _method_is_static(method)
    c_func = _c_func_name(project_ir, call_entity, method.name)
    has_status = _method_has_status_return(method)
    has_error_arg = _method_has_error_arg(method)
    has_error = has_status or has_error_arg
    values = _method_value_returns(entity_name, method)
    buffers = [a for a in method.arguments if _arg_is_buffer_output(a)]

    ind = "    "  # method bodies are emitted out-of-line in the .cpp (function scope)
    lines: list[str] = []

    if has_error_arg:
        lines.append(f"{ind}{prefix}_error_t error;")
        lines.append(f"{ind}{prefix}_error_reset(&error);")

    for buf in buffers:
        local = cpp_method_name(buf.name)
        cap = _buffer_capacity_expr(project_ir, entity_name, buf, is_static, call_entity)
        lines.append(f"{ind}std::vector<uint8_t> {local}({cap});")
        # The buffer control block wraps external (vector) memory, so it lives on the
        # stack — no heap allocation. This needs the complete vsc_buffer_t type, which
        # the .cpp pulls from private/vsc_buffer_defs.h (never exposed to consumers).
        lines.append(f"{ind}vsc_buffer_t {local}_buf;")
        lines.append(f"{ind}vsc_buffer_init(&{local}_buf);")
        lines.append(f"{ind}vsc_buffer_use(&{local}_buf, {local}.data(), {local}.size());")

    # ``disown`` object arguments: the callee adopts (and nulls) a ``vscf_*_t **`` handle.
    # Hand it a shallow copy so the caller's wrapper keeps ownership of its own object.
    for arg in (_resolve_self(entity_name, a) for a in method.arguments):
        if arg.access != "disown":
            continue
        local = cpp_method_name(arg.name)
        if arg.interface_name:
            lines.append(f"{ind}{prefix}_impl_t* {local}_ref = {prefix}_impl_shallow_copy({local}.impl());")
        elif arg.class_name and arg.class_name not in {"data", "buffer", "error"}:
            c_t = _c_type(project_ir, arg.class_name)
            snake = _entity_snake(arg.class_name)
            lines.append(f"{ind}{c_t}* {local}_ref = {prefix}_{snake}_shallow_copy({local}.c_ctx());")

    call_args = _c_call_args(project_ir, entity_name, method, is_static)
    if not is_static:
        call_args.insert(0, "c_ctx_")
    c_call = f"{c_func}({', '.join(call_args)})"

    capture_value = bool(values) and not has_status
    if has_status:
        lines.append(f"{ind}const {prefix}_status_t status = {c_call};")
    elif capture_value:
        lines.append(f"{ind}auto proxy_result = {c_call};")
    else:
        lines.append(f"{ind}{c_call};")

    for buf in buffers:
        local = cpp_method_name(buf.name)
        lines.append(f"{ind}{local}.resize(vsc_buffer_len(&{local}_buf));")
        lines.append(f"{ind}vsc_buffer_cleanup(&{local}_buf);")

    if has_status:
        lines.append(f"{ind}if (status != {prefix}_status_SUCCESS) {{")
        lines.append(f"{ind}    return tl::unexpected(static_cast<Error>(status));")
        lines.append(f"{ind}}}")
    elif has_error_arg:
        lines.append(f"{ind}if ({prefix}_error_has_error(&error)) {{")
        lines.append(f"{ind}    return tl::unexpected(static_cast<Error>({prefix}_error_status(&error)));")
        lines.append(f"{ind}}}")

    total = len(values) + len(buffers)
    if total == 0:
        if has_error:
            lines.append(f"{ind}return {{}};")
    elif total == 1 and not buffers and values[0].class_name == "buffer":
        # A vsc_buffer_t* return: copy the bytes out into a vector. Only free it when
        # the callee transferred ownership (access="disown"); a borrowed buffer
        # (readonly/readwrite) is still owned by the callee — deleting it would be a
        # double-free / use-after-free.
        lines.append(f"{ind}std::vector<uint8_t> result(vsc_buffer_bytes(proxy_result), "
                     f"vsc_buffer_bytes(proxy_result) + vsc_buffer_len(proxy_result));")
        if values[0].access == "disown":
            lines.append(f"{ind}vsc_buffer_delete(proxy_result);")
        lines.append(f"{ind}return result;")
    elif total == 1 and not buffers:
        lines.append(f"{ind}return {_cpp_return_expr(project_ir, values[0], 'proxy_result')};")
    elif total == 1 and buffers:
        lines.append(f"{ind}return {cpp_method_name(buffers[0].name)};")
    else:
        parts = []
        for ret in values:
            parts.append(f".{cpp_method_name(ret.name)} = {_cpp_return_expr(project_ir, ret, 'proxy_result')}")
        for buf in buffers:
            local = cpp_method_name(buf.name)
            parts.append(f".{local} = std::move({local})")
        struct = _result_struct_name(entity_name, method.name)
        lines.append(f"{ind}return {struct}{{{', '.join(parts)}}};")

    return lines


def _emit_result_structs(lines, project_ir, entity_name, methods):
    for method in methods:
        if not _method_should_wrap(method):
            continue
        values = _method_value_returns(entity_name, method)
        buffers = [a for a in method.arguments if _arg_is_buffer_output(a)]
        if len(values) + len(buffers) < 2:
            continue
        name = _result_struct_name(entity_name, method.name)
        lines.append(f"/// Result of {cpp_type_name(entity_name)}::{cpp_method_name(method.name)}().")
        lines.append(f"struct {name} {{")
        for ret in values:
            lines.append(f"    {_cpp_value_type(project_ir, ret)} {cpp_method_name(ret.name)};")
        for buf in buffers:
            lines.append(f"    std::vector<uint8_t> {cpp_method_name(buf.name)};")
        lines.append("};")
        lines.append("")


def _cpp_constant_type(const) -> str:
    t = (const.attrs.get("type") or "size").lower()
    if t == "boolean":
        return "bool"
    if t == "integer":
        return "int"
    return "std::size_t"


def _uses_output_buffer(methods) -> bool:
    """Whether any method needs the vsc_buffer API in its body — either a buffer
    output argument (init/use/cleanup) or a ``vsc_buffer_t*`` return (bytes/len/delete)."""
    for m in methods:
        if any(_arg_is_buffer_output(a) for a in m.arguments):
            return True
        if any(r.class_name == "buffer" for r in m.returns):
            return True
    return False


_COMMON_NS_PATH = "virgil/crypto/common"
_BUFFER_DEF_INCLUDES = [
    f"<{_COMMON_NS_PATH}/vsc_buffer.h>",
    f"<{_COMMON_NS_PATH}/private/vsc_buffer_defs.h>",
]


def _result_struct_member_classes(project_ir, entity_name, methods) -> set[str]:
    """Local class names appearing as by-value members of a result struct — those
    need the complete type in the .hpp (the struct is defined there)."""
    names: set[str] = set()
    for m in methods:
        if not _method_should_wrap(m):
            continue
        values = _method_value_returns(entity_name, m)
        buffers = [a for a in m.arguments if _arg_is_buffer_output(a)]
        if len(values) + len(buffers) < 2:
            continue
        for v in values:
            if (v.class_name and not v.interface_name
                    and v.class_name not in {"data", "buffer", "error"}
                    and not _ref_leaf(project_ir, v.project)):
                names.add(v.class_name)
    return names


def _hpp_ref_split(project_ir, entity_name, methods, deps):
    """(#include paths, forward-declared C++ type names) for a class/impl .hpp.

    The .hpp holds only declarations, so referenced wrapper types are forward-declared
    (avoids include cycles and keeps the header lean). Exceptions that need the complete
    type in the header, and so are #included: enums (by-value params/returns),
    cross-project types (a forward decl cannot re-open another project's namespace), and
    local classes used as by-value result-struct members."""
    includes: list[str] = []
    fwd: list[str] = []
    rs_members = _result_struct_member_classes(project_ir, entity_name, methods)

    def _add(name, project, is_iface):
        if _ref_leaf(project_ir, project) or (not is_iface and name in rs_members):
            includes.append(_ref_include(project_ir, name, project))
        else:
            fwd.append(cpp_type_name(name))

    for m in methods:
        if not _method_should_wrap(m):
            continue
        for a in list(m.arguments) + list(m.returns):
            a = _resolve_self(entity_name, a)
            if a.enum_name and a.enum_name not in _INFRASTRUCTURE_ENUMS:
                includes.append(_ref_include(project_ir, a.enum_name, a.project))
            elif a.interface_name:
                _add(a.interface_name, a.project, True)
            elif a.class_name and a.class_name not in {"data", "buffer", "error", entity_name}:
                _add(a.class_name, a.project, False)
    for d in deps:
        _add(d.type_name, d.attrs.get("project"), d.type_kind != "class")
    return sorted(set(includes)), sorted(set(fwd))


def _class_def_includes(project_ir, entity_name, methods, deps, *, returns_iface,
                        iface_names=()):
    """.cpp includes: the entity's own .hpp + the full C world it calls into."""
    ns_path = f"virgil/crypto/{_ns_leaf(project_ir)}"
    incs = [
        f"<{ns_path}/{_header_stem(entity_name)}.hpp>",
        f"<{ns_path}/{project_ir.prefix}_{_entity_snake(entity_name)}.h>",
    ]
    # The project's own impl infrastructure header exists only when it has interfaces
    # (foundation). phe/ratchet reach foundation's vscf_impl_t transitively via their
    # own C headers, so must not include a non-existent vsce_impl.h / vscr_impl.h.
    if project_ir.interfaces:
        incs.append(f"<{ns_path}/{project_ir.prefix}_impl.h>")
    for name in iface_names:
        incs.append(f"<{ns_path}/{_entity_snake(name)}.hpp>")
    for inc in _referenced_wrapper_includes(project_ir, entity_name, methods, deps):
        incs.append(f"<{inc}>")
    if returns_iface:
        incs.append(f"<{ns_path}/{_header_stem(project_ir.name)}_implementation.hpp>")
    if _uses_output_buffer(methods):
        incs += _BUFFER_DEF_INCLUDES
    return _dedup(incs)


def _emit_raii_decls(lines, type_name, c_type):
    """Declare the rule-of-five lifecycle + the c_ctx() accessor (in the .hpp);
    definitions are emitted out-of-line by _emit_raii_defs."""
    lines.append(f"    {type_name}();")
    lines.append(f"    /// Adopt ownership of an existing C handle.")
    lines.append(f"    explicit {type_name}({c_type}* c_ctx) noexcept;")
    lines.append(f"    {type_name}(const {type_name}& other);")
    lines.append(f"    {type_name}({type_name}&& other) noexcept;")
    lines.append(f"    {type_name}& operator=(const {type_name}& other);")
    lines.append(f"    {type_name}& operator=({type_name}&& other) noexcept;")
    lines.append(f"    ~{type_name}();")
    lines.append("")
    lines.append(f"    /// The underlying concrete C handle (non-owning).")
    lines.append(f"    {c_type}* c_ctx() const noexcept;")
    lines.append("")


def _emit_raii_defs(lines, type_name, c_type, prefix, entity):
    """Emit the out-of-line rule-of-five definitions (in the .cpp)."""
    lines.append(f"{type_name}::{type_name}() : c_ctx_({prefix}_{entity}_new()) {{}}")
    lines.append("")
    lines.append(f"{type_name}::{type_name}({c_type}* c_ctx) noexcept : c_ctx_(c_ctx) {{}}")
    lines.append("")
    lines.append(f"{type_name}::{type_name}(const {type_name}& other) : c_ctx_({prefix}_{entity}_shallow_copy(other.c_ctx_)) {{}}")
    lines.append("")
    lines.append(f"{type_name}::{type_name}({type_name}&& other) noexcept : c_ctx_(other.c_ctx_) {{ other.c_ctx_ = nullptr; }}")
    lines.append("")
    lines.append(f"{type_name}& {type_name}::operator=(const {type_name}& other) {{")
    lines.append(f"    if (this != &other) {{")
    lines.append(f"        {prefix}_{entity}_delete(c_ctx_);")
    lines.append(f"        c_ctx_ = {prefix}_{entity}_shallow_copy(other.c_ctx_);")
    lines.append(f"    }}")
    lines.append(f"    return *this;")
    lines.append(f"}}")
    lines.append("")
    lines.append(f"{type_name}& {type_name}::operator=({type_name}&& other) noexcept {{")
    lines.append(f"    if (this != &other) {{")
    lines.append(f"        {prefix}_{entity}_delete(c_ctx_);")
    lines.append(f"        c_ctx_ = other.c_ctx_;")
    lines.append(f"        other.c_ctx_ = nullptr;")
    lines.append(f"    }}")
    lines.append(f"    return *this;")
    lines.append(f"}}")
    lines.append("")
    lines.append(f"{type_name}::~{type_name}() {{ {prefix}_{entity}_delete(c_ctx_); }}")
    lines.append("")
    lines.append(f"{c_type}* {type_name}::c_ctx() const noexcept {{ return c_ctx_; }}")
    lines.append("")


def _referenced_wrapper_includes(project_ir, entity_name, methods, deps):
    """Wrapper-header include paths referenced by a set of methods + deps, each in
    its owning project's directory (cross-project references — e.g. a phe class
    depending on a foundation interface — point at ``foundation/``)."""
    ref: set[str] = set()
    for m in methods:
        if not _method_should_wrap(m):
            continue
        for a in list(m.arguments) + list(m.returns):
            a = _resolve_self(entity_name, a)
            if a.enum_name and a.enum_name not in _INFRASTRUCTURE_ENUMS:
                ref.add(_ref_include(project_ir, a.enum_name, a.project))
            elif a.interface_name:
                ref.add(_ref_include(project_ir, a.interface_name, a.project))
            elif a.class_name and a.class_name not in {"data", "buffer", "error", entity_name}:
                ref.add(_ref_include(project_ir, a.class_name, a.project))
            # A buffer's capacity may reference a constant/method on another class
            # (e.g. PheCommon::PHE_PRIVATE_KEY_LENGTH) — that class's header is needed.
            owner = a.length_attrs.get("class") if _arg_is_buffer_output(a) else None
            if owner and owner != "self" and owner != entity_name:
                ref.add(_ref_include(project_ir, owner, None))
    for d in deps:
        ref.add(_ref_include(project_ir, d.type_name, d.attrs.get("project")))
    return sorted(ref)


def _interface_ref_split(project_ir, iface):
    """Split an interface's referenced wrapper types into (include paths, local
    class/interface PascalCase names to forward-declare). Local class/interface refs
    are forward-declared (see generate_cpp_interface for the cycle they'd otherwise
    create); enums and *cross-project* class/interface refs are included, since a
    forward declaration cannot re-open another project's namespace and cross-project
    headers (e.g. foundation) never cycle back into this project."""
    includes: list[str] = []
    fwd: list[str] = []
    # By-value result-struct members need the complete type in this header (the struct
    # is defined here), so they are #included even when local — same rule as _hpp_ref_split.
    rs_members = _result_struct_member_classes(project_ir, iface.name, iface.methods)

    def _add(type_name, project, is_iface):
        if _ref_leaf(project_ir, project) or (not is_iface and type_name in rs_members):
            includes.append(_ref_include(project_ir, type_name, project))
        else:
            fwd.append(cpp_type_name(type_name))

    for m in iface.methods:
        if not _method_should_wrap(m):
            continue
        for a in list(m.arguments) + list(m.returns):
            a = _resolve_self(iface.name, a)
            if a.enum_name and a.enum_name not in _INFRASTRUCTURE_ENUMS:
                includes.append(_ref_include(project_ir, a.enum_name, a.project))
            elif a.interface_name:
                _add(a.interface_name, a.project, True)
            elif a.class_name and a.class_name not in {"data", "buffer", "error", iface.name}:
                _add(a.class_name, a.project, False)
    return sorted(set(includes)), sorted(set(fwd))


def _dep_setter_return_type(dep) -> str:
    """A validating ``use_<dep>`` (marked ``is_observers_return_status``, e.g.
    ``vscf_ctr_drbg_use_entropy_source`` which is ``VSCF_NODISCARD``) returns a status,
    so its setter returns ``expected<void, Error>``; otherwise ``void``."""
    return "tl::expected<void, Error>" if dep.is_observers_return_status else "void"


def _emit_dependency_setter_decl(lines, project_ir, dep):
    dep_snake = _entity_snake(dep.name)
    dep_type = _qual_type_name(project_ir, dep.type_name, dep.attrs.get("project"))
    local = cpp_method_name(dep.name)
    lines.append(f"    {_dep_setter_return_type(dep)} set_{dep_snake}(const {dep_type}& {local});")
    lines.append("")


def _emit_dependency_setter_def(lines, project_ir, type_name, entity, dep):
    prefix = project_ir.prefix
    dep_snake = _entity_snake(dep.name)
    dep_type = _qual_type_name(project_ir, dep.type_name, dep.attrs.get("project"))
    local = cpp_method_name(dep.name)
    use = f"{prefix}_{entity}_use_{dep_snake}(c_ctx_, {_dep_handle_expr(dep, local)})"
    ret = _dep_setter_return_type(dep)
    lines.append(f"{ret} {type_name}::set_{dep_snake}(const {dep_type}& {local}) {{")
    lines.append(f"    {prefix}_{entity}_release_{dep_snake}(c_ctx_);")
    if dep.is_observers_return_status:
        lines.append(f"    const {prefix}_status_t status = {use};")
        lines.append(f"    if (status != {prefix}_status_SUCCESS) {{")
        lines.append(f"        return tl::unexpected(static_cast<Error>(status));")
        lines.append(f"    }}")
        lines.append(f"    return {{}};")
    else:
        lines.append(f"    {use};")
    lines.append(f"}}")
    lines.append("")


def _dep_handle_expr(dep, local: str) -> str:
    """C handle expression for passing a dependency to a ``use_<dep>`` C call.

    Interface/impl dependencies take the polymorphic ``vscf_impl_t*`` (``.impl()``);
    a ``class``-typed dependency takes the concrete ``vscf_<class>_t*`` (``.c_ctx()``),
    e.g. ``vscf_curve25519_use_ecies(self, vscf_ecies_t *ecies)`` where ``Ecies`` is a
    plain class with no ``impl()`` accessor."""
    return f"{local}.c_ctx()" if dep.type_kind == "class" else f"{local}.impl()"


def _returns_interface(project_ir, entity_name, methods) -> bool:
    for m in methods:
        if not _method_should_wrap(m):
            continue
        for r in m.returns:
            if _resolve_self(entity_name, r).interface_name:
                return True
    return False


def _base_std_includes(needs_memory: bool) -> list[str]:
    inc = ["<cstddef>", "<cstdint>", "<span>", "<string>", "<string_view>", "<vector>", "<tl/expected.hpp>"]
    if needs_memory:
        inc.append("<memory>")
    return inc


def _dedup(items: list[str]) -> list[str]:
    seen: set[str] = set()
    return [i for i in items if not (i in seen or seen.add(i))]


def _method_params(project_ir, sig_entity, method):
    return ", ".join(
        f"{_cpp_param_type(project_ir, a)} {cpp_method_name(a.name)}"
        for a in _method_inputs(sig_entity, method)
    )


def _emit_method_decl(lines, project_ir, method, *, sig_entity, static_kw="", override_kw=""):
    """Emit a method declaration (doc + signature + ``;``) inside the class body (.hpp)."""
    ret = _cpp_signature_return(project_ir, sig_entity, method)
    params = _method_params(project_ir, sig_entity, method)
    const_kw = " const" if _method_is_const(method) else ""
    _emit_doc(lines, method.description, indent="    ")
    lines.append(f"    {static_kw}{ret} {cpp_method_name(method.name)}({params}){const_kw}{override_kw};")
    lines.append("")


def _emit_method_def(lines, project_ir, method, *, type_name, sig_entity, call_entity=None):
    """Emit an out-of-line method definition (.cpp). ``static``/``virtual``/``override``
    are omitted (declaration-only), ``const`` is kept, and the name is qualified with
    ``<type_name>::``."""
    ret = _cpp_signature_return(project_ir, sig_entity, method)
    params = _method_params(project_ir, sig_entity, method)
    const_kw = " const" if _method_is_const(method) else ""
    lines.append(f"{ret} {type_name}::{cpp_method_name(method.name)}({params}){const_kw} {{")
    lines.extend(_cpp_method_body(project_ir, sig_entity, method, call_entity=call_entity))
    lines.append("}")
    lines.append("")


def generate_cpp_class(project_ir: IRProject, cls: IRClass) -> tuple[str, str]:
    """Generate ``(header, source)`` for a class as an idiomatic RAII wrapper.

    The header holds declarations only (forward-declaring the C handle so consumers
    don't pull the C library); the source defines the bodies against the full C API."""
    type_name = cpp_type_name(cls.name)
    c_type = _c_type(project_ir, cls.name)
    entity = _entity_snake(cls.name)
    prefix = project_ir.prefix
    is_static = _is_static_class(cls)
    methods = [m for m in cls.methods if _method_should_wrap(m)]
    returns_iface = _returns_interface(project_ir, cls.name, cls.methods)
    consts = [c for c in cls.constants
              if c.attrs.get("definition") != "private"
              and (c.attrs.get("value") or "").strip().lstrip("-").isdigit()]

    # ---- Header (declarations) ----
    ref_incs, fwd = _hpp_ref_split(project_ir, cls.name, cls.methods, cls.dependencies)
    incs = _base_std_includes(returns_iface)
    incs.append(f"<virgil/crypto/{_ns_leaf(project_ir)}/error.hpp>")
    incs += [f"<{i}>" for i in ref_incs]
    c_fwd = [] if is_static else [f"struct {c_type}"]

    h: list[str] = []
    _header_open(h, project_ir, _dedup(incs), c_forward_decls=c_fwd)
    for f in fwd:
        h.append(f"class {f};")
    if fwd:
        h.append("")
    _emit_result_structs(h, project_ir, cls.name, cls.methods)
    _emit_doc(h, cls.description)
    h.append(f"class {type_name} {{")
    h.append("public:")
    if not is_static:
        _emit_raii_decls(h, type_name, c_type)
    for const in consts:
        _emit_doc(h, const.description, indent="    ")
        h.append(f"    static constexpr {_cpp_constant_type(const)} {cpp_constant_name(const.name)} = {const.attrs['value'].strip()};")
        h.append("")
    if not is_static:
        for dep in cls.dependencies:
            _emit_dependency_setter_decl(h, project_ir, dep)
    for method in methods:
        static_kw = "static " if (is_static or _method_is_static(method)) else ""
        _emit_method_decl(h, project_ir, method, sig_entity=cls.name, static_kw=static_kw)
    if not is_static:
        h.append("private:")
        h.append(f"    {c_type}* c_ctx_;")
    h.append("};")
    h.append("")
    _header_close(h, project_ir)

    # ---- Source (definitions) ----
    s: list[str] = []
    _source_open(s, project_ir, _class_def_includes(
        project_ir, cls.name, cls.methods, cls.dependencies, returns_iface=returns_iface))
    if not is_static:
        _emit_raii_defs(s, type_name, c_type, prefix, entity)
        for dep in cls.dependencies:
            _emit_dependency_setter_def(s, project_ir, type_name, entity, dep)
    for method in methods:
        _emit_method_def(s, project_ir, method, type_name=type_name, sig_entity=cls.name)
    _header_close(s, project_ir)

    return "\n".join(h), "\n".join(s)


# ---------------------------------------------------------------------------
# Interfaces (abstract base classes), implementations, and impl-tag dispatch
# ---------------------------------------------------------------------------

def generate_cpp_context(project_ir: IRProject) -> str:
    """Generate ``context.hpp``: the shared virtual base exposing the polymorphic
    C implementation handle (analogous to Swift's CContext)."""
    lines: list[str] = []
    _header_open(lines, project_ir, [], c_forward_decls=[f"struct {project_ir.prefix}_impl_t"])
    lines.append("/// Common virtual base of every interface: exposes the underlying")
    lines.append("/// polymorphic C implementation handle.")
    lines.append("class Context {")
    lines.append("public:")
    lines.append("    virtual ~Context() = default;")
    lines.append(f"    /// The underlying C implementation handle (non-owning).")
    lines.append(f"    virtual {project_ir.prefix}_impl_t* impl() const noexcept = 0;")
    lines.append("};")
    lines.append("")
    _header_close(lines, project_ir)
    return "\n".join(lines)


def generate_cpp_interface(project_ir: IRProject, iface) -> str:
    """Generate an interface as an abstract base class (pure-virtual methods)."""
    type_name = cpp_type_name(iface.name)
    ns_path = f"virgil/crypto/{_ns_leaf(project_ir)}"
    methods = [m for m in iface.methods if _method_should_wrap(m)]
    returns_iface = _returns_interface(project_ir, iface.name, iface.methods)

    incs = _base_std_includes(returns_iface)
    incs.append(f"<{ns_path}/context.hpp>")
    incs.append(f"<{ns_path}/error.hpp>")
    for parent in iface.inherits:
        incs.append(f"<{ns_path}/{_entity_snake(parent)}.hpp>")
    # Referenced enums are leaf headers (no wrapper-side includes) — safe to include so
    # by-value enum params/returns are complete. Referenced class/interface types are only
    # forward-declared: a pure-virtual declaration needs no definition, and *including*
    # their headers reintroduces the cycle (interface -> concrete class header ->
    # foundation_implementation.hpp -> every interface header -> back), which leaves
    # interface bases incomplete (e.g. `class KeyCipher : ... public KeyAlg` when KeyAlg
    # is mid-include). Completeness is only required at the call site — the concrete
    # class/impl that overrides the method and does include the full headers.
    ref_includes, fwd_types = _interface_ref_split(project_ir, iface)
    for inc in ref_includes:
        incs.append(f"<{inc}>")

    lines: list[str] = []
    _header_open(lines, project_ir, _dedup(incs))
    for fwd in fwd_types:
        lines.append(f"class {fwd};")
    if fwd_types:
        lines.append("")
    _emit_result_structs(lines, project_ir, iface.name, iface.methods)
    _emit_doc(lines, iface.description)
    bases = ["virtual public Context"] + [f"virtual public {cpp_type_name(p)}" for p in iface.inherits]
    lines.append(f"class {type_name} : {', '.join(bases)} {{")
    lines.append("public:")
    lines.append(f"    ~{type_name}() override = default;")
    lines.append("")
    for m in methods:
        _emit_doc(lines, m.description, indent="    ")
        ret = _cpp_signature_return(project_ir, iface.name, m)
        params = ", ".join(
            f"{_cpp_param_type(project_ir, a)} {cpp_method_name(a.name)}"
            for a in _method_inputs(iface.name, m)
        )
        const_kw = " const" if _method_is_const(m) else ""
        lines.append(f"    virtual {ret} {cpp_method_name(m.name)}({params}){const_kw} = 0;")
        lines.append("")
    lines.append("};")
    lines.append("")
    _header_close(lines, project_ir)
    return "\n".join(lines)


def _iface_closure(iface_by_name: dict, names: list[str]) -> list[str]:
    """Transitive closure of interface names via ``inherits`` (BFS, ordered)."""
    seen: list[str] = []
    stack = list(names)
    while stack:
        n = stack.pop(0)
        if n in seen:
            continue
        seen.append(n)
        if n in iface_by_name:
            stack.extend(iface_by_name[n].inherits)
    return seen


def generate_cpp_implementation(project_ir: IRProject, impl) -> tuple[str, str]:
    """Generate ``(header, source)`` for an implementation: an RAII class that
    inherits and overrides its bound interfaces."""
    type_name = cpp_type_name(impl.name)
    c_type = _c_type(project_ir, impl.name)
    entity = _entity_snake(impl.name)
    prefix = project_ir.prefix
    ns_path = f"virgil/crypto/{_ns_leaf(project_ir)}"

    iface_by_name = {i.name: i for i in project_ir.interfaces}
    direct_ifaces = [b.name for b in impl.interface_bindings]
    all_iface_names = _iface_closure(iface_by_name, direct_ifaces)
    iface_methods = []
    for name in all_iface_names:
        iface = iface_by_name.get(name)
        if iface:
            iface_methods.extend((name, m) for m in iface.methods if _method_should_wrap(m))
    own_methods = [m for m in impl.methods if _impl_own_method_is_public(m)]
    all_methods = own_methods + [m for _, m in iface_methods]
    returns_iface = _returns_interface(project_ir, impl.name, all_methods)

    def _emit_constants(dst):
        for binding in impl.interface_bindings:
            for bconst in binding.constants:
                val = (bconst.value or bconst.attrs.get("value") or "").strip()
                if val.lstrip("-").isdigit():
                    dst.append(f"    static constexpr std::size_t {cpp_constant_name(bconst.name)} = {val};")
                    dst.append("")
        for const in impl.constants:
            if const.attrs.get("definition") == "private":
                continue
            val = (const.attrs.get("value") or "").strip()
            if val.lstrip("-").isdigit():
                _emit_doc(dst, const.description, indent="    ")
                dst.append(f"    static constexpr {_cpp_constant_type(const)} {cpp_constant_name(const.name)} = {val};")
                dst.append("")

    # ---- Header (declarations) ----
    ref_incs, fwd = _hpp_ref_split(project_ir, impl.name, all_methods, impl.dependencies)
    incs = _base_std_includes(True)  # unique_ptr returns
    incs.append(f"<{ns_path}/error.hpp>")
    for name in all_iface_names:  # base classes need the complete interface type
        incs.append(f"<{ns_path}/{_entity_snake(name)}.hpp>")
    incs += [f"<{i}>" for i in ref_incs]

    h: list[str] = []
    _header_open(h, project_ir, _dedup(incs),
                 c_forward_decls=[f"struct {c_type}", f"struct {prefix}_impl_t"])
    for f in fwd:
        h.append(f"class {f};")
    if fwd:
        h.append("")
    _emit_result_structs(h, project_ir, impl.name, own_methods)
    _emit_doc(h, impl.description)
    bases = [f"virtual public {cpp_type_name(b)}" for b in direct_ifaces]
    base_str = (" : " + ", ".join(bases)) if bases else ""
    h.append(f"class {type_name}{base_str} {{")
    h.append("public:")
    _emit_raii_decls(h, type_name, c_type)
    h.append(f"    /// The polymorphic C implementation handle (non-owning).")
    h.append(f"    {prefix}_impl_t* impl() const noexcept override;")
    h.append("")
    _emit_constants(h)
    for dep in impl.dependencies:
        _emit_dependency_setter_decl(h, project_ir, dep)
    for method in own_methods:
        _emit_method_decl(h, project_ir, method, sig_entity=impl.name)
    for iface_name, method in iface_methods:
        _emit_method_decl(h, project_ir, method, sig_entity=iface_name, override_kw=" override")
    h.append("private:")
    h.append(f"    {c_type}* c_ctx_;")
    h.append("};")
    h.append("")
    _header_close(h, project_ir)

    # ---- Source (definitions) ----
    s: list[str] = []
    _source_open(s, project_ir, _class_def_includes(
        project_ir, impl.name, all_methods, impl.dependencies,
        returns_iface=returns_iface, iface_names=all_iface_names))
    _emit_raii_defs(s, type_name, c_type, prefix, entity)
    s.append(f"{prefix}_impl_t* {type_name}::impl() const noexcept {{ return {prefix}_{entity}_impl(c_ctx_); }}")
    s.append("")
    for dep in impl.dependencies:
        _emit_dependency_setter_def(s, project_ir, type_name, entity, dep)
    for method in own_methods:
        _emit_method_def(s, project_ir, method, type_name=type_name, sig_entity=impl.name)
    for iface_name, method in iface_methods:
        _emit_method_def(s, project_ir, method, type_name=type_name,
                         sig_entity=iface_name, call_entity=impl.name)
    _header_close(s, project_ir)

    return "\n".join(h), "\n".join(s)


def _iface_impl_map(project_ir: IRProject):
    """Ordered list of (interface_name, [impl_names]) from the bindings."""
    order: list[str] = []
    per: dict[str, list[str]] = {}
    public_impls = {
        i.name for i in project_ir.implementations
        if i.attrs.get("scope") not in {"private", "internal"}
    }
    for impl in project_ir.implementations:
        if impl.name not in public_impls:
            continue
        for binding in impl.interface_bindings:
            if binding.name not in per:
                order.append(binding.name)
            per.setdefault(binding.name, []).append(impl.name)
    return [(name, per[name]) for name in order]


def generate_cpp_project_implementation_header(project_ir: IRProject) -> str:
    """Declare the ``<Project>Implementation`` dispatch factory (definitions live
    in the .cpp to break the include cycle with the implementations)."""
    proj = _project_impl_type(project_ir)
    prefix = project_ir.prefix
    ns_path = f"virgil/crypto/{_ns_leaf(project_ir)}"
    mapping = _iface_impl_map(project_ir)

    incs = ["<memory>", f"<{ns_path}/{prefix}_impl.h>"]
    for name, _ in mapping:
        incs.append(f"<{ns_path}/{_entity_snake(name)}.hpp>")

    lines: list[str] = []
    _header_open(lines, project_ir, _dedup(incs))
    lines.append("/// Wraps a C implementation handle into its concrete C++ type by tag.")
    lines.append(f"class {proj} {{")
    lines.append("public:")
    for name, _ in mapping:
        t = cpp_type_name(name)
        s = _entity_snake(name)
        lines.append(f"    /// Adopt a returned C {name} implementation.")
        lines.append(f"    static std::unique_ptr<{t}> wrap_{s}({prefix}_impl_t* impl);")
    lines.append("};")
    lines.append("")
    _header_close(lines, project_ir)
    return "\n".join(lines)


def generate_cpp_project_implementation_source(project_ir: IRProject) -> str:
    proj = _project_impl_type(project_ir)
    prefix = project_ir.prefix
    ns_path = f"virgil/crypto/{_ns_leaf(project_ir)}"
    mapping = _iface_impl_map(project_ir)
    impl_names = sorted({n for _, names in mapping for n in names})

    lines: list[str] = []
    if _CPP_LICENSE:
        lines.append(_CPP_LICENSE)
        lines.append("")
    lines.append(f"#include <{ns_path}/{_header_stem(project_ir.name)}_implementation.hpp>")
    lines.append("")
    for n in impl_names:
        lines.append(f"#include <{ns_path}/{_entity_snake(n)}.hpp>")
    lines.append(f"#include <{ns_path}/{prefix}_impl.h>")
    lines.append("")
    lines.append(f"namespace {_cpp_namespace(project_ir)} {{")
    lines.append("")
    for name, names in mapping:
        t = cpp_type_name(name)
        s = _entity_snake(name)
        lines.append(f"std::unique_ptr<{t}> {proj}::wrap_{s}({prefix}_impl_t* impl) {{")
        lines.append(f"    switch ({prefix}_impl_tag(impl)) {{")
        for impl_name in names:
            tag = f"{prefix}_impl_tag_{impl_name.replace(' ', '_').upper()}"
            it = cpp_type_name(impl_name)
            ic = _c_type(project_ir, impl_name)
            lines.append(f"    case {tag}:")
            lines.append(f"        return std::make_unique<{it}>(reinterpret_cast<{ic}*>(impl));")
        lines.append("    default:")
        # We adopted ``impl``; on an unrecognised tag we cannot wrap it, so free it
        # rather than leak (only reachable for an impl not registered in this dispatch).
        lines.append(f"        {prefix}_impl_delete(impl);")
        lines.append("        return nullptr;")
        lines.append("    }")
        lines.append("}")
        lines.append("")
    lines.append(f"}}  // namespace {_cpp_namespace(project_ir)}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def generate_cpp_files(
    project_ir: IRProject, license_text: str = "",
    repo_root: str | Path = ".",
) -> list[tuple[str, str]]:
    """Generate all C++ wrapper files for a project.

    Returns a list of ``(repo_relative_path, file_content)`` tuples; the caller
    writes them to disk. All output is generated from the IR.

    Unit 1 emits the ``Error`` type and the enums. Classes, interfaces,
    implementations and the impl-tag dispatch are added in subsequent units.
    """
    global _CPP_LICENSE
    if license_text:
        _CPP_LICENSE = _format_license(license_text)

    output_dir = _output_dir(project_ir)
    files: list[tuple[str, str]] = []

    # --- error.hpp (from the status enum) ---
    if _find_status_enum(project_ir) is not None:
        files.append((f"{output_dir}error.hpp", generate_cpp_error(project_ir)))

    # --- Enums ---
    for enum in project_ir.enums:
        if enum.name in _INFRASTRUCTURE_ENUMS:
            continue
        if enum.attrs.get("scope") == "private":
            continue
        files.append((
            f"{output_dir}{_header_stem(enum.name)}.hpp",
            generate_cpp_enum(project_ir, enum),
        ))

    # --- Context base + interfaces (abstract base classes) ---
    if project_ir.interfaces:
        files.append((f"{output_dir}context.hpp", generate_cpp_context(project_ir)))
    for iface in project_ir.interfaces:
        if iface.attrs.get("scope") == "private":
            continue
        files.append((
            f"{output_dir}{_header_stem(iface.name)}.hpp",
            generate_cpp_interface(project_ir, iface),
        ))

    src_dir = f"wrappers/cpp/src/{_ns_leaf(project_ir)}/"

    # --- Classes (RAII wrappers: declaration .hpp + definition .cpp) ---
    for cls in project_ir.classes:
        if cls.attrs.get("scope") in {"private", "internal"}:
            continue
        if cls.name == "error":
            continue
        hpp, cpp = generate_cpp_class(project_ir, cls)
        stem = _header_stem(cls.name)
        files.append((f"{output_dir}{stem}.hpp", hpp))
        files.append((f"{src_dir}{stem}.cpp", cpp))

    # --- Implementations (declaration .hpp + definition .cpp) ---
    for impl in project_ir.implementations:
        if impl.attrs.get("scope") in {"private", "internal"}:
            continue
        hpp, cpp = generate_cpp_implementation(project_ir, impl)
        stem = _header_stem(impl.name)
        files.append((f"{output_dir}{stem}.hpp", hpp))
        files.append((f"{src_dir}{stem}.cpp", cpp))

    # --- {Project}Implementation dispatch (header decl + source def) ---
    if _iface_impl_map(project_ir):
        src_dir = f"wrappers/cpp/src/{_ns_leaf(project_ir)}/"
        stem = _header_stem(project_ir.name)
        files.append((
            f"{output_dir}{stem}_implementation.hpp",
            generate_cpp_project_implementation_header(project_ir),
        ))
        files.append((
            f"{src_dir}{stem}_implementation.cpp",
            generate_cpp_project_implementation_source(project_ir),
        ))

    return files
