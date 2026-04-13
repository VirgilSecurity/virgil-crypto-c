"""Go wrapper file generation for the project-rooted codegen pipeline.

Ports the legacy ``codegen/go.gsl`` / ``codegen/go_codegen.gsl`` templates
to Python, consuming the shared :class:`IRProject` already used by the
C and CMake backends.

Each entity (enum, interface, class, implementation) becomes a single
``.go`` file. Per-project infrastructure files (``context.go``,
``helper.go``, ``{project}_error.go``) are generated in later units.

All generation is model-driven — no per-project branching.

Unit 1 scope: name utilities + enum generator + orchestrator skeleton.
Unit 2 scope: interface wrappers — Go interface declarations with
constant-backed getters, methods, context embedding, and Delete().
"""
from __future__ import annotations

from tools.codegen.project_ir import (
    IRCArgument,
    IRCConstant,
    IRCMethod,
    IREnum,
    IRInterface,
    IRProject,
)


# ---------------------------------------------------------------------------
# Name utilities
# ---------------------------------------------------------------------------

def _split_words(name: str) -> list[str]:
    """Split a space-separated / underscore-separated entity name into words.

    ``"alg id"`` → ``["alg", "id"]``
    ``"aes256 gcm"`` → ``["aes256", "gcm"]``
    ``"round5_nd_1cca_5d"`` → ``["round5", "nd", "1cca", "5d"]``
    """
    return [w for w in name.replace("_", " ").split(" ") if w]


def go_type_name(entity_name: str) -> str:
    """Derive the exported Go type name for an entity.

    ``"alg id"`` → ``"AlgId"``
    ``"asn1 reader"`` → ``"Asn1Reader"``
    ``"aes256 gcm"`` → ``"Aes256Gcm"``
    """
    return "".join(w[:1].upper() + w[1:].lower() for w in _split_words(entity_name))


def go_method_name(method_name: str) -> str:
    """Derive the exported Go method name.

    Same PascalCase rule as types — ``"encrypt data"`` → ``"EncryptData"``.
    """
    return go_type_name(method_name)


def go_arg_name(arg_name: str) -> str:
    """Derive a camelCase Go argument/local name.

    ``"data"`` → ``"data"``; ``"plain text"`` → ``"plainText"``.
    """
    words = _split_words(arg_name)
    if not words:
        return arg_name
    head, tail = words[0], words[1:]
    return head.lower() + "".join(w[:1].upper() + w[1:].lower() for w in tail)


def go_constant_name(type_name: str, constant_name: str) -> str:
    """Prefix an enum constant with the enum type name.

    ``("alg id", "aes256 gcm")`` → ``"AlgIdAes256Gcm"``.
    """
    return go_type_name(type_name) + go_type_name(constant_name)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _package_name(project_ir: IRProject) -> str:
    """Go package name for a project — lower-cased project name."""
    return project_ir.name.lower()


def _doc_block(description: str, indent: str = "") -> str:
    """Render a description as a C-style doc comment, matching legacy output.

    Returns an empty string if there is no description. ``indent`` is a
    string (typically spaces) prepended to every output line — used to
    nest doc comments inside ``const (...)`` blocks.
    """
    if not description:
        return ""
    lines = [line.rstrip() for line in description.strip().splitlines()]
    body_lines = [f"{indent}* {line}" if line else f"{indent}*" for line in lines]
    return f"{indent}/*\n" + "\n".join(body_lines) + f"\n{indent}*/"


# ---------------------------------------------------------------------------
# Enum generator
# ---------------------------------------------------------------------------

def generate_go_enum(project_ir: IRProject, enum: IREnum) -> str:
    """Generate the ``.go`` file content for a single enum.

    Format (matches ``wrappers/go/foundation/alg_id.go``)::

        package <project>

        import "C"

        /*
        * <description>
        */
        type <TypeName> int
        const (
            <TypeName><ConstA> <TypeName> = <value>
            ...
        )

    Enum constants with an explicit ``value`` attribute use that literal
    verbatim (preserving hex like ``0x01``). Otherwise constants get
    sequential integer values starting at 0, following C enum defaults.
    """
    type_name = go_type_name(enum.name)

    lines: list[str] = []
    lines.append(f"package {_package_name(project_ir)}")
    lines.append("")
    lines.append('import "C"')
    lines.append("")
    doc = _doc_block(enum.description)
    if doc:
        lines.append(doc)
    lines.append(f"type {type_name} int")
    lines.append("const (")

    next_default = 0
    for const in enum.constants:
        const_name = go_constant_name(enum.name, const.name)
        raw_value = const.attrs.get("value")
        if raw_value is None or raw_value == "":
            value_str = str(next_default)
            next_default += 1
        else:
            value_str = raw_value.strip()
            # If value is a plain integer literal, track it so subsequent
            # implicit constants continue from the next integer (C enum semantics).
            try:
                next_default = int(value_str, 0) + 1
            except ValueError:
                # Non-numeric expression — leave counter unchanged.
                next_default += 1
        const_doc = _doc_block(const.description, indent="    ")
        if const_doc:
            lines.append(const_doc)
        lines.append(f"    {const_name} {type_name} = {value_str}")

    lines.append(")")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Type mapping (IR argument / return → Go type)
# ---------------------------------------------------------------------------

_INT_SIZE_SUFFIX = {"1": "8", "2": "16", "4": "32", "8": "64"}


def _go_integer_type(type_size: str | None) -> str:
    """Map ``type="integer" size="N"`` (byte widths) to a Go signed int type."""
    if type_size is None or type_size == "":
        return "int32"
    return f"int{_INT_SIZE_SUFFIX.get(type_size, '32')}"


def _go_unsigned_type(type_size: str | None) -> str:
    """Map ``type="unsigned" size="N"`` to a Go unsigned int type."""
    if type_size is None or type_size == "":
        return "uint32"
    return f"uint{_INT_SIZE_SUFFIX.get(type_size, '32')}"


def _arg_is_buffer_output(arg: IRCArgument) -> bool:
    """Buffer-class arguments act as output parameters — pushed to returns."""
    return arg.class_name == "buffer"


def _arg_should_skip(arg: IRCArgument) -> bool:
    """Arguments filtered from the wrapper API.

    Mirrors ``wrapper_method_should_skip_argument`` in the legacy GSL —
    writeonly access and error-class args don't appear in Go signatures.
    """
    if arg.access == "writeonly":
        return True
    if arg.class_name == "error":
        return True
    return False


def _go_type_for_arg(arg: IRCArgument) -> str:
    """Map an IR argument / return descriptor to its Go type name.

    Interface signatures only need the type spelling — not the marshalling
    code that implementations will generate in Unit 4.
    """
    # Enum references
    if arg.enum_name:
        return go_type_name(arg.enum_name)
    # Interface references
    if arg.interface_name:
        return go_type_name(arg.interface_name)
    # Class references (pointers to concrete Go structs)
    if arg.class_name == "data":
        return "[]byte"
    if arg.class_name == "buffer":
        # Only reached for return-class data; args are stripped upstream.
        return "[]byte"
    if arg.class_name and arg.class_name not in {"data", "buffer"}:
        # Concrete C class → pointer to matching Go struct.
        return f"*{go_type_name(arg.class_name)}"
    # Primitive types
    type_name = (arg.type_name or "").lower()
    if type_name == "size":
        return "uint"
    if type_name == "boolean":
        return "bool"
    if type_name == "integer":
        return _go_integer_type(arg.type_size)
    if type_name == "unsigned":
        return _go_unsigned_type(arg.type_size)
    if type_name == "byte":
        if arg.is_reference:
            return "unsafe.Pointer"
        if arg.is_array:
            return "[]byte"
        return "byte"
    # Fallback — unknown / not yet mapped.
    return type_name or "interface{}"


# ---------------------------------------------------------------------------
# Interface generator
# ---------------------------------------------------------------------------

def _constant_getter_signature(const: IRCConstant) -> str:
    """Emit the ``GetXxx () <type>`` getter for an interface constant."""
    # Constants carry their type directly on attrs (type/size/boolean).
    # Default to ``size`` (``uint`` in Go) when unspecified — matches legacy.
    type_name = (const.attrs.get("type") or "size").lower()
    size = const.attrs.get("size")
    if type_name == "size":
        go_type = "uint"
    elif type_name == "boolean":
        go_type = "bool"
    elif type_name == "integer":
        go_type = _go_integer_type(size)
    elif type_name == "unsigned":
        go_type = _go_unsigned_type(size)
    else:
        go_type = type_name
    getter = go_method_name("get " + const.name)
    return f"{getter} () {go_type}"


def _method_signature(method: IRCMethod) -> str:
    """Render the Go method signature line (no doc block, no newline).

    Handles:
    - Arg filtering (writeonly / error class)
    - Buffer-class args → pushed to return list as ``[]byte``
    - ``status`` return → trailing ``error``
    - Interface returns → always wrapped in ``(T, error)``
    """
    method_name = go_method_name(method.name)

    input_args: list[str] = []
    buffer_return_count = 0
    for arg in method.arguments:
        # Buffer-class args are writeonly outputs — they must be promoted to
        # returns even though the writeonly filter would otherwise drop them.
        if _arg_is_buffer_output(arg):
            buffer_return_count += 1
            continue
        if _arg_should_skip(arg):
            continue
        input_args.append(f"{go_arg_name(arg.name)} {_go_type_for_arg(arg)}")

    value_returns: list[str] = []
    has_error = False
    for ret in method.returns:
        if ret.enum_name == "status":
            has_error = True
            continue
        # Interface and class returns always ride with an error companion
        # — they can fail (NULL) and the legacy wrapper surfaces that.
        if ret.interface_name or (
            ret.class_name and ret.class_name not in {"data", "buffer"}
        ):
            value_returns.append(_go_type_for_arg(ret))
            has_error = True
            continue
        value_returns.append(_go_type_for_arg(ret))

    # Buffer-class outputs always render as ``[]byte`` returns, preserving
    # their XML position relative to other returns is not required because
    # the legacy GSL emits them in XML argument order — we mirror that by
    # appending them after value_returns.
    value_returns.extend(["[]byte"] * buffer_return_count)

    if has_error:
        value_returns.append("error")

    if not value_returns:
        returns_str = ""
    elif len(value_returns) == 1:
        returns_str = f" {value_returns[0]}"
    else:
        returns_str = f" ({', '.join(value_returns)})"

    args_str = ", ".join(input_args)
    return f"{method_name} ({args_str}){returns_str}"


def _method_should_wrap(method: IRCMethod) -> bool:
    """Port of ``wrapper_should_wrap_method`` — public scope, declaration, visibility."""
    scope = method.attrs.get("scope", "public")
    decl = method.declaration or method.attrs.get("declaration", "public")
    vis = method.visibility or method.attrs.get("visibility", "public")
    return scope == "public" and decl == "public" and vis == "public"


def _interface_needs_unsafe_import(iface: IRInterface) -> bool:
    """Does any wrapped member surface ``unsafe.Pointer`` in its signature?"""
    for method in iface.methods:
        if not _method_should_wrap(method):
            continue
        for ret in method.returns:
            if ret.type_name == "byte" and ret.is_reference:
                return True
        for arg in method.arguments:
            if _arg_should_skip(arg):
                continue
            if arg.type_name == "byte" and arg.is_reference:
                return True
    return False


def generate_go_interface(project_ir: IRProject, iface: IRInterface) -> str:
    """Generate the ``.go`` file content for a single interface.

    Format (matches ``wrappers/go/foundation/hash.go``)::

        package <project>

        import "C"

        /*
        * <description>
        */
        type <Name> interface {

            context

            /*
            * <constant description>
            */
            Get<Const> () <GoType>

            ...method blocks...

            /*
            * Release underlying C context.
            */
            Delete ()
        }
    """
    iface_name = go_type_name(iface.name)

    lines: list[str] = []
    lines.append(f"package {_package_name(project_ir)}")
    lines.append("")
    lines.append('import "C"')
    if _interface_needs_unsafe_import(iface):
        lines.append('import unsafe "unsafe"')
    lines.append("")
    desc = _doc_block(iface.description)
    if desc:
        lines.append(desc)
    lines.append(f"type {iface_name} interface {{")
    lines.append("")
    lines.append("    context")

    # Constants → getter methods, in XML order.
    for const in iface.constants:
        lines.append("")
        doc = _doc_block(const.description, indent="    ")
        if doc:
            lines.append(doc)
        lines.append(f"    {_constant_getter_signature(const)}")

    # Methods, filtered by wrapper_should_wrap_method.
    for method in iface.methods:
        if not _method_should_wrap(method):
            continue
        lines.append("")
        doc = _doc_block(method.description, indent="    ")
        if doc:
            lines.append(doc)
        lines.append(f"    {_method_signature(method)}")

    # Always emit the Delete entry at the end.
    lines.append("")
    lines.append("    /*")
    lines.append("    * Release underlying C context.")
    lines.append("    */")
    lines.append("    Delete ()")
    lines.append("}")
    lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

# Enums that are consumed by infrastructure files and must NOT produce a
# standalone .go file:
# - ``status`` is baked into ``{project}_error.go``
# - ``impl/tag`` drives the interface-cast dispatch in
#   ``{project}_implementation.go`` and is never rendered as a standalone enum
_INFRASTRUCTURE_ENUMS = frozenset({"status", "impl/tag"})


def _wrapper_output_dir(project_ir: IRProject) -> str:
    """Output directory for generated Go files, relative to repo root."""
    return f"wrappers/go/{project_ir.name}/"


def generate_go_files(
    project_ir: IRProject, license_text: str = ""
) -> list[tuple[str, str]]:
    """Generate all Go wrapper files for a project.

    Returns a list of ``(repo_relative_path, content)`` tuples — same
    contract as :func:`project_cmake_backend.generate_cmake_files`.

    Unit 1 scope: enums only. Later units add interfaces, classes,
    implementations, and infrastructure files.
    """
    # ``license_text`` is accepted for API parity with other backends;
    # legacy Go output does not prepend a license block so it is ignored
    # until a unit decides otherwise.
    del license_text

    output_dir = _wrapper_output_dir(project_ir)
    files: list[tuple[str, str]] = []

    for enum in project_ir.enums:
        if enum.name in _INFRASTRUCTURE_ENUMS:
            continue
        # Private-scope enums are internal C constructs and are not exposed
        # through the Go wrapper API.
        if enum.attrs.get("scope") == "private":
            continue
        stem = enum.name.replace(" ", "_").lower()
        files.append((f"{output_dir}{stem}.go", generate_go_enum(project_ir, enum)))

    for iface in project_ir.interfaces:
        if iface.attrs.get("scope") == "private":
            continue
        stem = iface.name.replace(" ", "_").lower()
        files.append((f"{output_dir}{stem}.go", generate_go_interface(project_ir, iface)))

    return files
