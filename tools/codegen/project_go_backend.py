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

Unit 3 scope: infrastructure files — context.go, helper.go, and the
status-enum-driven {project}_error.go.

Unit 4.1 scope (this change): class struct scaffolding — the struct
declaration + CGo lifecycle methods (Ctx, NewXxx, newXxxWithCtx,
newXxxCopy, Delete, delete). Method bodies, dependency wiring,
interface-binding dispatch, and the {project}_implementation.go file
are deferred to a follow-up slice (Unit 4.2+). The scaffolding
generator is exposed for testing but is NOT yet wired into
``generate_go_files`` — the legacy GSL output remains authoritative
for class/implementation files until Unit 4 completes.
"""
from __future__ import annotations

from tools.codegen.project_ir import (
    IRCArgument,
    IRCConstant,
    IRCMethod,
    IRClass,
    IREnum,
    IRImplementation,
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


def _pascalize_word(word: str) -> str:
    """Convert a single word to its PascalCase spelling.

    - All-uppercase acronyms (``"RNG"``, ``"AES"``) keep their case
    - Already-mixed-case words (``"Protobuf"``, ``"IPv4"``) keep their case
    - Lowercase words are title-cased (``"hash"`` → ``"Hash"``)
    """
    if not word:
        return word
    if len(word) > 1 and word.isupper():
        return word
    if word[:1].isupper():
        return word
    return word[:1].upper() + word[1:]


def go_type_name(entity_name: str) -> str:
    """Derive the exported Go type name for an entity.

    ``"alg id"`` → ``"AlgId"``
    ``"asn1 reader"`` → ``"Asn1Reader"``
    ``"aes256 gcm"`` → ``"Aes256Gcm"``
    ``"error RNG failed"`` → ``"ErrorRNGFailed"`` (uppercase acronym preserved)
    """
    return "".join(_pascalize_word(w) for w in _split_words(entity_name))


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


def _project_pkg_qualifier(arg: IRCArgument) -> str:
    """Go package qualifier for cross-project entity refs (``"foundation."``).

    Returns an empty string for same-project references. The IR's
    ``project`` attribute on each argument tells us the source project
    of an interface or class type; when set to a non-local project, the
    Go code must qualify the type (e.g. ``foundation.Random``) and
    import the package.
    """
    return f"{arg.project}." if arg.project else ""


def _go_type_for_arg(arg: IRCArgument) -> str:
    """Map an IR argument / return descriptor to its Go type name.

    Interface signatures only need the type spelling — not the marshalling
    code that implementations will generate in Unit 4.
    """
    # Enum references
    if arg.enum_name:
        return _project_pkg_qualifier(arg) + go_type_name(arg.enum_name)
    # Interface references
    if arg.interface_name:
        return _project_pkg_qualifier(arg) + go_type_name(arg.interface_name)
    # Class references (pointers to concrete Go structs)
    if arg.class_name == "data":
        return "[]byte"
    if arg.class_name == "buffer":
        # Only reached for return-class data; args are stripped upstream.
        return "[]byte"
    if arg.class_name and arg.class_name not in {"data", "buffer"}:
        # Concrete C class → pointer to matching Go struct.
        return f"*{_project_pkg_qualifier(arg)}{go_type_name(arg.class_name)}"
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

    # Interface context — no enclosing class, so self-refs pass through
    # untouched. Callers that need resolution should route through the
    # instance-method path.
    resolved_args = method.arguments
    resolved_returns = method.returns

    input_args: list[str] = []
    buffer_return_count = 0
    for arg in resolved_args:
        # Buffer-class args are writeonly outputs — they must be promoted to
        # returns even though the writeonly filter would otherwise drop them.
        if _arg_is_buffer_output(arg):
            buffer_return_count += 1
            continue
        if _arg_should_skip(arg):
            continue
        input_args.append(f"{go_arg_name(arg.name)} {_go_type_for_arg(arg)}")

    value_returns: list[str] = []
    has_error = _method_has_error_arg(method)
    for ret in resolved_returns:
        if ret.enum_name == "status":
            has_error = True
            continue
        # Interface returns always ride with an error companion — they
        # can fail (NULL via impl-tag dispatch). Class returns inherit
        # error only when the method carries an explicit class="error"
        # argument (handled by _method_has_error_arg above).
        if ret.interface_name:
            has_error = True
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


def _method_has_error_arg(method: IRCMethod) -> bool:
    """True if the method has an explicit ``class="error"`` argument.

    The C side takes a status pointer to signal failure; the Go wrapper
    strips that arg and surfaces a trailing ``error`` return instead.
    """
    return any(arg.class_name == "error" for arg in method.arguments)


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
# Infrastructure file generators (context.go, helper.go, {project}_error.go)
# ---------------------------------------------------------------------------

def _cgo_include_line(project_ir: IRProject) -> str:
    """Single-line cgo header include targeting the project's public umbrella."""
    return (
        f"// #include <{project_ir.include_namespace}/"
        f"{project_ir.prefix}_{project_ir.name}_public.h>"
    )


def _error_type_name(project_ir: IRProject) -> str:
    """Go struct name for the project's error type (e.g. ``FoundationError``)."""
    return go_type_name(project_ir.name) + "Error"


def _c_enum_symbol(prefix: str, enum_name: str, constant_name: str) -> str:
    """Render a cgo-qualified enum constant symbol.

    ``("vscf", "status", "error bad arguments")`` →
    ``"C.vscf_status_ERROR_BAD_ARGUMENTS"``.
    """
    symbol_stub = constant_name.replace(" ", "_").upper()
    return f"C.{prefix}_{enum_name.replace(' ', '_')}_{symbol_stub}"


def _flatten_description(description: str) -> str:
    """Collapse a multi-line description into a single space-joined line.

    Used inside the ``HandleStatus`` switch messages, where the legacy
    output emits the whole description on one line.
    """
    lines = [line.strip() for line in description.strip().splitlines()]
    return " ".join(line for line in lines if line)


def generate_go_context(project_ir: IRProject) -> str:
    """Generate the per-project ``context.go`` file.

    Template is constant across projects aside from the package name and
    the cgo include pointing at the project's public umbrella header.
    """
    return (
        f"package {_package_name(project_ir)}\n"
        "\n"
        f"{_cgo_include_line(project_ir)}\n"
        'import "C"\n'
        "\n"
        "type context interface {\n"
        "\n"
        "    /* Get C context */\n"
        "    Ctx () uintptr\n"
        "}\n"
        "\n"
    )


def generate_go_helper(project_ir: IRProject) -> str:
    """Generate the per-project ``helper.go`` file.

    Provides ``helperWrapData`` / ``helperExtractData`` for the
    ``vsc_data_t`` bridge and the ``buffer`` wrapper around
    ``vsc_buffer_t``. Only the package name, cgo include, and
    project-specific error type name vary between projects.
    """
    pkg = _package_name(project_ir)
    include = _cgo_include_line(project_ir)
    error_type = _error_type_name(project_ir)
    return (
        f"package {pkg}\n"
        "\n"
        f"{include}\n"
        'import "C"\n'
        'import unsafe "unsafe"\n'
        "\n"
        "\n"
        "type helper struct {\n"
        "}\n"
        "\n"
        "func helperBytesToBytePtr(data []byte) *C.uint8_t {\n"
        "    return (*C.uint8_t)(&data[0])\n"
        "}\n"
        "\n"
        "func helperWrapData(data []byte) C.vsc_data_t {\n"
        "    if len(data) == 0 {\n"
        "        return C.vsc_data_empty()\n"
        "    }\n"
        "    return C.vsc_data((*C.uint8_t)(&data[0]), C.size_t(len(data)))\n"
        "}\n"
        "\n"
        "func helperExtractData(data C.vsc_data_t) []byte {\n"
        "    newSize := data.len\n"
        "    //FIXME Verify data is not corrupted\n"
        "    //if newSize < len(data.bytes) {\n"
        '    //    panic("Underlying C buffer corrupt the memory.")\n'
        "    //}\n"
        "    return C.GoBytes(unsafe.Pointer(data.bytes), C.int(newSize))\n"
        "}\n"
        "\n"
        "type buffer struct {\n"
        "    memory []byte\n"
        "    ctx *C.vsc_buffer_t\n"
        "    data []byte\n"
        "}\n"
        "\n"
        "func newBuffer(cap int) (*buffer, error) {\n"
        "    capacity := C.size_t(cap)\n"
        "    if capacity == 0 {\n"
        f'        return nil, &{error_type}{{-1,"Buffer with zero capacity is not allowed."}}\n'
        "    }\n"
        "\n"
        "    ctxLen := C.vsc_buffer_ctx_size()\n"
        "    memory := make([]byte, int(ctxLen + capacity))\n"
        "    ctx := (*C.vsc_buffer_t)(unsafe.Pointer(&memory[0]))\n"
        "    data := memory[int(ctxLen):]\n"
        "\n"
        "    C.vsc_buffer_init(ctx)\n"
        "    C.vsc_buffer_use(ctx, (*C.byte)(unsafe.Pointer(&data[0])), capacity)\n"
        "\n"
        "    return &buffer {\n"
        "        memory: memory,\n"
        "        ctx: ctx,\n"
        "        data: data,\n"
        "    }, nil\n"
        "}\n"
        "\n"
        "func (obj *buffer) getData() []byte {\n"
        "    newSize := int(C.vsc_buffer_len(obj.ctx))\n"
        "    if newSize > len(obj.data) {\n"
        '        panic ("Underlying C buffer corrupt the memory.")\n'
        "    }\n"
        "    return obj.data[:newSize]\n"
        "}\n"
        "\n"
        "func (obj *buffer) cap() int {\n"
        "    return int(C.vsc_buffer_capacity(obj.ctx))\n"
        "}\n"
        "\n"
        "func (obj *buffer) len() int {\n"
        "    return int(C.vsc_buffer_len(obj.ctx))\n"
        "}\n"
        "\n"
        "/*\n"
        "* Release underlying C context.\n"
        "*/\n"
        "func (obj *buffer) delete() {\n"
        "    C.vsc_buffer_delete(obj.ctx)\n"
        "}\n"
    )


def _find_status_enum(project_ir: IRProject) -> IREnum | None:
    for enum in project_ir.enums:
        if enum.name == "status":
            return enum
    return None


def generate_go_error(project_ir: IRProject) -> str:
    """Generate the per-project ``{project}_error.go`` file.

    Uses the ``status`` enum from the IR as the single source of truth for
    error codes, messages, and the switch dispatch inside
    ``{ErrorType}HandleStatus``. Emitted only for projects that declare a
    status enum (all current wrapper-bearing projects do).
    """
    status = _find_status_enum(project_ir)
    if status is None:
        raise ValueError(
            f"project {project_ir.name!r} has no 'status' enum; "
            "cannot generate error file"
        )

    pkg = _package_name(project_ir)
    include = _cgo_include_line(project_ir)
    error_type = _error_type_name(project_ir)
    prefix = project_ir.prefix
    status_type = f"C.{prefix}_status_t"
    success_symbol = f"C.{prefix}_status_SUCCESS"

    # Non-success constants — everything in the const block and the switch.
    body_constants = [c for c in status.constants if c.name != "success"]

    lines: list[str] = []
    lines.append(f"package {pkg}")
    lines.append("")
    lines.append(include)
    lines.append('import "C"')
    lines.append('import "fmt"')
    lines.append("")
    lines.append("")
    desc = _doc_block(status.description)
    if desc:
        lines.append(desc)
    lines.append(f"type {error_type} struct {{")
    lines.append("    Code int")
    lines.append("    Message string")
    lines.append("}")

    # const() block — one entry per non-success status constant.
    lines.append("const (")
    for const in body_constants:
        doc = _doc_block(const.description, indent="    ")
        if doc:
            lines.append(doc)
        go_const = error_type + go_type_name(const.name)
        value = (const.attrs.get("value") or "0").strip()
        lines.append(f"    {go_const} int = {value}")
    lines.append(")")
    lines.append("")

    # Error() method.
    lines.append(f"func (obj *{error_type}) Error() string {{")
    lines.append(
        f'    return fmt.Sprintf("{error_type}{{code: %v message: %s}}", '
        "obj.Code, obj.Message)"
    )
    lines.append("}")
    lines.append("")

    # HandleStatus dispatch.
    lines.append(
        '/* Check given C status, and if it\'s not "success" then raise correspond error. */'
    )
    lines.append(
        f"func {error_type}HandleStatus(status {status_type}) error {{"
    )
    lines.append(f"    if status != {success_symbol} {{")
    lines.append("        switch (status) {")
    for const in body_constants:
        symbol = _c_enum_symbol(prefix, "status", const.name)
        message = _flatten_description(const.description).replace('\\', '\\\\').replace('"', '\\"')
        lines.append(f"        case {symbol}:")
        lines.append(
            f'            return &{error_type} {{int(status), "{message}"}}'
        )
    lines.append("        }")
    lines.append("    }")
    lines.append("    return nil")
    lines.append("}")
    lines.append("")

    # Trailing wrapError helper used by generated code.
    lines.append("type wrapError struct {")
    lines.append("    err error")
    lines.append("    msg string")
    lines.append("}")
    lines.append("")
    lines.append("func (obj *wrapError) Error() string {")
    lines.append(
        '    return fmt.Sprintf("%s: %v", obj.msg, obj.err)'
    )
    lines.append("}")
    lines.append("")
    lines.append("func (obj *wrapError) Unwrap() error {")
    lines.append("    return obj.err")
    lines.append("}")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Class / implementation scaffolding (Unit 4.1)
# ---------------------------------------------------------------------------
#
# The class scaffolding covers the parts of a Go struct wrapper that are
# uniform across every class: the struct declaration, the Ctx() accessor,
# NewXxx / newXxxWithCtx / newXxxCopy constructors, and the Delete /
# delete teardown pair. Method bodies, dependency setters, interface
# bindings, and the {project}_implementation.go dispatch file require
# the buffer-length proxy metadata and the impl_tag dispatch switch and
# are explicitly out of scope for this slice.

def _class_c_type(project_ir: IRProject, class_name: str) -> str:
    """Canonical cgo type for a class instance pointer (``*C.vscf_xxx_t``)."""
    stem = class_name.replace(" ", "_").lower()
    return f"*C.{project_ir.prefix}_{stem}_t"


def _class_c_symbol(project_ir: IRProject, class_name: str, suffix: str) -> str:
    """Compose a cgo-qualified class symbol: ``C.vscf_xxx_{suffix}``."""
    stem = class_name.replace(" ", "_").lower()
    return f"C.{project_ir.prefix}_{stem}_{suffix}"


def _is_static_class(cls: IRClass) -> bool:
    """Static-only classes (``context="none"``) carry no cCtx and no lifecycle."""
    return cls.attrs.get("context") == "none"


def _lifecycle_block(
    project_ir: IRProject,
    type_name_go: str,
    class_name: str,
    *,
    has_shallow_copy: bool = True,
) -> str:
    """Render the standard struct + lifecycle block for a class/impl.

    Produces:
    - ``type Xxx struct { cCtx *C.vscf_xxx_t }``
    - ``Ctx()`` returning ``uintptr``
    - ``NewXxx()`` default constructor
    - ``newXxxWithCtx(ctx)`` (unexported; used by generated code)
    - ``newXxxCopy(ctx)`` (unexported; uses shallow_copy — optional)
    - ``Delete()`` + ``delete()`` teardown pair

    The structure is the same for every wrapped class; only the Go type
    name, C type name, and C symbol prefix change.
    """
    c_type = _class_c_type(project_ir, class_name)
    new_sym = _class_c_symbol(project_ir, class_name, "new")
    delete_sym = _class_c_symbol(project_ir, class_name, "delete")
    shallow_copy_sym = _class_c_symbol(project_ir, class_name, "shallow_copy")

    parts: list[str] = []
    parts.append(f"type {type_name_go} struct {{")
    parts.append(f"    cCtx {c_type}")
    parts.append("}")
    parts.append("")
    parts.extend(
        _lifecycle_methods_lines(
            project_ir, type_name_go, class_name,
            has_shallow_copy=has_shallow_copy,
        )
    )
    return "\n".join(parts)


def _lifecycle_methods_lines(
    project_ir: IRProject,
    type_name_go: str,
    class_name: str,
    *,
    has_shallow_copy: bool = True,
) -> list[str]:
    """Render the lifecycle methods (Ctx + constructors + Delete pair).

    Returns a list of source lines (no trailing blank). Used both by the
    full :func:`_lifecycle_block` and by :func:`generate_go_implementation`,
    which interleaves dependency setters and impl-specific methods
    between the struct and these methods.
    """
    c_type = _class_c_type(project_ir, class_name)
    new_sym = _class_c_symbol(project_ir, class_name, "new")
    delete_sym = _class_c_symbol(project_ir, class_name, "delete")
    shallow_copy_sym = _class_c_symbol(project_ir, class_name, "shallow_copy")

    parts: list[str] = []
    parts.append("/* Handle underlying C context. */")
    parts.append(f"func (obj *{type_name_go}) Ctx() uintptr {{")
    parts.append("    return uintptr(unsafe.Pointer(obj.cCtx))")
    parts.append("}")
    parts.append("")
    parts.append(f"func New{type_name_go}() *{type_name_go} {{")
    parts.append(f"    ctx := {new_sym}()")
    parts.append(f"    obj := &{type_name_go} {{")
    parts.append("        cCtx: ctx,")
    parts.append("    }")
    parts.append(
        f"    runtime.SetFinalizer(obj, (*{type_name_go}).Delete)"
    )
    parts.append("    return obj")
    parts.append("}")
    parts.append("")
    parts.append("/* Acquire C context.")
    parts.append(
        "* Note. This method is used in generated code only, and SHOULD NOT be used in another way."
    )
    parts.append("*/")
    parts.append(
        f"func new{type_name_go}WithCtx(ctx {c_type}) *{type_name_go} {{"
    )
    parts.append(f"    obj := &{type_name_go} {{")
    parts.append("        cCtx: ctx,")
    parts.append("    }")
    parts.append(
        f"    runtime.SetFinalizer(obj, (*{type_name_go}).Delete)"
    )
    parts.append("    return obj")
    parts.append("}")
    parts.append("")
    if has_shallow_copy:
        parts.append("/* Acquire retained C context.")
        parts.append(
            "* Note. This method is used in generated code only, and SHOULD NOT be used in another way."
        )
        parts.append("*/")
        parts.append(
            f"func new{type_name_go}Copy(ctx {c_type}) *{type_name_go} {{"
        )
        parts.append(f"    obj := &{type_name_go} {{")
        parts.append(f"        cCtx: {shallow_copy_sym}(ctx),")
        parts.append("    }")
        parts.append(
            f"    runtime.SetFinalizer(obj, (*{type_name_go}).Delete)"
        )
        parts.append("    return obj")
        parts.append("}")
        parts.append("")
    parts.append("/*")
    parts.append("* Release underlying C context.")
    parts.append("*/")
    parts.append(f"func (obj *{type_name_go}) Delete() {{")
    parts.append("    if obj == nil {")
    parts.append("        return")
    parts.append("    }")
    parts.append("    runtime.SetFinalizer(obj, nil)")
    parts.append("    obj.delete()")
    parts.append("}")
    parts.append("")
    parts.append("/*")
    parts.append("* Release underlying C context.")
    parts.append("*/")
    parts.append(f"func (obj *{type_name_go}) delete() {{")
    parts.append(f"    {delete_sym}(obj.cCtx)")
    parts.append("}")
    return parts


def generate_go_class_scaffold(project_ir: IRProject, cls: IRClass) -> str:
    """Emit the struct declaration + CGo lifecycle for a class.

    Method bodies are NOT emitted here — they require buffer-length
    proxy resolution and interface casting that land in the next slice.
    Callers that need a complete, compilable file must fall back to the
    legacy GSL output until Unit 4.2 ships.

    For static-only classes (``context="none"``), the struct is empty,
    methods are top-level functions, and there are no lifecycle methods.
    This helper still produces the struct declaration + package header
    so callers can test that part in isolation.
    """
    pkg = _package_name(project_ir)
    include = _cgo_include_line(project_ir)
    type_name = go_type_name(cls.name)

    foreign_projects = _foreign_projects_for_entity(
        project_ir,
        methods=cls.methods,
        constructors=cls.constructors,
        dependencies=cls.dependencies,
    )

    header: list[str] = []
    header.append(f"package {pkg}")
    header.append("")
    header.append(include)
    header.append('import "C"')
    header.append('import unsafe "unsafe"')
    if not _is_static_class(cls):
        header.append('import "runtime"')
    header.extend(_foreign_import_lines(project_ir, foreign_projects))
    header.append("")
    header.append("")
    desc = _doc_block(cls.description)
    if desc:
        header.append(desc)

    if _is_static_class(cls):
        # Static classes have no cCtx and no lifecycle — just an empty struct
        # so callers can hang package-level helper functions around it.
        header.append(f"type {type_name} struct {{")
        header.append("}")
        header.append("")
        return "\n".join(header) + "\n"

    lifecycle = _lifecycle_block(
        project_ir,
        type_name,
        cls.name,
        has_shallow_copy=cls.attrs.get("lifecycle", "default") != "none",
    )
    return "\n".join(header) + "\n" + lifecycle + "\n"


# ---------------------------------------------------------------------------
# Method body generation (Unit 4.2 — static-only classes)
# ---------------------------------------------------------------------------
#
# This slice covers ``context="none"`` classes (base64, oid, pem, …):
# no cCtx, no SetFinalizer, no runtime.KeepAlive, no dependency setters.
# Methods become package-level ``func <ClassName><MethodName>(...)``
# functions. Full support for instance classes and implementations
# (with KeepAlive, dependency plumbing, and interface binding) lands in
# the next slices.

# Type-cast for a primitive argument passed straight through to C.
_PRIM_C_CASTS: dict[str, str] = {
    "size": "C.size_t",
    "boolean": "C.bool",
    "integer": "C.int",
    "unsigned": "C.uint",
    "byte": "C.byte",
}

# Sized C integer types — keyed by the source ``size="N"`` byte width.
_C_SIZED_INT: dict[str, str] = {
    "1": "C.int8_t",
    "2": "C.int16_t",
    "4": "C.int32_t",
    "8": "C.int64_t",
}
_C_SIZED_UINT: dict[str, str] = {
    "1": "C.uint8_t",
    "2": "C.uint16_t",
    "4": "C.uint32_t",
    "8": "C.uint64_t",
}


def _c_enum_type(project_ir: IRProject, enum_name: str) -> str:
    """Canonical cgo type for an enum value (``C.vscf_alg_id_t``)."""
    stem = enum_name.replace(" ", "_").lower()
    return f"C.{project_ir.prefix}_{stem}_t"


# Static fallback prefixes for cross-project entity references so the
# Go backend can still resolve cgo casts when the IR doesn't carry an
# explicit fallback project. Mirrors the table used by the CMake backend.
_PROJECT_PREFIX_FALLBACK = {
    "common": "vsc",
    "foundation": "vscf",
    "ratchet": "vscr",
    "phe": "vsce",
}


def _resolve_project_prefix(project_ir: IRProject, project_name: str | None) -> str:
    """Return the cgo prefix for the project that DEFINES an entity.

    When an interface or class reference carries a non-local
    ``project`` attribute, the cgo type cast must use that project's
    prefix (foundation interfaces in phe code still cast through
    ``vscf_impl_t``, never ``vsce_impl_t``).
    """
    if not project_name or project_name == project_ir.name:
        return project_ir.prefix
    for fp in getattr(project_ir, "fallback_projects", None) or []:
        if fp.name == project_name:
            return fp.prefix
    return _PROJECT_PREFIX_FALLBACK.get(project_name, project_name)


def _foreign_projects_for_entity(
    project_ir: IRProject,
    *,
    methods: list = (),
    constructors: list = (),
    dependencies: list = (),
    bindings: list = (),
    interfaces_index: dict | None = None,
) -> list[str]:
    """Collect every foreign project name referenced by an entity.

    Walks all method args/returns, dependency declarations, and (for
    implementations) the methods inherited via interface bindings —
    those bindings can pull in foundation methods from a phe impl.
    Returns a sorted, deduplicated list.
    """
    found: set[str] = set()
    local = project_ir.name

    def _scan_arg(a) -> None:
        if a.project and a.project != local:
            found.add(a.project)

    for m in methods:
        for a in m.arguments:
            _scan_arg(a)
        for r in m.returns:
            _scan_arg(r)
    for c in constructors:
        for a in c.arguments:
            _scan_arg(a)
        for r in c.returns:
            _scan_arg(r)
    for dep in dependencies:
        dp = dep.attrs.get("project")
        if dp and dp != local:
            found.add(dp)
    if bindings and interfaces_index is not None:
        for b in bindings:
            iface = interfaces_index.get(b.name)
            if iface is None:
                continue
            for m in iface.methods:
                for a in m.arguments:
                    _scan_arg(a)
                for r in m.returns:
                    _scan_arg(r)
    return sorted(found)


_GO_MODULE_ROOT = "github.com/VirgilSecurity/virgil-crypto-c/wrappers/go"


def _foreign_import_lines(project_ir: IRProject, foreign: list[str]) -> list[str]:
    """Render cross-project import lines using the canonical module path."""
    return [f'import {p} "{_GO_MODULE_ROOT}/{p}"' for p in foreign]


def _go_to_c_arg_expr(
    project_ir: IRProject, arg: IRCArgument, go_local: str
) -> str:
    """Render the Go expression that converts a Go argument value to its
    cgo-facing form for a direct C function call.
    """
    if arg.class_name == "data":
        # ``data`` arguments are pre-wrapped into a local named ``{name}Data``.
        return f"{go_local}Data"
    if arg.is_string or arg.type_name == "string":
        # String args are pre-wrapped into a ``{name}Str`` local.
        return f"{go_local}Str"
    if arg.interface_name:
        # Interface args flow through the impl pointer of the project
        # that DEFINES the interface — phe's ``Random`` arg, for
        # instance, comes from foundation, so the cast is
        # ``*C.vscf_impl_t`` not ``*C.vsce_impl_t``.
        cast_prefix = _resolve_project_prefix(project_ir, arg.project)
        return f"(*C.{cast_prefix}_impl_t)(unsafe.Pointer({go_local}.Ctx()))"
    if arg.class_name and arg.class_name not in {"data", "buffer"}:
        # Concrete class args keep their own C type — Ctx() returns an
        # opaque uintptr which we cast back to ``*C.<prefix>_<class>_t``
        # using the defining project's prefix.
        cast_prefix = _resolve_project_prefix(project_ir, arg.project)
        stem = arg.class_name.replace(" ", "_").lower()
        return (
            f"(*C.{cast_prefix}_{stem}_t)"
            f"(unsafe.Pointer({go_local}.Ctx()))"
        )
    if arg.enum_name:
        return f"{_c_enum_type(project_ir, arg.enum_name)}({go_local})"
    type_name = (arg.type_name or "").lower()
    if type_name == "size":
        return f"(C.size_t)({go_local})"
    if type_name == "boolean":
        return f"(C.bool)({go_local})"
    if type_name == "integer":
        # ``type="integer"`` with no explicit ``size`` defaults to
        # 4 bytes (matching the Go-side ``int32`` default in
        # _go_integer_type). The cast must agree or cgo refuses.
        sized = _C_SIZED_INT.get(arg.type_size or "4")
        return f"({sized})({go_local})"
    if type_name == "unsigned":
        sized = _C_SIZED_UINT.get(arg.type_size or "4")
        return f"({sized})({go_local})"
    if type_name == "byte":
        if arg.is_array:
            # ``type="byte"`` + ``<array>`` → Go ``[]byte`` argument
            # passed as ``(*C.byte)(unsafe.Pointer(&local[0]))``.
            return f"(*C.byte)(unsafe.Pointer(&{go_local}[0]))"
        if arg.is_reference:
            # Pointer-to-byte (``unsafe.Pointer`` Go type).
            return f"(*C.byte)({go_local})"
        return f"(C.byte)({go_local})"
    # Best-effort fallback — later slices replace this.
    return go_local


def _lookup_method_on_entity(
    project_ir: IRProject, entity, method_name: str
):
    """Find a method by name on an entity (class/impl), including its
    bound interfaces.

    Used to recover proxy-target argument types so the buffer-length
    expression can emit Go-required ``.(TargetType)`` type assertions
    when an arg's source type is broader than the proxy expects.
    """
    if entity is None:
        return None
    for m in getattr(entity, "methods", []):
        if m.name == method_name:
            return m
    iface_by_name = {i.name: i for i in project_ir.interfaces}
    for binding in getattr(entity, "interface_bindings", []):
        iface = iface_by_name.get(binding.name)
        if iface is None:
            continue
        for m in iface.methods:
            if m.name == method_name:
                return m
    return None


def _arg_interface_type(
    project_ir: IRProject, src_arg_name: str, entity
) -> str | None:
    """Return the Go interface type name of an arg in the CURRENT method.

    Looks up the arg by name across the entity's own methods/
    constructors AND the methods inherited via interface bindings (so
    impls can resolve args that came in through a Hash/Kem binding).
    Returns None when the arg isn't an interface or can't be resolved.
    """
    if entity is None:
        return None
    candidates = (
        list(getattr(entity, "methods", []))
        + list(getattr(entity, "constructors", []))
    )
    iface_by_name = {i.name: i for i in project_ir.interfaces}
    for binding in getattr(entity, "interface_bindings", []):
        iface = iface_by_name.get(binding.name)
        if iface is not None:
            candidates.extend(iface.methods)
    for m in candidates:
        for a in m.arguments:
            if a.name == src_arg_name and a.interface_name:
                return go_type_name(a.interface_name)
    return None


def _buffer_length_expression(
    project_ir: IRProject,
    cls_name: str,
    arg: IRCArgument,
    method_arg_locals: dict[str, str],
    *,
    instance_prefix: str = "",
    entity=None,
) -> str:
    """Resolve the Go expression used as capacity for ``newBuffer(...)``.

    Derived from the ``<length>`` metadata captured during parsing.
    Supported forms:
    - ``method="name"`` + zero-or-more ``<proxy>`` entries with
      ``cast="data_length"`` (``uint(len(<local>))``) or plain argument
      pass-through
    - ``constant="name"`` → refers to a class constant getter method
    - ``argument="name"`` → passes through a method argument directly

    ``instance_prefix`` is prepended to method-based length calls when
    the resolved length method lives on an instance (``"obj."`` for
    regular instance methods). Static callers omit it.

    Returns a raw Go expression suitable for wrapping in ``int(...)``.
    """
    la = arg.length_attrs
    if not la:
        return "0"
    if "method" in la:
        method_name = la["method"]
        if instance_prefix:
            # Instance-bound method — call through the receiver.
            call_name = f"{instance_prefix}{go_method_name(method_name)}"
        else:
            # Static-bound method — call via package-level function.
            call_name = go_type_name(cls_name) + go_method_name(method_name)
        # Locate the proxy method to recover its argument signature.
        # When the proxy targets a broader interface than the source
        # arg's type, Go requires a ``.(TargetType)`` type assertion.
        proxy_method = _lookup_method_on_entity(
            project_ir, entity, method_name
        )
        proxy_target_types: dict[str, str] = {}
        if proxy_method is not None:
            for parg in proxy_method.arguments:
                if parg.interface_name:
                    proxy_target_types[parg.name] = go_type_name(parg.interface_name)
        proxy_args: list[str] = []
        idx = 0
        while f"proxy_{idx}_to" in la:
            cast = la.get(f"proxy_{idx}_cast")
            src_arg = la.get(f"proxy_{idx}_argument")
            src_const = la.get(f"proxy_{idx}_constant")
            target_arg = la.get(f"proxy_{idx}_to")
            if src_const is not None:
                proxy_args.append(src_const)
            elif src_arg is not None:
                local = method_arg_locals.get(src_arg, go_arg_name(src_arg))
                if cast == "data_length":
                    proxy_args.append(f"uint(len({local}))")
                else:
                    target_type = proxy_target_types.get(target_arg)
                    # Source arg's type from the current method context.
                    src_type = _arg_interface_type(project_ir, src_arg, entity)
                    if target_type and src_type and target_type != src_type:
                        proxy_args.append(f"{local}.({target_type})")
                    else:
                        proxy_args.append(local)
            idx += 1
        return f"{call_name}({', '.join(proxy_args)})"
    if "constant" in la:
        const_name = la["constant"]
        # ``<length constant="X" class="other"/>`` tells us the
        # constant lives on a sibling class — qualify it with that
        # class's Go type name so we resolve to its package-level const.
        owner_class = la.get("class")
        if owner_class and owner_class != "self":
            return go_type_name(owner_class) + go_type_name(const_name)
        # Two resolution paths when the owner is the current class:
        # - The constant is declared on the entity's own ``<constant>``
        #   list (classes) → reference as a package-level identifier
        # - Otherwise, on an instance, defer to the getter method
        #   ``obj.GetXxx()`` — implementations get these from binding
        #   constants and don't have a class-level ``const`` block
        owns_const = entity is not None and any(
            c.name == const_name for c in getattr(entity, "constants", [])
        )
        if owns_const or not instance_prefix:
            return go_type_name(cls_name) + go_type_name(const_name)
        return f"{instance_prefix}{go_method_name('get ' + const_name)}()"
    if "argument" in la:
        src = la["argument"]
        local = method_arg_locals.get(src, go_arg_name(src))
        if la.get("cast") == "data_length":
            return f"uint(len({local}))"
        return local
    return "0"


def _go_return_from_c_expr(
    project_ir: IRProject, ret: IRCArgument, c_expr: str
) -> str:
    """Cast a cgo result back into the Go type returned by a method."""
    if ret.class_name == "buffer":
        # ``<return class="buffer" access="disown"/>`` — the C function
        # returns a heap-allocated ``vsc_buffer_t *`` whose ownership is
        # transferred to the caller.  Extract bytes here; the method body
        # emits ``defer C.vsc_buffer_delete(proxyResult)`` separately.
        return (
            f"C.GoBytes(unsafe.Pointer(C.vsc_buffer_bytes({c_expr})),"
            f" C.int(C.vsc_buffer_len({c_expr})))"
        )
    if ret.class_name == "data":
        # ``<return class="data"/>`` surfaces as a Go []byte — the C layer
        # returns a ``vsc_data_t`` that must be unpacked via the helper.
        return f"helperExtractData({c_expr})"
    if ret.interface_name:
        # Interface returns go through the project-wide impl-tag
        # dispatch in {project}_implementation.go — Unit 4.6 ships that
        # file. ``access="disown"`` means the C side has transferred
        # ownership so we wrap-without-copy; otherwise we shallow-copy.
        proj_prefix = go_type_name(project_ir.name)
        suffix = "" if ret.access == "disown" else "Copy"
        return (
            f"{proj_prefix}ImplementationWrap"
            f"{go_type_name(ret.interface_name)}{suffix}({c_expr})"
        )
    if ret.class_name and ret.class_name not in {"data", "buffer"}:
        # Class return — wrap the raw C context into a new Go value.
        # ``access="disown"`` means the C side already gave up ownership
        # so we use the non-copy ``newXxxWithCtx`` constructor; otherwise
        # ``newXxxCopy`` shallow-copies and shares lifetime correctly.
        wrap = "WithCtx" if ret.access == "disown" else "Copy"
        return f"new{go_type_name(ret.class_name)}{wrap}({c_expr})"
    if ret.enum_name:
        return f"{go_type_name(ret.enum_name)}({c_expr})"
    type_name = (ret.type_name or "").lower()
    if type_name == "size":
        return f"uint({c_expr})"
    if type_name == "boolean":
        return f"bool({c_expr})"
    if type_name == "integer":
        return f"{_go_integer_type(ret.type_size)}({c_expr})"
    if type_name == "unsigned":
        return f"{_go_unsigned_type(ret.type_size)}({c_expr})"
    if type_name == "byte" and ret.is_reference:
        # ``return type="byte" is_reference="1"`` surfaces as Go
        # ``unsafe.Pointer`` — wrap the cgo-side ``*C.byte``.
        return f"unsafe.Pointer({c_expr})"
    return c_expr


def _static_method_body(
    project_ir: IRProject,
    cls: IRClass,
    method: IRCMethod,
    func_name: str,
) -> str:
    """Render a static (top-level) function for a context="none" class."""
    c_sym = _class_c_symbol(project_ir, cls.name, method.name.replace(" ", "_"))
    error_type = _error_type_name(project_ir)

    # Resolve ``class="self"`` refs to the enclosing class before rendering.
    resolved_args = [_resolve_self(cls, a) for a in method.arguments]
    resolved_returns = [_resolve_self(cls, r) for r in method.returns]

    # Partition args / returns into the wrapper view.
    go_inputs: list[tuple[str, str]] = []  # (local_name, go_type)
    buffer_outputs: list[IRCArgument] = []
    locals_by_source: dict[str, str] = {}
    for arg in resolved_args:
        if _arg_is_buffer_output(arg):
            buffer_outputs.append(arg)
            continue
        if _arg_should_skip(arg):
            continue
        local = go_arg_name(arg.name)
        locals_by_source[arg.name] = local
        go_inputs.append((local, _go_type_for_arg(arg)))

    value_returns: list[str] = []
    has_error = _method_has_error_arg(method)
    has_value_return = False
    for ret in resolved_returns:
        if ret.enum_name == "status":
            has_error = True
            continue
        # Interface returns always ride with an error companion — they
        # can fail (NULL via impl-tag dispatch).
        if ret.interface_name:
            has_error = True
        value_returns.append(_go_type_for_arg(ret))
        has_value_return = True
    value_returns.extend(["[]byte"] * len(buffer_outputs))
    if has_error:
        value_returns.append("error")

    if not value_returns:
        returns_str = ""
    elif len(value_returns) == 1:
        returns_str = f" {value_returns[0]}"
    else:
        returns_str = f" ({', '.join(value_returns)})"

    args_str = ", ".join(f"{n} {t}" for n, t in go_inputs)

    # Zero-return expression used on early error exit.
    def _zero_returns() -> str:
        if not value_returns:
            return ""
        parts: list[str] = []
        for v in value_returns:
            # ``nil`` covers slices, pointers, interface and class refs,
            # and the trailing error slot. Note an unqualified named
            # type starts with an uppercase letter — that's an interface
            # value and ``nil`` is its zero.
            if (
                v.startswith("[]")
                or v.startswith("*")
                or v == "error"
                or (v[:1].isupper() if v else False)
                or "." in v  # qualified cross-project reference
            ):
                parts.append("nil")
            elif v == "bool":
                parts.append("false")
            else:
                parts.append("0")
        return ", ".join(parts)

    lines: list[str] = []
    if method.description:
        lines.append(_doc_block(method.description))
    lines.append(f"func {func_name}({args_str}){returns_str} {{")

    # Build the zero-return expression once, substituting ``err`` for the
    # trailing ``nil`` slot when the method returns an error so early-exit
    # paths propagate the originating error.
    def _zero_with_err(err_expr: str) -> str:
        z = _zero_returns()
        if not has_error or not z:
            return z
        parts = z.rsplit("nil", 1)
        return err_expr.join(parts) if len(parts) == 2 else z

    # Prologue ordering (matches legacy shape):
    #   1. CString allocs + defers for string inputs
    #   2. newBuffer allocs + defers for buffer outputs
    #   3. helperWrapData wraps for data inputs
    has_string_prologue = False
    for arg in resolved_args:
        if _arg_is_buffer_output(arg) or _arg_should_skip(arg):
            continue
        if arg.is_string or arg.type_name == "string":
            local = locals_by_source[arg.name]
            lines.append(f"    {local}Str := C.CString({local})")
            lines.append(f"    defer C.free(unsafe.Pointer({local}Str))")
            has_string_prologue = True
    if has_string_prologue and buffer_outputs:
        lines.append("")

    for buf_arg in buffer_outputs:
        buf_local = go_arg_name(buf_arg.name) + "Buf"
        err_local = buf_local + "Err"
        cap_expr = _buffer_length_expression(
            project_ir, cls.name, buf_arg, locals_by_source,
            entity=cls,
        )
        lines.append(
            f"    {buf_local}, {err_local} := newBuffer(int({cap_expr}))"
        )
        lines.append(f"    if {err_local} != nil {{")
        lines.append(f"        return {_zero_with_err(err_local)}")
        lines.append("    }")
        lines.append(f"    defer {buf_local}.delete()")

    # Methods with an explicit ``class="error"`` argument allocate a
    # local C-side error context up-front (same pattern as instance
    # methods). The C function fills the status field which we drain
    # through HandleStatus afterwards.
    error_arg = next(
        (a for a in resolved_args if a.class_name == "error"), None
    )
    if error_arg is not None:
        lines.append(f"    var error C.{project_ir.prefix}_error_t")
        lines.append(f"    C.{project_ir.prefix}_error_reset(&error)")
        lines.append("")

    # Wrap ``data``-class inputs into cgo ``vsc_data_t`` locals.
    for arg in resolved_args:
        if _arg_is_buffer_output(arg) or _arg_should_skip(arg):
            continue
        if arg.class_name == "data":
            local = locals_by_source[arg.name]
            lines.append(f"    {local}Data := helperWrapData ({local})")

    # Build the C call argument list — source args in XML order, with
    # buffer-output args substituted by ``<buf>.ctx``.
    call_args: list[str] = []
    for arg in resolved_args:
        if arg.class_name == "error":
            call_args.append("&error")
            continue
        if _arg_should_skip(arg) and not _arg_is_buffer_output(arg):
            continue
        if _arg_is_buffer_output(arg):
            call_args.append(f"{go_arg_name(arg.name)}Buf.ctx")
        elif arg.class_name == "data":
            call_args.append(locals_by_source[arg.name] + "Data")
        else:
            call_args.append(
                _go_to_c_arg_expr(project_ir, arg, locals_by_source[arg.name])
            )

    # Insert a blank line before the C call only if we emitted prologue
    # work (string allocs, buffer allocs, data wraps, error alloc) above
    # it — matches legacy shape.
    has_prologue = (
        has_string_prologue
        or bool(buffer_outputs)
        or error_arg is not None
        or any(
            a.class_name == "data"
            for a in method.arguments
            if not _arg_should_skip(a) and not _arg_is_buffer_output(a)
        )
    )
    if has_prologue:
        lines.append("")
    call = f"{c_sym}({', '.join(call_args)})"
    if has_error or has_value_return:
        lines.append(f"    proxyResult := {call}")
    else:
        lines.append(f"    {call}")

    # Status dispatch — three sources of error (status return, error
    # arg, interface return Wrap call which is self-contained).
    has_status_return = any(r.enum_name == "status" for r in resolved_returns)
    has_interface_return = any(r.interface_name for r in resolved_returns)
    error_slot_from_wrap = has_interface_return and len(resolved_returns) == 1
    if has_status_return:
        lines.append("")
        lines.append(f"    err := {error_type}HandleStatus(proxyResult)")
        lines.append("    if err != nil {")
        zero = _zero_returns().rsplit("nil", 1)
        zero_with_err = "err".join(zero) if len(zero) == 2 else _zero_returns()
        lines.append(f"        return {zero_with_err}")
        lines.append("    }")
    elif error_arg is not None:
        lines.append("")
        lines.append(f"    err := {error_type}HandleStatus(error.status)")
        lines.append("    if err != nil {")
        zero = _zero_returns().rsplit("nil", 1)
        zero_with_err = "err".join(zero) if len(zero) == 2 else _zero_returns()
        lines.append(f"        return {zero_with_err}")
        lines.append("    }")

    # KeepAlive each reference-typed arg — even on static functions
    # (no obj receiver) the GC could finalize a Go-wrapped reference
    # between the cgo cast and the C call returning.
    for arg in resolved_args:
        if _arg_is_buffer_output(arg) or _arg_should_skip(arg):
            continue
        if arg.interface_name or (
            arg.class_name and arg.class_name not in {"data", "buffer"}
        ):
            lines.append("")
            lines.append(
                f"    runtime.KeepAlive({locals_by_source[arg.name]})"
            )

    # Return statement.
    tail_parts: list[str] = []
    for ret in resolved_returns:
        if ret.enum_name == "status":
            continue
        tail_parts.append(_go_return_from_c_expr(project_ir, ret, "proxyResult"))
    for buf_arg in buffer_outputs:
        tail_parts.append(f"{go_arg_name(buf_arg.name)}Buf.getData()")
    # Add a trailing ``nil`` only when the error slot came from a
    # status return or an explicit ``class="error"`` argument. Interface
    # returns bring their own error pair via the Wrap call.
    if has_error and not error_slot_from_wrap:
        tail_parts.append("nil")

    if tail_parts:
        lines.append("")
        lines.append(f"    return {', '.join(tail_parts)}")
    else:
        lines.append("")
        lines.append("    return")
    lines.append("}")
    return "\n".join(lines)


def _static_class_needs_unsafe(cls: IRClass) -> bool:
    """True when any wrapped method needs the ``unsafe`` package.

    Three triggers:
    - String args go through ``C.CString`` + ``C.free(unsafe.Pointer(...))``
    - Interface or class-pointer args use
      ``unsafe.Pointer(arg.Ctx())`` casts
    - Returns of ``type="byte" is_reference="1"`` surface ``unsafe.Pointer``
    """
    for method in cls.methods:
        if not _method_should_wrap(method):
            continue
        for arg in method.arguments:
            if arg.is_string or arg.type_name == "string":
                return True
            if arg.interface_name:
                return True
            if arg.class_name and arg.class_name not in {"data", "buffer", "error"}:
                return True
        for ret in method.returns:
            if ret.type_name == "byte" and ret.is_reference:
                return True
    return False


def _static_class_needs_runtime(cls: IRClass) -> bool:
    """True when any wrapped method needs ``runtime.KeepAlive`` — i.e.
    has at least one interface or class-pointer argument the GC could
    finalize between cgo cast and C call returning.
    """
    for method in cls.methods:
        if not _method_should_wrap(method):
            continue
        for arg in method.arguments:
            if _arg_is_buffer_output(arg) or _arg_should_skip(arg):
                continue
            if arg.interface_name or (
                arg.class_name and arg.class_name not in {"data", "buffer", "error"}
            ):
                return True
    return False


def generate_go_static_class(project_ir: IRProject, cls: IRClass) -> str:
    """Emit a complete Go file for a static-only class.

    Includes the scaffolding header (empty struct) plus one top-level
    function per method. Raises ``ValueError`` if called on a non-static
    class — such classes need the instance-method path (a later slice).
    """
    if not _is_static_class(cls):
        raise ValueError(
            f"{cls.name!r} is not a static-only class — use the instance path"
        )

    pkg = _package_name(project_ir)
    include = _cgo_include_line(project_ir)
    type_name = go_type_name(cls.name)
    foreign_projects = _foreign_projects_for_entity(
        project_ir,
        methods=cls.methods,
    )

    lines: list[str] = []
    lines.append(f"package {pkg}")
    lines.append("")
    lines.append(include)
    lines.append('import "C"')
    if _static_class_needs_unsafe(cls):
        lines.append('import unsafe "unsafe"')
    if _static_class_needs_runtime(cls):
        lines.append('import "runtime"')
    lines.extend(_foreign_import_lines(project_ir, foreign_projects))
    lines.append("")
    lines.append("")
    desc = _doc_block(cls.description)
    if desc:
        lines.append(desc)
    lines.append(f"type {type_name} struct {{")
    lines.append("}")

    # Public class constants — same const block shape as instance
    # classes, just emitted on a static class for downstream lookups
    # (e.g. ``<length constant="X" class="phe common"/>`` from another
    # class refers to ``PheCommonX``).
    publics = [c for c in cls.constants if c.attrs.get("definition") != "private"]
    if publics:
        lines.append("const (")
        for const in publics:
            const_name = type_name + go_type_name(const.name)
            value = const.attrs.get("value", "0")
            type_attr = const.attrs.get("type", "size").lower()
            go_type = {
                "size": "uint",
                "boolean": "bool",
                "integer": _go_integer_type(const.attrs.get("size")),
                "unsigned": _go_unsigned_type(const.attrs.get("size")),
            }.get(type_attr, type_attr or "uint")
            lines.append(f"    {const_name} {go_type} = {value}")
        lines.append(")")

    for method in cls.methods:
        if not _method_should_wrap(method):
            continue
        lines.append("")
        func_name = type_name + go_method_name(method.name)
        lines.append(_static_method_body(project_ir, cls, method, func_name))

    return "\n".join(lines) + "\n"


def _resolve_self(cls: IRClass, arg: IRCArgument) -> IRCArgument:
    """Resolve ``class="self"`` references to the enclosing class name.

    The IR leaves ``self``-typed returns with ``class_name="self"``; the
    wrapper needs the concrete class name to emit the right Go type.
    Returns a shallow-modified copy of ``arg`` — the original IR stays
    untouched so the C backend keeps its semantics.
    """
    if arg.class_name == "self":
        import copy as _copy

        resolved = _copy.copy(arg)
        resolved.class_name = cls.name
        return resolved
    return arg


def _instance_method_body(
    project_ir: IRProject,
    cls: IRClass,
    method: IRCMethod,
) -> str:
    """Render an instance method (``func (obj *T) Method(...)``).

    Differs from :func:`_static_method_body` in three ways:
    - Function signature uses an ``(obj *T)`` receiver
    - The implicit ``obj.cCtx`` is the first C-call argument
    - Every method emits ``runtime.KeepAlive(obj)`` after the C call
    """
    type_name = go_type_name(cls.name)
    c_sym = _class_c_symbol(project_ir, cls.name, method.name.replace(" ", "_"))
    error_type = _error_type_name(project_ir)
    method_go_name = go_method_name(method.name)

    # Resolve ``class="self"`` references to the enclosing class so
    # downstream rendering emits the concrete Go type.
    resolved_args = [_resolve_self(cls, a) for a in method.arguments]
    resolved_returns = [_resolve_self(cls, r) for r in method.returns]

    go_inputs: list[tuple[str, str]] = []
    buffer_outputs: list[IRCArgument] = []
    locals_by_source: dict[str, str] = {}
    for arg in resolved_args:
        if _arg_is_buffer_output(arg):
            buffer_outputs.append(arg)
            continue
        if _arg_should_skip(arg):
            continue
        local = go_arg_name(arg.name)
        locals_by_source[arg.name] = local
        go_inputs.append((local, _go_type_for_arg(arg)))

    value_returns: list[str] = []
    has_error = _method_has_error_arg(method)
    has_value_return = False
    for ret in resolved_returns:
        if ret.enum_name == "status":
            has_error = True
            continue
        # Interface returns always ride with an error companion — they
        # can fail (NULL via impl-tag dispatch).
        if ret.interface_name:
            has_error = True
        value_returns.append(_go_type_for_arg(ret))
        has_value_return = True
    value_returns.extend(["[]byte"] * len(buffer_outputs))
    if has_error:
        value_returns.append("error")

    if not value_returns:
        returns_str = ""
    elif len(value_returns) == 1:
        returns_str = f" {value_returns[0]}"
    else:
        returns_str = f" ({', '.join(value_returns)})"

    args_str = ", ".join(f"{n} {t}" for n, t in go_inputs)

    def _zero_returns() -> str:
        if not value_returns:
            return ""
        parts: list[str] = []
        for v in value_returns:
            # Same rule as in _static_method_body — anything that's a
            # named type, slice, pointer, or qualified ref takes ``nil``.
            if (
                v.startswith("[]")
                or v.startswith("*")
                or v == "error"
                or (v[:1].isupper() if v else False)
                or "." in v
            ):
                parts.append("nil")
            elif v == "bool":
                parts.append("false")
            else:
                parts.append("0")
        return ", ".join(parts)

    def _zero_with_err(err_expr: str) -> str:
        z = _zero_returns()
        if not has_error or not z:
            return z
        parts = z.rsplit("nil", 1)
        return err_expr.join(parts) if len(parts) == 2 else z

    lines: list[str] = []
    if method.description:
        lines.append(_doc_block(method.description))
    lines.append(
        f"func (obj *{type_name}) {method_go_name}({args_str}){returns_str} {{"
    )

    # Methods with an explicit ``class="error"`` argument allocate a
    # local C-side error context up-front. The C function fills the
    # status field which we drain through HandleStatus afterwards.
    error_arg = next(
        (a for a in resolved_args if a.class_name == "error"), None
    )
    if error_arg is not None:
        lines.append(f"    var error C.{project_ir.prefix}_error_t")
        lines.append(f"    C.{project_ir.prefix}_error_reset(&error)")
        lines.append("")

    # Prologue (see _static_method_body for order rationale).
    has_string_prologue = False
    for arg in resolved_args:
        if _arg_is_buffer_output(arg) or _arg_should_skip(arg):
            continue
        if arg.is_string or arg.type_name == "string":
            local = locals_by_source[arg.name]
            lines.append(f"    {local}Str := C.CString({local})")
            lines.append(f"    defer C.free(unsafe.Pointer({local}Str))")
            has_string_prologue = True
    if has_string_prologue and buffer_outputs:
        lines.append("")

    has_data_wrap = any(
        a.class_name == "data"
        for a in resolved_args
        if not _arg_should_skip(a) and not _arg_is_buffer_output(a)
    )
    for idx, buf_arg in enumerate(buffer_outputs):
        buf_local = go_arg_name(buf_arg.name) + "Buf"
        err_local = buf_local + "Err"
        cap_expr = _buffer_length_expression(
            project_ir, cls.name, buf_arg, locals_by_source,
            instance_prefix="obj.", entity=cls,
        )
        lines.append(
            f"    {buf_local}, {err_local} := newBuffer(int({cap_expr}))"
        )
        lines.append(f"    if {err_local} != nil {{")
        lines.append(f"        return {_zero_with_err(err_local)}")
        lines.append("    }")
        lines.append(f"    defer {buf_local}.delete()")
        # Legacy GSL emits a blank line between consecutive buffer
        # allocations and an extra blank after the LAST buffer when no
        # data-wrap section follows. The single blank-before-call
        # branch below handles the data-wrap case.
        is_last = idx == len(buffer_outputs) - 1
        if not is_last:
            lines.append("")
        elif not has_data_wrap:
            lines.append("")

    for arg in resolved_args:
        if _arg_is_buffer_output(arg) or _arg_should_skip(arg):
            continue
        if arg.class_name == "data":
            local = locals_by_source[arg.name]
            lines.append(f"    {local}Data := helperWrapData ({local})")

    # Ownership-transfer args (``access="disown"``) need a shallow-copy
    # local that we can pass as ``&{name}Copy`` — the C side accepts
    # ``T**`` so it can NULL the caller's pointer after taking the
    # value. Same dance for both interface and class refs.
    disown_locals: dict[str, str] = {}
    for arg in resolved_args:
        if _arg_is_buffer_output(arg) or _arg_should_skip(arg):
            continue
        if arg.access != "disown":
            continue
        if not (arg.interface_name or (
            arg.class_name and arg.class_name not in {"data", "buffer"}
        )):
            continue
        local = locals_by_source[arg.name]
        copy_local = local + "Copy"
        disown_locals[arg.name] = copy_local
        cast_prefix = _resolve_project_prefix(project_ir, arg.project)
        if arg.interface_name:
            type_t = f"*C.{cast_prefix}_impl_t"
            copy_sym = f"C.{cast_prefix}_impl_shallow_copy"
        else:
            stem = arg.class_name.replace(" ", "_").lower()
            type_t = f"*C.{cast_prefix}_{stem}_t"
            copy_sym = f"C.{cast_prefix}_{stem}_shallow_copy"
        lines.append(
            f"    {copy_local} := {copy_sym}(({type_t})(unsafe.Pointer({local}.Ctx())))"
        )

    # First C-call argument is normally ``obj.cCtx``, but methods
    # marked ``is_static="1"`` on the source interface bypass the
    # instance pointer (e.g. ``Hash.hash`` is a stateless helper).
    is_static_method = method.attrs.get("is_static") == "1"
    call_args: list[str] = [] if is_static_method else ["obj.cCtx"]
    for arg in resolved_args:
        if arg.class_name == "error":
            # The C-side error context goes through as a pointer to the
            # local ``error`` variable allocated above.
            call_args.append("&error")
            continue
        if _arg_should_skip(arg) and not _arg_is_buffer_output(arg):
            continue
        if _arg_is_buffer_output(arg):
            call_args.append(f"{go_arg_name(arg.name)}Buf.ctx")
        elif arg.class_name == "data":
            call_args.append(locals_by_source[arg.name] + "Data")
        elif arg.name in disown_locals:
            call_args.append(f"&{disown_locals[arg.name]}")
        else:
            call_args.append(
                _go_to_c_arg_expr(project_ir, arg, locals_by_source[arg.name])
            )

    has_prologue = has_string_prologue or bool(buffer_outputs) or any(
        a.class_name == "data"
        for a in method.arguments
        if not _arg_should_skip(a) and not _arg_is_buffer_output(a)
    )
    if has_prologue:
        lines.append("")
    call = f"{c_sym}({', '.join(call_args)})"
    if has_error or has_value_return:
        lines.append(f"    proxyResult := {call}")
    else:
        lines.append(f"    {call}")

    # Disown buffer return — caller owns the heap-allocated vsc_buffer_t.
    for ret in resolved_returns:
        if ret.class_name == "buffer" and ret.access == "disown":
            lines.append("    defer C.vsc_buffer_delete(proxyResult)")
            break

    # Status dispatch precedes KeepAlive. Three sources of error:
    # - ``status`` enum return -> HandleStatus(proxyResult)
    # - ``class="error"`` arg -> HandleStatus(error.status)
    # - interface return Wrap -> brings its own error pair, no dispatch
    has_status_return = any(r.enum_name == "status" for r in method.returns)
    has_interface_return = any(r.interface_name for r in method.returns)
    # ``error_slot_from_wrap`` controls whether to APPEND a trailing
    # ``nil`` to the return statement. When an interface return is
    # present, the Wrap call already produces ``(T, error)`` so any
    # trailing nil would create a too-many-values error.
    error_slot_from_wrap = has_interface_return and len(method.returns) == 1
    if has_status_return:
        lines.append("")
        lines.append(f"    err := {error_type}HandleStatus(proxyResult)")
        lines.append("    if err != nil {")
        lines.append(f"        return {_zero_with_err('err')}")
        lines.append("    }")
    elif error_arg is not None:
        lines.append("")
        lines.append(f"    err := {error_type}HandleStatus(error.status)")
        lines.append("    if err != nil {")
        lines.append(f"        return {_zero_with_err('err')}")
        lines.append("    }")

    lines.append("")
    lines.append("    runtime.KeepAlive(obj)")
    # KeepAlive each reference-typed arg too — the GC could otherwise
    # finalize them between the Go-side wrap and the C call returning.
    for arg in resolved_args:
        if _arg_is_buffer_output(arg) or _arg_should_skip(arg):
            continue
        if arg.interface_name or (
            arg.class_name and arg.class_name not in {"data", "buffer"}
        ):
            lines.append("")
            lines.append(
                f"    runtime.KeepAlive({locals_by_source[arg.name]})"
            )

    tail_parts: list[str] = []
    for ret in resolved_returns:
        if ret.enum_name == "status":
            continue
        tail_parts.append(_go_return_from_c_expr(project_ir, ret, "proxyResult"))
    for buf_arg in buffer_outputs:
        tail_parts.append(f"{go_arg_name(buf_arg.name)}Buf.getData()")
    # Only add a trailing ``nil`` to the error slot when the method's
    # error companion came from a status return or an explicit
    # ``class="error"`` argument. Interface returns bring their own
    # error pairing via the Wrap call.
    if has_error and not error_slot_from_wrap:
        tail_parts.append("nil")

    if tail_parts:
        lines.append("")
        lines.append(f"    return {', '.join(tail_parts)}")
    else:
        lines.append("")
        lines.append("    return")
    lines.append("}")
    return "\n".join(lines)


def _dependency_setter(
    project_ir: IRProject, cls: IRClass, dep
) -> str:
    """Render a ``SetXxx`` method that swaps a dependency on the C context.

    Each dependency emits ``release_{dep}`` immediately followed by
    ``use_{dep}`` (the canonical Virgil idiom for non-leaking swap),
    then KeepAlive's both the dep and the receiver.
    """
    type_name = go_type_name(cls.name)
    dep_setter_name = "Set" + go_type_name(dep.name)
    # Cross-project dep types (phe's ``Random`` from foundation) need a
    # package-qualified Go type spelling AND the defining project's
    # cgo prefix for the impl-pointer cast.
    dep_project = dep.attrs.get("project")
    dep_pkg_qualifier = f"{dep_project}." if dep_project else ""
    # Class deps are wrapped Go structs so they take a pointer; interface
    # deps are Go interfaces and stay value-typed.
    dep_pointer = "*" if dep.type_kind != "interface" else ""
    dep_go_type = dep_pointer + dep_pkg_qualifier + go_type_name(dep.type_name)
    cast_prefix = _resolve_project_prefix(project_ir, dep_project)

    release_sym = _class_c_symbol(
        project_ir, cls.name, "release_" + dep.name.replace(" ", "_")
    )
    use_sym = _class_c_symbol(
        project_ir, cls.name, "use_" + dep.name.replace(" ", "_")
    )
    if dep.type_kind == "interface":
        cast_target = f"*C.{cast_prefix}_impl_t"
    else:
        stem = dep.type_name.replace(" ", "_").lower()
        cast_target = f"*C.{cast_prefix}_{stem}_t"

    local = go_arg_name(dep.name)
    error_type = _error_type_name(project_ir)
    # When the dep declares ``is_observers_return_status="1"``, the C
    # ``use_*`` call returns a status (observer callbacks may fail).
    # The Go setter then surfaces a trailing ``error`` and routes the
    # status through HandleStatus.
    returns_status = dep.is_observers_return_status

    use_call = (
        f"{use_sym}(obj.cCtx, ({cast_target})(unsafe.Pointer({local}.Ctx())))"
    )
    body: list[str] = []
    if returns_status:
        body.append(
            f"func (obj *{type_name}) {dep_setter_name}({local} {dep_go_type}) error {{"
        )
        body.append(f"    {release_sym}(obj.cCtx)")
        body.append(f"    proxyResult := {use_call}")
        body.append("")
        body.append(f"    err := {error_type}HandleStatus(proxyResult)")
        body.append("    if err != nil {")
        body.append("        return err")
        body.append("    }")
        body.append("")
        body.append(f"    runtime.KeepAlive({local})")
        body.append("    runtime.KeepAlive(obj)")
        body.append("")
        body.append("    return nil")
        body.append("}")
    else:
        body.append(
            f"func (obj *{type_name}) {dep_setter_name}({local} {dep_go_type}) {{"
        )
        body.append(f"    {release_sym}(obj.cCtx)")
        body.append(f"    {use_call}")
        body.append("")
        body.append(f"    runtime.KeepAlive({local})")
        body.append("    runtime.KeepAlive(obj)")
        body.append("}")
    return "\n".join(body)


def _instance_constructor_body(
    project_ir: IRProject,
    cls: IRClass,
    ctor: IRCMethod,
) -> str:
    """Render a named-constructor function (``func NewTWithXxx(...) *T``).

    Each constructor invokes ``{prefix}_{class}_new_with_{ctor_name}(...)``
    and wraps the returned raw context into a Go value with the standard
    SetFinalizer pairing.
    """
    type_name = go_type_name(cls.name)
    ctor_sym = _class_c_symbol(
        project_ir, cls.name, "new_" + ctor.name.replace(" ", "_")
    )
    func_name = f"New{type_name}" + go_type_name(ctor.name)

    go_inputs: list[tuple[str, str]] = []
    locals_by_source: dict[str, str] = {}
    for arg in ctor.arguments:
        if _arg_should_skip(arg):
            continue
        local = go_arg_name(arg.name)
        locals_by_source[arg.name] = local
        go_inputs.append((local, _go_type_for_arg(arg)))
    args_str = ", ".join(f"{n} {t}" for n, t in go_inputs)

    lines: list[str] = []
    if ctor.description:
        lines.append(_doc_block(ctor.description))
    lines.append(f"func {func_name}({args_str}) *{type_name} {{")

    # String prologue (rare on constructors but handled for completeness).
    for arg in ctor.arguments:
        if _arg_should_skip(arg):
            continue
        if arg.is_string or arg.type_name == "string":
            local = locals_by_source[arg.name]
            lines.append(f"    {local}Str := C.CString({local})")
            lines.append(f"    defer C.free(unsafe.Pointer({local}Str))")

    # Build the C call: no cCtx prefix; args in XML order.
    call_args: list[str] = []
    has_prologue = any(
        (a.is_string or a.type_name == "string" or a.class_name == "data")
        and not _arg_should_skip(a)
        for a in ctor.arguments
    )
    # Disown args go first so their copy locals are in scope before
    # the data wraps below.
    disown_locals: dict[str, str] = {}
    for arg in ctor.arguments:
        if _arg_should_skip(arg) or arg.access != "disown":
            continue
        if not (arg.interface_name or (
            arg.class_name and arg.class_name not in {"data", "buffer"}
        )):
            continue
        local = locals_by_source[arg.name]
        copy_local = local + "Copy"
        disown_locals[arg.name] = copy_local
        cast_prefix = _resolve_project_prefix(project_ir, arg.project)
        if arg.interface_name:
            type_t = f"*C.{cast_prefix}_impl_t"
            copy_sym = f"C.{cast_prefix}_impl_shallow_copy"
        else:
            stem = arg.class_name.replace(" ", "_").lower()
            type_t = f"*C.{cast_prefix}_{stem}_t"
            copy_sym = f"C.{cast_prefix}_{stem}_shallow_copy"
        lines.append(
            f"    {copy_local} := {copy_sym}(({type_t})(unsafe.Pointer({local}.Ctx())))"
        )

    for arg in ctor.arguments:
        if _arg_should_skip(arg):
            continue
        if arg.class_name == "data":
            local = locals_by_source[arg.name]
            lines.append(f"    {local}Data := helperWrapData ({local})")
            call_args.append(local + "Data")
        elif arg.name in disown_locals:
            call_args.append(f"&{disown_locals[arg.name]}")
        else:
            call_args.append(
                _go_to_c_arg_expr(project_ir, arg, locals_by_source[arg.name])
            )

    if has_prologue or disown_locals:
        lines.append("")
    lines.append(f"    proxyResult := {ctor_sym}({', '.join(call_args)})")

    # KeepAlive every reference-typed arg — the new wrapper takes
    # ownership/reference at the C layer but the Go value may still be
    # GC-finalized during the call window.
    for arg in ctor.arguments:
        if _arg_should_skip(arg):
            continue
        if arg.interface_name or (
            arg.class_name and arg.class_name not in {"data", "buffer"}
        ):
            lines.append("")
            lines.append(
                f"    runtime.KeepAlive({locals_by_source[arg.name]})"
            )

    lines.append("")
    lines.append(f"    obj := &{type_name} {{")
    lines.append("        cCtx: proxyResult,")
    lines.append("    }")
    lines.append(f"    runtime.SetFinalizer(obj, (*{type_name}).Delete)")
    lines.append("    return obj")
    lines.append("}")
    return "\n".join(lines)


def generate_go_instance_class(project_ir: IRProject, cls: IRClass) -> str:
    """Emit a complete Go file for an instance class (``context != "none"``).

    Uses the scaffolding lifecycle helper for struct + lifecycle
    boilerplate, then appends public class constants, constructors, and
    instance methods.
    """
    if _is_static_class(cls):
        raise ValueError(
            f"{cls.name!r} is static-only — use generate_go_static_class"
        )

    type_name = go_type_name(cls.name)

    # Header derived from the scaffold helper — fallback uses its exact
    # output so the lifecycle block stays in one place.
    scaffold = generate_go_class_scaffold(project_ir, cls)

    out_parts: list[str] = [scaffold.rstrip("\n")]

    # Class constants appear as a const block immediately after the struct.
    # Default visibility is public — only ``definition="private"`` is hidden.
    publics = [c for c in cls.constants if c.attrs.get("definition") != "private"]
    if publics:
        # Insert the const block into the scaffold output immediately
        # after the struct's closing brace. The scaffold's struct block
        # ends with ``}`` on its own line followed by a blank line.
        const_lines = ["const ("]
        for const in publics:
            const_name = type_name + go_type_name(const.name)
            value = const.attrs.get("value", "0")
            # The Go declaration form is ``Name type = value`` where the
            # type matches the constant type. Default to ``uint`` (size).
            type_attr = const.attrs.get("type", "size").lower()
            go_type = {
                "size": "uint",
                "boolean": "bool",
                "integer": _go_integer_type(const.attrs.get("size")),
                "unsigned": _go_unsigned_type(const.attrs.get("size")),
            }.get(type_attr, type_attr or "uint")
            const_lines.append(f"    {const_name} {go_type} = {value}")
        const_lines.append(")")
        const_block = "\n".join(const_lines)

        # Splice the const block in after ``type T struct { ... }``.
        marker = "\n}\n"
        # Find the first closing brace that belongs to the struct — this
        # is directly after ``cCtx ...``. The scaffold ends the struct
        # with a bare ``}``.
        parts_scaffold = scaffold.split("\n")
        for idx, line in enumerate(parts_scaffold):
            if line == "}" and idx > 0 and "cCtx" in parts_scaffold[idx - 1]:
                break
        else:
            idx = None  # pragma: no cover
        if idx is not None:
            parts_scaffold.insert(idx + 1, const_block)
            scaffold = "\n".join(parts_scaffold)
            out_parts[0] = scaffold.rstrip("\n")

    # Dependencies → SetXxx setters. These live between the lifecycle
    # block and the ordinary instance methods to mirror legacy ordering.
    for dep in cls.dependencies:
        out_parts.append("")
        out_parts.append(_dependency_setter(project_ir, cls, dep))

    # Constructors.
    for ctor in cls.constructors:
        if not _method_should_wrap(ctor):
            continue
        out_parts.append("")
        out_parts.append(_instance_constructor_body(project_ir, cls, ctor))

    # Instance methods.
    for method in cls.methods:
        if not _method_should_wrap(method):
            continue
        out_parts.append("")
        out_parts.append(_instance_method_body(project_ir, cls, method))

    return "\n".join(out_parts) + "\n"


def _binding_constant_getter(
    type_name_go: str,
    binding_name: str,
    const,
    interface_const,
) -> str:
    """Render a literal-valued ``GetXxx`` method for an impl-bound constant.

    The interface constant supplies the type; the binding constant
    supplies the per-impl literal value (e.g. ``GetDigestLen() uint
    { return 32 }`` for sha256's hash binding).
    """
    type_attr = (interface_const.attrs.get("type") or "size").lower()
    size = interface_const.attrs.get("size")
    if type_attr == "size":
        go_type = "uint"
    elif type_attr == "boolean":
        go_type = "bool"
    elif type_attr == "integer":
        go_type = _go_integer_type(size)
    elif type_attr == "unsigned":
        go_type = _go_unsigned_type(size)
    else:
        go_type = type_attr
    getter = go_method_name("get " + const.name)
    value = const.value or const.attrs.get("value", "0")

    lines: list[str] = []
    if interface_const.description:
        lines.append(_doc_block(interface_const.description))
    lines.append(f"func (obj *{type_name_go}) {getter}() {go_type} {{")
    lines.append(f"    return {value}")
    lines.append("}")
    return "\n".join(lines)


def generate_go_implementation(project_ir: IRProject, impl: IRImplementation) -> str:
    """Emit a complete Go file for an implementation.

    Layout (matches the legacy GSL output):
    1. Package + imports + class doc + struct
    2. Dependency setters (``SetXxx``)
    3. Impl-specific constructors and methods
    4. Lifecycle block (Ctx, NewT, newTWithCtx, newTCopy, Delete, delete)
    5. Per-binding expansion (interface constants as literal getters,
       then interface methods proxied through C)

    Note that this ordering differs from instance classes — on classes
    the lifecycle comes immediately after the struct.
    """
    pkg = _package_name(project_ir)
    include = _cgo_include_line(project_ir)
    type_name = go_type_name(impl.name)

    iface_by_name = {i.name: i for i in project_ir.interfaces}
    foreign_projects = _foreign_projects_for_entity(
        project_ir,
        methods=impl.methods,
        constructors=impl.constructors,
        dependencies=impl.dependencies,
        bindings=impl.interface_bindings,
        interfaces_index=iface_by_name,
    )

    header_parts: list[str] = []
    header_parts.append(f"package {pkg}")
    header_parts.append("")
    header_parts.append(include)
    header_parts.append('import "C"')
    # Legacy GSL emits these in import-discovery order which alternates
    # between ``unsafe``-first and ``runtime``-first depending on which
    # dependent symbol surfaced first during template expansion. We pick
    # the more common ordering (``unsafe`` before ``runtime``) and accept
    # a cosmetic diff on the minority — both orders compile identically.
    header_parts.append('import unsafe "unsafe"')
    header_parts.append('import "runtime"')
    header_parts.extend(_foreign_import_lines(project_ir, foreign_projects))
    header_parts.append("")
    header_parts.append("")
    desc = _doc_block(impl.description)
    if desc:
        header_parts.append(desc)
    header_parts.append(f"type {type_name} struct {{")
    header_parts.append(f"    cCtx {_class_c_type(project_ir, impl.name)}")
    header_parts.append("}")

    # Public impl-level constants render as a const block right after
    # the struct (e.g. ``KeyMaterialRngKeyMaterialLenMin``).
    publics = [c for c in impl.constants if c.attrs.get("definition") == "public"]
    if publics:
        header_parts.append("const (")
        for const in publics:
            const_name = type_name + go_type_name(const.name)
            value = const.attrs.get("value", "0")
            type_attr = const.attrs.get("type", "size").lower()
            go_type = {
                "size": "uint",
                "boolean": "bool",
                "integer": _go_integer_type(const.attrs.get("size")),
                "unsigned": _go_unsigned_type(const.attrs.get("size")),
            }.get(type_attr, type_attr or "uint")
            header_parts.append(f"    {const_name} {go_type} = {value}")
        header_parts.append(")")

    out_parts: list[str] = ["\n".join(header_parts)]

    # Dependency setters — appear immediately after the struct.
    for dep in impl.dependencies:
        out_parts.append("")
        out_parts.append(_dependency_setter(project_ir, impl, dep))

    # Impl-specific constructors and methods come BEFORE the lifecycle
    # block on implementations.
    for ctor in impl.constructors:
        if not _method_should_wrap(ctor):
            continue
        out_parts.append("")
        out_parts.append(_instance_constructor_body(project_ir, impl, ctor))

    for method in impl.methods:
        # Impl-specific methods need an explicit ``declaration="public"``
        # to surface in the wrapper. Without it they default to private
        # at the C level too — only the implementor module sees them.
        if method.attrs.get("declaration") != "public":
            continue
        if not _method_should_wrap(method):
            continue
        out_parts.append("")
        out_parts.append(_instance_method_body(project_ir, impl, method))

    # Lifecycle methods — Ctx + constructors + Delete pair (struct
    # already emitted at the top of the file).
    out_parts.append("")
    out_parts.append("\n".join(
        _lifecycle_methods_lines(
            project_ir, type_name, impl.name, has_shallow_copy=True
        )
    ))

    # Per-binding expansion: interface constants first, then methods.
    for binding in impl.interface_bindings:
        iface = iface_by_name.get(binding.name)
        if iface is None:
            continue
        iface_const_by_name = {c.name: c for c in iface.constants}
        for const in binding.constants:
            iface_const = iface_const_by_name.get(const.name)
            if iface_const is None:
                continue
            out_parts.append("")
            out_parts.append(
                _binding_constant_getter(type_name, binding.name, const, iface_const)
            )
        for method in iface.methods:
            if not _method_should_wrap(method):
                continue
            out_parts.append("")
            out_parts.append(_instance_method_body(project_ir, impl, method))

    return "\n".join(out_parts) + "\n"


def _impl_tag_symbol(prefix: str, impl_name: str) -> str:
    """Render the cgo symbol for an implementation's impl-tag constant.

    ``("vscf", "aes256 gcm")`` → ``"C.vscf_impl_tag_AES256_GCM"``.
    """
    return f"C.{prefix}_impl_tag_{impl_name.replace(' ', '_').upper()}"


def generate_go_project_implementation(project_ir: IRProject) -> str:
    """Generate the per-project ``{project}_implementation.go`` file.

    For each interface that has at least one implementation, emit a
    ``{Project}ImplementationWrap{Iface}`` function that switches on
    ``C.{prefix}_impl_tag(ctx)`` to route the opaque ``vscf_impl_t``
    pointer to the matching concrete Go wrapper, plus a ``...Copy``
    variant that ``shallow_copy``s the C ctx before delegating.

    This file makes the per-method ``FoundationImplementationWrapXxx``
    calls emitted by class/impl method bodies actually link — without
    it, generated wrapper code references undefined symbols.
    """
    pkg = _package_name(project_ir)
    include = _cgo_include_line(project_ir)
    project_pascal = go_type_name(project_ir.name)
    error_type = _error_type_name(project_ir)
    prefix = project_ir.prefix
    impl_t = f"*C.{prefix}_impl_t"

    # Group implementations by the interfaces they bind, AND track
    # the order in which interfaces are first discovered while iterating
    # implementations. Legacy GSL emits the dispatch table in this
    # discovery order — interface declared in the project XML but
    # without any binding doesn't appear at all, and an interface
    # appears at the position where the first impl that binds it
    # introduces it.
    impls_per_iface: dict[str, list[str]] = {}
    iface_order: list[str] = []
    for impl in project_ir.implementations:
        for binding in impl.interface_bindings:
            if binding.name not in impls_per_iface:
                iface_order.append(binding.name)
            impls_per_iface.setdefault(binding.name, []).append(impl.name)

    lines: list[str] = []
    lines.append(f"package {pkg}")
    lines.append("")
    lines.append(include)
    lines.append('import "C"')
    lines.append("")
    lines.append("")
    lines.append(f"type {project_pascal}Implementation struct {{")
    lines.append("}")

    # Iterate interfaces in impl-binding-discovery order — see the
    # comment on iface_order above for why this matches legacy.
    iface_by_name = {i.name: i for i in project_ir.interfaces}
    for iface_name in iface_order:
        iface = iface_by_name.get(iface_name)
        if iface is None:
            continue
        impls = impls_per_iface[iface_name]
        iface_pascal = go_type_name(iface.name)
        is_implemented_sym = (
            f"C.{prefix}_{iface.name.replace(' ', '_')}_is_implemented"
        )
        impl_tag_call = f"C.{prefix}_impl_tag(ctx)"

        # Wrap function — the workhorse that does the actual switch.
        lines.append("")
        lines.append(
            f"/* Wrap C implementation object to the Go object that "
            f"implements interface {iface_pascal}. */"
        )
        lines.append(
            f"func {project_pascal}ImplementationWrap{iface_pascal}"
            f"(ctx {impl_t}) ({iface_pascal}, error) {{"
        )
        lines.append(f"    if (!{is_implemented_sym}(ctx)) {{")
        lines.append(
            f'        return nil, &{error_type}{{-1,'
            f'"Given C implementation does not implement interface '
            f'{iface_pascal}."}}'
        )
        lines.append("    }")
        lines.append("")
        lines.append(f"    implTag := {impl_tag_call}")
        lines.append("    switch (implTag) {")
        for impl_name in impls:
            tag_sym = _impl_tag_symbol(prefix, impl_name)
            impl_pascal = go_type_name(impl_name)
            impl_c_type = _class_c_type(project_ir, impl_name)
            lines.append(f"    case {tag_sym}:")
            lines.append(
                f"        return new{impl_pascal}WithCtx"
                f"(({impl_c_type})(ctx)), nil"
            )
        lines.append("    default:")
        lines.append(
            f'        return nil, &{error_type}{{-1,'
            f'"Unexpected C implementation cast to the Go implementation."}}'
        )
        lines.append("    }")
        lines.append("}")

        # Copy variant — shallow_copy the C ctx so the Go wrapper owns
        # an independent reference, then delegate to the workhorse.
        lines.append("")
        lines.append(
            f"/* Wrap C implementation object to the Go object that "
            f"implements interface {iface_pascal}. */"
        )
        lines.append(
            f"func {project_pascal}ImplementationWrap{iface_pascal}Copy"
            f"(ctx {impl_t}) ({iface_pascal}, error) {{"
        )
        lines.append(f"    shallowCopy := C.{prefix}_impl_shallow_copy(ctx)")
        lines.append(
            f"    return {project_pascal}ImplementationWrap{iface_pascal}"
            "(shallowCopy)"
        )
        lines.append("}")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# platform.go generation — cgo CFLAGS / LDFLAGS directives
# ---------------------------------------------------------------------------
#
# The source XML declares ~4 ``<cgo_link>`` entries per project. The
# legacy ``platform.go`` files have 6 entries because darwin and linux
# are auto-expanded to include both amd64 and arm64 targets. The
# expansion is NOT symmetric:
#   - ``darwin`` → amd64 + arm64 (two distinct paths)
#   - ``linux,!legacy`` → amd64,!legacy + arm64 (arm64 has no legacy variant)
#   - ``linux,legacy`` → amd64,legacy only
#   - ``windows`` → amd64 + arm64 (two distinct paths)
#
# Adding new platforms (e.g. riscv64, freebsd) requires editing this
# table. This was an explicit design choice (user chose "fully codegen
# it" over enriching the source XML).

_PLATFORM_EXPANSIONS: dict[str, list[tuple[str, str | None]]] = {
    "darwin": [
        ("darwin,amd64", "darwin_amd64"),
        ("darwin,arm64", "darwin_arm64"),
    ],
    "linux,!legacy": [
        ("linux,amd64,!legacy", None),   # use source path verbatim
    ],
    "linux,legacy": [
        ("linux,amd64,legacy", None),    # use source path verbatim
        # arm64 linux appears after the legacy variant in legacy output.
        # Uses the same libraries as ``linux,legacy`` (both carry -lpthread).
        ("linux,arm64", "linux_arm64"),
    ],
    "windows": [
        # An unconstrained ``windows`` directive would resolve a
        # windows/arm64 build to the amd64 lib path and fail at link
        # time, so both arches carry an explicit constraint and path.
        ("windows,amd64", "windows_amd64"),
        ("windows,arm64", "windows_arm64"),
    ],
}


def generate_go_platform(project_ir: IRProject) -> str:
    """Generate the per-project ``platform.go`` file.

    Emits ``// #cgo`` CFLAGS + LDFLAGS directive pairs for each
    expanded platform target, followed by ``import "C"``. The expansion
    table ``_PLATFORM_EXPANSIONS`` maps each source-XML platform spec
    to the set of ``(emitted_platform_spec, path_override)`` pairs
    that the legacy hand-tuned files declared.

    Unrecognised platform specs are silently skipped so builds stay
    functional when the source XML evolves ahead of the table.
    """
    pkg = _package_name(project_ir)

    lines: list[str] = []
    lines.append(f"package {pkg}")
    lines.append("")

    for link in project_ir.cgo_links:
        platform = link.get("platform", "")
        libraries = link.get("libraries", "")
        src_path = link.get("path")

        expansions = _PLATFORM_EXPANSIONS.get(platform)
        if expansions is None:
            continue

        for spec, path_override in expansions:
            if path_override is not None:
                path = path_override
            elif src_path:
                path = src_path
            else:
                # Fallback: ``{platform}_amd64`` (legacy GSL default).
                path = f"{platform}_amd64"

            lines.append(
                f"// #cgo {spec} CFLAGS: "
                f"-I${{SRCDIR}}/../pkg/{path}/include/"
            )
            lines.append(
                f"// #cgo {spec} LDFLAGS: "
                f"-L${{SRCDIR}}/../pkg/{path}/lib {libraries}"
            )

    lines.append('import "C"')
    lines.append("")
    return "\n".join(lines) + "\n"


def generate_go_implementation_scaffold(
    project_ir: IRProject, impl: IRImplementation
) -> str:
    """Emit the struct declaration + CGo lifecycle for an implementation.

    Implementations share the same struct/lifecycle shape as classes;
    the divergence (interface method bindings, the impl_tag dispatch
    entry in the project-wide implementation file) is deferred.
    """
    pkg = _package_name(project_ir)
    include = _cgo_include_line(project_ir)
    type_name = go_type_name(impl.name)

    header: list[str] = []
    header.append(f"package {pkg}")
    header.append("")
    header.append(include)
    header.append('import "C"')
    header.append('import unsafe "unsafe"')
    header.append('import "runtime"')
    header.append("")
    header.append("")
    desc = _doc_block(impl.description)
    if desc:
        header.append(desc)

    lifecycle = _lifecycle_block(
        project_ir, type_name, impl.name, has_shallow_copy=True
    )
    return "\n".join(header) + "\n" + lifecycle + "\n"


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
    """Generate every Go wrapper file for a project.

    Returns a list of ``(repo_relative_path, content)`` tuples — same
    contract as :func:`project_cmake_backend.generate_cmake_files`.

    Output set:
    - One ``.go`` per public enum (status and impl/tag deferred to
      infrastructure / dispatch files)
    - One ``.go`` per public interface
    - ``context.go``, ``helper.go``, ``{project}_error.go`` (when the
      project declares a status enum)
    - One ``.go`` per public class — static-only classes go through
      :func:`generate_go_static_class`, the rest through
      :func:`generate_go_instance_class`
    - One ``.go`` per public implementation
    - ``{project}_implementation.go`` — impl-tag dispatch glue

    Test files (``*_test.go``) and the high-level handwritten layer
    under ``wrappers/go/crypto/`` are intentionally never emitted by
    this generator — they are owned by humans.
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

    # Infrastructure files — emitted for every project that ships Go wrappers.
    files.append((f"{output_dir}context.go", generate_go_context(project_ir)))
    files.append((f"{output_dir}helper.go", generate_go_helper(project_ir)))
    if _find_status_enum(project_ir) is not None:
        files.append(
            (f"{output_dir}{project_ir.name}_error.go", generate_go_error(project_ir))
        )
    files.append((f"{output_dir}platform.go", generate_go_platform(project_ir)))

    # Classes — route static-only and instance variants through their
    # respective generators. Skip:
    # - ``scope`` of ``private`` or ``internal`` (not part of the public
    #   wrapper API)
    # - the shared ``error`` class — it's a C-side helper for
    #   ``class="error"`` argument plumbing, not an end-user type
    for cls in project_ir.classes:
        if cls.attrs.get("scope") in {"private", "internal"}:
            continue
        if cls.name == "error":
            continue
        stem = cls.name.replace(" ", "_").lower()
        if _is_static_class(cls):
            content = generate_go_static_class(project_ir, cls)
        else:
            content = generate_go_instance_class(project_ir, cls)
        files.append((f"{output_dir}{stem}.go", content))

    # Implementations.
    for impl in project_ir.implementations:
        if impl.attrs.get("scope") in {"private", "internal"}:
            continue
        stem = impl.name.replace(" ", "_").lower()
        files.append((f"{output_dir}{stem}.go", generate_go_implementation(project_ir, impl)))

    # Project-wide impl-tag dispatch — must follow the per-impl files
    # since it references their unexported ``new<Impl>WithCtx``.
    files.append((
        f"{output_dir}{project_ir.name}_implementation.go",
        generate_go_project_implementation(project_ir),
    ))

    return files
