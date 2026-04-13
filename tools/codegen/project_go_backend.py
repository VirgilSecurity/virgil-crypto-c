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
    return "\n".join(parts)


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

    header: list[str] = []
    header.append(f"package {pkg}")
    header.append("")
    header.append(include)
    header.append('import "C"')
    header.append('import unsafe "unsafe"')
    if not _is_static_class(cls):
        header.append('import "runtime"')
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


def _c_enum_type(project_ir: IRProject, enum_name: str) -> str:
    """Canonical cgo type for an enum value (``C.vscf_alg_id_t``)."""
    stem = enum_name.replace(" ", "_").lower()
    return f"C.{project_ir.prefix}_{stem}_t"


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
        # Interface args flow through the project's universal impl
        # pointer ``vscf_impl_t`` — downcasts happen on the C side.
        return f"(*C.{project_ir.prefix}_impl_t)(unsafe.Pointer({go_local}.Ctx()))"
    if arg.class_name and arg.class_name not in {"data", "buffer"}:
        # Concrete class args keep their own C type — Ctx() returns an
        # opaque uintptr which we cast back to ``*C.<prefix>_<class>_t``.
        return (
            f"({_class_c_type(project_ir, arg.class_name)})"
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
        return f"({_PRIM_C_CASTS['integer']})({go_local})"
    if type_name == "unsigned":
        return f"({_PRIM_C_CASTS['unsigned']})({go_local})"
    if type_name == "byte":
        return f"(C.byte)({go_local})"
    # Best-effort fallback — later slices replace this.
    return go_local


def _buffer_length_expression(
    project_ir: IRProject,
    cls_name: str,
    arg: IRCArgument,
    method_arg_locals: dict[str, str],
    *,
    instance_prefix: str = "",
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
        method = la["method"]
        if instance_prefix:
            # Instance-bound method — call through the receiver.
            call_name = f"{instance_prefix}{go_method_name(method)}"
        else:
            # Static-bound method — call via package-level function.
            call_name = go_type_name(cls_name) + go_method_name(method)
        proxy_args: list[str] = []
        idx = 0
        while f"proxy_{idx}_to" in la:
            cast = la.get(f"proxy_{idx}_cast")
            src_arg = la.get(f"proxy_{idx}_argument")
            src_const = la.get(f"proxy_{idx}_constant")
            if src_const is not None:
                proxy_args.append(src_const)
            elif src_arg is not None:
                local = method_arg_locals.get(src_arg, go_arg_name(src_arg))
                if cast == "data_length":
                    proxy_args.append(f"uint(len({local}))")
                else:
                    proxy_args.append(local)
            idx += 1
        return f"{call_name}({', '.join(proxy_args)})"
    if "constant" in la:
        # Constant getter on an instance — emit ``obj.GetXxx()`` so the
        # buffer capacity resolves dynamically. Static callers currently
        # have no such case; fall back to zero and let the caller error.
        if instance_prefix:
            return f"{instance_prefix}{go_method_name('get ' + la['constant'])}()"
        return "0"
    if "argument" in la:
        src = la["argument"]
        local = method_arg_locals.get(src, go_arg_name(src))
        return local
    return "0"


def _go_return_from_c_expr(
    project_ir: IRProject, ret: IRCArgument, c_expr: str
) -> str:
    """Cast a cgo result back into the Go type returned by a method."""
    if ret.class_name == "data":
        # ``<return class="data"/>`` surfaces as a Go []byte — the C layer
        # returns a ``vsc_data_t`` that must be unpacked via the helper.
        return f"helperExtractData({c_expr})"
    if ret.interface_name:
        # Interface returns go through the project-wide impl-tag
        # dispatch in {project}_implementation.go — Unit 4.6 ships that
        # file. Until it lands, the generator still emits these calls so
        # downstream slices can iterate without rewriting this helper.
        proj_prefix = go_type_name(project_ir.name)
        return f"{proj_prefix}ImplementationWrap{go_type_name(ret.interface_name)}Copy({c_expr})"
    if ret.class_name and ret.class_name not in {"data", "buffer"}:
        # Class return — wrap the raw C context into a new Go value via
        # the unexported copy constructor from the scaffold lifecycle.
        return f"new{go_type_name(ret.class_name)}Copy({c_expr})"
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
            if v.startswith("[]") or v.startswith("*") or v == "error":
                parts.append("nil")
            elif v in {"bool"}:
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
            project_ir, cls.name, buf_arg, locals_by_source
        )
        lines.append(
            f"    {buf_local}, {err_local} := newBuffer(int({cap_expr}))"
        )
        lines.append(f"    if {err_local} != nil {{")
        lines.append(f"        return {_zero_with_err(err_local)}")
        lines.append("    }")
        lines.append(f"    defer {buf_local}.delete()")

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
    # work (string allocs, buffer allocs, data wraps) above it — matches
    # legacy shape.
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

    # Status dispatch.
    if has_error:
        lines.append("")
        lines.append(f"    err := {error_type}HandleStatus(proxyResult)")
        lines.append("    if err != nil {")
        zero = _zero_returns().rsplit("nil", 1)
        zero_with_err = "err".join(zero) if len(zero) == 2 else _zero_returns()
        lines.append(f"        return {zero_with_err}")
        lines.append("    }")

    # Return statement.
    tail_parts: list[str] = []
    for ret in resolved_returns:
        if ret.enum_name == "status":
            continue
        tail_parts.append(_go_return_from_c_expr(project_ir, ret, "proxyResult"))
    for buf_arg in buffer_outputs:
        tail_parts.append(f"{go_arg_name(buf_arg.name)}Buf.getData()")
    if has_error:
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
    """True when any wrapped method takes a string input or returns unsafe.Pointer.

    String args go through ``C.CString`` + ``C.free(unsafe.Pointer(...))``
    so the file needs ``import unsafe "unsafe"``.
    """
    for method in cls.methods:
        if not _method_should_wrap(method):
            continue
        for arg in method.arguments:
            if arg.is_string or arg.type_name == "string":
                return True
        for ret in method.returns:
            if ret.type_name == "byte" and ret.is_reference:
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

    lines: list[str] = []
    lines.append(f"package {pkg}")
    lines.append("")
    lines.append(include)
    lines.append('import "C"')
    if _static_class_needs_unsafe(cls):
        lines.append('import unsafe "unsafe"')
    lines.append("")
    lines.append("")
    desc = _doc_block(cls.description)
    if desc:
        lines.append(desc)
    lines.append(f"type {type_name} struct {{")
    lines.append("}")

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
            if v.startswith("[]") or v.startswith("*") or v == "error":
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

    for buf_arg in buffer_outputs:
        buf_local = go_arg_name(buf_arg.name) + "Buf"
        err_local = buf_local + "Err"
        cap_expr = _buffer_length_expression(
            project_ir, cls.name, buf_arg, locals_by_source,
            instance_prefix="obj.",
        )
        lines.append(
            f"    {buf_local}, {err_local} := newBuffer(int({cap_expr}))"
        )
        lines.append(f"    if {err_local} != nil {{")
        lines.append(f"        return {_zero_with_err(err_local)}")
        lines.append("    }")
        lines.append(f"    defer {buf_local}.delete()")

    for arg in resolved_args:
        if _arg_is_buffer_output(arg) or _arg_should_skip(arg):
            continue
        if arg.class_name == "data":
            local = locals_by_source[arg.name]
            lines.append(f"    {local}Data := helperWrapData ({local})")

    # First C-call argument is always ``obj.cCtx``; the rest follow in
    # XML order, with buffer outputs substituted.
    call_args: list[str] = ["obj.cCtx"]
    for arg in resolved_args:
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

    # Status dispatch precedes KeepAlive — but we skip it when the
    # error slot is filled by an interface-return Wrap function (which
    # produces ``(T, error)`` directly) or by the class="error" argument
    # the C side populated (the legacy wrapper doesn't call HandleStatus
    # on non-status methods).
    has_status_return = any(r.enum_name == "status" for r in method.returns)
    has_interface_return = any(r.interface_name for r in method.returns)
    error_slot_from_wrap = has_interface_return and not has_status_return
    if has_status_return:
        lines.append("")
        lines.append(f"    err := {error_type}HandleStatus(proxyResult)")
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
    dep_go_type = go_type_name(dep.type_name)

    release_sym = _class_c_symbol(
        project_ir, cls.name, "release_" + dep.name.replace(" ", "_")
    )
    use_sym = _class_c_symbol(
        project_ir, cls.name, "use_" + dep.name.replace(" ", "_")
    )
    if dep.type_kind == "interface":
        cast_target = f"*C.{project_ir.prefix}_impl_t"
    else:
        cast_target = _class_c_type(project_ir, dep.type_name)

    local = go_arg_name(dep.name)
    return "\n".join([
        f"func (obj *{type_name}) {dep_setter_name}({local} {dep_go_type}) {{",
        f"    {release_sym}(obj.cCtx)",
        f"    {use_sym}(obj.cCtx, ({cast_target})(unsafe.Pointer({local}.Ctx())))",
        "",
        f"    runtime.KeepAlive({local})",
        "    runtime.KeepAlive(obj)",
        "}",
    ])


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
    for arg in ctor.arguments:
        if _arg_should_skip(arg):
            continue
        if arg.class_name == "data":
            local = locals_by_source[arg.name]
            lines.append(f"    {local}Data := helperWrapData ({local})")
            call_args.append(local + "Data")
        else:
            call_args.append(
                _go_to_c_arg_expr(project_ir, arg, locals_by_source[arg.name])
            )

    if has_prologue:
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

    # Public constants appear as a const block immediately after the struct.
    publics = [c for c in cls.constants if c.attrs.get("definition") == "public"]
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

    # Infrastructure files — emitted for every project that ships Go wrappers.
    files.append((f"{output_dir}context.go", generate_go_context(project_ir)))
    files.append((f"{output_dir}helper.go", generate_go_helper(project_ir)))
    if _find_status_enum(project_ir) is not None:
        files.append(
            (f"{output_dir}{project_ir.name}_error.go", generate_go_error(project_ir))
        )

    return files
