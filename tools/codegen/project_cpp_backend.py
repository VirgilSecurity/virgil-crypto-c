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

from tools.codegen.project_ir import IRProject, IREnum


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


def _header_open(lines: list[str], project_ir: IRProject, includes: list[str]) -> None:
    """Common header preamble: license, pragma once, includes, namespace open."""
    if _CPP_LICENSE:
        lines.append(_CPP_LICENSE)
        lines.append("")
    lines.append("#pragma once")
    lines.append("")
    for inc in includes:
        lines.append(f"#include {inc}")
    if includes:
        lines.append("")
    lines.append(f"namespace {_cpp_namespace(project_ir)} {{")
    lines.append("")


def _header_close(lines: list[str], project_ir: IRProject) -> None:
    lines.append(f"}}  // namespace {_cpp_namespace(project_ir)}")
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
    """Generate the ``.hpp`` content for a single (non-infrastructure) enum."""
    type_name = cpp_type_name(enum.name)
    lines: list[str] = []
    _header_open(lines, project_ir, ["<cstdint>"])
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

    # NOTE (Units 2-3): interfaces, classes, implementations, and the
    # {Project}Implementation dispatch are appended here next.

    return files
