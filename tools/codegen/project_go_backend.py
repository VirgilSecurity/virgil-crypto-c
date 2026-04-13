"""Go wrapper file generation for the project-rooted codegen pipeline.

Ports the legacy ``codegen/go.gsl`` / ``codegen/go_codegen.gsl`` templates
to Python, consuming the shared :class:`IRProject` already used by the
C and CMake backends.

Each entity (enum, interface, class, implementation) becomes a single
``.go`` file. Per-project infrastructure files (``context.go``,
``helper.go``, ``{project}_error.go``) are generated in later units.

All generation is model-driven — no per-project branching.

Unit 1 scope: name utilities + enum generator + orchestrator skeleton.
"""
from __future__ import annotations

from tools.codegen.project_ir import IREnum, IRProject


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

    return files
