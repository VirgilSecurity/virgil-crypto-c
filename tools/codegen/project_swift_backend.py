"""Swift wrapper file generation for the project-rooted codegen pipeline.

Ports the legacy ``codegen/swift.gsl`` / ``codegen/swift_codegen.gsl``
templates to Python, consuming the shared :class:`IRProject` already
used by the C, CMake, and Go backends.

Each entity (enum, interface, class, implementation) becomes a single
``.swift`` file.  Per-project infrastructure files (``CContext.swift``,
``{Project}Error.swift``, ``{Project}Implementation.swift``) are also
generated.

All generation is model-driven — no per-project branching.

Unit 1 scope: name utilities + enum generator + orchestrator skeleton.
"""
from __future__ import annotations

from tools.codegen.project_ir import (
    IRCConstant,
    IRCMethod,
    IRClass,
    IREnum,
    IRImplementation,
    IRInterface,
    IRProject,
)


# ---------------------------------------------------------------------------
# Per-project configuration derived from IRProject
# ---------------------------------------------------------------------------

# Map project name -> (framework import, ObjC prefix, C prefix, namespace)
# Framework: the compiled C framework imported by Swift (e.g., VSCFoundation)
# ObjC prefix: used in @objc(...) annotations (e.g., VSCF)
# C prefix: used in C function/type names (e.g., vscf_)
# Namespace: Swift module directory name (e.g., VirgilCryptoFoundation)

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


# ---------------------------------------------------------------------------
# Name utilities
# ---------------------------------------------------------------------------

def _split_words(name: str) -> list[str]:
    """Split a space/underscore-separated entity name into words."""
    return [w for w in name.replace("_", " ").split(" ") if w]


def swift_type_name(entity_name: str) -> str:
    """Derive the exported Swift type name for an entity.

    ``"alg id"`` → ``"AlgId"``
    ``"sha256"`` → ``"Sha256"``
    ``"aes256 gcm"`` → ``"Aes256Gcm"``
    ``"asn1 reader"`` → ``"Asn1Reader"``
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

    ``"sha256"``        → ``"sha256"``
    ``"aes256 gcm"``    → ``"aes256Gcm"``
    ``"round5 nd 1cca 5d"`` → ``"round5Nd1cca5d"``
    ``"none"``          → ``"none"``
    """
    words = _split_words(constant_name)
    if not words:
        return constant_name
    head = words[0].lower()
    tail = [_pascalize_word(w) for w in words[1:]]
    return head + "".join(tail)


def swift_method_name(method_name: str) -> str:
    """Derive a Swift method name (camelCase).

    ``"alg id"`` → ``"algId"``
    ``"encrypt data"`` → ``"encryptData"``
    """
    return swift_case_name(method_name)


def _c_enum_type(project_ir: IRProject, enum: IREnum) -> str:
    """C type name for an enum (e.g., ``vscf_alg_id_t``)."""
    stem = enum.name.replace(" ", "_").lower()
    return f"{_c_prefix(project_ir)}{stem}_t"


def _from_c_param_name(enum: IREnum) -> str:
    """The ``fromC`` initializer parameter name (camelCase of enum name).

    ``"alg id"`` → ``"algId"``
    ``"cipher state"`` → ``"cipherState"``
    """
    return swift_case_name(enum.name)


# ---------------------------------------------------------------------------
# License header
# ---------------------------------------------------------------------------

_SWIFT_LICENSE = """\
/// Copyright (C) 2015-2022 Virgil Security, Inc.
///
/// All rights reserved.
///
/// Redistribution and use in source and binary forms, with or without
/// modification, are permitted provided that the following conditions are
/// met:
///
///     (1) Redistributions of source code must retain the above copyright
///     notice, this list of conditions and the following disclaimer.
///
///     (2) Redistributions in binary form must reproduce the above copyright
///     notice, this list of conditions and the following disclaimer in
///     the documentation and/or other materials provided with the
///     distribution.
///
///     (3) Neither the name of the copyright holder nor the names of its
///     contributors may be used to endorse or promote products derived from
///     this software without specific prior written permission.
///
/// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
/// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
/// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
/// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
/// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
/// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
/// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
/// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
/// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
/// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
/// POSSIBILITY OF SUCH DAMAGE.
///
/// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>"""


# ---------------------------------------------------------------------------
# Enum generator
# ---------------------------------------------------------------------------

# Enums that are NOT emitted as standalone .swift enum files:
# - "status" → becomes {Project}Error.swift (infrastructure, handled separately)
# - "impl/tag" → C-internal dispatch enum, part of {Project}Implementation.swift
_INFRASTRUCTURE_ENUMS = frozenset({"status", "impl/tag"})


def generate_swift_enum(project_ir: IRProject, enum: IREnum) -> str:
    """Generate the ``.swift`` file content for a single enum.

    Format (matches ``wrappers/swift/VirgilCrypto/VirgilCryptoFoundation/AlgId.swift``)::

        /// <license>

        import Foundation
        import <Framework>

        /// <description>
        @objc(<PREFIX><TypeName>) public enum <TypeName>: Int {

            case <caseName>
            ...

            /// Create enumeration value from the correspond C enumeration value.
            internal init(fromC <paramName>: <c_type_t>) {
                self.init(rawValue: Int(<paramName>.rawValue))!
            }
        }
    """
    type_name = swift_type_name(enum.name)
    objc_name = f"{_objc_prefix(project_ir)}{type_name}"
    framework = _framework(project_ir)
    c_type = _c_enum_type(project_ir, enum)
    param_name = _from_c_param_name(enum)

    lines: list[str] = []
    lines.append(_SWIFT_LICENSE)
    lines.append("")
    lines.append("")
    lines.append("import Foundation")
    lines.append(f"import {framework}")
    lines.append("")

    # Enum doc comment
    doc = enum.description.strip() if enum.description else ""
    if doc:
        lines.append(f"/// {doc}")

    lines.append(f"@objc({objc_name}) public enum {type_name}: Int {{")
    lines.append("")

    # Enum cases
    next_default = 0
    for const in enum.constants:
        case_name = swift_case_name(const.name)

        # Doc comment for this case
        const_doc = const.description.strip() if const.description else ""
        if const_doc:
            for doc_line in const_doc.splitlines():
                lines.append(f"    /// {doc_line.strip()}")

        # Value handling — emit an explicit ``= N`` whenever the source
        # XML model provides a value; omit when no value is specified
        # (Swift auto-increments from the previous raw value).
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
    lines.append(f"    internal init(fromC {param_name}: {c_type}) {{")
    lines.append(f"        self.init(rawValue: Int({param_name}.rawValue))!")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def generate_swift_files(
    project_ir: IRProject, license_text: str = ""
) -> list[tuple[str, str]]:
    """Generate all Swift wrapper files for a project.

    Returns a list of ``(repo_relative_path, file_content)`` tuples.
    The caller writes these to disk.
    """
    del license_text  # Accepted for API parity; Swift files use _SWIFT_LICENSE

    output_dir = _source_dir(project_ir)
    files: list[tuple[str, str]] = []

    # --- Enums ---
    for enum in project_ir.enums:
        if enum.name in _INFRASTRUCTURE_ENUMS:
            continue
        if enum.attrs.get("scope") == "private":
            continue
        stem = swift_type_name(enum.name)
        files.append((f"{output_dir}{stem}.swift", generate_swift_enum(project_ir, enum)))

    # --- Interfaces (protocols) ---
    # TODO: Unit 2 — generate_swift_protocol()

    # --- Infrastructure files ---
    # TODO: Unit 2 — CContext.swift, {Project}Error.swift, {Project}Implementation.swift

    # --- Classes ---
    # TODO: Unit 2 — generate_swift_class()

    # --- Implementations ---
    # TODO: Unit 2 — generate_swift_implementation()

    return files
