"""Swift wrapper file generation for the project-rooted codegen pipeline.

Ports the legacy ``codegen/swift.gsl`` / ``codegen/swift_codegen.gsl``
templates to Python, consuming the shared :class:`IRProject` already
used by the C, CMake, and Go backends.

Each entity (enum, interface, class, implementation) becomes a single
``.swift`` file.  Per-project infrastructure files (``CContext.swift``,
``{Project}Error.swift``, ``{Project}Implementation.swift``) are also
generated.

Enum files are generated from the IR (model-driven, no resolved XML).
All other file types (protocols, classes, implementations, infrastructure)
are assembled from the resolved Swift XML which contains pre-computed
Swift code blocks. This gives byte-perfect parity with the legacy GSL
output while the IR-based approach matures.
"""
from __future__ import annotations

import textwrap
import xml.etree.ElementTree as ET
from pathlib import Path

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
// Copyright (C) 2015-2022 Virgil Security, Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>"""


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
    lines.append("import Foundation")
    lines.append(f"import {framework}")
    lines.append("")

    # Enum doc comment
    doc = enum.description.strip() if enum.description else ""
    if doc:
        lines.append(f"/// {doc}")

    lines.append(f"@objc({objc_name}) public enum {type_name}: Int {{")

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
    lines.append(f"    init(fromC {param_name}: {c_type}) {{")
    lines.append(f"        self.init(rawValue: Int({param_name}.rawValue))!")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Resolved XML loading
# ---------------------------------------------------------------------------

def _load_resolved_swift_xml(
    project_name: str, repo_root: str | Path = "."
) -> ET.Element | None:
    """Load the resolved Swift XML for a project, or None if unavailable."""
    path = (
        Path(repo_root)
        / "codegen"
        / "generated"
        / project_name
        / f"swift_project_{project_name}.xml"
    )
    if not path.exists():
        return None
    return ET.parse(str(path)).getroot()


# ---------------------------------------------------------------------------
# Swift file renderer from resolved XML modules
# ---------------------------------------------------------------------------

def _dedent_block(text: str) -> list[str]:
    """Remove the common leading whitespace from a resolved XML text block.

    Returns a list of lines with relative indentation preserved.
    Empty lines in the original are preserved as empty strings.

    Multi-space runs within lines are collapsed to single spaces —
    the resolved XML stores code with alignment padding (e.g.,
    ``vsc_data(ptr.bindMemory(to:                  byte.self)``)
    that the GSL output normalizes to single spaces.
    """
    import re
    raw_lines = text.split("\n")
    # Find minimum indent among non-empty lines
    content_lines = [l for l in raw_lines if l.strip()]
    if not content_lines:
        return []
    min_indent = min(len(l) - len(l.lstrip()) for l in content_lines)
    result: list[str] = []
    for l in raw_lines:
        if l.strip():
            stripped = l[min_indent:]
            # Preserve leading indent, collapse internal multi-spaces
            leading = len(stripped) - len(stripped.lstrip())
            indent = stripped[:leading]
            body = stripped[leading:]
            body = re.sub(r"  +", " ", body)
            result.append(indent + body)
        else:
            result.append("")
    # Strip leading and trailing empty lines
    while result and not result[0]:
        result.pop(0)
    while result and not result[-1]:
        result.pop()
    return result


def _render_module_from_xml(
    module: ET.Element, project_root: ET.Element
) -> str:
    """Render a single ``<swift_module>`` element to a complete ``.swift`` file.

    Handles protocols, classes (with methods, properties, dependencies),
    enums (FoundationError style with handleStatus), and infrastructure.
    """
    prefix = project_root.get("prefix", "")

    lines: list[str] = []

    # --- License ---
    lic = module.find("swift_license")
    if lic is not None and lic.text:
        lic_lines = _dedent_block(lic.text)
        lines.extend(lic_lines)
    else:
        lines.append(_SWIFT_LICENSE)

    lines.append("")
    lines.append("")

    # --- Imports ---
    imports = module.findall("swift_import")
    for imp in imports:
        lines.append(f"import {imp.get('framework', '')}")

    if imports:
        lines.append("")

    # --- Entity (one per module: swift_protocol, swift_class, or swift_enum) ---
    entity = module.find("swift_protocol")
    if entity is None:
        entity = module.find("swift_class")
    if entity is None:
        entity = module.find("swift_enum")
    if entity is None:
        return "\n".join(lines) + "\n"

    tag = entity.tag

    if tag == "swift_protocol":
        _render_protocol(entity, lines)
    elif tag == "swift_class":
        _render_class(entity, prefix, lines)
    elif tag == "swift_enum":
        _render_enum_from_xml(entity, prefix, lines)

    lines.append("")
    return "\n".join(lines)


def _extract_doc(text: str | None) -> str | None:
    """Extract doc comment lines from an XML text block.

    Returns the dedented ``/// ...`` lines, or None if empty.
    """
    if not text:
        return None
    raw_lines = text.split("\n")
    content_lines = [l for l in raw_lines if l.strip()]
    if not content_lines:
        return None
    min_indent = min(len(l) - len(l.lstrip()) for l in content_lines)
    stripped = [l[min_indent:] if len(l) > min_indent else l.strip() for l in content_lines]
    return "\n".join(stripped)


def _entity_doc(entity: ET.Element) -> str | None:
    """Extract the doc comment from an entity's text content."""
    return _extract_doc(entity.text)


def _code_tail_doc(entity: ET.Element) -> str | None:
    """Extract the doc comment stored in the .tail of the last child element.

    The GSL stores method/constructor doc comments in the .tail of the
    <swift_code> child element rather than in the entity's own .text.
    """
    code = entity.find("swift_code")
    if code is not None and code.tail:
        return _extract_doc(code.tail)
    # Also check .tail of last child
    children = list(entity)
    if children:
        last = children[-1]
        if last.tail:
            return _extract_doc(last.tail)
    return None


def _render_protocol(proto: ET.Element, lines: list[str]) -> None:
    """Render a ``<swift_protocol>`` to lines."""
    name = proto.get("name", "")
    objc_name = proto.get("objc_name", "")

    # Doc comment
    doc = _entity_doc(proto)
    if doc:
        lines.append(doc)

    # Inheritance
    inherits = [inh.get("type", "") for inh in proto.findall("swift_inherit")]
    inherit_str = f" : {', '.join(inherits)}" if inherits else ""

    lines.append(f"@objc({objc_name}) public protocol {name}{inherit_str} {{")

    # Properties
    for prop in proto.findall("swift_property"):
        prop_doc = _entity_doc(prop)
        if prop_doc:
            lines.append(f"    {prop_doc}")
        prop_name = prop.get("name", "")
        prop_type = prop.get("type", "")
        lines.append(f"    @objc var {prop_name}: {prop_type} {{ get }}")

    # Methods
    for meth in proto.findall("swift_method"):
        _render_protocol_method(meth, lines)

    lines.append("}")


def _render_protocol_method(meth: ET.Element, lines: list[str]) -> None:
    """Render a single method declaration inside a protocol."""
    name = meth.get("name", "")
    throws = meth.get("throws", "0") == "1"

    # Doc comment — may be in .text or in a child text node
    doc = _entity_doc(meth)

    # Arguments
    args = meth.findall("swift_argument")
    arg_parts: list[str] = []
    for arg in args:
        arg_name = arg.get("name", "")
        arg_type = arg.get("type", "")
        arg_parts.append(f"{arg_name}: {arg_type}")

    # Return
    ret = meth.find("swift_return")
    ret_type = ret.get("type", "Void") if ret is not None else "Void"

    throws_str = " throws" if throws else ""
    ret_str = f" -> {ret_type}" if ret_type != "Void" else ""

    lines.append("")
    if doc:
        lines.append(f"    {doc}")
    lines.append(f"    @objc func {name}({', '.join(arg_parts)}){throws_str}{ret_str}")


def _render_class(cls: ET.Element, prefix: str, lines: list[str]) -> None:
    """Render a ``<swift_class>`` to lines."""
    name = cls.get("name", "")
    objc_name = cls.get("objc_name", "")

    # Inheritance
    inherits = [inh.get("type", "") for inh in cls.findall("swift_inherit")]
    inherit_str = f": {', '.join(inherits)}" if inherits else ""

    lines.append(f"@objc({objc_name}) public class {name}{inherit_str} {{")
    lines.append("")

    # Properties
    for prop in cls.findall("swift_property"):
        prop_doc = _entity_doc(prop)
        if prop_doc:
            lines.append(f"    {prop_doc}")
        prop_name = prop.get("name", "")
        prop_type = prop.get("type", "")
        prop_value = prop.get("value", "")
        if prop_value:
            lines.append(f"    @objc public let {prop_name}: {prop_type} = {prop_value}")
        else:
            lines.append(f"    @objc public let {prop_name}: {prop_type}")
        lines.append("")

    # Lifecycle (init, take, use, deinit) — from swift_constructor elements
    for ctor in cls.findall("swift_constructor"):
        _render_constructor(ctor, lines)

    # Deinit
    deinit_el = cls.find("swift_destructor")
    if deinit_el is not None:
        code = deinit_el.find("swift_code")
        if code is not None and code.text:
            code_lines = _dedent_block(code.text)
            lines.append("    /// Release underlying C context.")
            lines.append("    deinit {")
            for cl in code_lines:
                if cl:
                    lines.append(f"        {cl}")
                else:
                    lines.append("")
            lines.append("    }")
            lines.append("")

    # Methods (including setters)
    for meth in cls.findall("swift_method"):
        _render_class_method(meth, lines)

    lines.append("}")


def _render_constructor(ctor: ET.Element, lines: list[str]) -> None:
    """Render a ``<swift_constructor>`` (init, take, use) to lines."""
    doc = _entity_doc(ctor)
    if doc:
        lines.append(f"    {doc}")

    is_override = ctor.get("override", "0") == "1"

    args = ctor.findall("swift_argument")
    arg_parts: list[str] = []
    for arg in args:
        arg_name = arg.get("name", "")
        ext_name = arg.get("ext_name", "")
        arg_type = arg.get("type", "")
        if ext_name:
            arg_parts.append(f"{ext_name} {arg_name}: {arg_type}")
        else:
            arg_parts.append(f"{arg_name}: {arg_type}")

    override_str = "override " if is_override else ""
    args_str = ", ".join(arg_parts)

    code = ctor.find("swift_code")
    if code is not None and code.text:
        code_lines = _dedent_block(code.text)
        lines.append(f"    public {override_str}init({args_str}) {{")
        for cl in code_lines:
            if cl:
                lines.append(f"        {cl}")
            else:
                lines.append("")
        lines.append("    }")
        lines.append("")


def _render_class_method(meth: ET.Element, lines: list[str]) -> None:
    """Render a single method inside a class."""
    name = meth.get("name", "")
    throws = meth.get("throws", "0") == "1"
    modifier = meth.get("modifier", "")
    objc = meth.get("objc", "0") == "1"

    # Doc comment
    doc = _entity_doc(meth)

    # Arguments
    args = meth.findall("swift_argument")
    arg_parts: list[str] = []
    for arg in args:
        arg_name = arg.get("name", "")
        ext_name = arg.get("ext_name", "")
        arg_type = arg.get("type", "")
        if ext_name:
            arg_parts.append(f"{ext_name} {arg_name}: {arg_type}")
        else:
            arg_parts.append(f"{arg_name}: {arg_type}")

    # Return type — check for multi-return result struct
    returns = meth.findall("swift_return")
    if len(returns) == 0:
        ret_type = "Void"
    elif len(returns) == 1:
        ret_type = returns[0].get("type", "Void")
    else:
        # Multi-return: the method declares a named result type
        ret_type = meth.get("return_type", returns[0].get("type", "Void"))

    throws_str = " throws" if throws else ""
    ret_str = f" -> {ret_type}" if ret_type != "Void" else ""
    modifier_str = "static " if modifier == "static" else ""
    objc_str = "@objc " if objc else ""

    code = meth.find("swift_code")
    if code is not None and code.text:
        code_lines = _dedent_block(code.text)
        if doc:
            lines.append(f"    {doc}")
        lines.append(
            f"    {objc_str}public {modifier_str}func {name}"
            f"({', '.join(arg_parts)}){throws_str}{ret_str} {{"
        )
        for cl in code_lines:
            if cl:
                lines.append(f"        {cl}")
            else:
                lines.append("")
        lines.append("    }")
        lines.append("")


def _render_enum_from_xml(enum: ET.Element, prefix: str, lines: list[str]) -> None:
    """Render a ``<swift_enum>`` from resolved XML (used for FoundationError etc.)."""
    name = enum.get("name", "")
    objc_name = enum.get("objc_name", "")

    # Doc comment
    doc = _entity_doc(enum)
    if doc:
        lines.append(doc)

    # Inheritance
    inherits = [inh.get("type", "") for inh in enum.findall("swift_inherit")]
    inherit_str = f": {', '.join(inherits)}" if inherits else ""

    lines.append(f"@objc({objc_name}) public enum {name}{inherit_str} {{")
    lines.append("")

    # Constants (cases)
    for const in enum.findall("swift_constant"):
        const_doc = _entity_doc(const)
        if const_doc:
            lines.append(f"    {const_doc}")
        const_name = const.get("name", "")
        const_value = const.get("value", "")
        if const_value:
            lines.append(f"    case {const_name} = {const_value}")
        else:
            lines.append(f"    case {const_name}")
        lines.append("")

    # fromC initializer
    from_c = enum.find("swift_constructor")
    if from_c is not None:
        from_c_doc = _entity_doc(from_c)
        if from_c_doc:
            lines.append(f"    {from_c_doc}")
        args = from_c.findall("swift_argument")
        arg_parts: list[str] = []
        for a in args:
            ext = a.get("ext_name", "")
            nm = a.get("name", "")
            tp = a.get("type", "")
            arg_parts.append(f"{ext + ' ' if ext else ''}{nm}: {tp}")
        code = from_c.find("swift_code")
        if code is not None and code.text:
            code_lines = _dedent_block(code.text)
            lines.append(f"    internal init({', '.join(arg_parts)}) {{")
            for cl in code_lines:
                if cl:
                    lines.append(f"        {cl}")
                else:
                    lines.append("")
            lines.append("    }")

    # handleStatus method (on error enums)
    for meth in enum.findall("swift_method"):
        _render_class_method(meth, lines)

    lines.append("}")


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def generate_swift_files(
    project_ir: IRProject, license_text: str = "",
    repo_root: str | Path = ".",
) -> list[tuple[str, str]]:
    """Generate all Swift wrapper files for a project.

    Returns a list of ``(repo_relative_path, file_content)`` tuples.
    The caller writes these to disk.

    Enum files are generated from the IR (model-driven).
    All other files (protocols, classes, implementations, infrastructure)
    are assembled from the resolved Swift XML.
    """
    del license_text  # Accepted for API parity; Swift files use _SWIFT_LICENSE

    output_dir = _source_dir(project_ir)
    files: list[tuple[str, str]] = []

    # --- Enums (from IR) ---
    enum_names: set[str] = set()
    for enum in project_ir.enums:
        if enum.name in _INFRASTRUCTURE_ENUMS:
            continue
        if enum.attrs.get("scope") == "private":
            continue
        stem = swift_type_name(enum.name)
        enum_names.add(stem)
        files.append((f"{output_dir}{stem}.swift", generate_swift_enum(project_ir, enum)))

    # --- Everything else (from resolved XML) ---
    xml_root = _load_resolved_swift_xml(project_ir.name, repo_root)
    if xml_root is not None:
        for module in xml_root.findall(".//swift_module"):
            file_name = module.get("source_file_name", "")
            if not file_name:
                continue
            # Skip enum files that are already generated from IR
            stem = file_name.replace(".swift", "")
            if stem in enum_names:
                continue
            content = _render_module_from_xml(module, xml_root)
            files.append((f"{output_dir}{file_name}", content))

    return files
