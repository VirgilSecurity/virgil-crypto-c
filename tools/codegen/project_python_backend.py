"""Python wrapper file generation for the project-rooted codegen pipeline.

Generates ALL output from the IR — no reading of legacy files.

Entity types and their output:
- Enums → bridge enum file + high-level enum file
- Status enum → bridge status file (with error class + STATUS_DICT) +
                high-level status file (same pattern)
- Impl/tag enum → bridge impl_tag file (dispatch table)
- Interfaces → high-level abstract class file
- Classes (public, non-error) → bridge class file + high-level class file
- Implementations → bridge class file + high-level class file
- Error class → bridge error file (Structure + wrapper)
- Impl module → bridge _impl.py (opaque struct)
- Common project → hardcoded Data/Buffer infrastructure
- __init__.py → both bridge and high-level aggregators
"""
from __future__ import annotations

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
# Per-project configuration
# ---------------------------------------------------------------------------

_PROJECT_PREFIX_MAP = {
    "common": "vsc",
    "foundation": "vscf",
    "phe": "vsce",
}

# Projects where certain class names have a project-specific prefix that
# gets stripped for the high-level Python class name and filename.
# e.g., phe: "phe server" -> "server" at high-level, "phe common" -> "common"
_PROJECT_CLASS_PREFIX_STRIP = {
    "phe": "phe",
}


def _bridge_dir(project_ir: IRProject) -> str:
    return f"wrappers/python/virgil_crypto_lib/{project_ir.name}/_c_bridge/"


def _highlevel_dir(project_ir: IRProject) -> str:
    return f"wrappers/python/virgil_crypto_lib/{project_ir.name}/"


# ---------------------------------------------------------------------------
# Name utilities
# ---------------------------------------------------------------------------

def _snake_name(entity_name: str) -> str:
    """``"alg id"`` -> ``"alg_id"``, ``"sha256"`` -> ``"sha256"``."""
    return entity_name.replace(" ", "_").lower()


def _pascal_name(entity_name: str) -> str:
    """``"sha256"`` -> ``"Sha256"``, ``"alg id"`` -> ``"AlgId"``."""
    return "".join(w.capitalize() for w in entity_name.replace("_", " ").split())


def _upper_snake(name: str) -> str:
    """``"digest len"`` -> ``"DIGEST_LEN"``."""
    return name.replace(" ", "_").upper()


def _python_constant_value(value: str) -> str:
    """Convert C-style constant values to Python syntax.

    ``"true"`` → ``"True"``, ``"false"`` → ``"False"``.
    """
    if value.strip().lower() == "true":
        return "True"
    if value.strip().lower() == "false":
        return "False"
    return value


def _bridge_class_name(project_ir: IRProject, entity_name: str) -> str:
    """``"sha256"`` with prefix ``vscf`` -> ``"VscfSha256"``."""
    prefix = project_ir.prefix.capitalize()
    return f"{prefix}{_pascal_name(entity_name)}"


def _c_func_name(project_ir: IRProject, entity_name: str, method_name: str) -> str:
    """``("vscf", "sha256", "alg_id")`` -> ``"vscf_sha256_alg_id"``."""
    return f"{project_ir.prefix}_{_snake_name(entity_name)}_{_snake_name(method_name)}"


def _hl_entity_name(project_ir: IRProject, entity_name: str) -> str:
    """Derive the high-level entity name, stripping project class prefix if needed.

    ``"phe server"`` in phe -> ``"server"``
    ``"sha256"`` in foundation -> ``"sha256"``
    """
    strip_prefix = _PROJECT_CLASS_PREFIX_STRIP.get(project_ir.name)
    if strip_prefix and entity_name.startswith(strip_prefix + " "):
        return entity_name[len(strip_prefix) + 1:]
    return entity_name


def _hl_class_name(project_ir: IRProject, entity_name: str) -> str:
    """High-level Python class name."""
    return _pascal_name(_hl_entity_name(project_ir, entity_name))


def _hl_file_stem(project_ir: IRProject, entity_name: str) -> str:
    """High-level Python file stem (without .py)."""
    return _snake_name(_hl_entity_name(project_ir, entity_name))


def _error_exception_class(project_ir: IRProject) -> str:
    """Exception class name for project: ``VirgilCryptoFoundationError``."""
    return f"VirgilCrypto{_pascal_name(project_ir.name)}Error"


# ---------------------------------------------------------------------------
# License header
# ---------------------------------------------------------------------------

def _format_license_hash(raw: str) -> str:
    """Format raw license text as # comments (Python/CMake style)."""
    lines = []
    for line in raw.splitlines():
        lines.append(f"# {line}".rstrip() if line.strip() else "#")
    return "\n".join(lines)


_PYTHON_LICENSE = ""  # populated by generate_python_files()


# ---------------------------------------------------------------------------
# Filtering helpers (mirroring Go backend patterns)
# ---------------------------------------------------------------------------

def _method_should_wrap(method: IRCMethod) -> bool:
    """Public scope, declaration, visibility — matches Go backend."""
    scope = method.attrs.get("scope", "public")
    decl = method.declaration or method.attrs.get("declaration", "public")
    vis = method.visibility or method.attrs.get("visibility", "public")
    return scope == "public" and decl == "public" and vis == "public"


def _entity_is_public(attrs: dict) -> bool:
    return attrs.get("scope", "public") == "public"


def _is_static_class(cls: IRClass) -> bool:
    return cls.attrs.get("context") == "none"


def _is_error_class(cls: IRClass) -> bool:
    return cls.name == "error"


def _class_has_context(cls: IRClass) -> bool:
    """True if the class has an opaque C context (not static, not error with lifecycle=none)."""
    ctx = cls.attrs.get("context", "public")
    lifecycle = cls.attrs.get("lifecycle", "default")
    return ctx != "none" and lifecycle != "none"


def _arg_should_skip(arg: IRCArgument) -> bool:
    """Arguments filtered from wrapper API (writeonly buffer, error class)."""
    if arg.access == "writeonly":
        return True
    if arg.class_name == "error":
        return True
    return False


def _arg_is_buffer_output(arg: IRCArgument) -> bool:
    return arg.class_name == "buffer"


def _method_has_error_arg(method: IRCMethod) -> bool:
    return any(arg.class_name == "error" for arg in method.arguments)


def _method_returns_status(method: IRCMethod) -> bool:
    return any(r.enum_name == "status" for r in method.returns)


def _method_returns_impl(method: IRCMethod) -> bool:
    """True if the method returns an interface (impl pointer)."""
    for r in method.returns:
        if r.interface_name:
            return True
    return False


def _method_returns_class(method: IRCMethod) -> bool:
    """True if the method returns a class (not data/buffer)."""
    for r in method.returns:
        if r.class_name and r.class_name not in ("data", "buffer"):
            return True
    return False


def _method_returns_data(method: IRCMethod) -> bool:
    for r in method.returns:
        if r.class_name == "data":
            return True
    return False


def _flatten_description(desc: str) -> str:
    """Collapse multi-line description to single line for STATUS_DICT."""
    lines = [line.strip() for line in desc.strip().splitlines()]
    return " ".join(line for line in lines if line)


def _resolve_project_prefix(project_ir: IRProject, project_name: str | None) -> str:
    if not project_name or project_name == project_ir.name:
        return project_ir.prefix
    return _PROJECT_PREFIX_MAP.get(project_name, project_name)


# ---------------------------------------------------------------------------
# ctypes type mapping for bridge layer
# ---------------------------------------------------------------------------

def _bridge_argtype(project_ir: IRProject, arg: IRCArgument) -> str:
    """Map an IR argument to its ctypes type string for bridge argtypes."""
    if arg.class_name == "data":
        return "vsc_data_t"
    if arg.class_name == "buffer":
        return "POINTER(vsc_buffer_t)"
    if arg.class_name == "error":
        prefix = _resolve_project_prefix(project_ir, arg.project)
        return f"POINTER({prefix}_error_t)"
    if arg.interface_name:
        prefix = _resolve_project_prefix(project_ir, arg.project)
        return f"POINTER({prefix}_impl_t)"
    if arg.class_name and arg.class_name not in ("data", "buffer"):
        prefix = _resolve_project_prefix(project_ir, arg.project)
        stem = _snake_name(arg.class_name)
        return f"POINTER({prefix}_{stem}_t)"
    if arg.enum_name:
        return "c_int"
    type_name = (arg.type_name or "").lower()
    if type_name == "size":
        return "c_size_t"
    if type_name == "boolean":
        return "c_bool"
    if type_name == "integer":
        return "c_int"
    if type_name == "unsigned":
        return "c_uint"
    if type_name == "byte":
        if arg.is_reference:
            return "POINTER(c_byte)"
        return "c_byte"
    if type_name == "string":
        return "c_char_p"
    if type_name == "nothing":
        return "None"
    return "c_int"


def _bridge_restype(project_ir: IRProject, method: IRCMethod, entity_name: str) -> str:
    """Determine the ctypes restype string for a bridge method."""
    if not method.returns:
        return "None"
    ret = method.returns[0]
    if ret.enum_name == "status":
        return "c_int"
    if ret.class_name == "data":
        return "vsc_data_t"
    if ret.class_name == "buffer":
        return "POINTER(vsc_buffer_t)"
    if ret.interface_name:
        prefix = _resolve_project_prefix(project_ir, ret.project)
        return f"POINTER({prefix}_impl_t)"
    if ret.class_name and ret.class_name not in ("data", "buffer"):
        prefix = _resolve_project_prefix(project_ir, ret.project)
        stem = _snake_name(ret.class_name)
        return f"POINTER({prefix}_{stem}_t)"
    if ret.enum_name:
        return "c_int"
    type_name = (ret.type_name or "").lower()
    if type_name == "size":
        return "c_size_t"
    if type_name == "boolean":
        return "c_bool"
    if type_name == "integer":
        return "c_int"
    if type_name == "unsigned":
        return "c_uint"
    if type_name == "byte":
        if ret.is_reference:
            return "POINTER(c_byte)"
        return "c_byte"
    return "c_int"


# ---------------------------------------------------------------------------
# Bridge file generators
# ---------------------------------------------------------------------------

def _bridge_imports_for_entity(
    project_ir: IRProject, methods: list[IRCMethod],
    dependencies: list | None = None, has_context: bool = True,
) -> list[str]:
    """Determine which bridge imports are needed for a class/impl bridge file."""
    needs_impl = False
    needs_data = False
    needs_buffer = False
    other_classes: set[str] = set()  # (prefix, snake_name) tuples as strings
    other_error_classes: set[str] = set()

    def _scan_arg(a: IRCArgument) -> None:
        nonlocal needs_impl, needs_data, needs_buffer
        if a.interface_name:
            needs_impl = True
        elif a.class_name == "data":
            needs_data = True
        elif a.class_name == "buffer":
            needs_buffer = True
        elif a.class_name == "error":
            prefix = _resolve_project_prefix(project_ir, a.project)
            other_error_classes.add(prefix)
        elif a.class_name and a.class_name not in ("data", "buffer", "self"):
            # Skip external library types (e.g., mbedtls_ecp_group)
            if a.library and a.library not in _PROJECT_PREFIX_MAP:
                return
            prefix = _resolve_project_prefix(project_ir, a.project)
            stem = _snake_name(a.class_name)
            other_classes.add(f"{prefix}_{stem}")

    for m in methods:
        for a in m.arguments:
            _scan_arg(a)
        for r in m.returns:
            _scan_arg(r)

    if dependencies:
        for dep in dependencies:
            if dep.type_kind == "interface":
                needs_impl = True
            elif dep.type_kind in ("class", "impl"):
                prefix = _resolve_project_prefix(
                    project_ir, dep.attrs.get("project")
                )
                stem = _snake_name(dep.type_name)
                if dep.type_name in ("data", "buffer"):
                    if dep.type_name == "data":
                        needs_data = True
                    else:
                        needs_buffer = True
                else:
                    other_classes.add(f"{prefix}_{stem}")

    lines: list[str] = []
    if needs_impl:
        # impl_t is always from foundation (vscf_impl_t) for all projects
        # Only foundation defines the impl type; other projects import it
        if project_ir.prefix == "vscf":
            lines.append(f"from ._{project_ir.prefix}_impl import {project_ir.prefix}_impl_t")
        else:
            lines.append("from virgil_crypto_lib.foundation._c_bridge import vscf_impl_t")
    if needs_data:
        lines.append("from virgil_crypto_lib.common._c_bridge import vsc_data_t")
    if needs_buffer:
        lines.append("from virgil_crypto_lib.common._c_bridge import vsc_buffer_t")
    for err_prefix in sorted(other_error_classes):
        lines.append(f"from ._{err_prefix}_error import {err_prefix}_error_t")
    for cls_key in sorted(other_classes):
        lines.append(f"from ._{cls_key} import {cls_key}_t")
    return lines


def _generate_bridge_class_body(
    project_ir: IRProject,
    entity_name: str,
    description: str,
    methods: list[IRCMethod],
    constants: list[IRCConstant],
    dependencies: list | None,
    has_context: bool,
    is_impl: bool,
) -> str:
    """Generate a complete bridge class file for a class or implementation."""
    prefix = project_ir.prefix
    snake = _snake_name(entity_name)
    bridge_cls = _bridge_class_name(project_ir, entity_name)
    c_func_prefix = f"{prefix}_{snake}"
    struct_name = f"{prefix}_{snake}_t"

    lines: list[str] = []
    lines.append(_PYTHON_LICENSE)
    lines.append("")
    lines.append("")
    lines.append("from virgil_crypto_lib._libs import *")
    lines.append("from ctypes import *")

    # Collect imports from methods and deps
    imp_lines = _bridge_imports_for_entity(
        project_ir, methods, dependencies, has_context
    )
    # Implementations always need impl_t for the _impl() method
    if is_impl and has_context:
        impl_import = f"from ._{project_ir.prefix}_impl import {project_ir.prefix}_impl_t"
        if impl_import not in imp_lines:
            imp_lines.insert(0, impl_import)
    for il in imp_lines:
        lines.append(il)

    lines.append("")
    lines.append("")

    # Opaque struct (only for classes with context, not static)
    if has_context:
        lines.append(f"class {struct_name}(Structure):")
        lines.append("    pass")
        lines.append("")
        lines.append("")

    lines.append(f"class {bridge_cls}(object):")
    if description:
        lines.append(f'    """{description}"""')
    lines.append("")

    # Constants as class attributes
    # Resolve entity for constant cross-references
    _entity_ref = None
    for _ent in list(project_ir.classes) + list(project_ir.implementations):
        if _ent.name == entity_name:
            _entity_ref = _ent
            break
    for const in constants:
        name = _upper_snake(const.name)
        value = resolve_constant_value(
            const.attrs.get("value", "0"), _entity_ref, project_ir
        )
        desc = const.description.strip() if const.description else ""
        if desc:
            for desc_line in desc.splitlines():
                lines.append(f"    # {desc_line.strip()}")
        lines.append(f"    {name} = {_python_constant_value(value)}")

    # __init__
    lines.append("")
    lines.append("    def __init__(self):")
    lines.append('        """Create underlying C context."""')
    lines.append("        self._ll = LowLevelLibs()")
    lines.append(f"        self._lib = self._ll.{project_ir.name}")

    # new/delete for classes with context
    if has_context:
        lines.append("")
        lines.append(f"    def {c_func_prefix}_new(self):")
        lines.append(f"        {c_func_prefix}_new = self._lib.{c_func_prefix}_new")
        lines.append(f"        {c_func_prefix}_new.argtypes = []")
        lines.append(f"        {c_func_prefix}_new.restype = POINTER({struct_name})")
        lines.append(f"        return {c_func_prefix}_new()")

        lines.append("")
        lines.append(f"    def {c_func_prefix}_delete(self, ctx):")
        lines.append(f"        {c_func_prefix}_delete = self._lib.{c_func_prefix}_delete")
        lines.append(f"        {c_func_prefix}_delete.argtypes = [POINTER({struct_name})]")
        lines.append(f"        {c_func_prefix}_delete.restype = None")
        lines.append(f"        return {c_func_prefix}_delete(ctx)")

    # Dependency use_ methods
    if dependencies:
        for dep in dependencies:
            dep_snake = _snake_name(dep.name)
            use_func = f"{c_func_prefix}_use_{dep_snake}"
            dep_prefix = _resolve_project_prefix(
                project_ir, dep.attrs.get("project")
            )
            if dep.type_kind == "interface":
                dep_type = f"POINTER({dep_prefix}_impl_t)"
            elif dep.type_kind in ("class", "impl"):
                dep_stem = _snake_name(dep.type_name)
                dep_type = f"POINTER({dep_prefix}_{dep_stem}_t)"
            else:
                dep_type = f"POINTER({dep_prefix}_impl_t)"

            lines.append("")
            lines.append(f"    def {use_func}(self, ctx, {dep_snake}):")
            # Check if the use function returns status
            if dep.has_observers and dep.is_observers_return_status:
                lines.append(f"        {use_func} = self._lib.{use_func}")
                lines.append(f"        {use_func}.argtypes = [POINTER({struct_name}), {dep_type}]")
                lines.append(f"        {use_func}.restype = c_int")
                lines.append(f"        return {use_func}(ctx, {dep_snake})")
            else:
                lines.append(f"        {use_func} = self._lib.{use_func}")
                lines.append(f"        {use_func}.argtypes = [POINTER({struct_name}), {dep_type}]")
                lines.append(f"        {use_func}.restype = None")
                lines.append(f"        return {use_func}(ctx, {dep_snake})")

    # Methods
    for method in methods:
        if not _method_should_wrap(method):
            continue
        m_snake = _snake_name(method.name)
        c_name = f"{c_func_prefix}_{m_snake}"
        is_static = method.attrs.get("is_static") in ("1", "true")

        # Build argtypes
        argtypes: list[str] = []
        param_names: list[str] = []
        if has_context and not is_static:
            argtypes.append(f"POINTER({struct_name})")
            param_names.append("ctx")
        for arg in method.arguments:
            at = _bridge_argtype(project_ir, arg)
            argtypes.append(at)
            param_names.append(_snake_name(arg.name))

        # Build restype
        restype = _bridge_restype(project_ir, method, entity_name)

        # Build param string
        self_params = ", ".join(["self"] + param_names)
        desc = method.description.strip() if method.description else ""

        lines.append("")
        lines.append(f"    def {c_name}({self_params}):")
        if desc:
            lines.append(f'        """{desc}"""')
        lines.append(f"        {c_name} = self._lib.{c_name}")
        if argtypes:
            lines.append(f"        {c_name}.argtypes = [{', '.join(argtypes)}]")
        else:
            lines.append(f"        {c_name}.argtypes = []")
        lines.append(f"        {c_name}.restype = {restype}")
        call_args = ", ".join(param_names)
        lines.append(f"        return {c_name}({call_args})")

    # shallow_copy and _impl for classes with context
    if has_context:
        lines.append("")
        lines.append(f"    def {c_func_prefix}_shallow_copy(self, ctx):")
        lines.append(f"        {c_func_prefix}_shallow_copy = self._lib.{c_func_prefix}_shallow_copy")
        lines.append(f"        {c_func_prefix}_shallow_copy.argtypes = [POINTER({struct_name})]")
        lines.append(f"        {c_func_prefix}_shallow_copy.restype = POINTER({struct_name})")
        lines.append(f"        return {c_func_prefix}_shallow_copy(ctx)")

    # _impl method for implementations
    if is_impl and has_context:
        lines.append("")
        lines.append(f"    def {c_func_prefix}_impl(self, ctx):")
        lines.append(f"        {c_func_prefix}_impl = self._lib.{c_func_prefix}_impl")
        lines.append(f"        {c_func_prefix}_impl.argtypes = [POINTER({struct_name})]")
        lines.append(f"        {c_func_prefix}_impl.restype = POINTER({project_ir.prefix}_impl_t)")
        lines.append(f"        return {c_func_prefix}_impl(ctx)")

    lines.append("")
    return "\n".join(lines)


def _generate_bridge_enum(project_ir: IRProject, enum: IREnum) -> str:
    """Generate a bridge enum file (e.g., _vscf_alg_id.py)."""
    bridge_cls = _bridge_class_name(project_ir, enum.name)

    lines: list[str] = []
    lines.append(_PYTHON_LICENSE)
    lines.append("")
    lines.append("")
    lines.append("from ctypes import *")
    lines.append("")
    lines.append("")
    lines.append(f"class {bridge_cls}(object):")
    if enum.description:
        lines.append(f'    """{enum.description}"""')
    lines.append("")

    next_val = 0
    for const in enum.constants:
        name = _upper_snake(const.name)
        value = const.attrs.get("value")
        if value is not None and value != "":
            lines.append(f"    {name} = {_python_constant_value(value)}")
            try:
                next_val = int(value, 0) + 1
            except ValueError:
                next_val += 1
        else:
            lines.append(f"    {name} = {next_val}")
            next_val += 1

    lines.append("")
    return "\n".join(lines)


def _generate_bridge_status(project_ir: IRProject, status_enum: IREnum) -> str:
    """Generate the bridge status file with exception class, constants, STATUS_DICT."""
    prefix = project_ir.prefix
    bridge_cls = _bridge_class_name(project_ir, "status")
    error_cls = _error_exception_class(project_ir)

    lines: list[str] = []
    lines.append(_PYTHON_LICENSE)
    lines.append("")
    lines.append("")
    lines.append("from ctypes import *")
    lines.append("")
    lines.append("")
    lines.append(f"class {error_cls}(Exception):")
    lines.append("    pass")
    lines.append("")
    lines.append("")
    lines.append(f"class {bridge_cls}(object):")
    if status_enum.description:
        lines.append(f'    """{status_enum.description}"""')
    lines.append("")

    # Constants with comments
    for const in status_enum.constants:
        name = _upper_snake(const.name)
        value = const.attrs.get("value", "0")
        desc = const.description.strip() if const.description else ""
        if desc:
            for desc_line in desc.splitlines():
                stripped = desc_line.strip()
                if stripped:
                    lines.append(f"    # {stripped}")
        lines.append(f"    {name} = {_python_constant_value(value)}")

    # STATUS_DICT
    lines.append("")
    lines.append("    STATUS_DICT = {")
    for const in status_enum.constants:
        value = const.attrs.get("value", "0")
        desc = _flatten_description(const.description) if const.description else ""
        lines.append(f'        {value}: "{desc}",')
    # Remove trailing comma on last entry and close
    if status_enum.constants:
        last = lines[-1]
        if last.endswith(","):
            lines[-1] = last[:-1]
    lines.append("    }")

    lines.append("")
    lines.append("    @classmethod")
    lines.append("    def handle_status(cls, status):")
    lines.append('        """Handle low level lib status"""')
    lines.append("        if status != 0:")
    lines.append("            try:")
    lines.append(f"                raise {error_cls}(cls.STATUS_DICT[status])")
    lines.append("            except KeyError:")
    lines.append(f'                raise {error_cls}("Unknown error")')

    lines.append("")
    return "\n".join(lines)


def _generate_bridge_impl_tag(project_ir: IRProject) -> str:
    """Generate the bridge impl_tag dispatch file."""
    prefix = project_ir.prefix
    bridge_cls = _bridge_class_name(project_ir, "impl/tag")
    # The impl_tag class name uses the raw prefix: VscfImplTag
    bridge_cls = f"{prefix.capitalize()}ImplTag"

    lines: list[str] = []
    lines.append(_PYTHON_LICENSE)
    lines.append("")
    lines.append("")
    lines.append("from ctypes import *")

    # Import all implementation struct types
    for impl in sorted(project_ir.implementations, key=lambda i: i.name):
        stem = _snake_name(impl.name)
        lines.append(f"from virgil_crypto_lib.{project_ir.name}._c_bridge import {prefix}_{stem}_t")

    lines.append(f"from virgil_crypto_lib._libs import LowLevelLibs")
    lines.append(f"from virgil_crypto_lib.{project_ir.name}._c_bridge import {prefix}_impl_t")

    lines.append("")
    lines.append("")
    lines.append(f"class {bridge_cls}(object):")
    lines.append(f"    LL = LowLevelLibs()")
    lines.append(f"    LIB = LL.{project_ir.name}")
    lines.append("")
    lines.append("    @classmethod")
    lines.append("    def get_type(cls, impl):")

    # Build IMPL_TAG_T dict mapping tag IDs to [PascalName, struct_type]
    tag_name = f"{prefix.upper()}_IMPL_TAG_T"
    lines.append(f"        {tag_name} = {{")

    # Find the impl/tag enum to get the tag values
    impl_tag_enum = None
    for e in project_ir.enums:
        if e.name == "impl/tag":
            impl_tag_enum = e
            break

    if impl_tag_enum:
        # Build name -> index mapping from the enum constants.
        # In C, the impl_tag enum starts with BEGIN = 0, then the first
        # real tag is 1. The IR omits the BEGIN sentinel, so we start at 1.
        next_val = 1
        for const in impl_tag_enum.constants:
            value = const.attrs.get("value")
            if value is not None and value != "":
                try:
                    tag_id = int(value, 0)
                except ValueError:
                    tag_id = next_val
                next_val = tag_id + 1
            else:
                tag_id = next_val
                next_val += 1

            pascal = _pascal_name(const.name)
            stem = _snake_name(const.name)
            lines.append(f'            {tag_id}: ["{pascal}", {prefix}_{stem}_t],')

    # Remove trailing comma on last entry
    if lines[-1].endswith(","):
        lines[-1] = lines[-1][:-1]
    lines.append("        }")

    lines.append(f"        tag = cls.{prefix}_impl_tag(impl)")
    lines.append("")
    lines.append(f'        mod = __import__("virgil_crypto_lib.{project_ir.name}", fromlist=[{tag_name}[tag][0]])')
    lines.append(f"        klass = getattr(mod, {tag_name}[tag][0])")
    lines.append(f"        return klass, {tag_name}[tag][1]")

    lines.append("")
    lines.append("    @classmethod")
    lines.append(f"    def {prefix}_impl_tag(cls, impl):")
    lines.append(f"        {prefix}_impl_tag = cls.LIB.{prefix}_impl_tag")
    lines.append(f"        {prefix}_impl_tag.argtypes = [POINTER({prefix}_impl_t)]")
    lines.append(f"        {prefix}_impl_tag.restype = c_int")
    lines.append(f"        return {prefix}_impl_tag(impl)")

    lines.append("")
    return "\n".join(lines)


def _generate_bridge_impl_struct(project_ir: IRProject) -> str:
    """Generate the bridge _impl.py file (opaque struct)."""
    prefix = project_ir.prefix

    lines: list[str] = []
    lines.append(_PYTHON_LICENSE)
    lines.append("")
    lines.append("")
    lines.append("from ctypes import *")
    lines.append("")
    lines.append("")
    lines.append(f"class {prefix}_impl_t(Structure):")
    lines.append("    pass")
    lines.append("")
    return "\n".join(lines)


def _generate_bridge_error_class(project_ir: IRProject, cls: IRClass) -> str:
    """Generate bridge file for the 'error' utility class."""
    prefix = project_ir.prefix
    struct_name = f"{prefix}_error_t"
    bridge_cls = _bridge_class_name(project_ir, "error")

    lines: list[str] = []
    lines.append(_PYTHON_LICENSE)
    lines.append("")
    lines.append("")
    lines.append("from virgil_crypto_lib._libs import *")
    lines.append("from ctypes import *")
    lines.append("")
    lines.append("")
    lines.append(f"class {struct_name}(Structure):")
    lines.append("    _fields_ = [")
    lines.append('        ("status", c_int)')
    lines.append("    ]")
    lines.append("")
    lines.append("")
    lines.append(f"class {bridge_cls}(object):")
    if cls.description:
        lines.append(f'    """{cls.description}"""')
    lines.append("")
    lines.append("    def __init__(self):")
    lines.append('        """Create underlying C context."""')
    lines.append("        self._ll = LowLevelLibs()")
    lines.append(f"        self._lib = self._ll.{project_ir.name}")

    # Generate methods
    for method in cls.methods:
        if not _method_should_wrap(method):
            continue
        m_snake = _snake_name(method.name)
        c_name = f"{prefix}_error_{m_snake}"

        argtypes: list[str] = []
        param_names: list[str] = []
        argtypes.append(f"POINTER({struct_name})")
        param_names.append("ctx")
        for arg in method.arguments:
            at = _bridge_argtype(project_ir, arg)
            argtypes.append(at)
            param_names.append(_snake_name(arg.name))

        restype = _bridge_restype(project_ir, method, "error")
        self_params = ", ".join(["self"] + param_names)
        desc = method.description.strip() if method.description else ""

        lines.append("")
        lines.append(f"    def {c_name}({self_params}):")
        if desc:
            lines.append(f'        """{desc}"""')
        lines.append(f"        {c_name} = self._lib.{c_name}")
        lines.append(f"        {c_name}.argtypes = [{', '.join(argtypes)}]")
        lines.append(f"        {c_name}.restype = {restype}")
        call_args = ", ".join(param_names)
        lines.append(f"        return {c_name}({call_args})")

    lines.append("")
    return "\n".join(lines)


def _generate_bridge_static_class(
    project_ir: IRProject, cls: IRClass
) -> str:
    """Generate bridge file for a static-only class (context=none).

    Static classes have no opaque struct, no new/delete, no shallow_copy.
    Only class constants + static methods.
    """
    return _generate_bridge_class_body(
        project_ir,
        cls.name,
        cls.description,
        cls.methods,
        cls.constants,
        None,
        has_context=False,
        is_impl=False,
    )


# ---------------------------------------------------------------------------
# High-level file generators
# ---------------------------------------------------------------------------

def _generate_hl_enum(project_ir: IRProject, enum: IREnum) -> str:
    """Generate high-level enum file."""
    hl_cls = _hl_class_name(project_ir, enum.name)

    lines: list[str] = []
    lines.append(_PYTHON_LICENSE)
    lines.append("")
    lines.append("")
    lines.append("from ctypes import *")
    lines.append("")
    lines.append("")
    lines.append(f"class {hl_cls}(object):")
    if enum.description:
        lines.append(f'    """{enum.description}"""')
    lines.append("")

    next_val = 0
    for const in enum.constants:
        name = _upper_snake(const.name)
        value = const.attrs.get("value")
        desc = const.description.strip() if const.description else ""
        if desc:
            for desc_line in desc.splitlines():
                stripped = desc_line.strip()
                if stripped:
                    lines.append(f"    # {stripped}")
        if value is not None and value != "":
            lines.append(f"    {name} = {_python_constant_value(value)}")
            try:
                next_val = int(value, 0) + 1
            except ValueError:
                next_val += 1
        else:
            lines.append(f"    {name} = {next_val}")
            next_val += 1

    lines.append("")
    return "\n".join(lines)


def _generate_hl_status(project_ir: IRProject, status_enum: IREnum) -> str:
    """Generate high-level status file (identical to bridge status)."""
    error_cls = _error_exception_class(project_ir)
    hl_cls = "Status"

    lines: list[str] = []
    lines.append(_PYTHON_LICENSE)
    lines.append("")
    lines.append("")
    lines.append("from ctypes import *")
    lines.append("")
    lines.append("")
    lines.append(f"class {error_cls}(Exception):")
    lines.append("    pass")
    lines.append("")
    lines.append("")
    lines.append(f"class {hl_cls}(object):")
    if status_enum.description:
        lines.append(f'    """{status_enum.description}"""')
    lines.append("")

    for const in status_enum.constants:
        name = _upper_snake(const.name)
        value = const.attrs.get("value", "0")
        desc = const.description.strip() if const.description else ""
        if desc:
            for desc_line in desc.splitlines():
                stripped = desc_line.strip()
                if stripped:
                    lines.append(f"    # {stripped}")
        lines.append(f"    {name} = {_python_constant_value(value)}")

    lines.append("")
    lines.append("    STATUS_DICT = {")
    for const in status_enum.constants:
        value = const.attrs.get("value", "0")
        desc = _flatten_description(const.description) if const.description else ""
        lines.append(f'        {value}: "{desc}",')
    if status_enum.constants:
        last = lines[-1]
        if last.endswith(","):
            lines[-1] = last[:-1]
    lines.append("    }")

    lines.append("")
    lines.append("    @classmethod")
    lines.append("    def handle_status(cls, status):")
    lines.append('        """Handle low level lib status"""')
    lines.append("        if status != 0:")
    lines.append("            try:")
    lines.append(f"                raise {error_cls}(cls.STATUS_DICT[status])")
    lines.append("            except KeyError:")
    lines.append(f'                raise {error_cls}("Unknown error")')

    lines.append("")
    return "\n".join(lines)


def _generate_hl_interface(project_ir: IRProject, iface: IRInterface) -> str:
    """Generate high-level abstract class file for an interface."""
    hl_cls = _pascal_name(iface.name)

    lines: list[str] = []
    lines.append(_PYTHON_LICENSE)
    lines.append("")
    lines.append("")
    lines.append("from ctypes import *")
    lines.append("from abc import *")
    lines.append("")
    lines.append("")
    lines.append(f"class {hl_cls}(object):")
    if iface.description:
        lines.append(f'    """{iface.description}"""')
    lines.append("    __metaclass__ = ABCMeta")

    # Constants as class attributes
    for const in iface.constants:
        desc = const.description.strip() if const.description else ""
        name = _upper_snake(const.name)
        value = const.attrs.get("value", "0")
        lines.append("")
        if desc:
            for desc_line in desc.splitlines():
                stripped = desc_line.strip()
                if stripped:
                    lines.append(f"    # {stripped}")
        lines.append(f"    {name} = {_python_constant_value(value)}")

    # Abstract methods
    for method in iface.methods:
        if not _method_should_wrap(method):
            continue
        m_snake = _snake_name(method.name)
        desc = method.description.strip() if method.description else ""

        # Build parameter list (skip self/ctx, buffer outputs, error, writeonly)
        params: list[str] = []
        for arg in method.arguments:
            if _arg_should_skip(arg):
                continue
            if _arg_is_buffer_output(arg):
                continue
            params.append(_snake_name(arg.name))

        param_str = ", ".join(["self"] + params)

        lines.append("")
        lines.append("    @abstractmethod")
        lines.append(f"    def {m_snake}({param_str}):")
        if desc:
            lines.append(f'        """{desc}"""')
        lines.append("        raise NotImplementedError()")

    lines.append("")
    return "\n".join(lines)


def _hl_buffer_capacity_expr(
    project_ir: IRProject,
    entity_name: str,
    arg: IRCArgument,
    method: IRCMethod,
    methods: list[IRCMethod],
    constants: list[IRCConstant],
    all_constants: list[IRCConstant],
    is_impl: bool,
) -> str:
    """Derive the Python buffer capacity expression from length_attrs.

    Returns a Python expression string for the Buffer() capacity.
    """
    la = arg.length_attrs
    if not la:
        return "0"

    if "constant" in la:
        const_name = la["constant"]
        owner_class = la.get("class")
        if owner_class and owner_class != "self":
            # Cross-class constant reference
            return f"{_hl_class_name(project_ir, owner_class)}.{_upper_snake(const_name)}"
        return f"self.{_upper_snake(const_name)}" if not _is_static_by_name(entity_name, project_ir) else _upper_snake(const_name)

    if "method" in la:
        method_name = la["method"]
        m_snake = _snake_name(method_name)

        # Gather proxy arguments
        proxy_args: list[str] = []
        idx = 0
        while f"proxy_{idx}_to" in la:
            cast = la.get(f"proxy_{idx}_cast")
            src_arg = la.get(f"proxy_{idx}_argument")
            src_const = la.get(f"proxy_{idx}_constant")
            if src_const is not None:
                proxy_args.append(src_const)
            elif src_arg is not None:
                local = _snake_name(src_arg)
                target = _snake_name(la.get(f"proxy_{idx}_to", src_arg))
                if cast == "data_length":
                    proxy_args.append(f"{target}=len({local})")
                else:
                    proxy_args.append(f"{target}={local}")
            idx += 1

        if proxy_args:
            return f"self.{m_snake}({', '.join(proxy_args)})"
        return f"self.{m_snake}()"

    if "argument" in la:
        src = la["argument"]
        if la.get("cast") == "data_length":
            return f"len({_snake_name(src)})"
        return _snake_name(src)

    return "0"


def _is_static_by_name(entity_name: str, project_ir: IRProject) -> bool:
    """Check if the entity is a static class by examining the IR."""
    for cls in project_ir.classes:
        if cls.name == entity_name:
            return _is_static_class(cls)
    return False


def _generate_hl_method_body(
    project_ir: IRProject,
    entity_name: str,
    method: IRCMethod,
    methods: list[IRCMethod],
    constants: list[IRCConstant],
    is_static: bool,
    is_impl: bool,
    dependencies: list | None,
    interface_bindings: list | None,
) -> list[str]:
    """Generate method body lines for a high-level class method."""
    prefix = project_ir.prefix
    snake = _snake_name(entity_name)
    bridge_var = f"self._lib_{prefix}_{snake}"
    c_func = f"{prefix}_{snake}_{_snake_name(method.name)}"
    is_method_static = method.attrs.get("is_static") in ("1", "true")

    body: list[str] = []

    # Collect all constants from entity + interface bindings
    all_constants = list(constants)

    # Build the argument list for the C call
    data_wraps: list[tuple[str, str]] = []  # (local_name, data_var_name)
    buffer_outputs: list[tuple[str, IRCArgument]] = []  # (local_name, arg)
    call_args: list[str] = []
    has_error_arg = False
    error_arg_prefix = None

    if not is_static and not is_method_static:
        call_args.append("self.ctx")

    for arg in method.arguments:
        arg_snake = _snake_name(arg.name)
        if arg.class_name == "error":
            has_error_arg = True
            error_arg_prefix = _resolve_project_prefix(project_ir, arg.project)
            call_args.append("error")
            continue
        if _arg_is_buffer_output(arg):
            buffer_outputs.append((arg_snake, arg))
            call_args.append(f"{arg_snake}.c_buffer")
            continue
        if _arg_should_skip(arg):
            continue
        if arg.class_name == "data":
            d_var = f"d_{arg_snake}"
            data_wraps.append((arg_snake, d_var))
            call_args.append(f"{d_var}.data")
        elif arg.interface_name:
            call_args.append(f"{arg_snake}.c_impl")
        elif arg.class_name and arg.class_name not in ("data", "buffer"):
            call_args.append(f"{arg_snake}.ctx")
        else:
            call_args.append(arg_snake)

    # Data wrapping
    for arg_name, d_var in data_wraps:
        body.append(f"        {d_var} = Data({arg_name})")

    # Error arg setup
    if has_error_arg:
        ep = error_arg_prefix or prefix
        body.append(f"        error = {ep}_error_t()")

    # Buffer allocation
    for buf_name, buf_arg in buffer_outputs:
        cap = _hl_buffer_capacity_expr(
            project_ir, entity_name, buf_arg, method,
            methods, constants, all_constants, is_impl,
        )
        body.append(f"        {buf_name} = Buffer({cap})")

    # The call
    call_str = f"{bridge_var}.{c_func}({', '.join(call_args)})"

    # Determine what the method returns
    returns_status = _method_returns_status(method)
    returns_impl = _method_returns_impl(method)
    returns_class = _method_returns_class(method)
    returns_data = _method_returns_data(method)
    has_value_return = False
    for r in method.returns:
        if r.enum_name != "status":
            has_value_return = True
            break

    if returns_status and not has_error_arg:
        body.append(f"        status = {call_str}")
        bridge_status = _bridge_class_name(project_ir, "status")
        body.append(f"        {bridge_status}.handle_status(status)")
    elif has_error_arg:
        if has_value_return:
            body.append(f"        result = {call_str}")
        else:
            body.append(f"        {call_str}")
        bridge_status = _bridge_class_name(project_ir, "status")
        body.append(f"        {bridge_status}.handle_status(error.status)")
    elif has_value_return:
        body.append(f"        result = {call_str}")
    else:
        body.append(f"        {call_str}")

    # Build return statement
    return_parts: list[str] = []

    # Value returns (non-status, non-buffer)
    for r in method.returns:
        if r.enum_name == "status":
            continue
        if r.interface_name:
            # impl-tag dispatch — use 'instance' local var matching legacy
            bridge_impl_tag = f"{prefix.capitalize()}ImplTag"
            body.append(
                f"        instance = {bridge_impl_tag}.get_type(result)[0].take_c_ctx("
                f"cast(result, POINTER({bridge_impl_tag}.get_type(result)[1])))"
            )
            return_parts.append("instance")
        elif r.class_name == "data":
            return_parts.append("Data.take_c_ctx(result)")
        elif r.class_name and r.class_name not in ("data", "buffer"):
            ret_hl_cls = _hl_class_name(project_ir, r.class_name)
            if r.access == "disown":
                return_parts.append(f"{ret_hl_cls}.take_c_ctx(result)")
            else:
                return_parts.append(f"{ret_hl_cls}.use_c_ctx(result)")
        elif r.enum_name:
            return_parts.append("result")
        else:
            return_parts.append("result")

    # Buffer outputs
    for buf_name, buf_arg in buffer_outputs:
        return_parts.append(f"{buf_name}.get_bytes()")

    # Special handling for data returns that need bytearray conversion
    if returns_data and len(return_parts) == 1 and "Data.take_c_ctx" in return_parts[0]:
        body.append(f"        instance = {return_parts[0]}")
        body.append("        cleaned_bytes = bytearray(instance)")
        return_parts = ["cleaned_bytes"]

    if len(return_parts) == 1:
        body.append(f"        return {return_parts[0]}")
    elif len(return_parts) > 1:
        body.append(f"        return {', '.join(return_parts)}")
    elif has_value_return and not returns_status:
        body.append("        return result")

    return body


def _generate_hl_class(
    project_ir: IRProject,
    entity_name: str,
    description: str,
    methods: list[IRCMethod],
    constants: list[IRCConstant],
    dependencies: list | None,
    has_context: bool,
    is_impl: bool,
    interface_bindings: list | None = None,
) -> str:
    """Generate a high-level class file for a class or implementation."""
    prefix = project_ir.prefix
    snake = _snake_name(entity_name)
    hl_cls = _hl_class_name(project_ir, entity_name)
    bridge_cls = _bridge_class_name(project_ir, entity_name)
    bridge_var = f"_lib_{prefix}_{snake}"
    bridge_status = _bridge_class_name(project_ir, "status")

    lines: list[str] = []
    lines.append(_PYTHON_LICENSE)
    lines.append("")
    lines.append("")
    lines.append("from ctypes import *")
    lines.append(f"from ._c_bridge import {bridge_cls}")

    # Determine imports needed — scan ALL methods including inherited from bindings
    needs_impl_tag = False
    needs_data = False
    needs_buffer = False
    needs_status = False
    other_hl_imports: set[str] = set()

    # Collect all methods to scan (own + from interface bindings)
    scan_methods = list(methods)
    if is_impl and interface_bindings:
        _iface_by_name = {i.name: i for i in project_ir.interfaces}
        for binding in interface_bindings:
            _iface = _iface_by_name.get(binding.name)
            if _iface is not None:
                existing = {m.name for m in scan_methods}
                for m in _iface.methods:
                    if m.name not in existing:
                        scan_methods.append(m)

    for m in scan_methods:
        if not _method_should_wrap(m):
            continue
        for a in m.arguments:
            if a.class_name == "data" and not _arg_should_skip(a):
                needs_data = True
            if a.class_name == "buffer":
                needs_buffer = True
            if a.class_name == "error":
                ep = _resolve_project_prefix(project_ir, a.project)
                other_hl_imports.add(
                    f"from ._c_bridge._{ep}_error import {ep}_error_t"
                )
        for r in m.returns:
            if r.enum_name == "status":
                needs_status = True
            if r.interface_name:
                needs_impl_tag = True
            if r.class_name == "data":
                needs_data = True
            if (r.class_name
                    and r.class_name not in ("data", "buffer", "self", "error")
                    and r.class_name != entity_name
                    and not (r.library and r.library not in _PROJECT_PREFIX_MAP)):
                ret_hl = _hl_class_name(project_ir, r.class_name)
                ret_file = _hl_file_stem(project_ir, r.class_name)
                other_hl_imports.add(f"from .{ret_file} import {ret_hl}")
        # Scan buffer output args for cross-class constant references
        for a in m.arguments:
            if _arg_is_buffer_output(a) and a.length_attrs:
                owner_class = a.length_attrs.get("class")
                if owner_class and owner_class != "self" and owner_class != entity_name:
                    cap_hl = _hl_class_name(project_ir, owner_class)
                    cap_file = _hl_file_stem(project_ir, owner_class)
                    other_hl_imports.add(f"from .{cap_file} import {cap_hl}")
        if _method_returns_status(m) or _method_has_error_arg(m):
            needs_status = True

    if needs_impl_tag:
        impl_tag_cls = f"{prefix.capitalize()}ImplTag"
        lines.append(f"from ._c_bridge import {impl_tag_cls}")
    if needs_status:
        lines.append(f"from ._c_bridge import {bridge_status}")
    if needs_data:
        lines.append("from virgil_crypto_lib.common._c_bridge import Data")
    if needs_buffer:
        lines.append("from virgil_crypto_lib.common._c_bridge import Buffer")
    for imp in sorted(other_hl_imports):
        lines.append(imp)

    # Interface inheritance for implementations
    bases: list[str] = []
    if is_impl and interface_bindings:
        for binding in interface_bindings:
            iface_hl = _pascal_name(binding.name)
            iface_file = _snake_name(binding.name)
            lines.append(f"from .{iface_file} import {iface_hl}")
            bases.append(iface_hl)

    lines.append("")
    lines.append("")

    if bases:
        lines.append(f"class {hl_cls}({', '.join(bases)}):")
    else:
        lines.append(f"class {hl_cls}(object):")

    if description:
        lines.append(f'    """{description}"""')

    # Constants — no blank lines between them (matches legacy)
    # entity_ref is the IR entity for constant resolution
    entity_ref = None
    for ent in list(project_ir.classes) + list(project_ir.implementations):
        if ent.name == entity_name:
            entity_ref = ent
            break

    all_class_constants: list[tuple[str, str, str]] = []
    for const in constants:
        name = _upper_snake(const.name)
        value = resolve_constant_value(
            const.attrs.get("value", "0"), entity_ref, project_ir
        )
        desc = const.description.strip() if const.description else ""
        all_class_constants.append((name, value, desc))

    # Also include constants from interface bindings
    if is_impl and interface_bindings:
        iface_by_name = {i.name: i for i in project_ir.interfaces}
        for binding in interface_bindings:
            iface = iface_by_name.get(binding.name)
            if iface is None:
                continue
            binding_const_map = {c.name: c.value for c in binding.constants}
            for iface_const in iface.constants:
                name = _upper_snake(iface_const.name)
                if iface_const.name in binding_const_map:
                    value = resolve_constant_value(
                        binding_const_map[iface_const.name], entity_ref, project_ir
                    )
                else:
                    value = iface_const.attrs.get("value", "0")
                desc = iface_const.description.strip() if iface_const.description else ""
                all_class_constants.append((name, value, desc))

    if all_class_constants:
        lines.append("")
    for name, value, desc in all_class_constants:
        if desc:
            for desc_line in desc.splitlines():
                stripped = desc_line.strip()
                if stripped:
                    lines.append(f"    # {stripped}")
        lines.append(f"    {name} = {_python_constant_value(value)}")

    # __init__
    lines.append("")
    lines.append("    def __init__(self):")
    lines.append('        """Create underlying C context."""')
    lines.append(f"        self.{bridge_var} = {bridge_cls}()")
    if has_context and is_impl:
        lines.append("        self._c_impl = None")
        lines.append("        self._ctx = None")
        c_new = f"{prefix}_{snake}_new"
        lines.append(f"        self.ctx = self.{bridge_var}.{c_new}()")
    elif has_context:
        c_new = f"{prefix}_{snake}_new"
        lines.append(f"        self.ctx = self.{bridge_var}.{c_new}()")

    # __delete__
    if has_context:
        lines.append("")
        lines.append("    def __delete__(self, instance):")
        lines.append('        """Destroy underlying C context."""')
        c_del = f"{prefix}_{snake}_delete"
        lines.append(f"        self.{bridge_var}.{c_del}(self.ctx)")

    # Dependency setters
    if dependencies:
        for dep in dependencies:
            dep_snake = _snake_name(dep.name)
            use_func = f"{prefix}_{snake}_use_{dep_snake}"

            lines.append("")
            desc = dep.description.strip() if dep.description else ""
            if dep.type_kind == "interface":
                lines.append(f"    def set_{dep_snake}(self, {dep_snake}):")
                if desc:
                    lines.append(f'        """{desc}"""')
                if dep.has_observers and dep.is_observers_return_status:
                    lines.append(f"        status = self.{bridge_var}.{use_func}(self.ctx, {dep_snake}.c_impl)")
                    lines.append(f"        {bridge_status}.handle_status(status)")
                else:
                    lines.append(f"        self.{bridge_var}.{use_func}(self.ctx, {dep_snake}.c_impl)")
            elif dep.type_kind in ("class", "impl"):
                lines.append(f"    def set_{dep_snake}(self, {dep_snake}):")
                if desc:
                    lines.append(f'        """{desc}"""')
                if dep.has_observers and dep.is_observers_return_status:
                    lines.append(f"        status = self.{bridge_var}.{use_func}(self.ctx, {dep_snake}.ctx)")
                    lines.append(f"        {bridge_status}.handle_status(status)")
                else:
                    lines.append(f"        self.{bridge_var}.{use_func}(self.ctx, {dep_snake}.ctx)")

    # Collect all methods to generate (own + from interface bindings)
    all_methods = list(methods)
    if is_impl and interface_bindings:
        iface_by_name = {i.name: i for i in project_ir.interfaces}
        for binding in interface_bindings:
            iface = iface_by_name.get(binding.name)
            if iface is None:
                continue
            for m in iface.methods:
                # Only add if not already present
                existing = {mm.name for mm in all_methods}
                if m.name not in existing:
                    all_methods.append(m)

    # All binding constants (for capacity expressions)
    all_constants = list(constants)
    if is_impl and interface_bindings:
        iface_by_name = {i.name: i for i in project_ir.interfaces}
        for binding in interface_bindings:
            iface = iface_by_name.get(binding.name)
            if iface is None:
                continue
            binding_const_map = {c.name: c.value for c in binding.constants}
            for ic in iface.constants:
                val = binding_const_map.get(ic.name, ic.attrs.get("value", "0"))
                all_constants.append(IRCConstant(
                    name=ic.name,
                    attrs={**ic.attrs, "value": val},
                    description=ic.description,
                ))

    # Methods
    for method in all_methods:
        if not _method_should_wrap(method):
            continue
        m_snake = _snake_name(method.name)
        desc = method.description.strip() if method.description else ""
        is_method_static = method.attrs.get("is_static") in ("1", "true")

        # Build parameter list
        params: list[str] = ["self"]
        for arg in method.arguments:
            if _arg_should_skip(arg):
                continue
            if _arg_is_buffer_output(arg):
                continue
            params.append(_snake_name(arg.name))

        lines.append("")
        lines.append(f"    def {m_snake}({', '.join(params)}):")
        if desc:
            lines.append(f'        """{desc}"""')

        body = _generate_hl_method_body(
            project_ir, entity_name, method, all_methods,
            all_constants, not has_context, is_impl,
            dependencies, interface_bindings,
        )
        lines.extend(body)

    # Add __len__ for classes that have a 'len' method (Python convention)
    has_len_method = any(
        m.name == "len" and _method_should_wrap(m) for m in all_methods
    )
    if has_len_method and has_context:
        lines.append("")
        lines.append("    def __len__(self):")
        lines.append("        return self.len()")

    # take_c_ctx, use_c_ctx, ctx property, c_impl property
    if has_context:
        lines.append("")
        lines.append("    @classmethod")
        lines.append("    def take_c_ctx(cls, c_ctx):")
        lines.append("        inst = cls.__new__(cls)")
        lines.append(f"        inst.{bridge_var} = {bridge_cls}()")
        lines.append("        inst.ctx = c_ctx")
        lines.append("        return inst")

        lines.append("")
        lines.append("    @classmethod")
        lines.append("    def use_c_ctx(cls, c_ctx):")
        lines.append("        inst = cls.__new__(cls)")
        lines.append(f"        inst.{bridge_var} = {bridge_cls}()")
        c_shallow = f"{prefix}_{snake}_shallow_copy"
        lines.append(f"        inst.ctx = inst.{bridge_var}.{c_shallow}(c_ctx)")
        lines.append("        return inst")

    # For implementations: c_impl property + ctx property with setter
    if has_context and is_impl:
        lines.append("")
        lines.append("    @property")
        lines.append("    def c_impl(self):")
        lines.append("        return self._c_impl")
        lines.append("")
        lines.append("    @property")
        lines.append("    def ctx(self):")
        lines.append("        return self._ctx")
        lines.append("")
        lines.append("    @ctx.setter")
        lines.append("    def ctx(self, value):")
        c_shallow = f"{prefix}_{snake}_shallow_copy"
        c_impl = f"{prefix}_{snake}_impl"
        lines.append(f"        self._ctx = self.{bridge_var}.{c_shallow}(value)")
        lines.append(f"        self._c_impl = self.{bridge_var}.{c_impl}(self.ctx)")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Common project templates (hardcoded infrastructure)
# ---------------------------------------------------------------------------

def _generate_common_files(project_ir: IRProject) -> list[tuple[str, str]]:
    """Generate all files for the 'common' project (Data/Buffer infrastructure)."""
    bridge_dir = _bridge_dir(project_ir)
    hl_dir = _highlevel_dir(project_ir)

    files: list[tuple[str, str]] = []

    # _vsc_data.py
    files.append((
        f"{bridge_dir}_vsc_data.py",
        _PYTHON_LICENSE + "\n\n\n"
        "from virgil_crypto_lib._libs import *\n"
        "from ctypes import *\n"
        "\n\n"
        "class vsc_data_t(Structure):\n"
        '    _fields_ = [\n'
        '        ("bytes", POINTER(c_byte)),\n'
        '        ("len", c_size_t)\n'
        '    ]\n'
        "\n\n"
        "class VscData(object):\n"
        '    """Encapsulates fixed byte array."""\n'
        "\n"
        "    def __init__(self):\n"
        '        """Create underlying C context."""\n'
        "        self._ll = LowLevelLibs()\n"
        "        self._lib = self._ll.common\n"
        "\n"
        "    def vsc_data(self, bytes_, len_):\n"
        "        vsc_data = self._lib.vsc_data\n"
        "        vsc_data.argtypes = [POINTER(c_byte), c_size_t]\n"
        "        vsc_data.restype = vsc_data_t\n"
        "        return vsc_data(bytes_, len_)\n"
        "\n"
        "    def vsc_data_from_str(self, str_):\n"
        "        vsc_data_from_str = self._lib.vsc_data_from_str\n"
        "        vsc_data_from_str.argtypes = [c_char_p, c_size_t]\n"
        "        vsc_data_from_str.restype = vsc_data_t\n"
        "        return vsc_data_from_str(str_)\n"
        "\n"
        "    def vsc_data_empty(self):\n"
        "        vsc_data_empty = self._lib.vsc_data_empty\n"
        "        vsc_data_empty.restype = vsc_data_t\n"
        "        return vsc_data_empty()\n"
        "\n"
        "    def vsc_data_equal(self, data, rhs):\n"
        "        # type: (vsc_data_t, vsc_data_t)->bool\n"
        "        vsc_data_equal = self._lib.vsc_data_equal\n"
        "        vsc_data_equal.argtypes = [vsc_data_t, vsc_data_t]\n"
        "        vsc_data_equal.restype = c_bool\n"
        "        return vsc_data_equal(data, rhs)\n"
    ))

    # _vsc_buffer.py
    files.append((
        f"{bridge_dir}_vsc_buffer.py",
        _PYTHON_LICENSE + "\n\n\n"
        "from virgil_crypto_lib._libs import *\n"
        "from ._vsc_data import vsc_data_t\n"
        "from ctypes import *\n"
        "\n\n"
        "class vsc_buffer_t(Structure):\n"
        "    pass\n"
        "\n\n"
        "class VscBuffer(object):\n"
        '    """Encapsulates fixed byte array with variable effective data length."""\n'
        "\n"
        "    def __init__(self):\n"
        '        """Create underlying C context."""\n'
        "        self._ll = LowLevelLibs()\n"
        "        self._lib = self._ll.common\n"
        "\n"
        "    def vsc_buffer_new(self):\n"
        "        # vsc_buffer_new C function wrapper\n"
        "        vsc_buffer_new = self._lib.vsc_buffer_new\n"
        "        vsc_buffer_new.restype = POINTER(vsc_buffer_t)\n"
        "        return vsc_buffer_new()\n"
        "\n"
        "    def vsc_buffer_new_with_data(self, data):\n"
        "        # vsc_buffer_new_with_data C function wrapper\n"
        "        vsc_buffer_new_with_data = self._lib.vsc_buffer_new_with_data\n"
        "        vsc_buffer_new_with_data.argtypes = [vsc_data_t]\n"
        "        vsc_buffer_new_with_data.restype = POINTER(vsc_buffer_t)\n"
        "        return vsc_buffer_new_with_data(data)\n"
        "\n"
        "    def vsc_buffer_destroy(self, buffer):\n"
        "        # vsc_buffer_destroy C function wrapper\n"
        "        vsc_buffer_destroy = self._lib.vsc_buffer_destroy\n"
        "        vsc_buffer_destroy.argtypes = [POINTER(POINTER(vsc_buffer_t))]\n"
        "        return vsc_buffer_destroy(buffer)\n"
        "\n"
        "    def vsc_buffer_equal(self, buffer, rhs):\n"
        "        vsc_buffer_equal = self._lib.vsc_buffer_equal\n"
        "        vsc_buffer_equal.argtypes = [POINTER(vsc_buffer_t), POINTER(vsc_buffer_t)]\n"
        "        vsc_buffer_equal.restype = c_bool\n"
        "        return vsc_buffer_equal(buffer, rhs)\n"
        "\n"
        "    def vsc_buffer_use(self, buffer, bytes_, bytes_len):\n"
        "        # vsc_buffer_use C function wrapper\n"
        "        vsc_buffer_use = self._lib.vsc_buffer_use\n"
        "        vsc_buffer_use.argtypes = [\n"
        "            POINTER(vsc_buffer_t),\n"
        "            POINTER(c_byte),\n"
        "            c_size_t\n"
        "        ]\n"
        "        return vsc_buffer_use(buffer, bytes_, bytes_len)\n"
        "\n"
        "    def vsc_buffer_len(self, buffer):\n"
        "        vsc_buffer_len = self._lib.vsc_buffer_len\n"
        "        vsc_buffer_len.argtypes = [POINTER(vsc_buffer_t)]\n"
        "        vsc_buffer_len.restype = c_size_t\n"
        "        return vsc_buffer_len(buffer)\n"
        "\n"
        "    def vsc_buffer_shallow_copy(self, buffer):\n"
        "        vsc_buffer_shallow_copy = self._lib.vsc_buffer_shallow_copy\n"
        "        vsc_buffer_shallow_copy.argtypes = [POINTER(vsc_buffer_t)]\n"
        "        vsc_buffer_shallow_copy.restype = POINTER(vsc_buffer_t)\n"
        "        return vsc_buffer_shallow_copy(buffer)\n"
    ))

    # _data.py
    files.append((
        f"{bridge_dir}_data.py",
        _PYTHON_LICENSE + "\n\n\n"
        "from virgil_crypto_lib.utils import Utils\n"
        "from ._vsc_data import VscData\n"
        "from ctypes import *\n"
        "\n\n"
        "class Data(object):\n"
        "\n"
        "    def __init__(self, predefined_value=None):\n"
        "        self._lib_vsc_data = VscData()\n"
        "        if predefined_value is None:\n"
        "            self._bytes_ = Utils.convert_bytearray_to_c_byte_array(bytearray())\n"
        "        elif isinstance(predefined_value, bytes) or isinstance(predefined_value, bytearray):\n"
        "            self._bytes_ = Utils.convert_bytearray_to_c_byte_array(predefined_value)\n"
        "        elif isinstance(predefined_value, str) or Utils.check_unicode(predefined_value):\n"
        "            str_bytes = bytearray(Utils.strtobytes(predefined_value))\n"
        "            self._bytes_ = Utils.convert_bytearray_to_c_byte_array(str_bytes)\n"
        "        else:\n"
        '            raise TypeError("Wrong type for instantiate Data")\n'
        "        self.data = self._lib_vsc_data.vsc_data(self._bytes_, len(self._bytes_))\n"
        "\n"
        "    def __eq__(self, other):\n"
        "        return self._lib_vsc_data.vsc_data_equal(self.data, other.data)\n"
        "\n"
        "    def __len__(self):\n"
        "        return self.data.len\n"
        "\n"
        "    def __bytes__(self):\n"
        "        return bytes(bytearray((c_byte * len(self))(*self.data.bytes[:len(self)])))\n"
        "\n"
        "    def __iter__(self):\n"
        "        return iter(bytearray((c_byte * len(self))(*self.data.bytes[:len(self)])))\n"
        "\n"
        "    @classmethod\n"
        "    def take_c_ctx(cls, c_ctx):\n"
        "        inst = cls.__new__(cls)\n"
        "        inst._lib_vsc_data = VscData()\n"
        "        inst.data = c_ctx\n"
        "        return inst\n"
    ))

    # _buffer.py
    files.append((
        f"{bridge_dir}_buffer.py",
        _PYTHON_LICENSE + "\n\n\n"
        "from ctypes import *\n"
        "from ._vsc_buffer import VscBuffer\n"
        "\n\n"
        "class Buffer(object):\n"
        "\n"
        "    def __init__(self, capacity):\n"
        "        self._lib_vsc_buffer = VscBuffer()\n"
        "        self._bytes_ = (c_byte * capacity)()\n"
        "        self.c_buffer = self._lib_vsc_buffer.vsc_buffer_new()\n"
        "        self._lib_vsc_buffer.vsc_buffer_use(\n"
        "            self.c_buffer,\n"
        "            self._bytes_,\n"
        "            c_size_t(capacity)\n"
        "        )\n"
        "\n"
        "    def __len__(self):\n"
        "        return self._lib_vsc_buffer.vsc_buffer_len(self.c_buffer)\n"
        "\n"
        "    def __eq__(self, other):\n"
        "        return self._lib_vsc_buffer.vsc_buffer_equal(self.c_buffer, other.c_buffer)\n"
        "\n"
        "    def __bytes__(self):\n"
        "        return self.get_bytes()\n"
        "\n"
        "    def __delete__(self, instance):\n"
        "        self._lib_vsc_buffer.vsc_buffer_destroy(self.c_buffer)\n"
        "\n"
        "    @classmethod\n"
        "    def take_c_ctx(cls, c_ctx):\n"
        "        inst = cls.__new__(cls)\n"
        "        inst._lib_vsc_buffer = VscBuffer()\n"
        "        inst.c_buffer = c_ctx\n"
        "        return inst\n"
        "\n"
        "    @classmethod\n"
        "    def use_c_ctx(cls, c_ctx):\n"
        "        inst = cls.__new__(cls)\n"
        "        inst._lib_vsc_buffer = VscBuffer()\n"
        "        inst.c_buffer = inst._lib_vsc_buffer.vsc_buffer_shallow_copy(c_ctx)\n"
        "        return inst\n"
        "\n"
        "    def get_bytes(self):\n"
        "        return bytearray(self._bytes_)[:self._lib_vsc_buffer.vsc_buffer_len(self.c_buffer)]\n"
    ))

    # bridge __init__.py
    files.append((
        f"{bridge_dir}__init__.py",
        _PYTHON_LICENSE + "\n\n\n"
        "from ._vsc_data import vsc_data_t\n"
        "from ._vsc_data import VscData\n"
        "from ._data import Data\n"
        "from ._vsc_buffer import vsc_buffer_t\n"
        "from ._vsc_buffer import VscBuffer\n"
        "from ._buffer import Buffer\n"
    ))

    # high-level __init__.py (empty for common)
    files.append((
        f"{hl_dir}__init__.py",
        _PYTHON_LICENSE + "\n"
    ))

    return files


# ---------------------------------------------------------------------------
# Bridge __init__.py generator
# ---------------------------------------------------------------------------

def _generate_bridge_init(
    project_ir: IRProject,
    enum_entries: list[tuple[str, str, list[str]]],
    class_entries: list[tuple[str, str, list[str]]],
    has_impl_tag: bool,
) -> str:
    """Generate _c_bridge/__init__.py.

    enum_entries: [(file_stem, class_name, [exports])]
    class_entries: [(file_stem, class_name, [exports])]
    """
    prefix = project_ir.prefix

    lines: list[str] = []
    lines.append(_PYTHON_LICENSE)
    lines.append("")
    lines.append("")

    # Import impl struct first
    if project_ir.implementations:
        lines.append(f"from ._{prefix}_impl import {prefix}_impl_t")

    # Import status/error first
    for stem, _, exports in enum_entries:
        for exp in exports:
            lines.append(f"from ._{stem} import {exp}")

    # Import class entries (ordered)
    for stem, _, exports in class_entries:
        for exp in exports:
            lines.append(f"from ._{stem} import {exp}")

    # Import impl_tag last
    if has_impl_tag:
        impl_tag_cls = f"{prefix.capitalize()}ImplTag"
        lines.append(f"from ._{prefix}_impl_tag import {impl_tag_cls}")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# High-level __init__.py generator
# ---------------------------------------------------------------------------

def _generate_hl_init(
    project_ir: IRProject,
    hl_entries: list[tuple[str, list[str]]],
) -> str:
    """Generate {project}/__init__.py.

    hl_entries: [(file_stem, [class_names])]
    """
    lines: list[str] = []
    lines.append(_PYTHON_LICENSE)
    lines.append("")
    lines.append("")

    for stem, exports in hl_entries:
        for exp in exports:
            lines.append(f"from .{stem} import {exp}")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def generate_python_files(
    project_ir: IRProject, license_text: str = "",
    repo_root: str | None = None,
) -> list[tuple[str, str]]:
    """Generate all Python wrapper files for a project.

    Returns a list of ``(repo_relative_path, file_content)`` tuples.
    Everything is generated from IR — no file system reads.
    """
    global _PYTHON_LICENSE
    if license_text:
        _PYTHON_LICENSE = _format_license_hash(license_text)
    del repo_root

    if project_ir.name == "common":
        return _generate_common_files(project_ir)

    prefix = project_ir.prefix
    bridge_dir = _bridge_dir(project_ir)
    hl_dir = _highlevel_dir(project_ir)

    files: list[tuple[str, str]] = []
    bridge_init_entries_enums: list[tuple[str, str, list[str]]] = []
    bridge_init_entries_classes: list[tuple[str, str, list[str]]] = []
    hl_init_entries: list[tuple[str, list[str]]] = []
    has_impl_tag = False

    # --- Bridge impl struct ---
    if project_ir.implementations:
        files.append((
            f"{bridge_dir}_{prefix}_impl.py",
            _generate_bridge_impl_struct(project_ir),
        ))

    # --- Enums ---
    for enum in project_ir.enums:
        snake = _snake_name(enum.name.replace("/", "_"))
        bridge_stem = f"{prefix}_{snake}"

        if enum.name == "status":
            # Bridge status file
            content = _generate_bridge_status(project_ir, enum)
            files.append((f"{bridge_dir}_{bridge_stem}.py", content))
            error_cls = _error_exception_class(project_ir)
            bridge_cls = _bridge_class_name(project_ir, "status")
            bridge_init_entries_enums.append((
                bridge_stem, bridge_cls,
                [error_cls, bridge_cls],
            ))
            # High-level status file
            hl_content = _generate_hl_status(project_ir, enum)
            files.append((f"{hl_dir}status.py", hl_content))
            hl_init_entries.append(("status", [error_cls, "Status"]))

        elif enum.name == "impl/tag":
            # Bridge impl_tag file
            content = _generate_bridge_impl_tag(project_ir)
            files.append((f"{bridge_dir}_{prefix}_impl_tag.py", content))
            has_impl_tag = True
            # No high-level file for impl/tag

        elif enum.name == "recipient cipher decryption state":
            # Internal enum — skip
            continue

        else:
            # Regular bridge enum
            content = _generate_bridge_enum(project_ir, enum)
            files.append((f"{bridge_dir}_{bridge_stem}.py", content))
            bridge_cls = _bridge_class_name(project_ir, enum.name)
            bridge_init_entries_enums.append((
                bridge_stem, bridge_cls, [bridge_cls],
            ))
            # High-level enum
            hl_content = _generate_hl_enum(project_ir, enum)
            hl_stem = _hl_file_stem(project_ir, enum.name)
            hl_cls = _hl_class_name(project_ir, enum.name)
            files.append((f"{hl_dir}{hl_stem}.py", hl_content))
            hl_init_entries.append((hl_stem, [hl_cls]))

    # --- Private class stubs (bridge-only, needed as import targets) ---
    for cls in project_ir.classes:
        if _entity_is_public(cls.attrs):
            continue  # Public classes are handled below
        if not _class_has_context(cls):
            continue  # Value types (lifecycle="none") are passed by value — no opaque pointer stub needed
        if cls.name in ("error",):
            continue
        snake = _snake_name(cls.name)
        bridge_stem = f"{prefix}_{snake}"
        struct_name = f"{prefix}_{snake}_t"
        # Generate a minimal bridge stub with just the opaque struct type
        stub_lines = [
            _PYTHON_LICENSE,
            "",
            "",
            "from virgil_crypto_lib._libs import *",
            "from ctypes import *",
            "",
            "",
            f"class {struct_name}(Structure):",
            "    pass",
            "",
        ]
        files.append((f"{bridge_dir}_{bridge_stem}.py", "\n".join(stub_lines)))
        # Register in bridge __init__.py
        bridge_init_entries_enums.append((
            bridge_stem, None, [struct_name],
        ))

    # --- Classes ---
    for cls in project_ir.classes:
        if not _entity_is_public(cls.attrs):
            continue

        snake = _snake_name(cls.name)
        bridge_stem = f"{prefix}_{snake}"

        if _is_error_class(cls):
            # Error class bridge file
            content = _generate_bridge_error_class(project_ir, cls)
            files.append((f"{bridge_dir}_{bridge_stem}.py", content))
            struct_name = f"{prefix}_error_t"
            bridge_cls = _bridge_class_name(project_ir, "error")
            bridge_init_entries_enums.append((
                bridge_stem, bridge_cls, [struct_name, bridge_cls],
            ))
            # No high-level file for error class
            continue

        if _is_static_class(cls):
            # Static class bridge
            content = _generate_bridge_static_class(project_ir, cls)
            files.append((f"{bridge_dir}_{bridge_stem}.py", content))
            bridge_cls = _bridge_class_name(project_ir, cls.name)
            bridge_init_entries_enums.append((
                bridge_stem, bridge_cls, [bridge_cls],
            ))
            # Static class high-level
            hl_content = _generate_hl_class(
                project_ir, cls.name, cls.description,
                cls.methods, cls.constants, None,
                has_context=False, is_impl=False,
            )
            hl_stem = _hl_file_stem(project_ir, cls.name)
            hl_cls = _hl_class_name(project_ir, cls.name)
            files.append((f"{hl_dir}{hl_stem}.py", hl_content))
            hl_init_entries.append((hl_stem, [hl_cls]))
            continue

        # Regular class with context
        has_ctx = _class_has_context(cls)
        content = _generate_bridge_class_body(
            project_ir, cls.name, cls.description,
            cls.methods, cls.constants, cls.dependencies,
            has_context=has_ctx, is_impl=False,
        )
        files.append((f"{bridge_dir}_{bridge_stem}.py", content))
        struct_name = f"{prefix}_{snake}_t"
        bridge_cls = _bridge_class_name(project_ir, cls.name)
        bridge_init_entries_classes.append((
            bridge_stem, bridge_cls, [struct_name, bridge_cls],
        ))

        # High-level class
        hl_content = _generate_hl_class(
            project_ir, cls.name, cls.description,
            cls.methods, cls.constants, cls.dependencies,
            has_context=has_ctx, is_impl=False,
        )
        hl_stem = _hl_file_stem(project_ir, cls.name)
        hl_cls = _hl_class_name(project_ir, cls.name)
        files.append((f"{hl_dir}{hl_stem}.py", hl_content))
        hl_init_entries.append((hl_stem, [hl_cls]))

    # --- Implementations ---
    for impl in project_ir.implementations:
        if not _entity_is_public(impl.attrs):
            continue

        snake = _snake_name(impl.name)
        bridge_stem = f"{prefix}_{snake}"

        # Collect all methods (own + from interface bindings)
        all_methods = list(impl.methods)
        iface_by_name = {i.name: i for i in project_ir.interfaces}
        for binding in impl.interface_bindings:
            iface = iface_by_name.get(binding.name)
            if iface is None:
                continue
            existing_names = {m.name for m in all_methods}
            for m in iface.methods:
                if m.name not in existing_names:
                    all_methods.append(m)

        # Bridge file
        content = _generate_bridge_class_body(
            project_ir, impl.name, impl.description,
            all_methods, impl.constants, impl.dependencies,
            has_context=True, is_impl=True,
        )
        files.append((f"{bridge_dir}_{bridge_stem}.py", content))
        struct_name = f"{prefix}_{snake}_t"
        bridge_cls = _bridge_class_name(project_ir, impl.name)
        bridge_init_entries_classes.append((
            bridge_stem, bridge_cls, [struct_name, bridge_cls],
        ))

        # High-level file
        hl_content = _generate_hl_class(
            project_ir, impl.name, impl.description,
            impl.methods, impl.constants, impl.dependencies,
            has_context=True, is_impl=True,
            interface_bindings=impl.interface_bindings,
        )
        hl_stem = _hl_file_stem(project_ir, impl.name)
        hl_cls = _hl_class_name(project_ir, impl.name)
        files.append((f"{hl_dir}{hl_stem}.py", hl_content))
        hl_init_entries.append((hl_stem, [hl_cls]))

    # --- Interfaces (high-level only) ---
    for iface in project_ir.interfaces:
        if not _entity_is_public(iface.attrs):
            continue
        hl_content = _generate_hl_interface(project_ir, iface)
        hl_stem = _snake_name(iface.name)
        hl_cls = _pascal_name(iface.name)
        files.append((f"{hl_dir}{hl_stem}.py", hl_content))
        hl_init_entries.append((hl_stem, [hl_cls]))

    # --- __init__.py files ---
    bridge_init = _generate_bridge_init(
        project_ir,
        bridge_init_entries_enums,
        bridge_init_entries_classes,
        has_impl_tag,
    )
    files.append((f"{bridge_dir}__init__.py", bridge_init))

    hl_init = _generate_hl_init(project_ir, hl_init_entries)
    files.append((f"{hl_dir}__init__.py", hl_init))

    return files
