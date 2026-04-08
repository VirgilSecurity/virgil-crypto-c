from __future__ import annotations

"""Compatibility adapter for `common`-specific direct C builders over the shared backend."""

from pathlib import Path
from typing import cast
import xml.etree.ElementTree as ET

from tools.codegen.project_c_backend import (
    ClassFieldSpec,
    ClassMethodSpec,
    DirectRendererSpec,
    argument_from_source,
    callback_symbol,
    c_module_root,
    c_module_root_attrs,
    class_ir,
    class_type_symbol,
    comment_text,
    derived_module_output_from_class,
    direct_renderer_map,
    direct_xml_name,
    include_file_for_entity,
    module_ir,
    render_class_c_module,
    render_module_c_module,
    return_from_source,
    snake_name,
    text_element,
    type_map,
)
from tools.codegen.project_ir import IRProject, IROutputTarget, project_to_ir
from tools.codegen.project_source import load_named_project_source


_SUPPORT_DIR = Path(__file__).resolve().parent / "support" / "common_runtime"


def _load_common_project(repo_root: str | Path = "."):
    return load_named_project_source("common", repo_root)


def _load_common_ir(repo_root: str | Path = ".") -> IRProject:
    return project_to_ir(_load_common_project(repo_root))


_text = text_element
_snake = snake_name
_module_ir = module_ir
_class_ir = class_ir
_type_symbol = class_type_symbol
_c_module_root_attrs = c_module_root_attrs
_c_module_root = c_module_root
_direct_xml_name = direct_xml_name
_type_map = type_map
_comment_text = comment_text
_argument_from_source = argument_from_source
_return_from_source = return_from_source
_callback_symbol = callback_symbol


__all__ = [
    "build_direct_assert_c_module",
    "build_direct_atomic_c_module",
    "build_direct_buffer_c_module",
    "build_direct_buffer_defs_c_module",
    "build_direct_data_c_module",
    "build_direct_library_c_module",
    "build_direct_memory_c_module",
    "custom_renderer_overrides",
    "direct_c_renderers",
]


def _include_file(project_ir: IRProject, *, module_name: str | None = None, class_name: str | None = None) -> str:
    if module_name is not None:
        return include_file_for_entity(project_ir, entity_kind="module", entity_name=module_name)
    if class_name is not None:
        return include_file_for_entity(project_ir, entity_kind="class", entity_name=class_name)
    raise ValueError("either module_name or class_name must be provided")



def _buffer_defs_output(project_ir: IRProject) -> IROutputTarget:
    buffer_output = cast(IROutputTarget, _class_ir(project_ir, "buffer").output)
    return derived_module_output_from_class(
        buffer_output,
        entity_name="buffer_defs",
        stem_suffix="defs",
        generated_source_stem="buffer_defs",
        header_visibility="private",
    )


def custom_renderer_overrides(repo_root: str | Path = ".") -> dict[str, object]:
    """Return custom renderers that override the default IR-driven discovery.

    These are entities whose rendering requires bespoke logic beyond what the
    generic ``render_module_c_module`` / ``render_class_c_module`` produce.
    The returned dict is keyed by XML output filename.
    """
    project_ir = _load_common_ir(repo_root)
    specs = [
        DirectRendererSpec(entity_kind="class", entity_name="data", renderer=build_direct_data_c_module),
        DirectRendererSpec(entity_kind="module", entity_name="assert", renderer=build_direct_assert_c_module),
        DirectRendererSpec(entity_kind="module", entity_name="library", renderer=build_direct_library_c_module),
        DirectRendererSpec(entity_kind="module", entity_name="atomic", renderer=build_direct_atomic_c_module),
        DirectRendererSpec(entity_kind="module", entity_name="memory", renderer=build_direct_memory_c_module),
        DirectRendererSpec(entity_kind="class", entity_name="buffer", renderer=build_direct_buffer_c_module),
        DirectRendererSpec(
            entity_kind="class",
            entity_name="buffer",
            renderer=build_direct_buffer_defs_c_module,
            output_resolver=_buffer_defs_output,
        ),
    ]
    return direct_renderer_map(project_ir, specs)


def direct_c_renderers(repo_root: str | Path = ".") -> dict[str, object]:
    """Legacy entry point — returns the full renderer map via auto-discovery."""
    from tools.codegen.project_direct_registry import direct_c_renderers_for_project

    return direct_c_renderers_for_project("common", repo_root)


def build_direct_library_c_module(repo_root: str | Path = '.') -> ET.Element:
    return render_module_c_module(_load_common_ir(repo_root), _module_ir(_load_common_ir(repo_root), 'library'))


def build_direct_memory_c_module(repo_root: str | Path = '.') -> ET.Element:
    return render_module_c_module(_load_common_ir(repo_root), _module_ir(_load_common_ir(repo_root), 'memory'))


def build_direct_atomic_c_module(repo_root: str | Path = '.') -> ET.Element:
    return render_module_c_module(_load_common_ir(repo_root), _module_ir(_load_common_ir(repo_root), 'atomic'))


def build_direct_assert_c_module(repo_root: str | Path = '.') -> ET.Element:
    return render_module_c_module(_load_common_ir(repo_root), _module_ir(_load_common_ir(repo_root), 'assert'))


def build_direct_data_c_module(repo_root: str | Path = '.') -> ET.Element:
    project_ir = _load_common_ir(repo_root)
    data_cls = _class_ir(project_ir, 'data')

    return render_class_c_module(
        project_ir,
        data_cls,
        feature=f"{project_ir.prefix.upper()}_DATA",
        private_includes=[
            _include_file(project_ir, module_name='memory'),
            _include_file(project_ir, module_name='assert'),
        ],
    )


def _buffer_argument(parent: ET.Element, attrs: dict[str, str], *, name: str, project_ir: IRProject | None = None) -> ET.Element:
    if attrs.get('class') == 'self':
        extra = {'is_const_type': '1'} if attrs.get('access') == 'readonly' else {}
        accessed_by = 'reference' if attrs.get('passed_by') == 'reference' else 'pointer'
        type_name = _type_symbol(project_ir, 'buffer') if project_ir is not None else 'vsc_buffer_t'
        return _text(parent, 'c_argument', name=name, accessed_by=accessed_by, type=type_name, type_is='class', **extra)
    if attrs.get('class') == 'data':
        type_name = _type_symbol(project_ir, 'data') if project_ir is not None else 'vsc_data_t'
        return _text(parent, 'c_argument', name=name, accessed_by='value', type=type_name, type_is='class')
    if 'callback' in attrs:
        callback_type = _callback_symbol(project_ir, 'dealloc') if project_ir is not None else 'vsc_dealloc_fn'
        return _text(parent, 'c_argument', name=name, accessed_by='value', type=callback_type, type_is='callback')

    type_name, type_kind = _type_map(attrs.get('type'))
    accessed_by = 'pointer' if attrs.get('is_reference') in {'1', 'true'} else 'value'
    return _text(parent, 'c_argument', name=name, accessed_by=accessed_by, type=type_name, type_is=type_kind)


def _buffer_return(parent: ET.Element, attrs: dict[str, str], *, project_ir: IRProject | None = None) -> ET.Element:
    if attrs.get('class') == 'self':
        type_name = _type_symbol(project_ir, 'buffer') if project_ir is not None else 'vsc_buffer_t'
        return _text(parent, 'c_return', accessed_by='pointer', type=type_name, type_is='class')
    if attrs.get('class') == 'data':
        type_name = _type_symbol(project_ir, 'data') if project_ir is not None else 'vsc_data_t'
        return _text(parent, 'c_return', accessed_by='value', type=type_name, type_is='class')
    if attrs.get('type') == 'byte' and attrs.get('is_reference') in {'1', 'true'}:
        extra = {'is_const_type': '1'} if attrs.get('access') != 'readwrite' else {}
        return _text(parent, 'c_return', accessed_by='pointer', type='byte', type_is='primitive', **extra)

    type_name, type_kind = _type_map(attrs.get('type'))
    return _text(parent, 'c_return', accessed_by='value', type=type_name, type_is=type_kind)


def _buffer_public_method(root: ET.Element, name: str, description: str, *, uid: str, args: list[dict[str, dict[str, str]]] | None = None,
                          return_attrs: dict[str, str] | None = None, code: str | None = None,
                          project_ir: IRProject | None = None) -> ET.Element:
    definition = 'public' if code is not None else 'external'
    method = _text(root, 'c_method', name=name, visibility='public', declaration='public', definition=definition, uid=uid)
    if args:
        for arg in args:
            _buffer_argument(method, arg['attrs'], name=arg['name'], project_ir=project_ir)
    else:
        _text(method, 'c_argument', type='void', accessed_by='value')

    if return_attrs is None:
        _text(method, 'c_return', type='void', accessed_by='value')
    else:
        _buffer_return(method, return_attrs, project_ir=project_ir)

    if code is not None:
        _text(method, 'c_code', code, type='generated', lang='c')

    _text(method, 'c_modifier', value='VSC_PUBLIC')
    method.text = _comment_text(description)
    return method


def build_direct_buffer_c_module(repo_root: str | Path = '.') -> ET.Element:
    project_ir = _load_common_ir(repo_root)
    buffer_cls = _class_ir(project_ir, 'buffer')

    runtime_methods = (
        ClassMethodSpec(name='vsc_buffer_init', description='Perform initialization of pre-allocated context.', arguments=({'name': 'self', 'class': 'self'},), code_path=_SUPPORT_DIR / 'buffer' / 'init.cfrag', uid='direct_buffer_init'),
        ClassMethodSpec(name='vsc_buffer_cleanup', description='Release all inner resources including class dependencies.', arguments=({'name': 'self', 'class': 'self'},), code_path=_SUPPORT_DIR / 'buffer' / 'cleanup.cfrag', uid='direct_buffer_cleanup'),
        ClassMethodSpec(name='vsc_buffer_new', description="Allocate context and perform it's initialization.", return_attrs={'class': 'self'}, code_path=_SUPPORT_DIR / 'buffer' / 'new.cfrag', uid='direct_buffer_new'),
        ClassMethodSpec(name='vsc_buffer_init_with_capacity', description='Perform initialization of pre-allocated context.\nAllocate inner buffer of given capacity.', arguments=({'name': 'self', 'class': 'self'}, {'name': 'capacity', 'type': 'size'}), code_path=_SUPPORT_DIR / 'buffer' / 'init_with_capacity.cfrag', uid='direct_buffer_init_with_capacity'),
        ClassMethodSpec(name='vsc_buffer_new_with_capacity', description="Allocate class context and perform it's initialization.\nAllocate inner buffer of given capacity.", arguments=({'name': 'capacity', 'type': 'size'},), return_attrs={'class': 'self'}, code_path=_SUPPORT_DIR / 'buffer' / 'new_with_capacity.cfrag', uid='direct_buffer_new_with_capacity'),
        ClassMethodSpec(name='vsc_buffer_init_with_data', description='Perform initialization of pre-allocated context.\nAllocate inner buffer buffer as copy of given data.', arguments=({'name': 'self', 'class': 'self'}, {'name': 'data', 'class': 'data'}), code_path=_SUPPORT_DIR / 'buffer' / 'init_with_data.cfrag', uid='direct_buffer_init_with_data'),
        ClassMethodSpec(name='vsc_buffer_new_with_data', description="Allocate class context and perform it's initialization.\nAllocate inner buffer buffer as copy of given data.", arguments=({'name': 'data', 'class': 'data'},), return_attrs={'class': 'self'}, code_path=_SUPPORT_DIR / 'buffer' / 'new_with_data.cfrag', uid='direct_buffer_new_with_data'),
        ClassMethodSpec(name='vsc_buffer_delete', description='Release all inner resources and deallocate context if needed.\nIt is safe to call this method even if the context was statically allocated.', arguments=({'name': 'self', 'class': 'self'},), code_path=_SUPPORT_DIR / 'buffer' / 'delete.cfrag', uid='direct_buffer_delete'),
        ClassMethodSpec(name='vsc_buffer_destroy', description="Delete given context and nullifies reference.\nThis is a reverse action of the function 'vsc_buffer_new ()'.", arguments=({'name': 'self_ref', 'class': 'self', 'access': 'readwrite', 'passed_by': 'reference'},), code_path=_SUPPORT_DIR / 'buffer' / 'destroy.cfrag', uid='direct_buffer_destroy'),
        ClassMethodSpec(name='vsc_buffer_shallow_copy', description='Copy given class context by increasing reference counter.', arguments=({'name': 'self', 'class': 'self'},), return_attrs={'class': 'self'}, code_path=_SUPPORT_DIR / 'buffer' / 'shallow_copy.cfrag', uid='direct_buffer_shallow_copy'),
    )

    return render_class_c_module(
        project_ir,
        buffer_cls,
        module_class_name='buffer',
        private_includes=[
            _include_file(project_ir, module_name='memory'),
            _include_file(project_ir, module_name='assert'),
            _buffer_defs_output(project_ir).include_file,
        ],
        extra_methods=runtime_methods,
    )


def build_direct_buffer_defs_c_module(repo_root: str | Path = '.') -> ET.Element:
    project_ir = _load_common_ir(repo_root)
    buffer_cls = _class_ir(project_ir, 'buffer')

    return render_class_c_module(
        project_ir,
        buffer_cls,
        output=_buffer_defs_output(project_ir),
        entity_id='buffer_defs',
        scope='private',
        module_class_name='buffer',
        public_includes=[_include_file(project_ir, module_name='atomic')],
        struct_declaration='private',
        struct_definition='public',
        include_own_header_public=False,
        generate_ctx_size=False,
        render_variables=False,
        render_reference_support=False,
        render_methods=False,
        extra_struct_fields=(
            ClassFieldSpec(name='self_dealloc_cb', attrs={'callback': '.(global_callback_dealloc)'}, description='Function do deallocate self context.'),
            ClassFieldSpec(name='refcnt', attrs={'type': 'VSC_ATOMIC size_t'}, description='Reference counter.'),
        ),
    )
