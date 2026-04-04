from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET

from tools.codegen.common_source import load_project_common


def _text(parent: ET.Element, tag: str, text: str | None = None, **attrs: str) -> ET.Element:
    elem = ET.SubElement(parent, tag, {k: v for k, v in attrs.items() if v is not None})
    if text:
        elem.text = text
    return elem


def _snake(name: str) -> str:
    return name.replace(' ', '_')


def _type_map(type_name: str | None) -> tuple[str, str]:
    mapping = {
        'boolean': ('bool', 'primitive'),
        'size': ('size_t', 'primitive'),
        'integer': ('int', 'primitive'),
        'byte': ('byte', 'primitive'),
        'char': ('char', 'primitive'),
        'string': ('char', 'primitive'),
    }
    if type_name in mapping:
        return mapping[type_name]
    return type_name or 'void', 'primitive'


def _comment_text(desc: str) -> str:
    desc = desc.strip()
    if not desc:
        return ''
    return '\n' + '\n'.join(f'        //  {line}' if line else '        //' for line in desc.splitlines()) + '\n    '


def _argument_from_source(parent: ET.Element, src: dict, *, name: str | None = None) -> ET.Element:
    attrs = src
    arg_name = name if name is not None else attrs.get('name', '')
    if attrs.get('class') in {'self', 'data'}:
        elem = _text(parent, 'c_argument', name=arg_name, accessed_by='value', type='vsc_data_t', type_is='class')
    elif attrs.get('type') == 'string':
        elem = _text(parent, 'c_argument', name=arg_name, accessed_by='value', type='char', type_is='primitive', string='given', is_const_type='1')
    else:
        t, kind = _type_map(attrs.get('type'))
        extra = {}
        if attrs.get('type') == 'byte' and attrs.get('_array') == 'given':
            extra['array'] = 'given'
            extra['is_const_type'] = '1'
        elem = _text(parent, 'c_argument', name=arg_name, accessed_by='value', type=t, type_is=kind, **extra)
    return elem


def _return_from_source(parent: ET.Element, attrs: dict) -> ET.Element:
    if attrs.get('class') in {'self', 'data'}:
        return _text(parent, 'c_return', accessed_by='value', type='vsc_data_t', type_is='class')
    if attrs.get('type') == 'byte' and attrs.get('is_reference') in {'1', 'true'}:
        return _text(parent, 'c_return', accessed_by='pointer', type='byte', type_is='primitive', is_const_type='1')
    t, kind = _type_map(attrs.get('type'))
    return _text(parent, 'c_return', accessed_by='value', type=t, type_is=kind)


def build_direct_data_c_module(repo_root: str | Path = '.') -> ET.Element:
    project = load_project_common(repo_root)
    data_cls = next(c for c in project.classes if c.name == 'data')

    root = ET.Element('c_module', {
        'lang': 'C',
        'id': 'data',
        'name': 'vsc_data',
        'class': '',
        'scope': 'public',
        'has_cmakedefine': '0',
        'uid': 'c_module_data',
        'feature': 'VSC_DATA',
        'c_include_file': 'vsc_data.h',
        'c_source_file': 'vsc_data.c',
        'header_file': '../library/common/include/virgil/crypto/common/vsc_data.h',
        'source_file': '../library/common/src/vsc_data.c',
        'once_guard': 'vsc_data_h_included',
    })

    _text(root, 'c_include', file='vsc_data.h', is_system='0', scope='private')
    _text(root, 'c_include', file='vsc_library.h', is_system='0', scope='public')
    _text(root, 'c_include', file='vsc_memory.h', is_system='0', scope='private')
    _text(root, 'c_include', file='vsc_assert.h', is_system='0', scope='private')
    _text(root, 'c_include', file='vsc_data.h', is_system='0', scope='public')

    struct = _text(root, 'c_struct', name='vsc_data_t', visibility='public', declaration='public', definition='public', uid='c_class_data_struct_data')
    for prop in data_cls.properties:
        attrs = dict(prop.attrs)
        if prop.name == 'bytes':
            p = _text(struct, 'c_property', name='bytes', accessed_by='value', type='byte', type_is='primitive', array='given', is_const_type='1', uid='c_class_data_struct_data_property_bytes')
            p.text = _comment_text('Underlying byte array.')
        elif prop.name == 'len':
            p = _text(struct, 'c_property', name='len', accessed_by='value', type='size_t', type_is='primitive', uid='c_class_data_struct_data_property_len')
            p.text = _comment_text('Byte array length.')
    struct.text = _comment_text("Handle 'data' context.")

    var = _text(root, 'c_variable', name='empty_data', uid='c_class_data_variable_empty_data', visibility='public', declaration='private', definition='private', accessed_by='value', type='byte', type_is='primitive', array='derived', is_const_type='1')
    _text(var, 'c_value', value='0x00', accessed_by='value', type='byte', type_is='primitive')
    _text(var, 'c_modifier', value='VSC_PUBLIC')
    var.text = _comment_text('Byte array that is used as "empty array" mark.')

    # synthetic ctx_size
    m = _text(root, 'c_method', name='vsc_data_ctx_size', visibility='public', declaration='public', definition='private', uid='c_class_data_method_ctx_size')
    _text(m, 'c_argument', type='void', accessed_by='value')
    _text(m, 'c_return', accessed_by='value', type='size_t', type_is='primitive')
    code = _text(m, 'c_code', lang='c', type='generated')
    code.text = 'return sizeof(vsc_data_t);'
    _text(m, 'c_modifier', value='VSC_PUBLIC')
    m.text = _comment_text("Return size of 'vsc_data_t'.")

    # constructors
    ctor_names = {'data': 'vsc_data', 'from str': 'vsc_data_from_str', 'empty': 'vsc_data_empty'}
    for ctor in data_cls.constructors:
        m = _text(root, 'c_method', name=ctor_names[ctor.name], visibility='public', declaration='public', definition='private', uid=f"direct_data_ctor_{_snake(ctor.name)}")
        if not ctor.arguments:
            _text(m, 'c_argument', type='void', accessed_by='value')
        else:
            for arg in ctor.arguments:
                attrs = dict(arg.attrs)
                if arg.name == 'bytes':
                    attrs['_array'] = 'given'
                _argument_from_source(m, attrs, name=arg.name)
        _text(m, 'c_return', accessed_by='value', type='vsc_data_t', type_is='class')
        code = _text(m, 'c_code', type='stub', lang='c')
        code.text = 'vsc_data_t self;\n\n//  TODO: Perform initialization.\n\nreturn self;'
        _text(m, 'c_modifier', value='VSC_PUBLIC')
        m.text = _comment_text(ctor.description)

    for method in data_cls.methods:
        c_name = f"vsc_data_{_snake(method.name)}"
        m = _text(root, 'c_method', name=c_name, visibility='public', declaration='public', definition='private', uid=f"direct_data_method_{_snake(method.name)}")
        # implicit self for non-value helpers except slice/static-like? data methods all take self
        _argument_from_source(m, {'name': 'self', 'class': 'data'}, name='self')
        for arg in method.arguments:
            _argument_from_source(m, dict(arg.attrs), name=arg.name)
        if method.returns:
            _return_from_source(m, method.returns[0])
        else:
            _text(m, 'c_return', type='void', accessed_by='value')
        code = _text(m, 'c_code', type='stub', lang='c')
        code.text = '//  TODO: This is STUB. Implement me.'
        _text(m, 'c_modifier', value='VSC_PUBLIC')
        m.text = _comment_text(method.description)

    return root
