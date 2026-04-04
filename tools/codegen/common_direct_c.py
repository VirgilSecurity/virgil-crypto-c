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


def build_direct_assert_c_module(repo_root: str | Path = '.') -> ET.Element:
    project = load_project_common(repo_root)
    mod = next(m for m in project.modules if m.name == 'assert')

    root = ET.Element('c_module', {
        'lang': 'C',
        'id': 'assert',
        'name': 'vsc_assert',
        'class': '',
        'scope': 'public',
        'has_cmakedefine': '0',
        'uid': 'c_module_assert',
        'c_include_file': 'vsc_assert.h',
        'c_source_file': 'vsc_assert.c',
        'header_file': '../library/common/include/virgil/crypto/common/vsc_assert.h',
        'source_file': '../library/common/src/vsc_assert.c',
        'once_guard': 'vsc_assert_h_included',
    })

    _text(root, 'c_include', file='vsc_assert.h', is_system='0', scope='private')
    _text(root, 'c_include', file='vsc_library.h', is_system='0', scope='public')
    _text(root, 'c_include', file='stdio.h', is_system='1', scope='private')
    _text(root, 'c_include', file='assert.h', is_system='1', scope='private', **{'if': 'VSC_HAVE_ASSERT_H'})

    macro_specs = [
        ('VSC_FILE_PATH_OR_NAME', 'Contains file path or file name.', '#if defined (__FILENAME__)\n#   define VSC_FILE_PATH_OR_NAME __FILENAME__\n#else\n#   define VSC_FILE_PATH_OR_NAME __FILE__\n#endif', '0'),
        ('VSC_ASSERT_INTERNAL', 'Asserts always.', '#define VSC_ASSERT_INTERNAL(X)\n    do {\n        if (!(X)) {\n            vsc_assert_trigger (#X, VSC_FILE_PATH_OR_NAME, __LINE__);\n        }\n    } while (false)', '1'),
        ('VSC_ASSERT_OPT', 'Asserts even in optimized mode.', '#define VSC_ASSERT_OPT(X) VSC_ASSERT_INTERNAL(X)', '1'),
        ('VSC_ASSERT', 'Default assert, that is enabled in debug mode.', '#define VSC_ASSERT(X) VSC_ASSERT_INTERNAL(X)', '1'),
        ('VSC_ASSERT_SAFE', 'Heavy assert, that is enabled in a special (safe) cases.', '#define VSC_ASSERT_SAFE(X) VSC_ASSERT_INTERNAL(X)', '1'),
        ('VSC_ASSERT_STATIC', 'Asserts during compilation. Has no runtime impact.', '#define VSC_ASSERT_STATIC(X) (void) sizeof(char[(X) ? 1 : -1])', '1'),
        ('VSC_ASSERT_PTR', 'Assert that given pointer is not NULL. It is enabled in debug mode.', '#define VSC_ASSERT_PTR(X)\n    do {\n        if (!(X)) {\n            vsc_assert_trigger (#X" != NULL",   VSC_FILE_PATH_OR_NAME, __LINE__);\n        }\n    } while (false)', '1'),
        ('VSC_ASSERT_NULL', 'Assert that given pointer is NULL. It is enabled in debug mode.', '#define VSC_ASSERT_NULL(X)\n    do {\n        if(X) {\n            vsc_assert_trigger (#X" == NULL",   VSC_FILE_PATH_OR_NAME, __LINE__);\n        }\n    } while (false)', '1'),
        ('VSC_ASSERT_ALLOC', 'Assert that memory was successfully allocated.\nThis macros is enabled by default and can be disabled by special macros.', '#define VSC_ASSERT_ALLOC(X)\n    do {\n        if (!(X)) {\n            vsc_assert_trigger ("No memory",   VSC_FILE_PATH_OR_NAME, __LINE__);\n        }\n    } while (false)', '1'),
    ]
    for name, desc, code_text, is_method in macro_specs:
        m = _text(root, 'c_macros', name=name, definition='public', is_method=is_method, uid=f'direct_assert_macro_{name.lower()}')
        _text(m, 'c_code', code_text, lang='c', type='generated')
        m.text = _comment_text(desc)

    cb_src = next(c for c in mod.callbacks if c.name == 'handler')
    cb = _text(root, 'c_callback', name='vsc_assert_handler_fn', uid='c_class_assert_callback_handler', declaration='public')
    _text(cb, 'c_argument', name='message', accessed_by='value', type='char', type_is='primitive', string='null_terminated', is_const_type='1')
    _text(cb, 'c_argument', name='file', accessed_by='value', type='char', type_is='primitive', string='null_terminated', is_const_type='1')
    _text(cb, 'c_argument', name='line', accessed_by='value', type='int', type_is='primitive')
    _text(cb, 'c_return', type='void', accessed_by='value')
    _text(cb, 'c_modifier', value='VSC_NORETURN')
    cb.text = _comment_text(cb_src.description)

    var_src = next(v for v in mod.variables if v.name == 'active handler')
    var = _text(root, 'c_variable', name='active_handler', uid='c_class_assert_variable_active_handler', visibility='private', declaration='private', definition='private', accessed_by='value', type='vsc_assert_handler_fn', type_is='callback')
    _text(var, 'c_value', value='vsc_assert_abort', accessed_by='value', type='vsc_assert_handler_fn', type_is='callback')
    _text(var, 'c_modifier', value='VSC_PRIVATE')
    var.text = _comment_text(var_src.description)

    methods = [
        ('vsc_assert_change_handler', [('handler_cb', {'accessed_by':'value','type':'vsc_assert_handler_fn','type_is':'callback'})], {'type':'void','accessed_by':'value'}, 'VSC_ASSERT (handler_cb);\nactive_handler = handler_cb;', ['VSC_PUBLIC'], next(m.description for m in mod.methods if m.name == 'change handler'), 'public', 'public'),
        ('vsc_assert_abort', [('message', {'accessed_by':'value','type':'char','type_is':'primitive','string':'null_terminated','is_const_type':'1'}), ('file', {'accessed_by':'value','type':'char','type_is':'primitive','string':'null_terminated','is_const_type':'1'}), ('line', {'accessed_by':'value','type':'int','type_is':'primitive'})], {'type':'void','accessed_by':'value'}, 'printf("Assertion failed: %s, file %s, line %d\\n",\n        message, vsc_assert_path_basename (file), line);\n\nprintf("Abort");\nfflush(stdout);\n\nabort();', ['VSC_PUBLIC','VSC_NORETURN'], next(m.description for m in mod.methods if m.name == 'abort'), 'public', 'public'),
        ('vsc_assert_trigger', [('message', {'accessed_by':'value','type':'char','type_is':'primitive','string':'null_terminated','is_const_type':'1'}), ('file', {'accessed_by':'value','type':'char','type_is':'primitive','string':'null_terminated','is_const_type':'1'}), ('line', {'accessed_by':'value','type':'int','type_is':'primitive'})], {'type':'void','accessed_by':'value'}, 'active_handler (message, file, line);', ['VSC_PUBLIC','VSC_NORETURN'], next(m.description for m in mod.methods if m.name == 'trigger'), 'public', 'public'),
        ('vsc_assert_path_basename', [('path', {'accessed_by':'value','type':'char','type_is':'primitive','string':'null_terminated','is_const_type':'1'})], {'type':'char','accessed_by':'value','type_is':'primitive','string':'null_terminated','is_const_type':'1'}, "const char *result = path;\nfor (   const char *symbol = path;   *symbol != '\\0' &&   (symbol - path < 255);   ++symbol) {\n\n    const char *next_symbol = symbol + 1;\n\n    if (*next_symbol != '\\0' && (*symbol == '\\\\' || *symbol == '/')) {\n        result = next_symbol;\n    }\n}\n\nreturn result;", ['static'], next(m.description for m in mod.methods if m.name == 'path basename'), 'private', 'private'),
    ]
    for name, args, ret, code_text, modifiers, desc, decl, vis in methods:
        m = _text(root, 'c_method', name=name, visibility=vis, declaration=decl, definition='private', uid=f'direct_assert_{name}')
        for arg_name, arg_attrs in args:
            _text(m, 'c_argument', name=arg_name, **arg_attrs)
        _text(m, 'c_return', **ret)
        _text(m, 'c_code', code_text, lang='c', type='generated')
        for modifier in modifiers:
            _text(m, 'c_modifier', value=modifier)
        m.text = _comment_text(desc)

    return root


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
