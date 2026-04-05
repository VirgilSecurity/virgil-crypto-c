from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast
import xml.etree.ElementTree as ET

from tools.codegen.common_ir import IRClass, IRCModule, IRProjectCommon, IROutputTarget, project_common_to_ir
from tools.codegen.common_source import load_project_source, project_common_path


def _load_common_project(repo_root: str | Path = "."):
    return load_project_source(project_common_path(repo_root))


def _load_common_ir(repo_root: str | Path = ".") -> IRProjectCommon:
    return project_common_to_ir(_load_common_project(repo_root))


def _text(parent: ET.Element, tag: str, text: str | None = None, **attrs: str) -> ET.Element:
    elem = ET.SubElement(parent, tag, {k: v for k, v in attrs.items() if v is not None})
    if text:
        elem.text = text
    return elem


def _snake(name: str) -> str:
    return name.replace(' ', '_')


def _module_ir(project_ir: IRProjectCommon, name: str) -> IRCModule:
    try:
        return next(module for module in project_ir.resolved_modules if module.name == name)
    except StopIteration as exc:
        raise KeyError(f"module not found in IR: {name}") from exc



def _class_ir(project_ir: IRProjectCommon, name: str) -> IRClass:
    try:
        return next(cls for cls in project_ir.classes if cls.name == name)
    except StopIteration as exc:
        raise KeyError(f"class not found in IR: {name}") from exc



def _type_symbol(project_ir: IRProjectCommon, class_name: str) -> str:
    return f"{_class_ir(project_ir, class_name).output.c_symbol}_t"



def _include_file(project_ir: IRProjectCommon, *, module_name: str | None = None, class_name: str | None = None) -> str:
    if module_name is not None:
        return cast(IROutputTarget, _module_ir(project_ir, module_name).output).include_file
    if class_name is not None:
        return cast(IROutputTarget, _class_ir(project_ir, class_name).output).include_file
    raise ValueError("either module_name or class_name must be provided")



def _buffer_defs_output(project_ir: IRProjectCommon) -> IROutputTarget:
    buffer_output = cast(IROutputTarget, _class_ir(project_ir, 'buffer').output)
    stem = f"{buffer_output.c_symbol}_defs"
    header_path = buffer_output.header_path.replace(f"/{buffer_output.include_file}", f"/private/{stem}.h")
    source_path = buffer_output.source_path.replace(buffer_output.source_file, f"{stem}.c")
    generated_header_path = buffer_output.generated_header_path.replace(buffer_output.include_file.removesuffix('.h'), stem)
    generated_source_path = buffer_output.generated_source_path.replace('buffer.xml', 'buffer_defs.xml')
    return IROutputTarget(
        entity_kind='module',
        entity_name='buffer_defs',
        c_artifact_kind='module',
        c_symbol=stem,
        stem=stem,
        include_file=f'{stem}.h',
        source_file=f'{stem}.c',
        header_path=header_path,
        source_path=source_path,
        generated_header_path=generated_header_path,
        generated_source_path=generated_source_path,
        once_guard=f'{stem}_h_included',
        header_visibility='private',
        source_visibility='public',
    )



def _callback_symbol(project_ir: IRProjectCommon, callback_name: str, *, module_name: str | None = None) -> str:
    if module_name is None:
        return f"{project_ir.prefix}_{_snake(callback_name)}_fn"
    module = _module_ir(project_ir, module_name)
    return f"{module.output.c_symbol}_{_snake(callback_name)}_fn"



def _c_module_root_attrs(output: IROutputTarget, *, entity_id: str, scope: str, class_name: str = "") -> dict[str, str]:
    return {
        'lang': 'C',
        'id': entity_id,
        'name': output.c_symbol,
        'class': class_name,
        'scope': scope,
        'has_cmakedefine': '0',
        'uid': f"c_module_{entity_id}",
        'c_include_file': output.include_file,
        'c_source_file': output.source_file,
        'header_file': output.header_path,
        'source_file': output.source_path,
        'once_guard': output.once_guard,
    }



def _c_module_root(output: IROutputTarget, *, entity_id: str, scope: str, class_name: str = "") -> ET.Element:
    return ET.Element('c_module', _c_module_root_attrs(output, entity_id=entity_id, scope=scope, class_name=class_name))



def _direct_xml_name(output: IROutputTarget) -> str:
    return Path(output.generated_header_path).name



def direct_c_renderers(repo_root: str | Path = ".") -> dict[str, Callable[[str | Path], ET.Element]]:
    project_ir = _load_common_ir(repo_root)
    return {
        _direct_xml_name(_class_ir(project_ir, 'data').output): build_direct_data_c_module,
        _direct_xml_name(_module_ir(project_ir, 'assert').output): build_direct_assert_c_module,
        _direct_xml_name(_module_ir(project_ir, 'library').output): build_direct_library_c_module,
        _direct_xml_name(_module_ir(project_ir, 'atomic').output): build_direct_atomic_c_module,
        _direct_xml_name(_module_ir(project_ir, 'memory').output): build_direct_memory_c_module,
        _direct_xml_name(_class_ir(project_ir, 'buffer').output): build_direct_buffer_c_module,
        _direct_xml_name(_buffer_defs_output(project_ir)): build_direct_buffer_defs_c_module,
    }


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


def _argument_from_source(parent: ET.Element, src: dict, *, name: str | None = None,
                          project_ir: IRProjectCommon | None = None, owner_class: str = 'data') -> ET.Element:
    attrs = src
    arg_name = name if name is not None else attrs.get('name', '')
    if attrs.get('class') in {'self', 'data'}:
        resolved_class = owner_class if attrs.get('class') == 'self' else attrs.get('class', owner_class)
        type_name = _type_symbol(project_ir, resolved_class) if project_ir is not None else 'vsc_data_t'
        elem = _text(parent, 'c_argument', name=arg_name, accessed_by='value', type=type_name, type_is='class')
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


def _return_from_source(parent: ET.Element, attrs: dict, *, project_ir: IRProjectCommon | None = None,
                        owner_class: str = 'data') -> ET.Element:
    if attrs.get('class') in {'self', 'data'}:
        resolved_class = owner_class if attrs.get('class') == 'self' else attrs.get('class', owner_class)
        type_name = _type_symbol(project_ir, resolved_class) if project_ir is not None else 'vsc_data_t'
        return _text(parent, 'c_return', accessed_by='value', type=type_name, type_is='class')
    if attrs.get('type') == 'byte' and attrs.get('is_reference') in {'1', 'true'}:
        return _text(parent, 'c_return', accessed_by='pointer', type='byte', type_is='primitive', is_const_type='1')
    t, kind = _type_map(attrs.get('type'))
    return _text(parent, 'c_return', accessed_by='value', type=t, type_is=kind)


def build_direct_library_c_module(repo_root: str | Path = '.') -> ET.Element:
    project = _load_common_project(repo_root)
    project_ir = project_common_to_ir(project)
    mod = project.module_named('library')
    output = cast(IROutputTarget, _module_ir(project_ir, 'library').output)
    version = project.version or {'major': '0', 'minor': '0', 'patch': '0'}

    root = _c_module_root(output, entity_id='library', scope=mod.attrs.get('scope', 'public'))
    _text(root, 'c_include', file=output.include_file, is_system='0', scope='private')
    _text(root, 'c_include', file='vsc_platform.h', is_system='0', scope='public')
    for inc in ['stdint.h','stddef.h','string.h','stdlib.h','stdbool.h']:
        _text(root, 'c_include', file=inc, is_system='1', scope='public')

    alias = _text(root, 'c_alias', name='byte', type='uint8_t', declaration='public')
    alias.text = _comment_text('Portable representation of the byte.')

    enum = _text(root, 'c_enum', declaration='public', definition='public')
    const = _text(enum, 'c_constant', name='vsc_POINTER_SIZE', value='sizeof (void *)', definition='public', uid='c_global_constant_pointer_size')
    const.text = _comment_text('Pointer size in bytes.')
    enum.text = _comment_text('Public integral constants.')

    macro_entries = [
        ('VSC_VERSION_MAJOR', f'#define VSC_VERSION_MAJOR {version["major"]}', ''),
        ('VSC_VERSION_MINOR', f'#define VSC_VERSION_MINOR {version["minor"]}', ''),
        ('VSC_VERSION_PATCH', f'#define VSC_VERSION_PATCH {version["patch"]}', ''),
        ('VSC_VERSION_MAKE', '#define VSC_VERSION_MAKE (major, minor, patch) ((major) * 10000 + (minor) * 100 + (patch))', ''),
        ('VSC_VERSION', '#define VSC_VERSION\n        VSC_VERSION_MAKE (\n                VSC_VERSION_MAJOR,\n                VSC_VERSION_MINOR,\n                VSC_VERSION_PATCH)', ''),
        ('VSC_NODISCARD', '#if (defined(__GNUC__) && __GNUC__ >= 4) || defined(__clang__)\n#   define VSC_NODISCARD __attribute__ ((warn_unused_result))\n#else\n#   define VSC_NODISCARD\n#endif', ''),
        ('VSC_NORETURN', '#if (defined(__GNUC__) && __GNUC__ >= 4) || defined(__clang__)\n#   define VSC_NORETURN __attribute__ ((noreturn))\n#else\n#   define VSC_NORETURN\n#endif', ''),
        ('VSC_CEIL', '#define VSC_CEIL (x,y) (0 == (x) ? 0 : 1 + (((x) - 1) / (y)))', 'Custom implementation of the number ceil algorithm.'),
        ('VSC_UNUSED', '#define VSC_UNUSED (x) (void)(x)', 'Mark argument or function return value as "unused".'),
    ]
    for name, code_text, desc in macro_entries:
        m = _text(root, 'c_macros', name=name, uid=f'direct_library_{name.lower()}', definition='public', is_method='1' if name == 'VSC_VERSION_MAKE' else '0')
        _text(m, 'c_code', code_text, lang='c', type='generated')
        if desc:
            m.text = _comment_text(desc)

    macs = _text(root, 'c_macroses', definition='public')
    for name, uid in [('VSC_PUBLIC','c_global_macros_public'),('VSC_PRIVATE','c_global_macros_private'),('VSC_SHARED_LIBRARY','c_global_macros_shared_library'),('VSC_INTERNAL_BUILD','c_global_macros_internal_build')]:
        _text(macs, 'c_macros', name=name, uid=uid, definition='public', is_method='0')
    _text(macs, 'c_code', '#if defined(_WIN32) || defined(__CYGWIN__)\n#   if VSC_SHARED_LIBRARY\n#       if defined(VSC_INTERNAL_BUILD)\n#           ifdef __GNUC__\n#               define VSC_PUBLIC __attribute__ ((dllexport))\n#           else\n#               define VSC_PUBLIC __declspec(dllexport)\n#           endif\n#       else\n#           ifdef __GNUC__\n#               define VSC_PUBLIC __attribute__ ((dllimport))\n#           else\n#               define VSC_PUBLIC __declspec(dllimport)\n#           endif\n#       endif\n#   else\n#       define VSC_PUBLIC\n#   endif\n#   define VSC_PRIVATE\n#else\n#   if (defined(__GNUC__) && __GNUC__ >= 4) || defined(__INTEL_COMPILER) || defined(__clang__)\n#       define VSC_PUBLIC                 __attribute__ ((visibility ("default")))\n#       define VSC_PRIVATE __attribute__ ((visibility ("hidden")))\n#   else\n#       define VSC_PRIVATE\n#   endif\n#endif', lang='c', type='generated')

    cb = _text(root, 'c_callback', name=_callback_symbol(project_ir, 'alloc'), uid='c_global_callback_alloc', declaration='public')
    _text(cb, 'c_argument', name='size', accessed_by='value', type='size_t', type_is='primitive')
    _text(cb, 'c_return', accessed_by='pointer', type='void', type_is='any')
    cb.text = _comment_text('Generic allocation function type.')

    cb = _text(root, 'c_callback', name=_callback_symbol(project_ir, 'dealloc'), uid='c_global_callback_dealloc', declaration='public')
    _text(cb, 'c_argument', name='mem', accessed_by='pointer', type='void', type_is='any')
    _text(cb, 'c_return', type='void', accessed_by='value')
    cb.text = _comment_text('Generic de-allocation function type.')

    return root


def build_direct_memory_c_module(repo_root: str | Path = '.') -> ET.Element:
    project_ir = _load_common_ir(repo_root)
    module_ir = _module_ir(project_ir, 'memory')
    output = cast(IROutputTarget, module_ir.output)

    root = _c_module_root(output, entity_id='memory', scope=module_ir.attrs.get('scope', 'public'))
    _text(root, 'c_include', file=output.include_file, is_system='0', scope='private')
    _text(root, 'c_include', file=_include_file(project_ir, module_name='library'), is_system='0', scope='public')
    _text(root, 'c_include', file=_include_file(project_ir, module_name='assert'), is_system='0', scope='private')

    m = _text(root, 'c_macroses', definition='private')
    _text(m, 'c_code', '#ifdef VIRGIL_PLATFORM_INCLUDE_STATEMENT\n#   include VIRGIL_PLATFORM_INCLUDE_STATEMENT\n#endif', lang='c', type='generated')
    m.text = _comment_text('Include external platform header if defined.')

    for name, desc, code_text in [
        ('VSC_ALLOC_DEFAULT', 'Compile-time configuration of the default alloc function.', '#ifdef VIRGIL_PLATFORM_ALLOC\n#   define VSC_ALLOC_DEFAULT(size) VIRGIL_PLATFORM_ALLOC((size))\n#else\n#   define VSC_ALLOC_DEFAULT(size) calloc(1, (size))\n#endif'),
        ('VSC_DEALLOC_DEFAULT', 'Compile-time configuration of the default dealloc function.', '#ifdef VIRGIL_PLATFORM_DEALLOC\n#   define VSC_DEALLOC_DEFAULT(mem) VIRGIL_PLATFORM_DEALLOC(mem)\n#else\n#   define VSC_DEALLOC_DEFAULT(mem) free((mem))\n#endif'),
    ]:
        mm = _text(root, 'c_macros', name=name, uid=f'direct_memory_{name.lower()}', definition='private', is_method='1')
        _text(mm, 'c_code', code_text, lang='c', type='generated')
        mm.text = _comment_text(desc)

    for name, init, desc, typ in [
        ('inner_alloc', 'vsc_default_alloc', 'Current allocation function.', _callback_symbol(project_ir, 'alloc')),
        ('inner_dealloc', 'vsc_default_dealloc', 'Current de-allocation function.', _callback_symbol(project_ir, 'dealloc')),
    ]:
        v = _text(root, 'c_variable', name=name, uid=f'direct_memory_var_{name}', visibility='public', declaration='private', definition='private', accessed_by='value', type=typ, type_is='callback')
        _text(v, 'c_value', value=init, accessed_by='value', type=typ, type_is='callback')
        _text(v, 'c_modifier', value='VSC_PUBLIC')
        v.text = _comment_text(desc)

    strnstr_code = """/*-
 * Copyright (c) 2001 Mike Barcroft <mike@FreeBSD.org>
 * Copyright (c) 1990, 1993
 *  The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *  This product includes software developed by the University of
 *  California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

char c, sc;
size_t len;

if ((c = *find++) != '\\0') {
    len = strlen(find);
    do {
        do {
            if (slen-- < 1 || (sc = *s++) == '\\0') // Fixed by Virgil Security, Inc.
                return (NULL);
        } while (sc != c);
        if (len > slen)
            return (NULL);
    } while (strncmp(s, find, len) != 0);
    s--;
}
return ((char *)s);"""

    methods = [
        ('vsc_default_alloc', [('size', {'accessed_by':'value','type':'size_t','type_is':'primitive'})], {'accessed_by':'pointer','type':'void','type_is':'any'}, 'return VSC_ALLOC_DEFAULT(size);', ['static'], 'Default allocation function, that is configured during compilation.', 'private', 'private'),
        ('vsc_default_dealloc', [('mem', {'accessed_by':'pointer','type':'void','type_is':'any'})], {'type':'void','accessed_by':'value'}, 'VSC_DEALLOC_DEFAULT(mem);', ['static'], 'Default de-allocation function, that is configured during compilation.', 'private', 'private'),
        ('vsc_alloc', [('size', {'accessed_by':'value','type':'size_t','type_is':'primitive'})], {'accessed_by':'pointer','type':'void','type_is':'any'}, 'return inner_alloc(size);', ['VSC_PUBLIC'], 'Allocate required amount of memory by usging current allocation function.\nReturns NULL if memory allocation fails.', 'public', 'public'),
        ('vsc_calloc', [('count', {'accessed_by':'value','type':'size_t','type_is':'primitive'}),('size', {'accessed_by':'value','type':'size_t','type_is':'primitive'})], {'accessed_by':'pointer','type':'void','type_is':'any'}, 'return inner_alloc(count * size);', ['VSC_PUBLIC'], 'Allocate required amount of memory by usging current allocation function.\nReturns NULL if memory allocation fails.', 'public', 'public'),
        ('vsc_dealloc', [('mem', {'accessed_by':'pointer','type':'void','type_is':'any'})], {'type':'void','accessed_by':'value'}, 'inner_dealloc(mem);', ['VSC_PUBLIC'], 'Deallocate given memory by usging current de-allocation function.', 'public', 'public'),
        ('vsc_set_allocators', [('alloc_cb', {'accessed_by':'value','type': _callback_symbol(project_ir, 'alloc'),'type_is':'callback'}),('dealloc_cb', {'accessed_by':'value','type': _callback_symbol(project_ir, 'dealloc'),'type_is':'callback'})], {'type':'void','accessed_by':'value'}, 'VSC_ASSERT_PTR(alloc_cb);\nVSC_ASSERT_PTR(dealloc_cb);\n\ninner_alloc = alloc_cb;\ninner_dealloc = dealloc_cb;', ['VSC_PUBLIC'], 'Change current used memory functions in the runtime.', 'public', 'public'),
        ('vsc_zeroize', [('mem', {'accessed_by':'pointer','type':'void','type_is':'any'}),('size', {'accessed_by':'value','type':'size_t','type_is':'primitive'})], {'type':'void','accessed_by':'value'}, 'VSC_ASSERT_PTR(mem);\nmemset(mem, 0, size);', ['VSC_PUBLIC'], 'Zeroize memory.\nNote, this function can be reduced by compiler during optimization step.\nFor sensitive data erasing use vsc_erase().', 'public', 'public'),
        ('vsc_erase', [('mem', {'accessed_by':'pointer','type':'void','type_is':'any'}),('size', {'accessed_by':'value','type':'size_t','type_is':'primitive'})], {'type':'void','accessed_by':'value'}, 'VSC_ASSERT_PTR(mem);\n\nvolatile uint8_t* p = (uint8_t*)mem;\nwhile (size--) { *p++ = 0; }', ['VSC_PUBLIC'], 'Zeroize memory in a secure manner.\nCompiler can not reduce this function during optimization step.', 'public', 'public'),
        ('vsc_memory_secure_equal', [('a', {'accessed_by':'pointer','type':'void','type_is':'any','is_const_type':'1'}),('b', {'accessed_by':'pointer','type':'void','type_is':'any','is_const_type':'1'}),('len', {'accessed_by':'value','type':'size_t','type_is':'primitive'})], {'accessed_by':'value','type':'bool','type_is':'primitive'}, 'VSC_ASSERT_PTR(a);\nVSC_ASSERT_PTR(b);\n\nconst volatile uint8_t *in_a = a;\nconst volatile uint8_t *in_b = b;\nvolatile uint8_t c = 0x00;\n\nfor (size_t i = 0; i < len; ++i) {\n    c |= in_a[i] ^ in_b[i];\n}\n\nreturn c == 0;', ['VSC_PUBLIC'], 'Perform constant-time memory comparison.\nThe time depends on the given length but not on the compared memory.\nReturn true of given memory chunks are equal.', 'public', 'public'),
        ('vsc_strnstr', [('s', {'accessed_by':'value','type':'char','type_is':'primitive','string':'null_terminated','is_const_type':'1'}),('find', {'accessed_by':'value','type':'char','type_is':'primitive','string':'null_terminated','is_const_type':'1'}),('slen', {'accessed_by':'value','type':'size_t','type_is':'primitive'})], {'accessed_by':'value','type':'char','type_is':'primitive','string':'null_terminated'}, strnstr_code, ['VSC_PUBLIC'], 'Find the first occurrence of find in s, where the search is limited to the\nfirst slen characters of s.', 'public', 'public'),
    ]
    for name, args, ret, code_text, modifiers, desc, decl, vis in methods:
        m = _text(root, 'c_method', name=name, visibility=vis, declaration=decl, definition='private', uid=f'direct_memory_{name}')
        for arg_name, arg_attrs in args:
            _text(m, 'c_argument', name=arg_name, **arg_attrs)
        _text(m, 'c_return', **ret)
        _text(m, 'c_code', code_text, lang='c', type='generated')
        for modifier in modifiers:
            _text(m, 'c_modifier', value=modifier)
        m.text = _comment_text(desc)
    return root


def build_direct_atomic_c_module(repo_root: str | Path = '.') -> ET.Element:
    project_ir = _load_common_ir(repo_root)
    module_ir = _module_ir(project_ir, 'atomic')
    output = cast(IROutputTarget, module_ir.output)

    root = _c_module_root(output, entity_id='atomic', scope=module_ir.attrs.get('scope', 'public'))
    _text(root, 'c_include', file=output.include_file, is_system='0', scope='private')
    _text(root, 'c_include', file=_include_file(project_ir, module_name='library'), is_system='0', scope='public')
    _text(root, 'c_include', file='stdatomic.h', is_system='1', scope='public', **{'if':'VSC_HAVE_STDATOMIC_H'})
    _text(root, 'c_code', '#if VSC_MULTI_THREADING && defined(_MSC_VER) && !defined(__INTEL_COMPILER)\n#   pragma intrinsic(_InterlockedCompareExchange)\n    inline bool vsc_atomic_compare_exchange_weak(volatile long *obj, long* expected, long desired) {\n        const long expected_local = *expected;\n        const long old = _InterlockedCompareExchange(obj, desired, expected_local);\n        if (old == expected_local) {\n            return true;\n        } else {\n            *expected = old;\n            return false;\n        }\n    }\n#endif', definition='public')
    m = _text(root, 'c_macroses', definition='public')
    _text(m, 'c_macros', name='VSC_ATOMIC', uid='c_class_atomic_macros_atomic', definition='public', is_method='0')
    _text(m, 'c_macros', name='VSC_ATOMIC_COMPARE_EXCHANGE_WEAK', uid='c_class_atomic_macros_compare_exchange_weak', definition='public', is_method='0')
    _text(m, 'c_code', '#if VSC_MULTI_THREADING\n#   if VSC_HAVE_STDATOMIC_H && !defined(__STDC_NO_ATOMICS__)\n#       define VSC_ATOMIC _Atomic\n#       define VSC_ATOMIC_COMPARE_EXCHANGE_WEAK(obj, expected, desired) atomic_compare_exchange_weak(obj, expected, desired)\n#   elif defined(__GNUC__) || defined(__clang__)\n#       define VSC_ATOMIC_COMPARE_EXCHANGE_WEAK(obj, expected, desired) __atomic_compare_exchange_n(obj, expected, desired, 1, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)\n#   elif defined(_MSC_VER) && !defined(__INTEL_COMPILER)\n#       define VSC_ATOMIC_COMPARE_EXCHANGE_WEAK(obj, expected, desired) vsc_atomic_compare_exchange_weak(obj, expected, desired)\n#   else\n#       error "Atomic operations are not suppored for this platform, but CMake option VSC_MULTI_THREADING is ON."\n#   endif\n#   ifndef VSC_ATOMIC\n#       define VSC_ATOMIC\n#   endif\n#else\n#   define VSC_ATOMIC\n#endif', lang='c', type='generated')
    m = _text(root, 'c_macroses', definition='public')
    _text(m, 'c_macros', name='VSC_ATOMIC_CRITICAL_SECTION_DECLARE', uid='c_class_atomic_macros_critical_section_declare', definition='public', is_method='0')
    _text(m, 'c_macros', name='VSC_ATOMIC_CRITICAL_SECTION_BEGIN', uid='c_class_atomic_macros_critical_section_begin', definition='public', is_method='0')
    _text(m, 'c_macros', name='VSC_ATOMIC_CRITICAL_SECTION_END', uid='c_class_atomic_macros_critical_section_end', definition='public', is_method='0')
    _text(m, 'c_code', '#if defined(VSC_ATOMIC_COMPARE_EXCHANGE_WEAK)\n#   define VSC_ATOMIC_CRITICAL_SECTION_DECLARE(name) static VSC_ATOMIC int is_busy_##name = 0; int is_not_busy_##name = 0;\n#   define VSC_ATOMIC_CRITICAL_SECTION_BEGIN(name)                do { is_not_busy_##name = 0; } while (!VSC_ATOMIC_COMPARE_EXCHANGE_WEAK(&is_busy_##name, &is_not_busy_##name, 1))\n#   define VSC_ATOMIC_CRITICAL_SECTION_END(name) do { is_busy_##name = 0; } while(0)\n#else\n#   define VSC_ATOMIC_CRITICAL_SECTION_DECLARE(name) do {} while(0)\n#   define VSC_ATOMIC_CRITICAL_SECTION_BEGIN(name) do {} while(0)\n#   define VSC_ATOMIC_CRITICAL_SECTION_END(name) do {} while(0)\n#endif', lang='c', type='generated')
    meth = _text(root, 'c_method', name='vsc_atomic_compare_exchange_weak', visibility='public', declaration='external', definition='external', uid='c_class_atomic_method_compare_exchange_weak')
    _text(meth, 'c_argument', type='void', accessed_by='value')
    _text(meth, 'c_return', type='void', accessed_by='value')
    _text(meth, 'c_code', '//  TODO: This is STUB. Implement me.', lang='c', type='stub')
    _text(meth, 'c_modifier', value='VSC_PUBLIC')
    return root


def build_direct_assert_c_module(repo_root: str | Path = '.') -> ET.Element:
    project = _load_common_project(repo_root)
    project_ir = project_common_to_ir(project)
    mod = project.module_named('assert')
    output = cast(IROutputTarget, _module_ir(project_ir, 'assert').output)

    root = _c_module_root(output, entity_id='assert', scope=mod.attrs.get('scope', 'public'))

    _text(root, 'c_include', file=output.include_file, is_system='0', scope='private')
    _text(root, 'c_include', file=_include_file(project_ir, module_name='library'), is_system='0', scope='public')
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
    cb = _text(root, 'c_callback', name=_callback_symbol(project_ir, 'handler', module_name='assert'), uid='c_class_assert_callback_handler', declaration='public')
    _text(cb, 'c_argument', name='message', accessed_by='value', type='char', type_is='primitive', string='null_terminated', is_const_type='1')
    _text(cb, 'c_argument', name='file', accessed_by='value', type='char', type_is='primitive', string='null_terminated', is_const_type='1')
    _text(cb, 'c_argument', name='line', accessed_by='value', type='int', type_is='primitive')
    _text(cb, 'c_return', type='void', accessed_by='value')
    _text(cb, 'c_modifier', value='VSC_NORETURN')
    cb.text = _comment_text(cb_src.description)

    var_src = next(v for v in mod.variables if v.name == 'active handler')
    assert_handler_type = _callback_symbol(project_ir, 'handler', module_name='assert')
    var = _text(root, 'c_variable', name='active_handler', uid='c_class_assert_variable_active_handler', visibility='private', declaration='private', definition='private', accessed_by='value', type=assert_handler_type, type_is='callback')
    _text(var, 'c_value', value='vsc_assert_abort', accessed_by='value', type=assert_handler_type, type_is='callback')
    _text(var, 'c_modifier', value='VSC_PRIVATE')
    var.text = _comment_text(var_src.description)

    methods = [
        ('vsc_assert_change_handler', [('handler_cb', {'accessed_by':'value','type': assert_handler_type,'type_is':'callback'})], {'type':'void','accessed_by':'value'}, 'VSC_ASSERT (handler_cb);\nactive_handler = handler_cb;', ['VSC_PUBLIC'], next(m.description for m in mod.methods if m.name == 'change handler'), 'public', 'public'),
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
    project = _load_common_project(repo_root)
    project_ir = project_common_to_ir(project)
    data_cls = project.class_named('data')
    output = cast(IROutputTarget, _class_ir(project_ir, 'data').output)
    data_type = _type_symbol(project_ir, 'data')

    root = _c_module_root(output, entity_id='data', scope='public')
    root.set('feature', f"{project_ir.prefix.upper()}_DATA")

    _text(root, 'c_include', file=output.include_file, is_system='0', scope='private')
    _text(root, 'c_include', file=_include_file(project_ir, module_name='library'), is_system='0', scope='public')
    _text(root, 'c_include', file=_include_file(project_ir, module_name='memory'), is_system='0', scope='private')
    _text(root, 'c_include', file=_include_file(project_ir, module_name='assert'), is_system='0', scope='private')
    _text(root, 'c_include', file=output.include_file, is_system='0', scope='public')

    struct = _text(root, 'c_struct', name=data_type, visibility='public', declaration='public', definition='public', uid='c_class_data_struct_data')
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
    code.text = f'return sizeof({data_type});'
    _text(m, 'c_modifier', value='VSC_PUBLIC')
    m.text = _comment_text(f"Return size of '{data_type}'.")

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
                _argument_from_source(m, attrs, name=arg.name, project_ir=project_ir, owner_class='data')
        _text(m, 'c_return', accessed_by='value', type=data_type, type_is='class')
        code = _text(m, 'c_code', type='stub', lang='c')
        code.text = f'{data_type} self;\n\n//  TODO: Perform initialization.\n\nreturn self;'
        _text(m, 'c_modifier', value='VSC_PUBLIC')
        m.text = _comment_text(ctor.description)

    for method in data_cls.methods:
        c_name = f"vsc_data_{_snake(method.name)}"
        m = _text(root, 'c_method', name=c_name, visibility='public', declaration='public', definition='private', uid=f"direct_data_method_{_snake(method.name)}")
        # implicit self for non-value helpers except slice/static-like? data methods all take self
        _argument_from_source(m, {'name': 'self', 'class': 'data'}, name='self', project_ir=project_ir, owner_class='data')
        for arg in method.arguments:
            _argument_from_source(m, dict(arg.attrs), name=arg.name, project_ir=project_ir, owner_class='data')
        if method.returns:
            _return_from_source(m, method.returns[0], project_ir=project_ir, owner_class='data')
        else:
            _text(m, 'c_return', type='void', accessed_by='value')
        code = _text(m, 'c_code', type='stub', lang='c')
        code.text = '//  TODO: This is STUB. Implement me.'
        _text(m, 'c_modifier', value='VSC_PUBLIC')
        m.text = _comment_text(method.description)

    return root


def _buffer_argument(parent: ET.Element, attrs: dict[str, str], *, name: str, project_ir: IRProjectCommon | None = None) -> ET.Element:
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


def _buffer_return(parent: ET.Element, attrs: dict[str, str], *, project_ir: IRProjectCommon | None = None) -> ET.Element:
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
                          project_ir: IRProjectCommon | None = None) -> ET.Element:
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
    project = _load_common_project(repo_root)
    project_ir = project_common_to_ir(project)
    buffer_cls = project.class_named('buffer')
    methods_by_name = {method.name: method for method in buffer_cls.methods}
    ctors_by_name = {ctor.name: ctor for ctor in buffer_cls.constructors}
    output = cast(IROutputTarget, _class_ir(project_ir, 'buffer').output)

    root = _c_module_root(output, entity_id='buffer', scope='public', class_name='buffer')

    struct = _text(root, 'c_struct', name=_type_symbol(project_ir, 'buffer'), visibility='public', declaration='public', definition='external', uid='direct_buffer_struct_buffer')
    struct.text = _comment_text("Handle 'buffer' context.")

    private_methods = [
        ('vsc_buffer_init_ctx', "Perform context specific initialization.\nNote, this method is called automatically when method vsc_buffer_init() is called.\nNote, that context is already zeroed.", [{'name': 'self', 'attrs': {'class': 'self'}}]),
        ('vsc_buffer_cleanup_ctx', "Release all inner resources.\nNote, this method is called automatically once when class is completely cleaning up.\nNote, that context will be zeroed automatically next this method.", [{'name': 'self', 'attrs': {'class': 'self'}}]),
        ('vsc_buffer_init_ctx_with_capacity', ctors_by_name['with capacity'].description, [{'name': 'self', 'attrs': {'class': 'self'}}, {'name': 'capacity', 'attrs': {'type': 'size'}}]),
        ('vsc_buffer_init_ctx_with_data', ctors_by_name['with data'].description, [{'name': 'self', 'attrs': {'class': 'self'}}, {'name': 'data', 'attrs': {'class': 'data'}}]),
    ]
    for name, description, args in private_methods:
        method = _text(root, 'c_method', name=name, visibility='private', declaration='private', definition='external', uid=f'direct_buffer_private_{name}')
        for arg in args:
            _buffer_argument(method, arg['attrs'], name=arg['name'], project_ir=project_ir)
        _text(method, 'c_return', type='void', accessed_by='value')
        _text(method, 'c_modifier', value='static')
        method.text = _comment_text(description)

    buffer_type = _type_symbol(project_ir, 'buffer')
    dealloc_callback_type = _callback_symbol(project_ir, 'dealloc')

    _buffer_public_method(root, 'vsc_buffer_ctx_size', f"Return size of '{buffer_type}'.", uid='direct_buffer_ctx_size', return_attrs={'type': 'size'}, code=f'return sizeof({buffer_type});', project_ir=project_ir)
    _buffer_public_method(root, 'vsc_buffer_init', 'Perform initialization of pre-allocated context.', uid='direct_buffer_init', args=[{'name': 'self', 'attrs': {'class': 'self'}}], code=f'VSC_ASSERT_PTR(self);\n\nvsc_zeroize(self, sizeof({buffer_type}));\n\nself->refcnt = 1;\n\nvsc_buffer_init_ctx(self);', project_ir=project_ir)
    _buffer_public_method(root, 'vsc_buffer_cleanup', 'Release all inner resources including class dependencies.', uid='direct_buffer_cleanup', args=[{'name': 'self', 'attrs': {'class': 'self'}}], code=f'if (self == NULL) {{\n    return;\n}}\n\nvsc_buffer_cleanup_ctx(self);\n\nvsc_zeroize(self, sizeof({buffer_type}));', project_ir=project_ir)
    _buffer_public_method(root, 'vsc_buffer_new', "Allocate context and perform it's initialization.", uid='direct_buffer_new', return_attrs={'class': 'self'}, code=f'{buffer_type} *self = ({buffer_type} *) vsc_alloc(sizeof ({buffer_type}));\nVSC_ASSERT_ALLOC(self);\n\nvsc_buffer_init(self);\n\nself->self_dealloc_cb = vsc_dealloc;\n\nreturn self;', project_ir=project_ir)
    _buffer_public_method(root, 'vsc_buffer_init_with_capacity', 'Perform initialization of pre-allocated context.\nAllocate inner buffer of given capacity.', uid='direct_buffer_init_with_capacity', args=[{'name': 'self', 'attrs': {'class': 'self'}}, {'name': 'capacity', 'attrs': {'type': 'size'}}], code=f'VSC_ASSERT_PTR(self);\n\nvsc_zeroize(self, sizeof({buffer_type}));\n\nself->refcnt = 1;\n\nvsc_buffer_init_ctx_with_capacity(self, capacity);', project_ir=project_ir)
    _buffer_public_method(root, 'vsc_buffer_new_with_capacity', "Allocate class context and perform it's initialization.\nAllocate inner buffer of given capacity.", uid='direct_buffer_new_with_capacity', args=[{'name': 'capacity', 'attrs': {'type': 'size'}}], return_attrs={'class': 'self'}, code=f'{buffer_type} *self = ({buffer_type} *) vsc_alloc(sizeof ({buffer_type}));\nVSC_ASSERT_ALLOC(self);\n\nvsc_buffer_init_with_capacity(self, capacity);\n\nself->self_dealloc_cb = vsc_dealloc;\n\nreturn self;', project_ir=project_ir)
    _buffer_public_method(root, 'vsc_buffer_init_with_data', 'Perform initialization of pre-allocated context.\nAllocate inner buffer buffer as copy of given data.', uid='direct_buffer_init_with_data', args=[{'name': 'self', 'attrs': {'class': 'self'}}, {'name': 'data', 'attrs': {'class': 'data'}}], code=f'VSC_ASSERT_PTR(self);\n\nvsc_zeroize(self, sizeof({buffer_type}));\n\nself->refcnt = 1;\n\nvsc_buffer_init_ctx_with_data(self, data);', project_ir=project_ir)
    _buffer_public_method(root, 'vsc_buffer_new_with_data', "Allocate class context and perform it's initialization.\nAllocate inner buffer buffer as copy of given data.", uid='direct_buffer_new_with_data', args=[{'name': 'data', 'attrs': {'class': 'data'}}], return_attrs={'class': 'self'}, code=f'{buffer_type} *self = ({buffer_type} *) vsc_alloc(sizeof ({buffer_type}));\nVSC_ASSERT_ALLOC(self);\n\nvsc_buffer_init_with_data(self, data);\n\nself->self_dealloc_cb = vsc_dealloc;\n\nreturn self;', project_ir=project_ir)
    _buffer_public_method(root, 'vsc_buffer_delete', 'Release all inner resources and deallocate context if needed.\nIt is safe to call this method even if the context was statically allocated.', uid='direct_buffer_delete', args=[{'name': 'self', 'attrs': {'class': 'self'}}], code=f'if (self == NULL) {{\n    return;\n}}\n\nsize_t old_counter = self->refcnt;\nVSC_ASSERT(old_counter != 0);\nsize_t new_counter = old_counter - 1;\n\n#if defined(VSC_ATOMIC_COMPARE_EXCHANGE_WEAK)\n//  CAS loop\nwhile (!VSC_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {{\n    old_counter = self->refcnt;\n    VSC_ASSERT(old_counter != 0);\n    new_counter = old_counter - 1;\n}}\n#else\nself->refcnt = new_counter;\n#endif\n\nif (new_counter > 0) {{\n    return;\n}}\n\n{dealloc_callback_type} self_dealloc_cb = self->self_dealloc_cb;\n\nvsc_buffer_cleanup(self);\n\nif (self_dealloc_cb != NULL) {{\n    self_dealloc_cb(self);\n}}', project_ir=project_ir)
    _buffer_public_method(root, 'vsc_buffer_destroy', "Delete given context and nullifies reference.\nThis is a reverse action of the function 'vsc_buffer_new ()'.", uid='direct_buffer_destroy', args=[{'name': 'self_ref', 'attrs': {'class': 'self', 'access': 'readwrite', 'passed_by': 'reference'}}], code=f'VSC_ASSERT_PTR(self_ref);\n\n{buffer_type} *self = *self_ref;\n*self_ref = NULL;\n\nvsc_buffer_delete(self);', project_ir=project_ir)
    _buffer_public_method(root, 'vsc_buffer_shallow_copy', 'Copy given class context by increasing reference counter.', uid='direct_buffer_shallow_copy', args=[{'name': 'self', 'attrs': {'class': 'self'}}], return_attrs={'class': 'self'}, code='VSC_ASSERT_PTR(self);\n\n#if defined(VSC_ATOMIC_COMPARE_EXCHANGE_WEAK)\n//  CAS loop\nsize_t old_counter;\nsize_t new_counter;\ndo {\n    old_counter = self->refcnt;\n    new_counter = old_counter + 1;\n} while (!VSC_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));\n#else\n++self->refcnt;\n#endif\n\nreturn self;', project_ir=project_ir)

    for method_name in ['is empty', 'is reverse', 'equal', 'secure equal', 'alloc', 'release', 'use', 'take', 'make secure', 'switch reverse mode', 'is full', 'is valid', 'bytes', 'data', 'capacity', 'len', 'unused len', 'begin', 'unused bytes', 'inc used', 'dec used', 'write data', 'append data', 'reset', 'erase']:
        method_src = methods_by_name[method_name]
        method = _text(root, 'c_method', name=f"vsc_buffer_{_snake(method_src.name)}", visibility='public', declaration='public', definition='external', uid=f"direct_buffer_method_{_snake(method_src.name)}")
        self_attrs = {'class': 'self'}
        if method_src.attrs.get('is_const') in {'1', 'true'}:
            self_attrs['access'] = 'readonly'
        _buffer_argument(method, self_attrs, name='self', project_ir=project_ir)
        for arg in method_src.arguments:
            arg_name = {'dealloc': 'dealloc_cb'}.get(arg.name, _snake(arg.name))
            _buffer_argument(method, dict(arg.attrs), name=arg_name, project_ir=project_ir)
        if method_src.returns:
            _buffer_return(method, method_src.returns[0], project_ir=project_ir)
        else:
            _text(method, 'c_return', type='void', accessed_by='value')
        _text(method, 'c_modifier', value='VSC_PUBLIC')
        method.text = _comment_text(method_src.description)

    return root


def build_direct_buffer_defs_c_module(repo_root: str | Path = '.') -> ET.Element:
    project = _load_common_project(repo_root)
    project_ir = project_common_to_ir(project)
    buffer_cls = project.class_named('buffer')
    output = _buffer_defs_output(project_ir)

    root = _c_module_root(output, entity_id='buffer_defs', scope='private', class_name='buffer')

    struct = _text(root, 'c_struct', name=_type_symbol(project_ir, 'buffer'), visibility='public', declaration='private', definition='public', uid='direct_buffer_defs_struct_buffer')
    struct.text = _comment_text("Handle 'buffer' context.")

    synthetic_fields = [
        ('self_dealloc_cb', _callback_symbol(project_ir, 'dealloc'), 'callback', 'Function do deallocate self context.'),
        ('refcnt', 'VSC_ATOMIC size_t', 'primitive', 'Reference counter.'),
    ]
    for name, type_name, type_kind, desc in synthetic_fields:
        field = _text(struct, 'c_property', name=name, accessed_by='value', type=type_name, type_is=type_kind)
        field.text = _comment_text(desc)

    for prop in buffer_cls.properties:
        attrs = dict(prop.attrs)
        field_attrs = {
            'name': {
                'bytes_dealloc': 'bytes_dealloc_cb',
                'is secure': 'is_secure',
                'is owner': 'is_owner',
                'is reverse': 'is_reverse',
            }.get(prop.name, prop.name.replace(' ', '_')),
            'accessed_by': 'pointer' if attrs.get('is_reference') in {'1', 'true'} else 'value',
        }

        if 'callback' in attrs:
            field_attrs['type'] = _callback_symbol(project_ir, 'dealloc')
            field_attrs['type_is'] = 'callback'
        else:
            type_name, type_kind = _type_map(attrs.get('type'))
            field_attrs['type'] = type_name
            field_attrs['type_is'] = type_kind

        field = _text(struct, 'c_property', **field_attrs)
        field.text = _comment_text(prop.description)

    return root
