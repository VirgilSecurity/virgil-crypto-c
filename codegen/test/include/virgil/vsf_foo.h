//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2018 Virgil Security Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#ifndef VSF_FOO_H_INCLUDED
#define VSF_FOO_H_INCLUDED
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------

#ifndef BYTE_DEFINED
#define BYTE_DEFINED
    //  Portable representation of the byte.
    typedef uint8_t byte;
#endif // BYTE_DEFINED

//
//  Macros as a global constant .
//
#define VSF_PI 3.1415

//
//  Macros as a local constant.
//
#define VSF_FOO_MAGIC_CONSTANT 777.25

//
//  Macros as a method.
//
#define VSF_FOO_DO_MAGIC(a) !(~(a))

//
//  Macros as a multiline method.
//
#define VSF_FOO_DO_MULTILINE(x) \
    do {                        \
        x += 1;                 \
        x *= 2;                 \
    } while (0)

//
//  Define several macros constants in a one implementation.
//
#if defined (__WINDOWS__)
#   if defined VSF_STATIC
#       define VSF_PUBLIC
#   elif defined VSF_INTERNAL_BUILD
#       if defined DLL_PUBLIC
#           define VSF_PUBLIC __declspec(dllexport)
#       else
#           define VSF_PUBLIC
#       endif
#   elif defined VSF_PUBLICS
#       define VSF_PUBLIC __declspec(dllexport)
#   else
#       define VSF_PUBLIC __declspec(dllimport)
#   endif
#   define VSF_PRIVATE
#else
#   if (defined __GNUC__ && __GNUC__ >= 4) || defined __INTEL_COMPILER
#       define VSF_PUBLIC __attribute__ ((visibility ("default")))
#       define VSF_PRIVATE __attribute__ ((visibility ("hidden")))
#   else
#       define VSF_PUBLIC
#       define VSF_PRIVATE
#   endif
#endif

//
//  Public integral constants.
//
enum {
    //
    //  Constant that is defined out of a typed enum.
    //
    vsf_foo_INTEGRAL_A = 25,
    //
    //  Constant that is defined out of a typed enum.
    //
    vsf_foo_INTEGRAL_B = 111
};

//
//  Enumeration type with public definition.
//
enum vsf_foo_tag_t {
    //
    //  Simple comment.
    //
    vsf_foo_tag_SIMPLE = 1,
    //
    //  Complex comment.
    //  Too complex.
    //
    vsf_foo_tag_COMPLEX
};
typedef enum vsf_foo_tag_t vsf_foo_tag_t;

//
//  Enumeration type with private definition.
//
typedef enum vsf_foo_bag_t vsf_foo_bag_t;

//
//  Structure with a public definition.
//
struct vsf_foo_context_t {
    //
    //  Integral type.
    //
    int number;
    //
    //  Integral type 8 bits.
    //
    int8_t number_1_byte;
    //
    //  Integral type 16 bits.
    //
    int16_t number_2_bytes;
    //
    //  Integral type 32 bits.
    //
    int32_t number_4_bytes;
    //
    //  Integral type 64 bits.
    //
    int64_t number_8_bytes;

    bool flag_without_description;
    //
    //  Bitfield type.
    //
    int bitfield:1;
    //
    //  One byte.
    //
    byte one_byte;
    //
    //  Callback type.
    //
    some_callback_fn call_me_cb;
    //
    //  Enumeration type.
    //
    some_enum_type_t some_tag;
    //
    //  Any type is a power of the C language.
    //
    void* any;
    //
    //  Special class impl.
    //
    vsf_impl_t* impl;
    //
    //  Special class buffer.
    //
    vsf_buffer_t* buffer;
    //
    //  Null-terminated string.
    //
    char* readwrite_str;
    //
    //  Null-terminated readonly string.
    //
    const char* readonly_str;
    //
    //  Readonly byte array.
    //
    const byte* readonly_bytes;
    //
    //  Modifiable byte array.
    //
    byte* readwrite_bytes;
    //
    //  Fixed size array.
    //
    byte fixed_byte_array[32];
    //
    //  Derived size array.
    //
    byte derived_byte_array[];
    //
    //  Null-terminated array of classes.
    //
    vsf_impl_t** array_of_classes;
    //
    //  Fixed size array of classes.
    //
    vsf_impl_t* fixed_array_of_classes[32];
};
typedef struct vsf_foo_context_t vsf_foo_context_t;

typedef struct vsf_impl_t vsf_impl_t;

typedef struct vsf_buffer_t vsf_buffer_t;

//
//  Structure with a private definition.
//
typedef struct vsf_foo_secret_t vsf_foo_secret_t;

//
//  Class self destruction callback type.
//
typedef void (*vsf_foo_destroy_fn) (vsf_impl_t** impl_ref);

//
//  Global variable that conatins derived size array of strings.
//
VSF_PUBLIC extern const char *const vsf_foo_features[];

//
//  Just do nothing.
//
VSF_PUBLIC void
vsf_foo_do_nothing (void);

//
//  Public visibility.
//
VSF_PUBLIC void
vsf_foo_do_public (void);

//
//  Private visibility
//
VSF_PRIVATE void
vsf_foo_do_private (void);


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSF_FOO_H_INCLUDED
//  @end
