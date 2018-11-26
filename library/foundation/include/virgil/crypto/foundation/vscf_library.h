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
// clang-format off


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  This module contains:
//      - library version;
//      - portable API visibility attributes;
//      - common constants;
//      - common types;
// --------------------------------------------------------------------------

#ifndef VSCF_LIBRARY_H_INCLUDED
#define VSCF_LIBRARY_H_INCLUDED

#include "vscf_platform.h"

#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <math.h>

// clang-format on
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

#ifndef BYTE_DEFINED
#define BYTE_DEFINED
    //  Portable representation of the byte.
    typedef uint8_t byte;
#endif // BYTE_DEFINED

#define VSCF_VERSION_MAJOR 5

#define VSCF_VERSION_MINOR 0

#define VSCF_VERSION_PATCH 1

#define VSCF_VERSION_MAKE(major, minor, patch) ((major) * 10000 + (minor) * 100 + (patch))

#define VSCF_VERSION                \
        VSCF_VERSION_MAKE (         \
                VSCF_VERSION_MAJOR, \
                VSCF_VERSION_MINOR, \
                VSCF_VERSION_PATCH)

//
//  Custom implementation of the number ceil algorithm.
//
#define VSCF_CEIL(x,y) (1 + (((x) - 1) / (y)))

//
//  Mark argument or function return value as "unused".
//
#define VSCF_UNUSED(x) (void)(x)

//  TDOD: Review with approach: https://gcc.gnu.org/wiki/Visibility
#if defined (__WINDOWS__)
#   if defined VSCF_STATIC
#       define VSCF_PUBLIC
#   elif defined VSCF_INTERNAL_BUILD
#       if defined DLL_PUBLIC
#           define VSCF_PUBLIC __declspec(dllexport)
#       else
#           define VSCF_PUBLIC
#       endif
#   elif defined VSCF_PUBLICS
#       define VSCF_PUBLIC __declspec(dllexport)
#   else
#       define VSCF_PUBLIC __declspec(dllimport)
#   endif
#   define VSCF_PRIVATE
#else
#   if (defined __GNUC__ && __GNUC__ >= 4) || defined __INTEL_COMPILER
#       define VSCF_PUBLIC __attribute__ ((visibility ("default")))
#       define VSCF_PRIVATE __attribute__ ((visibility ("hidden")))
#   else
#       define VSCF_PUBLIC
#       define VSCF_PRIVATE
#   endif
#endif

//
//  Public integral constants.
//
enum {
    //
    //  Pointer size in bytes.
    //
    vscf_POINTER_SIZE = sizeof (void *)
};

//
//  Generic allocation function type.
//
typedef void * (*vscf_alloc_fn)(size_t size);

//
//  Generic de-allocation function type.
//
typedef void (*vscf_dealloc_fn)(void *mem);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCF_LIBRARY_H_INCLUDED
//  @end
