//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2021 Virgil Security, Inc.
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

#ifndef VSSK_LIBRARY_H_INCLUDED
#define VSSK_LIBRARY_H_INCLUDED

#include "vssk_platform.h"

#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

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

#if defined(_WIN32) || defined(__CYGWIN__)
#   if VSSK_SHARED_LIBRARY
#       if defined(VSSK_INTERNAL_BUILD)
#           ifdef __GNUC__
#               define VSSK_PUBLIC __attribute__ ((dllexport))
#           else
#               define VSSK_PUBLIC __declspec(dllexport)
#           endif
#       else
#           ifdef __GNUC__
#               define VSSK_PUBLIC __attribute__ ((dllimport))
#           else
#               define VSSK_PUBLIC __declspec(dllimport)
#           endif
#       endif
#   else
#       define VSSK_PUBLIC
#   endif
#   define VSSK_PRIVATE
#else
#   if (defined(__GNUC__) && __GNUC__ >= 4) || defined(__INTEL_COMPILER) || defined(__clang__)
#       define VSSK_PUBLIC __attribute__ ((visibility ("default")))
#       define VSSK_PRIVATE __attribute__ ((visibility ("hidden")))
#   else
#       define VSSK_PRIVATE
#   endif
#endif

#define VSSK_VERSION_MAJOR 0

#define VSSK_VERSION_MINOR 16

#define VSSK_VERSION_PATCH 0

#define VSSK_VERSION_MAKE(major, minor, patch) ((major) * 10000 + (minor) * 100 + (patch))

#define VSSK_VERSION                \
        VSSK_VERSION_MAKE (         \
                VSSK_VERSION_MAJOR, \
                VSSK_VERSION_MINOR, \
                VSSK_VERSION_PATCH)

#if (defined(__GNUC__) && __GNUC__ >= 4) || defined(__clang__)
#   define VSSK_NODISCARD __attribute__ ((warn_unused_result))
#else
#   define VSSK_NODISCARD
#endif

//
//  Custom implementation of the number ceil algorithm.
//
#define VSSK_CEIL(x,y) (0 == (x) ? 0 : 1 + (((x) - 1) / (y)))

//
//  Returns max of two numbers.
//
#define VSSK_MAX(x,y) ((x) > (y) ? (x) : (y))

//
//  Mark argument or function return value as "unused".
//
#define VSSK_UNUSED(x) (void)(x)

//
//  Public integral constants.
//
enum {
    //
    //  Pointer size in bytes.
    //
    vssk_POINTER_SIZE = sizeof (void *)
};

//
//  Generic allocation function type.
//
typedef void * (*vssk_alloc_fn)(size_t size);

//
//  Generic de-allocation function type.
//
typedef void (*vssk_dealloc_fn)(void *mem);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSSK_LIBRARY_H_INCLUDED
//  @end
