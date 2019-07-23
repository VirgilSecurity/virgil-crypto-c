//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  FreeBSD Clause-3
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

#ifndef CODEGEN_LIBRARY_H_INCLUDED
#define CODEGEN_LIBRARY_H_INCLUDED

#include "codegen_platform.h"

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
#   ifdef CODEGEN_BUILD_SHARED_LIBS
#       ifdef __GNUC__
#           define CODEGEN_PUBLIC __attribute__ ((dllexport))
#       else
#           define CODEGEN_PUBLIC __declspec(dllexport)
#       endif
#   elif !defined(CODEGEN_INTERNAL_BUILD)
#       ifdef __GNUC__
#           define CODEGEN_PUBLIC __attribute__ ((dllimport))
#       else
#           define CODEGEN_PUBLIC __declspec(dllimport)
#       endif
#   else
#       define CODEGEN_PUBLIC
#   endif
#   define CODEGEN_PRIVATE
#else
#   if (defined(__GNUC__) && __GNUC__ >= 4) || defined(__INTEL_COMPILER) || defined(__clang__)
#       define CODEGEN_PUBLIC __attribute__ ((visibility ("default")))
#       define CODEGEN_PRIVATE __attribute__ ((visibility ("hidden")))
#   else
#       define CODEGEN_PRIVATE
#   endif
#endif

#define CODEGEN_VERSION_MAJOR 0

#define CODEGEN_VERSION_MINOR 9

#define CODEGEN_VERSION_PATCH 0

#define CODEGEN_VERSION_MAKE(major, minor, patch) ((major) * 10000 + (minor) * 100 + (patch))

#define CODEGEN_VERSION                \
        CODEGEN_VERSION_MAKE (         \
                CODEGEN_VERSION_MAJOR, \
                CODEGEN_VERSION_MINOR, \
                CODEGEN_VERSION_PATCH)

#if (defined(__GNUC__) && __GNUC__ >= 4) || defined(__clang__)
#   define CODEGEN_NODISCARD __attribute__ ((warn_unused_result))
#else
#   define CODEGEN_NODISCARD
#endif

//
//  Custom implementation of the number ceil algorithm.
//
#define CODEGEN_CEIL(x,y) (0 == (x) ? 0 : 1 + (((x) - 1) / (y)))

//
//  Mark argument or function return value as "unused".
//
#define CODEGEN_UNUSED(x) (void)(x)

//
//  Public integral constants.
//
enum {
    //
    //  Pointer size in bytes.
    //
    codegen_POINTER_SIZE = sizeof (void *)
};

//
//  Generic allocation function type.
//
typedef void * (*codegen_alloc_fn)(size_t size);

//
//  Generic de-allocation function type.
//
typedef void (*codegen_dealloc_fn)(void *mem);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // CODEGEN_LIBRARY_H_INCLUDED
//  @end
