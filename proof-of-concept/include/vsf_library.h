//  Copyright (c) 2015-2018 Virgil Security Inc.
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

#ifndef VSF_LIBRARY_H_INCLUDED
#define VSF_LIBRARY_H_INCLUDED

#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

// --------------------------------------------------------------------------
//  Version.
// --------------------------------------------------------------------------
#define VSF_VERSION_MAJOR 5
#define VSF_VERSION_MINOR 0
#define VSF_VERSION_PATCH 0

#define VSF_MAKE_VERSION(major, minor, patch) \
    ((major) * 10000 + (minor) * 100 + (patch))
#define VSF_VERSION \
    VSF_MAKE_VERSION (VSF_VERSION_MAJOR, VSF_VERSION_MINOR, VSF_VERSION_PATCH)

// --------------------------------------------------------------------------
//  Visibility.
// --------------------------------------------------------------------------

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
#   define VSF_PUBLIC
#   if (defined __GNUC__ && __GNUC__ >= 4) || defined __INTEL_COMPILER
#       define VSF_PRIVATE __attribute__ ((visibility ("hidden")))
#   else
#       define VSF_PRIVATE
#   endif
#endif


// --------------------------------------------------------------------------
//  Constants.
// --------------------------------------------------------------------------
enum {
    vsf_POINTER_SIZE = sizeof (void *)
};


// --------------------------------------------------------------------------
//  Types.
// --------------------------------------------------------------------------

#ifndef byte
#   define byte uint8_t
#endif


// --------------------------------------------------------------------------
//  Callbacks.
// --------------------------------------------------------------------------

typedef void * (*vsf_alloc_fn) (size_t size);
typedef void (*vsf_dealloc_fn) (void *ptr);


#endif // VSF_LIBRARY_H_INCLUDED
