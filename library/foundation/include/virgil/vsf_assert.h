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


//  @description
// --------------------------------------------------------------------------
//  Implements custom assert mechanism, which:
//      - allows to choose assertion handler from predefined set,
//        or provide custom assertion handler;
//      - allows to choose which assertion leave in production build.
// --------------------------------------------------------------------------

#ifndef VSF_ASSERT_H_INCLUDED
#define VSF_ASSERT_H_INCLUDED

#include "vsf_library.h"
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Contains file path or file name.
//
#if defined (__FILENAME__)
#   define VSF_FILE_PATH_OR_NAME __FILENAME__
#else
#   define VSF_FILE_PATH_OR_NAME __FILE__
#endif

//
//  Asserts always.
//
#define VSF_ASSERT_INTERNAL(X)                                        \
    do {                                                              \
        if (!(X)) {                                                   \
            vsf_assert_trigger (#X, VSF_FILE_PATH_OR_NAME, __LINE__); \
        }                                                             \
    } while (false)

//
//  Asserts even in optimized mode.
//
#define VSF_ASSERT_OPT(X) VSF_ASSERT_INTERNAL (X)

//
//  Default assert, that is enabled in debug mode.
//
#define VSF_ASSERT(X) VSF_ASSERT_INTERNAL (X)

//
//  Heavy assert, that is enabled in a special (safe) cases.
//
#define VSF_ASSERT_SAFE(X) VSF_ASSERT_INTERNAL (X)

//
//  Asserts during compilation. Has no runtime impact.
//
#define VSF_ASSERT_STATIC(X) (void) sizeof(char[(X) ? 1 : -1])

//
//  Assert that given pointer is not NULL. It is enabled in debug mode.
//
#define VSF_ASSERT_PTR(X)                                                       \
    do {                                                                        \
        if (!(X)) {                                                             \
            vsf_assert_trigger (#X" != NULL", VSF_FILE_PATH_OR_NAME, __LINE__); \
        }                                                                       \
    } while (false)

//
//  Assertion handler callback type.
//
typedef void (*vsf_assert_handler_fn)(const char* message, const char* file, int line);

//
//  Change active assertion handler.
//
VSF_PUBLIC void
vsf_assert_change_handler(vsf_assert_handler_fn handler_cb);

//
//  Assertion handler, that print given information and abort program.
//  This is default handler.
//
VSF_PUBLIC void
vsf_assert_abort(const char* message, const char* file, int line);

//
//  Trigger active assertion handler.
//
VSF_PUBLIC void
vsf_assert_trigger(const char* message, const char* file, int line);


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSF_ASSERT_H_INCLUDED
//  @end
