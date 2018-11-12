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
//  Implements custom assert mechanism, which:
//      - allows to choose assertion handler from predefined set,
//        or provide custom assertion handler;
//      - allows to choose which assertion leave in production build.
// --------------------------------------------------------------------------

#ifndef VSCP_ASSERT_H_INCLUDED
#define VSCP_ASSERT_H_INCLUDED

#include "vscp_library.h"

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

//
//  Contains file path or file name.
//
#if defined (__FILENAME__)
#   define VSCP_FILE_PATH_OR_NAME __FILENAME__
#else
#   define VSCP_FILE_PATH_OR_NAME __FILE__
#endif

//
//  Asserts always.
//
#define VSCP_ASSERT_INTERNAL(X)                                         \
    do {                                                                \
        if (!(X)) {                                                     \
            vscp_assert_trigger (#X, VSCP_FILE_PATH_OR_NAME, __LINE__); \
        }                                                               \
    } while (false)

//
//  Asserts even in optimized mode.
//
#define VSCP_ASSERT_OPT(X) VSCP_ASSERT_INTERNAL (X)

//
//  Default assert, that is enabled in debug mode.
//
#define VSCP_ASSERT(X) VSCP_ASSERT_INTERNAL (X)

//
//  Heavy assert, that is enabled in a special (safe) cases.
//
#define VSCP_ASSERT_SAFE(X) VSCP_ASSERT_INTERNAL (X)

//
//  Asserts during compilation. Has no runtime impact.
//
#define VSCP_ASSERT_STATIC(X) (void) sizeof(char[(X) ? 1 : -1])

//
//  Assert that given pointer is not NULL. It is enabled in debug mode.
//
#define VSCP_ASSERT_PTR(X)                                                        \
    do {                                                                          \
        if (!(X)) {                                                               \
            vscp_assert_trigger (#X" != NULL", VSCP_FILE_PATH_OR_NAME, __LINE__); \
        }                                                                         \
    } while (false)

//
//  Assert that memory was successfully allocated.
//  This macros is enabled by default and can be disabled by special macros.
//
#define VSCP_ASSERT_ALLOC(X)                                                     \
    do {                                                                         \
        if (!(X)) {                                                              \
            vscp_assert_trigger ("No memory", VSCP_FILE_PATH_OR_NAME, __LINE__); \
        }                                                                        \
    } while (false)

//
//  This macros can be used as library 'mbedtls' error handlind post-condition.
//
#define VSCP_ASSERT_LIBRARY_MBEDTLS_UNHANDLED_ERROR(error)                                                      \
    do {                                                                                                        \
        VSCP_ASSERT((error) != 0);                                                                              \
        vscp_assert_trigger_unhandled_error_of_library_mbedtls((int)(error), VSCP_FILE_PATH_OR_NAME, __LINE__); \
    } while (0)

//
//  This macros can be used to ensure that library 'mbedtls' operation
//  returns success status code.
//
#define VSCP_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status)              \
    do {                                                         \
        if ((status) != 0) {                                     \
            VSCP_ASSERT_LIBRARY_MBEDTLS_UNHANDLED_ERROR(status); \
        }                                                        \
    } while (0)

//
//  Assertion handler callback type.
//
typedef void (*vscp_assert_handler_fn)(const char *message, const char *file, int line);

//
//  Change active assertion handler.
//
VSCP_PUBLIC void
vscp_assert_change_handler(vscp_assert_handler_fn handler_cb);

//
//  Assertion handler, that print given information and abort program.
//  This is default handler.
//
VSCP_PUBLIC void
vscp_assert_abort(const char *message, const char *file, int line);

//
//  Trigger active assertion handler.
//
VSCP_PUBLIC void
vscp_assert_trigger(const char *message, const char *file, int line);

//
//  Tell assertion handler that error of library 'mbedtls' is not handled.
//
VSCP_PUBLIC void
vscp_assert_trigger_unhandled_error_of_library_mbedtls(int error, const char *file, int line);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCP_ASSERT_H_INCLUDED
//  @end
