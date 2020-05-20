//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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

#ifndef VSCS_CORE_ASSERT_H_INCLUDED
#define VSCS_CORE_ASSERT_H_INCLUDED

#include "vscs_core_library.h"

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
#   define VSCS_CORE_FILE_PATH_OR_NAME __FILENAME__
#else
#   define VSCS_CORE_FILE_PATH_OR_NAME __FILE__
#endif

//
//  Asserts always.
//
#define VSCS_CORE_ASSERT_INTERNAL(X)                                              \
    do {                                                                          \
        if (!(X)) {                                                               \
            vscs_core_assert_trigger (#X, VSCS_CORE_FILE_PATH_OR_NAME, __LINE__); \
        }                                                                         \
    } while (false)

//
//  Asserts even in optimized mode.
//
#define VSCS_CORE_ASSERT_OPT(X) VSCS_CORE_ASSERT_INTERNAL(X)

//
//  Default assert, that is enabled in debug mode.
//
#define VSCS_CORE_ASSERT(X) VSCS_CORE_ASSERT_INTERNAL(X)

//
//  Heavy assert, that is enabled in a special (safe) cases.
//
#define VSCS_CORE_ASSERT_SAFE(X) VSCS_CORE_ASSERT_INTERNAL(X)

//
//  Asserts during compilation. Has no runtime impact.
//
#define VSCS_CORE_ASSERT_STATIC(X) (void) sizeof(char[(X) ? 1 : -1])

//
//  Assert that given pointer is not NULL. It is enabled in debug mode.
//
#define VSCS_CORE_ASSERT_PTR(X)                                                             \
    do {                                                                                    \
        if (!(X)) {                                                                         \
            vscs_core_assert_trigger (#X" != NULL", VSCS_CORE_FILE_PATH_OR_NAME, __LINE__); \
        }                                                                                   \
    } while (false)

//
//  Assert that given reference is not NULL. And reference pointer is not NULL too.
//  It is enabled in debug mode.
//
#define VSCS_CORE_ASSERT_REF(X)   \
    do {                          \
        VSCS_CORE_ASSERT_PTR(X);  \
        VSCS_CORE_ASSERT_PTR(*X); \
    } while (false)

//
//  Assert that given pointer is NULL. It is enabled in debug mode.
//
#define VSCS_CORE_ASSERT_NULL(X)                                                            \
    do {                                                                                    \
        if(X) {                                                                             \
            vscs_core_assert_trigger (#X" == NULL", VSCS_CORE_FILE_PATH_OR_NAME, __LINE__); \
        }                                                                                   \
    } while (false)

//
//  Assert that memory was successfully allocated.
//  This macros is enabled by default and can be disabled by special macros.
//
#define VSCS_CORE_ASSERT_ALLOC(X)                                                          \
    do {                                                                                   \
        if (!(X)) {                                                                        \
            vscs_core_assert_trigger ("No memory", VSCS_CORE_FILE_PATH_OR_NAME, __LINE__); \
        }                                                                                  \
    } while (false)

//
//  This macros can be used as library 'json_c' error handlind post-condition.
//
#define VSCS_CORE_ASSERT_LIBRARY_JSON_C_UNHANDLED_ERROR(error)                                                           \
    do {                                                                                                                 \
        VSCS_CORE_ASSERT((error) != 0);                                                                                  \
        vscs_core_assert_trigger_unhandled_error_of_library_json_c((int)(error), VSCS_CORE_FILE_PATH_OR_NAME, __LINE__); \
    } while (0)

//
//  This macros can be used to ensure that library 'json_c' operation
//  returns success status code.
//
#define VSCS_CORE_ASSERT_LIBRARY_JSON_C_SUCCESS(status)              \
    do {                                                             \
        if ((status) != 0) {                                         \
            VSCS_CORE_ASSERT_LIBRARY_JSON_C_UNHANDLED_ERROR(status); \
        }                                                            \
    } while (0)

//
//  This macros can be used as project 'foundation' error handlind post-condition.
//
#define VSCS_CORE_ASSERT_PROJECT_FOUNDATION_UNHANDLED_ERROR(error)                                                           \
    do {                                                                                                                     \
        VSCS_CORE_ASSERT((error) != 0);                                                                                      \
        vscs_core_assert_trigger_unhandled_error_of_project_foundation((int)(error), VSCS_CORE_FILE_PATH_OR_NAME, __LINE__); \
    } while (0)

//
//  This macros can be used to ensure that project 'foundation' operation
//  returns success status code.
//
#define VSCS_CORE_ASSERT_PROJECT_FOUNDATION_SUCCESS(status)              \
    do {                                                                 \
        if ((status) != 0) {                                             \
            VSCS_CORE_ASSERT_PROJECT_FOUNDATION_UNHANDLED_ERROR(status); \
        }                                                                \
    } while (0)

//
//  Assertion handler callback type.
//
typedef void (*vscs_core_assert_handler_fn)(const char *message, const char *file, int line);

//
//  Change active assertion handler.
//
VSCS_CORE_PUBLIC void
vscs_core_assert_change_handler(vscs_core_assert_handler_fn handler_cb);

//
//  Assertion handler, that print given information and abort program.
//  This is default handler.
//
VSCS_CORE_PUBLIC void
vscs_core_assert_abort(const char *message, const char *file, int line);

//
//  Trigger active assertion handler.
//
VSCS_CORE_PUBLIC void
vscs_core_assert_trigger(const char *message, const char *file, int line);

//
//  Tell assertion handler that error of library 'json_c' is not handled.
//
VSCS_CORE_PUBLIC void
vscs_core_assert_trigger_unhandled_error_of_library_json_c(int error, const char *file, int line);

//
//  Tell assertion handler that error of project 'foundation' is not handled.
//
VSCS_CORE_PUBLIC void
vscs_core_assert_trigger_unhandled_error_of_project_foundation(int error, const char *file, int line);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSCS_CORE_ASSERT_H_INCLUDED
//  @end