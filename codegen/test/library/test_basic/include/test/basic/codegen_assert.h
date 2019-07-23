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
//  Implements custom assert mechanism, which:
//      - allows to choose assertion handler from predefined set,
//        or provide custom assertion handler;
//      - allows to choose which assertion leave in production build.
// --------------------------------------------------------------------------

#ifndef CODEGEN_ASSERT_H_INCLUDED
#define CODEGEN_ASSERT_H_INCLUDED

#include "codegen_library.h"

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
#   define CODEGEN_FILE_PATH_OR_NAME __FILENAME__
#else
#   define CODEGEN_FILE_PATH_OR_NAME __FILE__
#endif

//
//  Asserts always.
//
#define CODEGEN_ASSERT_INTERNAL(X)                                            \
    do {                                                                      \
        if (!(X)) {                                                           \
            codegen_assert_trigger (#X, CODEGEN_FILE_PATH_OR_NAME, __LINE__); \
        }                                                                     \
    } while (false)

//
//  Asserts even in optimized mode.
//
#define CODEGEN_ASSERT_OPT(X) CODEGEN_ASSERT_INTERNAL(X)

//
//  Default assert, that is enabled in debug mode.
//
#define CODEGEN_ASSERT(X) CODEGEN_ASSERT_INTERNAL(X)

//
//  Heavy assert, that is enabled in a special (safe) cases.
//
#define CODEGEN_ASSERT_SAFE(X) CODEGEN_ASSERT_INTERNAL(X)

//
//  Asserts during compilation. Has no runtime impact.
//
#define CODEGEN_ASSERT_STATIC(X) (void) sizeof(char[(X) ? 1 : -1])

//
//  Assert that given pointer is not NULL. It is enabled in debug mode.
//
#define CODEGEN_ASSERT_PTR(X)                                                           \
    do {                                                                                \
        if (!(X)) {                                                                     \
            codegen_assert_trigger (#X" != NULL", CODEGEN_FILE_PATH_OR_NAME, __LINE__); \
        }                                                                               \
    } while (false)

//
//  Assert that given pointer is NULL. It is enabled in debug mode.
//
#define CODEGEN_ASSERT_NULL(X)                                                          \
    do {                                                                                \
        if(X) {                                                                         \
            codegen_assert_trigger (#X" == NULL", CODEGEN_FILE_PATH_OR_NAME, __LINE__); \
        }                                                                               \
    } while (false)

//
//  Assert that memory was successfully allocated.
//  This macros is enabled by default and can be disabled by special macros.
//
#define CODEGEN_ASSERT_ALLOC(X)                                                        \
    do {                                                                               \
        if (!(X)) {                                                                    \
            codegen_assert_trigger ("No memory", CODEGEN_FILE_PATH_OR_NAME, __LINE__); \
        }                                                                              \
    } while (false)

//
//  Assertion handler callback type.
//
typedef void (*codegen_assert_handler_fn)(const char *message, const char *file, int line);

//
//  Change active assertion handler.
//
CODEGEN_PUBLIC void
codegen_assert_change_handler(codegen_assert_handler_fn handler_cb);

//
//  Assertion handler, that print given information and abort program.
//  This is default handler.
//
CODEGEN_PUBLIC void
codegen_assert_abort(const char *message, const char *file, int line);

//
//  Trigger active assertion handler.
//
CODEGEN_PUBLIC void
codegen_assert_trigger(const char *message, const char *file, int line);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // CODEGEN_ASSERT_H_INCLUDED
//  @end
