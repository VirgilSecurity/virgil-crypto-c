//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
//
//  All rights reserved.
//
//  FreeBSD Clause-3
// --------------------------------------------------------------------------
// clang-format off


//  @description
// --------------------------------------------------------------------------
//  Implements custom assert mechanism, which:
//      - allows to choose assertion handler from predefined set,
//        or provide custom assertion handler;
//      - allows to choose which assertion leave in production build.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "codegen_assert.h"

#include <stdio.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Return pointer to the last component in the path.
//
static const char *
codegen_assert_path_basename(const char *path);

//
//  Active handler for assertion fail.
//
static codegen_assert_handler_fn active_handler = codegen_assert_abort;

//
//  Change active assertion handler.
//
CODEGEN_PUBLIC void
codegen_assert_change_handler(codegen_assert_handler_fn handler_cb) {

    CODEGEN_ASSERT (handler_cb);
    active_handler = handler_cb;
}

//
//  Assertion handler, that print given information and abort program.
//  This is default handler.
//
CODEGEN_PUBLIC void
codegen_assert_abort(const char *message, const char *file, int line) {

    printf("Assertion failed: %s, file %s, line %d\n",
            message, codegen_assert_path_basename (file), line);

    printf("Abort");
    fflush(stdout);

    abort();
}

//
//  Trigger active assertion handler.
//
CODEGEN_PUBLIC void
codegen_assert_trigger(const char *message, const char *file, int line) {

    active_handler (message, file, line);
}

//
//  Return pointer to the last component in the path.
//
static const char *
codegen_assert_path_basename(const char *path) {

    const char *result = path;
    for (const char *symbol = path; *symbol != '\0' && (symbol - path < 255); ++symbol) {

        const char *next_symbol = symbol + 1;

        if (*next_symbol != '\0' && (*symbol == '\\' || *symbol == '/')) {
            result = next_symbol;
        }
    }

    return result;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
