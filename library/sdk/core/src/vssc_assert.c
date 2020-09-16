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

#include "vssc_assert.h"

#include <virgil/crypto/foundation/vscf_status.h>
#include <stdio.h>

#if VSSC_HAVE_ASSERT_H
#   include <assert.h>
#endif

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
vssc_assert_path_basename(const char *path);

//
//  Active handler for assertion fail.
//
static vssc_assert_handler_fn active_handler = vssc_assert_abort;

//
//  Change active assertion handler.
//
VSSC_PUBLIC void
vssc_assert_change_handler(vssc_assert_handler_fn handler_cb) {

    VSSC_ASSERT (handler_cb);
    active_handler = handler_cb;
}

//
//  Assertion handler, that print given information and abort program.
//  This is default handler.
//
VSSC_PUBLIC void
vssc_assert_abort(const char *message, const char *file, int line) {

    printf("Assertion failed: %s, file %s, line %d\n",
            message, vssc_assert_path_basename (file), line);

    printf("Abort");
    fflush(stdout);

    abort();
}

//
//  Trigger active assertion handler.
//
VSSC_PUBLIC void
vssc_assert_trigger(const char *message, const char *file, int line) {

    active_handler (message, file, line);
}

//
//  Return pointer to the last component in the path.
//
static const char *
vssc_assert_path_basename(const char *path) {

    const char *result = path;
    for (const char *symbol = path; *symbol != '\0' && (symbol - path < 255); ++symbol) {

        const char *next_symbol = symbol + 1;

        if (*next_symbol != '\0' && (*symbol == '\\' || *symbol == '/')) {
            result = next_symbol;
        }
    }

    return result;
}

//
//  Tell assertion handler that error of library 'json_c' is not handled.
//
VSSC_PUBLIC void
vssc_assert_trigger_unhandled_error_of_library_json_c(int error, const char *file, int line) {

    char error_message[32] = {0x00};
    snprintf(error_message, sizeof(error_message), "Unhandled JSON-C error %4d", error);

    vssc_assert_trigger(error_message, file, line);
}

//
//  Tell assertion handler that error of project 'foundation' is not handled.
//
VSSC_PUBLIC void
vssc_assert_trigger_unhandled_error_of_project_foundation(int error, const char *file, int line) {

    char error_message[48] = {0x00};
    snprintf(error_message, sizeof(error_message), "Unhandled vsc::foundation error -0x%04x", error);

    vssc_assert_trigger(error_message, file, line);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end