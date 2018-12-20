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

#include "vscf_assert.h"

#include <mbedtls/config.h>
#include <mbedtls/error.h>
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
vscf_assert_path_basename(const char *path);

//
//  Active handler for assertion fail.
//
static vscf_assert_handler_fn active_handler = vscf_assert_abort;

//
//  Change active assertion handler.
//
VSCF_PUBLIC void
vscf_assert_change_handler(vscf_assert_handler_fn handler_cb) {

    VSCF_ASSERT (handler_cb);
    active_handler = handler_cb;
}

//
//  Assertion handler, that print given information and abort program.
//  This is default handler.
//
VSCF_PUBLIC void
vscf_assert_abort(const char *message, const char *file, int line) {

    printf ("Assertion failed: %s, file %s, line %d\n",
            message, vscf_assert_path_basename (file), line);

    printf ("Abort");

    abort ();
}

//
//  Trigger active assertion handler.
//
VSCF_PUBLIC void
vscf_assert_trigger(const char *message, const char *file, int line) {

    active_handler (message, file, line);
}

//
//  Return pointer to the last component in the path.
//
static const char *
vscf_assert_path_basename(const char *path) {

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
//  Tell assertion handler that error of library 'mbedtls' is not handled.
//
VSCF_PUBLIC void
vscf_assert_trigger_unhandled_error_of_library_mbedtls(int error, const char *file, int line) {

    #if defined(MBEDTLS_ERROR_C)
        char error_message[256] = {0x00};
        mbedtls_strerror(error, error_message, sizeof(error_message));
    #else
        char error_message[32] = {0x00};
        if (error < 0) {
            error = -error;
        }
        snprintf(error_message, sizeof(error_message), "Unhandled mbedTLS error -0x%04x", error);
    #endif

    vscf_assert_trigger(error_message, file, line);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
