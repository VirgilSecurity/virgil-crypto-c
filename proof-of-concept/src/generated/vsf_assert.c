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

#include "vsf_assert.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------


// ==========================================================================
//  Generated functions.
// ==========================================================================


// --------------------------------------------------------------------------
//  Configuration.
// --------------------------------------------------------------------------

//  Change active assertion handler.
VSF_PUBLIC void
vsf_assert_change_handler (vsf_assert_handler_fn handler_cb) {

    VSF_ASSERT (handler_cb);
    active_handler = handler_cb;
}


// --------------------------------------------------------------------------
//  Action.
// --------------------------------------------------------------------------

//  Assertion handler, that print given information and abort program.
//  This is default handler.
VSF_PUBLIC void
vsf_assert_abort (const char *message, const char *file, int line) {

    printf ("Assertion failed: %s, file %s, line %d\n",
            msg, vsf_assert_path_basename (file), line);
    printf ("Abort");
    abort ();
}

//  Trigger active assertion handler.
VSF_PUBLIC void
vsf_assert_trigger (const char *message, const char *file, int line) {

    active_handler (message, file, line);
}

//  Return pointer to the last component in the path.
VSF_PRIVATE const char *
vsf_assert_path_basename (const char *path) {

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
// --------------------------------------------------------------------------
//  @end
