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

#include "vsf_assert.h"

#include <stdio.h>
#include <stdlib.h>

static vsf_assert_handler_fn inner_assert_handler = vsf_assert_abort;

static const char * basename (const char *path) {
    const char *result = path;
    for (const char *symbol = path; *symbol != '\0'; ++symbol) {
        const char *next_symbol = symbol + 1;
        if (*next_symbol != '\0' && (*symbol == '\\' || *symbol == '/')) {
            result = next_symbol;
        }
    }
    return result;
}

void vsf_assert_abort (const char *msg, const char *file, int line) {
    printf ("Assertion failed: %s, file %s, line %d\n", msg, basename (file), line);
    printf ("Abort");
    abort ();
}

void vsf_assert_set_handler (vsf_assert_handler_fn assert_handler_fn) {
    VSF_ASSERT (assert_handler_fn);
    inner_assert_handler = assert_handler_fn;
}

void vsf_assert_handle (const char *msg, const char *file, int line) {
    inner_assert_handler (msg, file, line);
}
