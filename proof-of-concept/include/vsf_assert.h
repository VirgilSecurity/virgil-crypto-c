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

#ifndef VSF_ASSERT_H_INCLUDED
#define VSF_ASSERT_H_INCLUDED

#include <stdbool.h>

typedef __attribute__((noreturn)) void (*vsf_assert_handler_fn) (const char *msg, const char *file, int line);

__attribute__((noreturn)) void vsf_assert_abort (const char *msg, const char *file, int line);

void vsf_assert_set_handler (vsf_assert_handler_fn assert_handler_fn);

__attribute__((noreturn)) void vsf_assert_handle (const char *msg, const char *file, int line);

#define VSF_ASSERT_ASSERT(X)                            \
    do {                                                \
        if (!(X)) {                                     \
            vsf_assert_handle (#X, __FILE__, __LINE__); \
        }                                               \
    } while (false)

#define VSF_ASSERT_OPT(X) VSF_ASSERT_ASSERT(X)
#define VSF_ASSERT(X) VSF_ASSERT_ASSERT(X)
#define VSF_ASSERT_SAFE(X) VSF_ASSERT_ASSERT(X)
#define VSF_ASSERT_STATIC(X) (void) sizeof(char[(X) ? 1 : -1])

#endif // VSF_ASSERT_H_INCLUDED
