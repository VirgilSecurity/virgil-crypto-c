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
//  This module contains 'sha256' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsf_sha256.h"
#include "vsf_assert.h"
#include "vsf_memory.h"
#include "vsf_sha256_impl.h"
#include "vsf_sha256_internal.h"

#include <mbedtls/sha256.h>
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//
VSF_PRIVATE vsf_error_t
vsf_sha256_init_ctx(vsf_sha256_impl_t *sha256_impl) {

    VSF_ASSERT_PTR(sha256_impl);

    mbedtls_sha256_init(&sha256_impl->hash_ctx);

    return vsf_SUCCESS;
}

//
//  Provides cleanup of the implementation specific context.
//
VSF_PRIVATE void
vsf_sha256_cleanup_ctx(vsf_sha256_impl_t *sha256_impl) {

    VSF_ASSERT_PTR(sha256_impl);

    mbedtls_sha256_free(&sha256_impl->hash_ctx);
}

//
//  Calculate hash over given data.
//
VSF_PUBLIC void
vsf_sha256_hash(const byte *data, size_t data_len, byte *digest, size_t digest_len) {

    VSF_ASSERT_PTR(data);
    VSF_ASSERT_PTR(digest);
    VSF_ASSERT_OPT(digest_len >= vsf_sha256_DIGEST_SIZE);

    const int is224 = 0;
    mbedtls_sha256(data, data_len, digest, is224);
}

//
//  Start a new hashing.
//
VSF_PUBLIC void
vsf_sha256_start(vsf_sha256_impl_t *sha256_impl) {

    VSF_ASSERT_PTR(sha256_impl);

    const int is224 = 0;
    mbedtls_sha256_starts(&sha256_impl->hash_ctx, is224);
}

//
//  Add given data to the hash.
//
VSF_PUBLIC void
vsf_sha256_update(vsf_sha256_impl_t *sha256_impl, const byte *data, size_t data_len) {

    VSF_ASSERT_PTR(sha256_impl);
    VSF_ASSERT_PTR(data);

    mbedtls_sha256_update(&sha256_impl->hash_ctx, data, data_len);
}

//
//  Accompilsh hashing and return it's result (a message digest).
//
VSF_PUBLIC void
vsf_sha256_finish(vsf_sha256_impl_t *sha256_impl, byte *digest, size_t digest_len) {

    VSF_ASSERT_PTR(sha256_impl);
    VSF_ASSERT_PTR(digest);
    VSF_ASSERT_OPT(digest_len >= vsf_sha256_DIGEST_SIZE);

    mbedtls_sha256_finish(&sha256_impl->hash_ctx, digest);
}
