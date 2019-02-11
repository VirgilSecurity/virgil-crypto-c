//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2019 Virgil Security, Inc.
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
//  This module contains 'sha512' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_sha512.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_alg_info.h"
#include "vscf_simple_alg_info.h"
#include "vscf_sha512_defs.h"
#include "vscf_sha512_internal.h"

// clang-format on
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
//  Note, this method is called automatically when method vscf_sha512_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_sha512_init_ctx(vscf_sha512_t *sha512) {

    VSCF_ASSERT_PTR(sha512);

    mbedtls_sha512_init(&sha512->hash_ctx);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_sha512_cleanup_ctx(vscf_sha512_t *sha512) {

    VSCF_ASSERT_PTR(sha512);

    mbedtls_sha512_free(&sha512->hash_ctx);
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_sha512_alg_id(const vscf_sha512_t *sha512) {

    VSCF_ASSERT_PTR(sha512);

    return vscf_alg_id_SHA512;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_sha512_produce_alg_info(const vscf_sha512_t *sha512) {

    VSCF_ASSERT_PTR(sha512);

    return vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_SHA512));
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_error_t
vscf_sha512_restore_alg_info(vscf_sha512_t *sha512, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(sha512);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_SHA512);

    return vscf_SUCCESS;
}

//
//  Calculate hash over given data.
//
VSCF_PUBLIC void
vscf_sha512_hash(vsc_data_t data, vsc_buffer_t *digest) {

    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_buffer_is_valid(digest));
    VSCF_ASSERT(vsc_buffer_unused_len(digest) >= vscf_sha512_DIGEST_LEN);

    vscf_sha512_t sha512;
    vscf_sha512_init(&sha512);
    vscf_sha512_start(&sha512);
    vscf_sha512_update(&sha512, data);
    vscf_sha512_finish(&sha512, digest);
    vscf_sha512_cleanup(&sha512);
}

//
//  Start a new hashing.
//
VSCF_PUBLIC void
vscf_sha512_start(vscf_sha512_t *sha512) {

    VSCF_ASSERT_PTR(sha512);

    const int is384 = 0;
    mbedtls_sha512_starts(&sha512->hash_ctx, is384);
}

//
//  Add given data to the hash.
//
VSCF_PUBLIC void
vscf_sha512_update(vscf_sha512_t *sha512, vsc_data_t data) {

    VSCF_ASSERT_PTR(sha512);
    VSCF_ASSERT(vsc_data_is_valid(data));

    mbedtls_sha512_update(&sha512->hash_ctx, data.bytes, data.len);
}

//
//  Accompilsh hashing and return it's result (a message digest).
//
VSCF_PUBLIC void
vscf_sha512_finish(vscf_sha512_t *sha512, vsc_buffer_t *digest) {

    VSCF_ASSERT_PTR(sha512);
    VSCF_ASSERT(vsc_buffer_is_valid(digest));
    VSCF_ASSERT(vsc_buffer_unused_len(digest) >= vscf_sha512_DIGEST_LEN);

    mbedtls_sha512_finish(&sha512->hash_ctx, vsc_buffer_unused_bytes(digest));
    vsc_buffer_inc_used(digest, vscf_sha512_DIGEST_LEN);
}
