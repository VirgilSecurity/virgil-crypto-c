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
//  This module contains 'hmac' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_hmac.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_alg.h"
#include "vscf_alg_info.h"
#include "vscf_alg_factory.h"
#include "vscf_hash_based_alg_info.h"
#include "vscf_hash.h"
#include "vscf_hmac_defs.h"
#include "vscf_hmac_internal.h"

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
//  Note, this method is called automatically when method vscf_hmac_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_hmac_init_ctx(vscf_hmac_t *hmac) {

    VSCF_ASSERT_PTR(hmac);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_hmac_cleanup_ctx(vscf_hmac_t *hmac) {

    VSCF_ASSERT_PTR(hmac);

    vsc_buffer_destroy(&hmac->ipad);
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_hmac_alg_id(const vscf_hmac_t *hmac) {

    VSCF_ASSERT_PTR(hmac);

    return vscf_alg_id_HMAC;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_hmac_produce_alg_info(const vscf_hmac_t *hmac) {

    VSCF_ASSERT_PTR(hmac);
    VSCF_ASSERT_PTR(hmac->hash);

    vscf_impl_t *hash_alg_info = vscf_alg_produce_alg_info(hmac->hash);
    vscf_impl_t *hmac_alg_info =
            vscf_hash_based_alg_info_impl(vscf_hash_based_alg_info_new_with_members(vscf_alg_id_HMAC, &hash_alg_info));

    return hmac_alg_info;
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_error_t
vscf_hmac_restore_alg_info(vscf_hmac_t *hmac, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(hmac);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_HMAC);

    const vscf_hash_based_alg_info_t *hash_based_alg_info = (const vscf_hash_based_alg_info_t *)alg_info;

    vscf_impl_t *hash = vscf_alg_factory_create_hash_alg(vscf_hash_based_alg_info_hash_alg_info(hash_based_alg_info));
    vscf_hmac_release_hash(hmac);
    vscf_hmac_take_hash(hmac, hash);

    return vscf_SUCCESS;
}

//
//  Size of the digest (mac output) in bytes.
//
VSCF_PUBLIC size_t
vscf_hmac_digest_len(vscf_hmac_t *hmac) {

    VSCF_ASSERT_PTR(hmac);
    VSCF_ASSERT_PTR(hmac->hash);

    return vscf_hash_digest_len(vscf_hash_api(hmac->hash));
}

//
//  Calculate MAC over given data.
//
VSCF_PUBLIC void
vscf_hmac_mac(vscf_hmac_t *hmac, vsc_data_t key, vsc_data_t data, vsc_buffer_t *mac) {

    VSCF_ASSERT_PTR(hmac);
    VSCF_ASSERT(vsc_data_is_valid(key));
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(mac);
    VSCF_ASSERT(vsc_buffer_is_valid(mac));
    VSCF_ASSERT(vsc_buffer_unused_len(mac) >= vscf_hmac_digest_len(hmac));

    vscf_hmac_start(hmac, key);
    vscf_hmac_update(hmac, data);
    vscf_hmac_finish(hmac, mac);
}

//
//  Start a new MAC.
//
VSCF_PUBLIC void
vscf_hmac_start(vscf_hmac_t *hmac, vsc_data_t key) {

    VSCF_ASSERT_PTR(hmac);
    VSCF_ASSERT_PTR(hmac->hash);
    VSCF_ASSERT(vsc_data_is_valid(key));

    size_t digest_len = vscf_hash_digest_len(vscf_hash_api(hmac->hash));
    size_t block_len = vscf_hash_block_len(vscf_hash_api(hmac->hash));
    VSCF_ASSERT_SAFE(digest_len <= block_len);

    //  Pre-process key.
    vsc_buffer_t *key_digest = NULL;

    if (key.len > block_len) {
        key_digest = vsc_buffer_new_with_capacity(digest_len);
        vsc_buffer_make_secure(key_digest);
        vscf_hash_start(hmac->hash);
        vscf_hash_update(hmac->hash, key);
        vscf_hash_finish(hmac->hash, key_digest);
        key = vsc_buffer_data(key_digest);
    }

    //  Reset ipad buffer.
    if (NULL == hmac->ipad || vsc_buffer_len(hmac->ipad) != block_len) {
        vsc_buffer_delete(hmac->ipad);
        hmac->ipad = vsc_buffer_new_with_capacity(block_len);
        vsc_buffer_make_secure(hmac->ipad);
    }
    vsc_buffer_reset(hmac->ipad);

    //  Derive ipad string.
    byte *ipad = vsc_buffer_begin(hmac->ipad);
    size_t ipad_len = vsc_buffer_capacity(hmac->ipad);
    VSCF_ASSERT_SAFE(ipad_len >= key.len);
    vsc_buffer_inc_used(hmac->ipad, ipad_len);

    for (size_t i = 0; i < key.len; ++i) {
        ipad[i] = key.bytes[i] ^ 0x36;
    }

    memset(ipad + key.len, 0x36, ipad_len - key.len);

    //  Start hashing.
    vscf_hash_start(hmac->hash);
    vscf_hash_update(hmac->hash, vsc_buffer_data(hmac->ipad));

    //  Cleanup.
    vsc_buffer_destroy(&key_digest);
}

//
//  Add given data to the MAC.
//
VSCF_PUBLIC void
vscf_hmac_update(vscf_hmac_t *hmac, vsc_data_t data) {

    VSCF_ASSERT_PTR(hmac);
    VSCF_ASSERT_PTR(hmac->hash);

    vscf_hash_update(hmac->hash, data);
}

//
//  Accomplish MAC and return it's result (a message digest).
//
VSCF_PUBLIC void
vscf_hmac_finish(vscf_hmac_t *hmac, vsc_buffer_t *mac) {

    VSCF_ASSERT_PTR(hmac);
    VSCF_ASSERT_PTR(mac);
    VSCF_ASSERT(vsc_buffer_is_valid(mac));
    VSCF_ASSERT(vsc_buffer_unused_len(mac) >= vscf_hmac_digest_len(hmac));

    VSCF_ASSERT_PTR(hmac->hash);
    VSCF_ASSERT_PTR(hmac->ipad);
    VSCF_ASSERT(vsc_buffer_is_valid(hmac->ipad));

    //  Derive opad.
    size_t opad_len = vscf_hash_block_len(vscf_hash_api(hmac->hash));
    byte *opad = vscf_alloc(opad_len);
    VSCF_ASSERT_ALLOC(opad);

    byte *ipad = vsc_buffer_begin(hmac->ipad);
    size_t ipad_len = vsc_buffer_len(hmac->ipad);
    VSCF_ASSERT_SAFE(ipad_len == opad_len);

    for (size_t i = 0; i < opad_len; ++i) {
        opad[i] = ipad[i] ^ 0x6A;
    }

    //  Store temporary digest.
    size_t digest_len = vscf_hash_digest_len(vscf_hash_api(hmac->hash));
    vscf_hash_finish(hmac->hash, mac);
    vsc_buffer_dec_used(mac, digest_len);

    //  Get resulting digest.
    vscf_hash_start(hmac->hash);
    vscf_hash_update(hmac->hash, vsc_data(opad, opad_len));
    vscf_hash_update(hmac->hash, vsc_data(vsc_buffer_unused_bytes(mac), digest_len));
    vscf_hash_finish(hmac->hash, mac);

    vscf_dealloc(opad);
}

//
//  Prepare to authenticate a new message with the same key
//  as the previous MAC operation.
//
VSCF_PUBLIC void
vscf_hmac_reset(vscf_hmac_t *hmac) {

    VSCF_ASSERT_PTR(hmac);
    VSCF_ASSERT_PTR(hmac->ipad);
    VSCF_ASSERT(vsc_buffer_is_valid(hmac->ipad));

    //  Start hashing.
    vscf_hash_start(hmac->hash);
    vscf_hash_update(hmac->hash, vsc_buffer_data(hmac->ipad));
}
