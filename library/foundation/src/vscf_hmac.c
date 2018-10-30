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
#include "vscf_hash_stream.h"
#include "vscf_hmac_impl.h"
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
vscf_hmac_init_ctx(vscf_hmac_impl_t *hmac_impl) {

    VSCF_ASSERT_PTR(hmac_impl);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_hmac_cleanup_ctx(vscf_hmac_impl_t *hmac_impl) {

    VSCF_ASSERT_PTR(hmac_impl);

    vsc_buffer_destroy(&hmac_impl->ipad);
}

//
//  Size of the digest (mac output) in bytes.
//
VSCF_PUBLIC size_t
vscf_hmac_digest_len(vscf_hmac_impl_t *hmac_impl) {

    VSCF_ASSERT_PTR(hmac_impl);
    VSCF_ASSERT_PTR(hmac_impl->hash);

    return vscf_hash_info_digest_len(vscf_hash_info_api(hmac_impl->hash));
}

//
//  Calculate MAC over given data.
//
VSCF_PUBLIC void
vscf_hmac_mac(vscf_hmac_impl_t *hmac_impl, vsc_data_t key, vsc_data_t data, vsc_buffer_t *mac) {

    VSCF_ASSERT_PTR(hmac_impl);
    VSCF_ASSERT(vsc_data_is_valid(key));
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(mac);
    VSCF_ASSERT(vsc_buffer_is_valid(mac));
    VSCF_ASSERT(vsc_buffer_left(mac) >= vscf_hmac_digest_len(hmac_impl));

    vscf_hmac_start(hmac_impl, key);
    vscf_hmac_update(hmac_impl, data);
    vscf_hmac_finish(hmac_impl, mac);
}

//
//  Start a new MAC.
//
VSCF_PUBLIC void
vscf_hmac_start(vscf_hmac_impl_t *hmac_impl, vsc_data_t key) {

    VSCF_ASSERT_PTR(hmac_impl);
    VSCF_ASSERT_PTR(hmac_impl->hash);
    VSCF_ASSERT(vsc_data_is_valid(key));

    size_t digest_len = vscf_hash_info_digest_len(vscf_hash_info_api(hmac_impl->hash));
    size_t block_len = vscf_hash_info_block_len(vscf_hash_info_api(hmac_impl->hash));
    VSCF_ASSERT_SAFE(digest_len <= block_len);

    //  Pre-process key.
    vsc_buffer_t *key_digest = NULL;

    if (key.len > block_len) {
        key_digest = vsc_buffer_new_with_capacity(digest_len);
        vsc_buffer_make_secure(key_digest);
        vscf_hash_stream_start(hmac_impl->hash);
        vscf_hash_stream_update(hmac_impl->hash, key);
        vscf_hash_stream_finish(hmac_impl->hash, key_digest);
        key = vsc_buffer_data(key_digest);
    }

    //  Reset ipad buffer.
    if (NULL == hmac_impl->ipad || vsc_buffer_len(hmac_impl->ipad) != block_len) {
        vsc_buffer_delete(hmac_impl->ipad);
        hmac_impl->ipad = vsc_buffer_new_with_capacity(block_len);
        vsc_buffer_make_secure(hmac_impl->ipad);
    }
    vsc_buffer_reset(hmac_impl->ipad);

    //  Derive ipad string.
    byte *ipad = vsc_buffer_begin(hmac_impl->ipad);
    size_t ipad_len = vsc_buffer_capacity(hmac_impl->ipad);
    VSCF_ASSERT_SAFE(ipad_len >= key.len);
    vsc_buffer_reserve(hmac_impl->ipad, ipad_len);

    for (size_t i = 0; i < key.len; ++i) {
        ipad[i] = key.bytes[i] ^ 0x36;
    }

    memset(ipad + key.len, 0x36, ipad_len - key.len);

    //  Start hashing.
    vscf_hash_stream_start(hmac_impl->hash);
    vscf_hash_stream_update(hmac_impl->hash, vsc_buffer_data(hmac_impl->ipad));

    //  Cleanup.
    vsc_buffer_destroy(&key_digest);
}

//
//  Add given data to the MAC.
//
VSCF_PUBLIC void
vscf_hmac_update(vscf_hmac_impl_t *hmac_impl, vsc_data_t data) {

    VSCF_ASSERT_PTR(hmac_impl);
    VSCF_ASSERT_PTR(hmac_impl->hash);

    vscf_hash_stream_update(hmac_impl->hash, data);
}

//
//  Accomplish MAC and return it's result (a message digest).
//
VSCF_PUBLIC void
vscf_hmac_finish(vscf_hmac_impl_t *hmac_impl, vsc_buffer_t *mac) {

    VSCF_ASSERT_PTR(hmac_impl);
    VSCF_ASSERT_PTR(mac);
    VSCF_ASSERT(vsc_buffer_is_valid(mac));
    VSCF_ASSERT(vsc_buffer_left(mac) >= vscf_hmac_digest_len(hmac_impl));

    VSCF_ASSERT_PTR(hmac_impl->hash);
    VSCF_ASSERT_PTR(hmac_impl->ipad);
    VSCF_ASSERT(vsc_buffer_is_valid(hmac_impl->ipad));

    //  Derive opad.
    size_t opad_len = vscf_hash_info_block_len(vscf_hash_info_api(hmac_impl->hash));
    byte *opad = vscf_alloc(opad_len);
    VSCF_ASSERT_ALLOC(opad);

    byte *ipad = vsc_buffer_begin(hmac_impl->ipad);
    size_t ipad_len = vsc_buffer_len(hmac_impl->ipad);
    VSCF_ASSERT_SAFE(ipad_len == opad_len);

    for (size_t i = 0; i < opad_len; ++i) {
        opad[i] = ipad[i] ^ 0x6A;
    }

    //  Store temporary digest.
    size_t digest_len = vscf_hash_info_digest_len(vscf_hash_info_api(hmac_impl->hash));
    vscf_hash_stream_finish(hmac_impl->hash, mac);
    vsc_buffer_decrease_used_bytes(mac, digest_len);

    //  Get resulting digest.
    vscf_hash_stream_start(hmac_impl->hash);
    vscf_hash_stream_update(hmac_impl->hash, vsc_data(opad, opad_len));
    vscf_hash_stream_update(hmac_impl->hash, vsc_data(vsc_buffer_ptr(mac), digest_len));
    vscf_hash_stream_finish(hmac_impl->hash, mac);

    vscf_dealloc(opad);
}

//
//  Prepare to authenticate a new message with the same key
//  as the previous MAC operation.
//
VSCF_PUBLIC void
vscf_hmac_reset(vscf_hmac_impl_t *hmac_impl) {

    VSCF_ASSERT_PTR(hmac_impl);
    VSCF_ASSERT_PTR(hmac_impl->ipad);
    VSCF_ASSERT(vsc_buffer_is_valid(hmac_impl->ipad));

    //  Start hashing.
    vscf_hash_stream_start(hmac_impl->hash);
    vscf_hash_stream_update(hmac_impl->hash, vsc_buffer_data(hmac_impl->ipad));
}
