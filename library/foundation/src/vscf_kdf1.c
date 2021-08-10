//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2021 Virgil Security, Inc.
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
//  This module contains 'kdf1' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_kdf1.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_kdf1_defs.h"
#include "vscf_kdf1_internal.h"
#include "vscf_alg.h"
#include "vscf_alg_info.h"
#include "vscf_alg_factory.h"
#include "vscf_hash_based_alg_info.h"

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
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_kdf1_alg_id(const vscf_kdf1_t *self) {

    VSCF_ASSERT_PTR(self);
    return vscf_alg_id_KDF1;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_kdf1_produce_alg_info(const vscf_kdf1_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->hash);

    vscf_impl_t *hash_alg_info = vscf_alg_produce_alg_info(self->hash);
    vscf_impl_t *kdf1_alg_info =
            vscf_hash_based_alg_info_impl(vscf_hash_based_alg_info_new_with_members(vscf_alg_id_KDF1, &hash_alg_info));

    return kdf1_alg_info;
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_kdf1_restore_alg_info(vscf_kdf1_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_KDF1);

    const vscf_hash_based_alg_info_t *hash_based_alg_info = (const vscf_hash_based_alg_info_t *)alg_info;

    vscf_impl_t *hash =
            vscf_alg_factory_create_hash_from_info(vscf_hash_based_alg_info_hash_alg_info(hash_based_alg_info));
    vscf_kdf1_release_hash(self);
    vscf_kdf1_take_hash(self, hash);

    return vscf_status_SUCCESS;
}

//
//  Derive key of the requested length from the given data.
//
VSCF_PUBLIC void
vscf_kdf1_derive(vscf_kdf1_t *self, vsc_data_t data, size_t key_len, vsc_buffer_t *key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->hash);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_buffer_is_valid(key));
    VSCF_ASSERT(vsc_buffer_unused_len(key) >= key_len);


    // Get HASH parameters
    size_t digest_len = vscf_hash_digest_len(vscf_hash_api(self->hash));

    // Get KDF parameters
    size_t counter_len = VSCF_CEIL(key_len, digest_len);
    size_t key_left_len = key_len;
    unsigned char counter_string[4] = {0x0};

    // Start hashing
    for (size_t counter = 0; counter < counter_len; ++counter) {
        counter_string[0] = (unsigned char)((counter >> 24) & 255);
        counter_string[1] = (unsigned char)((counter >> 16) & 255);
        counter_string[2] = (unsigned char)((counter >> 8) & 255);
        counter_string[3] = (unsigned char)(counter & 255);

        vscf_hash_start(self->hash);
        vscf_hash_update(self->hash, data);
        vscf_hash_update(self->hash, vsc_data(counter_string, sizeof(counter_string)));

        if (digest_len <= key_left_len) {
            vscf_hash_finish(self->hash, key);
            key_left_len -= digest_len;

        } else {
            vsc_buffer_t *digest = vsc_buffer_new_with_capacity(digest_len);

            vscf_hash_finish(self->hash, digest);
            memcpy(vsc_buffer_unused_bytes(key), vsc_buffer_bytes(digest), key_left_len);
            vsc_buffer_inc_used(key, key_left_len);
            key_left_len = 0;

            vsc_buffer_erase(digest);
            vsc_buffer_destroy(&digest);
        }
    }
}
