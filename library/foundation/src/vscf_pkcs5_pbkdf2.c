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
//  This module contains 'pkcs5 pbkdf2' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_pkcs5_pbkdf2.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_alg.h"
#include "vscf_alg_info.h"
#include "vscf_alg_factory.h"
#include "vscf_hmac.h"
#include "vscf_sha384.h"
#include "vscf_salted_kdf_alg_info.h"
#include "vscf_mac.h"
#include "vscf_pkcs5_pbkdf2_defs.h"
#include "vscf_pkcs5_pbkdf2_internal.h"

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
//  Note, this method is called automatically when method vscf_pkcs5_pbkdf2_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_pkcs5_pbkdf2_init_ctx(vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2) {

    VSCF_ASSERT_PTR(pkcs5_pbkdf2);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_pkcs5_pbkdf2_cleanup_ctx(vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2) {

    VSCF_ASSERT_PTR(pkcs5_pbkdf2);
    vsc_buffer_destroy(&pkcs5_pbkdf2->salt);
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_error_t
vscf_pkcs5_pbkdf2_setup_defaults(vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2) {

    VSCF_ASSERT_PTR(pkcs5_pbkdf2);

    if (NULL == pkcs5_pbkdf2->hmac) {
        vscf_impl_t *hash = vscf_sha384_impl(vscf_sha384_new());
        vscf_hmac_t *hmac = vscf_hmac_new();
        vscf_hmac_take_hash(hmac, hash);
        pkcs5_pbkdf2->hmac = vscf_hmac_impl(hmac);
    }

    return vscf_SUCCESS;
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_pkcs5_pbkdf2_alg_id(const vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2) {

    VSCF_ASSERT_PTR(pkcs5_pbkdf2);

    return vscf_alg_id_PKCS5_PBKDF2;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_pkcs5_pbkdf2_produce_alg_info(const vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2) {

    VSCF_ASSERT_PTR(pkcs5_pbkdf2);
    VSCF_ASSERT_PTR(pkcs5_pbkdf2->hmac);
    VSCF_ASSERT_PTR(pkcs5_pbkdf2->salt);

    vscf_impl_t *hmac_alg_info = vscf_alg_produce_alg_info(pkcs5_pbkdf2->hmac);
    vscf_impl_t *pbkdf2_alg_info =
            vscf_salted_kdf_alg_info_impl(vscf_salted_kdf_alg_info_new_with_members(vscf_alg_id_PKCS5_PBKDF2,
                    hmac_alg_info, vsc_buffer_data(pkcs5_pbkdf2->salt), pkcs5_pbkdf2->iteration_count));

    vscf_impl_destroy(&hmac_alg_info);

    return pbkdf2_alg_info;
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_error_t
vscf_pkcs5_pbkdf2_restore_alg_info(vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(pkcs5_pbkdf2);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_PKCS5_PBKDF2);

    const vscf_salted_kdf_alg_info_t *salted_kdf_alg_info = (const vscf_salted_kdf_alg_info_t *)alg_info;

    vscf_impl_t *hmac = vscf_alg_factory_create_hash_alg(vscf_salted_kdf_alg_info_hash_alg_info(salted_kdf_alg_info));
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_HMAC);

    vscf_pkcs5_pbkdf2_release_hmac(pkcs5_pbkdf2);
    vscf_pkcs5_pbkdf2_take_hmac(pkcs5_pbkdf2, hmac);
    vscf_pkcs5_pbkdf2_reset(pkcs5_pbkdf2, vscf_salted_kdf_alg_info_salt(salted_kdf_alg_info),
            vscf_salted_kdf_alg_info_iteration_count(salted_kdf_alg_info));

    return vscf_SUCCESS;
}

//
//  Derive key of the requested length from the given data.
//
VSCF_PUBLIC void
vscf_pkcs5_pbkdf2_derive(vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2, vsc_data_t data, size_t key_len, vsc_buffer_t *key) {

    VSCF_ASSERT_PTR(pkcs5_pbkdf2);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT_PTR(vsc_buffer_is_valid(key));
    VSCF_ASSERT(vsc_buffer_unused_len(key) >= key_len);
    VSCF_ASSERT_PTR(pkcs5_pbkdf2->hmac);

    size_t key_len_left = key_len;
    size_t hash_len = vscf_mac_digest_len(pkcs5_pbkdf2->hmac);
    size_t hash_count = VSCF_CEIL(key_len, hash_len);
    byte counter_string[4] = {0x0};

    vsc_buffer_t *u_1 = vsc_buffer_new_with_capacity(hash_len);
    vsc_buffer_t *u_2 = vsc_buffer_new_with_capacity(hash_len);

    for (size_t counter = 1; counter < hash_count + 1; ++counter) {
        counter_string[0] = (byte)((counter >> 24) & 255);
        counter_string[1] = (byte)((counter >> 16) & 255);
        counter_string[2] = (byte)((counter >> 8) & 255);
        counter_string[3] = (byte)(counter & 255);

        // F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c

        // U_1 = PRF (P, S || INT (i)) ,
        // U_2 = PRF (P, U_1)

        //
        //  Calculate U_1, that will be accumulator.
        //
        vsc_buffer_reset(u_1);
        vscf_mac_start(pkcs5_pbkdf2->hmac, data);
        if (pkcs5_pbkdf2->salt) {
            vscf_mac_update(pkcs5_pbkdf2->hmac, vsc_buffer_data(pkcs5_pbkdf2->salt));
        }
        vscf_mac_update(pkcs5_pbkdf2->hmac, vsc_data(counter_string, 4));
        vscf_mac_finish(pkcs5_pbkdf2->hmac, u_1);
        vsc_data_t u_1_data = vsc_buffer_data(u_1);
        byte *u_1_bytes = vsc_buffer_begin(u_1);

        //
        //  Calculate U_2.
        //
        vsc_buffer_reset(u_2);
        vsc_buffer_write_data(u_2, u_1_data);
        for (size_t iteration = 1; iteration < pkcs5_pbkdf2->iteration_count; ++iteration) {
            vsc_data_t u_2_data = vsc_buffer_data(u_2);
            vscf_mac_start(pkcs5_pbkdf2->hmac, data);
            vscf_mac_update(pkcs5_pbkdf2->hmac, u_2_data);
            vsc_buffer_reset(u_2);
            vscf_mac_finish(pkcs5_pbkdf2->hmac, u_2);

            //
            //  Calculate U_1 xor U_2.
            //
            VSCF_ASSERT(u_1_data.len == u_2_data.len);
            for (size_t i = 0; i < u_1_data.len; ++i) {
                u_1_bytes[i] = u_1_data.bytes[i] ^ u_2_data.bytes[i];
            }
        }

        //
        //  Write derived key.
        //
        VSCF_ASSERT(key_len_left != 0);
        if (key_len_left >= u_1_data.len) {
            vsc_buffer_write_data(key, u_1_data);
            key_len_left -= u_1_data.len;
        } else {
            vsc_buffer_write_data(key, vsc_data_slice_beg(u_1_data, 0, key_len_left));
            key_len_left = 0;
        }
    }

    vsc_buffer_destroy(&u_1);
    vsc_buffer_destroy(&u_2);
}

//
//  Prepare algorithm to derive new key.
//
VSCF_PUBLIC void
vscf_pkcs5_pbkdf2_reset(vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2, vsc_data_t salt, size_t iteration_count) {

    VSCF_ASSERT_PTR(pkcs5_pbkdf2);
    VSCF_ASSERT(vsc_data_is_valid(salt));

    vsc_buffer_destroy(&pkcs5_pbkdf2->salt);
    if (!vsc_data_is_empty(salt)) {
        pkcs5_pbkdf2->salt = vsc_buffer_new_with_data(salt);
    }
    pkcs5_pbkdf2->iteration_count = iteration_count;
}

//
//  Setup application specific information (optional).
//  Can be empty.
//
VSCF_PUBLIC void
vscf_pkcs5_pbkdf2_set_info(vscf_pkcs5_pbkdf2_t *pkcs5_pbkdf2, vsc_data_t info) {

    VSCF_ASSERT_PTR(pkcs5_pbkdf2);
    VSCF_UNUSED(info);
}
