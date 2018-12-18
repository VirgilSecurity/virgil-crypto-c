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
//  This module contains 'hkdf' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_hkdf.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_hash_stream.h"
#include "vscf_hkdf_defs.h"
#include "vscf_hkdf_internal.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Private integral constants.
//
enum {
    vscf_hkdf_HASH_COUNTER_MAX = 255
};

//
//  Extracts fixed-length pseudorandom key from keying material.
//
static void
vscf_hkdf_extract(vscf_hkdf_t *hkdf, vsc_data_t data, vsc_data_t salt, vsc_buffer_t *pr_key);

//
//  Expands the pseudorandom key to the desired length.
//
static void
vscf_hkdf_expand(vscf_hkdf_t *hkdf, vsc_buffer_t *pr_key, vsc_data_t info, vsc_buffer_t *key, size_t key_len);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_hkdf_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_hkdf_init_ctx(vscf_hkdf_t *hkdf) {

    VSCF_ASSERT_PTR(hkdf);

    vscf_hmac_init(&hkdf->hmac);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_hkdf_cleanup_ctx(vscf_hkdf_t *hkdf) {

    VSCF_ASSERT_PTR(hkdf);

    vscf_hmac_cleanup(&hkdf->hmac);
}

//
//  Extracts fixed-length pseudorandom key from keying material.
//
static void
vscf_hkdf_extract(vscf_hkdf_t *hkdf, vsc_data_t data, vsc_data_t salt, vsc_buffer_t *pr_key) {

    vscf_hmac_start(&hkdf->hmac, salt);
    vscf_hmac_update(&hkdf->hmac, data);
    vscf_hmac_finish(&hkdf->hmac, pr_key);
}

//
//  Expands the pseudorandom key to the desired length.
//
static void
vscf_hkdf_expand(vscf_hkdf_t *hkdf, vsc_buffer_t *pr_key, vsc_data_t info, vsc_buffer_t *key, size_t key_len) {

    unsigned char counter = 0x00;
    size_t hmac_len = vscf_hmac_digest_len(&hkdf->hmac);

    vscf_hmac_start(&hkdf->hmac, vsc_buffer_data(pr_key));
    vsc_data_t previous_mac = vsc_data_empty();
    do {
        ++counter;
        size_t need = key_len - ((counter - 1) * hmac_len);
        vscf_hmac_reset(&hkdf->hmac);
        vscf_hmac_update(&hkdf->hmac, previous_mac);
        vscf_hmac_update(&hkdf->hmac, info);
        vscf_hmac_update(&hkdf->hmac, vsc_data(&counter, 1));

        if (need >= hmac_len) {
            vscf_hmac_finish(&hkdf->hmac, key);
            previous_mac = vsc_data(vsc_buffer_unused_bytes(key) - hmac_len, hmac_len);
        } else {
            vsc_buffer_reset(pr_key);
            vscf_hmac_finish(&hkdf->hmac, pr_key);
            memcpy(vsc_buffer_unused_bytes(key), vsc_buffer_bytes(pr_key), need);
            vsc_buffer_inc_used(key, need);
        }
    } while (counter * hmac_len < key_len);
}

//
//  Derive key of the requested length from the given data, salt and info.
//
VSCF_PUBLIC void
vscf_hkdf_derive(
        vscf_hkdf_t *hkdf, vsc_data_t data, vsc_data_t salt, vsc_data_t info, vsc_buffer_t *key, size_t key_len) {

    VSCF_ASSERT_PTR(hkdf);
    VSCF_ASSERT_PTR(hkdf->hash);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_data_is_valid(salt));
    VSCF_ASSERT(vsc_data_is_valid(info));
    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT(key_len > 0);
    VSCF_ASSERT(vsc_buffer_unused_len(key) >= key_len);

    vscf_hmac_release_hash(&hkdf->hmac);
    vscf_hmac_use_hash(&hkdf->hmac, hkdf->hash);

    size_t pr_key_len = vscf_hmac_digest_len(&hkdf->hmac);
    VSCF_ASSERT_OPT(key_len <= vscf_hkdf_HASH_COUNTER_MAX * pr_key_len);

    vsc_buffer_t *pr_key = vsc_buffer_new_with_capacity(pr_key_len);

    vscf_hkdf_extract(hkdf, data, salt, pr_key);
    vscf_hkdf_expand(hkdf, pr_key, info, key, key_len);

    vsc_buffer_destroy(&pr_key);
}
