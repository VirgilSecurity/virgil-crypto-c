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
#include "vscf_alg.h"
#include "vscf_alg_info.h"
#include "vscf_alg_factory.h"
#include "vscf_hash_based_alg_info.h"
#include "vscf_hash.h"
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
vscf_hkdf_extract(vscf_hkdf_t *self, vsc_data_t data, vsc_buffer_t *pr_key);

//
//  Expands the pseudorandom key to the desired length.
//
static void
vscf_hkdf_expand(vscf_hkdf_t *self, vsc_buffer_t *pr_key, vsc_buffer_t *key, size_t key_len);


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
vscf_hkdf_init_ctx(vscf_hkdf_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_hmac_init(&self->hmac);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_hkdf_cleanup_ctx(vscf_hkdf_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_hmac_cleanup(&self->hmac);
    vsc_buffer_destroy(&self->salt);
    vsc_buffer_destroy(&self->context_info);
}

//
//  Extracts fixed-length pseudorandom key from keying material.
//
static void
vscf_hkdf_extract(vscf_hkdf_t *self, vsc_data_t data, vsc_buffer_t *pr_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(pr_key);
    VSCF_ASSERT(vsc_buffer_is_valid(pr_key));

    if (self->salt) {
        VSCF_ASSERT(vsc_buffer_is_valid(self->salt));
        vscf_hmac_start(&self->hmac, vsc_buffer_data(self->salt));
    } else {
        vscf_hmac_start(&self->hmac, vsc_data_empty());
    }
    vscf_hmac_update(&self->hmac, data);
    vscf_hmac_finish(&self->hmac, pr_key);
}

//
//  Expands the pseudorandom key to the desired length.
//
static void
vscf_hkdf_expand(vscf_hkdf_t *self, vsc_buffer_t *pr_key, vsc_buffer_t *key, size_t key_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(pr_key);
    VSCF_ASSERT(vsc_buffer_is_valid(pr_key));
    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT(vsc_buffer_is_valid(key));

    unsigned char counter = 0x00;
    size_t hmac_len = vscf_hmac_digest_len(&self->hmac);

    vscf_hmac_start(&self->hmac, vsc_buffer_data(pr_key));
    vsc_data_t previous_mac = vsc_data_empty();
    do {
        ++counter;
        size_t need = key_len - ((counter - 1) * hmac_len);
        vscf_hmac_reset(&self->hmac);
        vscf_hmac_update(&self->hmac, previous_mac);
        if (self->context_info != NULL) {
            vscf_hmac_update(&self->hmac, vsc_buffer_data(self->context_info));
        }
        vscf_hmac_update(&self->hmac, vsc_data(&counter, 1));

        if (need >= hmac_len) {
            vscf_hmac_finish(&self->hmac, key);
            previous_mac = vsc_data(vsc_buffer_unused_bytes(key) - hmac_len, hmac_len);
        } else {
            vsc_buffer_reset(pr_key);
            vscf_hmac_finish(&self->hmac, pr_key);
            memcpy(vsc_buffer_unused_bytes(key), vsc_buffer_bytes(pr_key), need);
            vsc_buffer_inc_used(key, need);
        }
    } while (counter * hmac_len < key_len);
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_hkdf_alg_id(const vscf_hkdf_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_alg_id_HKDF;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_hkdf_produce_alg_info(const vscf_hkdf_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->hash);

    vscf_impl_t *hash_alg_info = vscf_alg_produce_alg_info(self->hash);
    vscf_impl_t *hkdf_alg_info =
            vscf_hash_based_alg_info_impl(vscf_hash_based_alg_info_new_with_members(vscf_alg_id_HKDF, &hash_alg_info));

    return hkdf_alg_info;
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_error_t
vscf_hkdf_restore_alg_info(vscf_hkdf_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_HKDF);

    const vscf_hash_based_alg_info_t *hash_based_alg_info = (const vscf_hash_based_alg_info_t *)alg_info;

    vscf_impl_t *hash = vscf_alg_factory_create_hash_alg(vscf_hash_based_alg_info_hash_alg_info(hash_based_alg_info));
    vscf_hkdf_release_hash(self);
    vscf_hkdf_take_hash(self, hash);

    return vscf_SUCCESS;
}

//
//  Derive key of the requested length from the given data.
//
VSCF_PUBLIC void
vscf_hkdf_derive(vscf_hkdf_t *self, vsc_data_t data, size_t key_len, vsc_buffer_t *key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->hash);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT(key_len > 0);
    VSCF_ASSERT(vsc_buffer_unused_len(key) >= key_len);

    vscf_hmac_release_hash(&self->hmac);
    vscf_hmac_use_hash(&self->hmac, self->hash);

    size_t pr_key_len = vscf_hmac_digest_len(&self->hmac);
    VSCF_ASSERT_OPT(key_len <= vscf_hkdf_HASH_COUNTER_MAX * pr_key_len);

    vsc_buffer_t *pr_key = vsc_buffer_new_with_capacity(pr_key_len);

    vscf_hkdf_extract(self, data, pr_key);
    vscf_hkdf_expand(self, pr_key, key, key_len);

    vsc_buffer_destroy(&pr_key);
}

//
//  Prepare algorithm to derive new key.
//
VSCF_PUBLIC void
vscf_hkdf_reset(vscf_hkdf_t *self, vsc_data_t salt, size_t iteration_count) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(salt));
    VSCF_UNUSED(iteration_count);

    vsc_buffer_destroy(&self->salt);
    if (!vsc_data_is_empty(salt)) {
        self->salt = vsc_buffer_new_with_data(salt);
    }
}

//
//  Setup application specific information (optional).
//  Can be empty.
//
VSCF_PUBLIC void
vscf_hkdf_set_info(vscf_hkdf_t *self, vsc_data_t info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(info));

    vsc_buffer_destroy(&self->context_info);

    if (!vsc_data_is_empty(info)) {
        self->context_info = vsc_buffer_new_with_data(info);
    }
}
