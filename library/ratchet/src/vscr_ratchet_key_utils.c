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
//  Utils class for working with keys formats.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_ratchet_key_utils.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_key_utils_defs.h"

#include <virgil/crypto/foundation/vscf_key_asn1_deserializer.h>
#include <ed25519/ed25519.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_hkdf.h>
#include <virgil/crypto/foundation/private/vscf_hkdf_private.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_key_utils_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_key_utils_init_ctx(vscr_ratchet_key_utils_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_key_utils_cleanup_ctx(vscr_ratchet_key_utils_t *self);

//
//  Return size of 'vscr_ratchet_key_utils_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_key_utils_ctx_size(void) {

    return sizeof(vscr_ratchet_key_utils_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_key_utils_init(vscr_ratchet_key_utils_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_key_utils_t));

    self->refcnt = 1;

    vscr_ratchet_key_utils_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_key_utils_cleanup(vscr_ratchet_key_utils_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_ratchet_key_utils_cleanup_ctx(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_key_utils_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_key_utils_t *
vscr_ratchet_key_utils_new(void) {

    vscr_ratchet_key_utils_t *self = (vscr_ratchet_key_utils_t *) vscr_alloc(sizeof (vscr_ratchet_key_utils_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_key_utils_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCR_PUBLIC void
vscr_ratchet_key_utils_delete(vscr_ratchet_key_utils_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    size_t new_counter = old_counter > 0 ? old_counter - 1 : old_counter;
    #if defined(VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        new_counter = old_counter > 0 ? old_counter - 1 : old_counter;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0 || (new_counter == old_counter)) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscr_ratchet_key_utils_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_key_utils_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_key_utils_destroy(vscr_ratchet_key_utils_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_key_utils_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_key_utils_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_key_utils_t *
vscr_ratchet_key_utils_shallow_copy(vscr_ratchet_key_utils_t *self) {

    VSCR_ASSERT_PTR(self);

    #if defined(VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_key_utils_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_key_utils_init_ctx(vscr_ratchet_key_utils_t *self) {

    VSCR_ASSERT_PTR(self);

    self->key_asn1_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(self->key_asn1_deserializer);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_key_utils_cleanup_ctx(vscr_ratchet_key_utils_t *self) {

    VSCR_ASSERT_PTR(self);

    vscf_key_asn1_deserializer_destroy(&self->key_asn1_deserializer);
}

VSCR_PUBLIC vsc_buffer_t *
vscr_ratchet_key_utils_extract_ratchet_public_key(vscr_ratchet_key_utils_t *self, vsc_data_t data, bool ed25519,
        bool curve25519, bool convert_to_curve25519, vscr_error_t *error) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->key_asn1_deserializer);
    VSCR_ASSERT(vsc_data_is_valid(data));

    vscf_error_t error_ctx;
    vscf_error_reset(&error_ctx);

    vsc_buffer_t *result = NULL;

    vscf_raw_key_t *raw_key =
            vscf_key_asn1_deserializer_deserialize_public_key(self->key_asn1_deserializer, data, &error_ctx);

    if (vscf_error_has_error(&error_ctx)) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_KEY_DESERIALIZATION_FAILED);

        goto err;
    }

    if (vscf_raw_key_alg_id(raw_key) == vscf_alg_id_CURVE25519 && curve25519) {
        if (vscf_raw_key_data(raw_key).len != vscr_ratchet_common_hidden_KEY_LEN) {
            VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_KEY_DESERIALIZATION_FAILED);

            goto err;
        }

        result = vsc_buffer_new_with_data(vscf_raw_key_data(raw_key));
    } else if (vscf_raw_key_alg_id(raw_key) == vscf_alg_id_ED25519 && ed25519) {
        if (vscf_raw_key_data(raw_key).len != vscr_ratchet_common_hidden_KEY_LEN) {
            VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_KEY_DESERIALIZATION_FAILED);

            goto err;
        }

        if (convert_to_curve25519) {
            result = vsc_buffer_new_with_capacity(vscr_ratchet_common_hidden_KEY_LEN);

            int curve25519_status =
                    ed25519_pubkey_to_curve25519(vsc_buffer_unused_bytes(result), vscf_raw_key_data(raw_key).bytes);

            if (curve25519_status != 0) {
                VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_CURVE25519);

                vsc_buffer_destroy(&result);

                goto err;
            }

            vsc_buffer_inc_used(result, vscr_ratchet_common_hidden_KEY_LEN);
        } else {
            result = vsc_buffer_new_with_data(vscf_raw_key_data(raw_key));
        }
    } else {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_INVALID_KEY_TYPE);

        goto err;
    }

err:
    vscf_raw_key_destroy(&raw_key);

    return result;
}

VSCR_PUBLIC vsc_buffer_t *
vscr_ratchet_key_utils_extract_ratchet_private_key(vscr_ratchet_key_utils_t *self, vsc_data_t data, bool ed25519,
        bool curve25519, bool convert_to_curve25519, vscr_error_t *error) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->key_asn1_deserializer);
    VSCR_ASSERT(vsc_data_is_valid(data));

    vscf_error_t error_ctx;
    vscf_error_reset(&error_ctx);

    VSCR_ASSERT(ed25519 || curve25519);
    VSCR_ASSERT(ed25519 || !(curve25519 && convert_to_curve25519));

    vsc_buffer_t *result = NULL;

    vscf_raw_key_t *raw_key =
            vscf_key_asn1_deserializer_deserialize_private_key(self->key_asn1_deserializer, data, &error_ctx);

    if (vscf_error_has_error(&error_ctx)) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_KEY_DESERIALIZATION_FAILED);

        goto err;
    }

    if (vscf_raw_key_alg_id(raw_key) == vscf_alg_id_CURVE25519 && curve25519) {
        if (vscf_raw_key_data(raw_key).len != vscr_ratchet_common_hidden_KEY_LEN) {
            VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_INVALID_KEY_TYPE);

            goto err;
        }

        result = vsc_buffer_new_with_data(vscf_raw_key_data(raw_key));
        vsc_buffer_make_secure(result);
    } else if (vscf_raw_key_alg_id(raw_key) == vscf_alg_id_ED25519 && ed25519) {
        if (vscf_raw_key_data(raw_key).len != vscr_ratchet_common_hidden_KEY_LEN) {
            VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_KEY_DESERIALIZATION_FAILED);

            goto err;
        }

        if (convert_to_curve25519) {
            result = vsc_buffer_new_with_capacity(vscr_ratchet_common_hidden_KEY_LEN);
            vsc_buffer_make_secure(result);

            int curve25519_status =
                    ed25519_key_to_curve25519(vsc_buffer_unused_bytes(result), vscf_raw_key_data(raw_key).bytes);

            if (curve25519_status != 0) {
                VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_CURVE25519);

                vsc_buffer_destroy(&result);

                goto err;
            }

            vsc_buffer_inc_used(result, vscr_ratchet_common_hidden_KEY_LEN);
        } else {
            result = vsc_buffer_new_with_data(vscf_raw_key_data(raw_key));
        }
    } else {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_INVALID_KEY_TYPE);

        goto err;
    }

err:
    vscf_raw_key_destroy(&raw_key);

    return result;
}

VSCR_PUBLIC vscr_ratchet_chain_key_t *
vscr_ratchet_key_utils_derive_participant_key(
        const vscr_ratchet_symmetric_key_t root_key, const vscr_ratchet_participant_id_t participant_id) {

    vscf_hkdf_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    vscr_ratchet_chain_key_t *chain_key = vscr_ratchet_chain_key_new();

    vsc_buffer_t buffer;
    vsc_buffer_init(&buffer);
    vsc_buffer_use(&buffer, chain_key->key, vscr_ratchet_common_hidden_SHARED_KEY_LEN);

    vscf_hkdf_set_info(hkdf, vsc_data(participant_id, vscr_ratchet_common_PARTICIPANT_ID_LEN));
    // FIXME
    vscf_hkdf_derive(hkdf, vsc_data(root_key, vscr_ratchet_common_hidden_SHARED_KEY_LEN),
            vscr_ratchet_common_hidden_SHARED_KEY_LEN, &buffer);

    vsc_buffer_delete(&buffer);

    vscf_hkdf_destroy(&hkdf);

    return chain_key;
}
