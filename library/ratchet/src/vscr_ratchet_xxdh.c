//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_ratchet_xxdh.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_xxdh_defs.h"
#include "vscr_ratchet_common_hidden.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_private_key.h>
#include <virgil/crypto/foundation/vscf_public_key.h>
#include <ed25519/ed25519.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_hkdf.h>

// clang-format on
//  @end


// clang-format off

// VIRGIL_RATCHET_KDF_ROOT_INFO
static const uint8_t ratchet_kdf_root_info[] = {
        0x56, 0x49, 0x52, 0x47, 0x49, 0x4c, 0x5f, 0x52,
        0x41, 0x54, 0x43, 0x48, 0x45, 0x54, 0x5f, 0x4b,
        0x44, 0x46, 0x5f, 0x52, 0x4f, 0x4f, 0x54, 0x5f,
        0x49, 0x4e, 0x46, 0x4f
};

// clang-format on


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_xxdh_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_xxdh_init_ctx(vscr_ratchet_xxdh_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_xxdh_cleanup_ctx(vscr_ratchet_xxdh_t *self);

//
//  This method is called when interface 'random' was setup.
//
static void
vscr_ratchet_xxdh_did_setup_rng(vscr_ratchet_xxdh_t *self);

//
//  This method is called when interface 'random' was released.
//
static void
vscr_ratchet_xxdh_did_release_rng(vscr_ratchet_xxdh_t *self);

//
//  Return size of 'vscr_ratchet_xxdh_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_xxdh_ctx_size(void) {

    return sizeof(vscr_ratchet_xxdh_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_xxdh_init(vscr_ratchet_xxdh_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_xxdh_t));

    self->refcnt = 1;

    vscr_ratchet_xxdh_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_xxdh_cleanup(vscr_ratchet_xxdh_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_ratchet_xxdh_cleanup_ctx(self);

    vscr_ratchet_xxdh_release_rng(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_xxdh_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_xxdh_t *
vscr_ratchet_xxdh_new(void) {

    vscr_ratchet_xxdh_t *self = (vscr_ratchet_xxdh_t *) vscr_alloc(sizeof (vscr_ratchet_xxdh_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_xxdh_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCR_PUBLIC void
vscr_ratchet_xxdh_delete(vscr_ratchet_xxdh_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCR_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCR_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscr_ratchet_xxdh_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_xxdh_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_xxdh_destroy(vscr_ratchet_xxdh_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_xxdh_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_xxdh_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_xxdh_t *
vscr_ratchet_xxdh_shallow_copy(vscr_ratchet_xxdh_t *self) {

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

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCR_PUBLIC void
vscr_ratchet_xxdh_use_rng(vscr_ratchet_xxdh_t *self, vscf_impl_t *rng) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT(self->rng == NULL);

    VSCR_ASSERT(vscf_random_is_implemented(rng));

    self->rng = vscf_impl_shallow_copy(rng);

    vscr_ratchet_xxdh_did_setup_rng(self);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_xxdh_take_rng(vscr_ratchet_xxdh_t *self, vscf_impl_t *rng) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT(self->rng == NULL);

    VSCR_ASSERT(vscf_random_is_implemented(rng));

    self->rng = rng;

    vscr_ratchet_xxdh_did_setup_rng(self);
}

//
//  Release dependency to the interface 'random'.
//
VSCR_PUBLIC void
vscr_ratchet_xxdh_release_rng(vscr_ratchet_xxdh_t *self) {

    VSCR_ASSERT_PTR(self);

    vscf_impl_destroy(&self->rng);

    vscr_ratchet_xxdh_did_release_rng(self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_xxdh_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_xxdh_init_ctx(vscr_ratchet_xxdh_t *self) {

    VSCR_ASSERT_PTR(self);

    self->round5 = vscf_round5_new();
    self->falcon = vscf_falcon_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_xxdh_cleanup_ctx(vscr_ratchet_xxdh_t *self) {

    VSCR_ASSERT_PTR(self);

    vscf_round5_destroy(&self->round5);
    vscf_falcon_destroy(&self->falcon);
}

//
//  This method is called when interface 'random' was setup.
//
static void
vscr_ratchet_xxdh_did_setup_rng(vscr_ratchet_xxdh_t *self) {

    if (self->rng != NULL) {
        vscf_round5_use_random(self->round5, self->rng);
        vscf_falcon_use_random(self->falcon, self->rng);
    }
}

//
//  This method is called when interface 'random' was released.
//
static void
vscr_ratchet_xxdh_did_release_rng(vscr_ratchet_xxdh_t *self) {

    VSCR_ASSERT_PTR(self);
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_xxdh_encapsulate_pqc_key(vscr_ratchet_xxdh_t *self, const vscf_impl_t *public_key,
        vsc_buffer_t **encapsulated_key_ref, vsc_buffer_t *shared_secret) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->round5);
    VSCR_ASSERT_PTR(public_key);
    VSCR_ASSERT_PTR(encapsulated_key_ref);
    VSCR_ASSERT_PTR(shared_secret);

    size_t len = vscf_round5_kem_encapsulated_key_len(self->round5, NULL);
    *encapsulated_key_ref = vsc_buffer_new_with_capacity(len);
    vscf_status_t f_status =
            vscf_round5_kem_encapsulate(self->round5, public_key, shared_secret, *encapsulated_key_ref);

    if (f_status != vscf_status_SUCCESS) {
        // FIXME
        return vscr_status_ERROR_CURVE25519;
    }

    return vscr_status_SUCCESS;
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_xxdh_decapsulate_pqc_key(vscr_ratchet_xxdh_t *self, const vscf_impl_t *private_key,
        vsc_data_t encapsulated_key, vsc_buffer_t *shared_secret) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->round5);
    VSCR_ASSERT_PTR(private_key);
    VSCR_ASSERT_PTR(vsc_data_is_valid(encapsulated_key));
    VSCR_ASSERT_PTR(shared_secret);

    vscf_status_t f_status = vscf_round5_kem_decapsulate(self->round5, encapsulated_key, private_key, shared_secret);

    if (f_status != vscf_status_SUCCESS) {
        // FIXME
        return vscr_status_ERROR_CURVE25519;
    }

    return vscr_status_SUCCESS;
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_xxdh_compute_initiator_xxdh_secret(vscr_ratchet_xxdh_t *self,
        const vscr_ratchet_private_key_t sender_identity_private_key_first,
        const vscr_ratchet_public_key_t receiver_identity_public_key_first,
        const vscr_ratchet_public_key_t receiver_long_term_public_key_first, bool receiver_has_one_time_key,
        const vscr_ratchet_public_key_t receiver_one_time_public_key_first,
        vscr_ratchet_public_key_t ephemeral_public_key_first,
        const vscf_impl_t *sender_identity_private_key_second_signer,
        const vscf_impl_t *receiver_identity_public_key_second, const vscf_impl_t *receiver_long_term_public_key_second,
        const vscf_impl_t *receiver_one_time_public_key_second, vsc_buffer_t **encapsulated_key_1_ref,
        vsc_buffer_t **encapsulated_key_2_ref, vsc_buffer_t **encapsulated_key_3_ref,
        vsc_buffer_t **decapsulated_keys_signature_ref, vscr_ratchet_symmetric_key_t shared_key) {

    vsc_buffer_t *shared_secret = vsc_buffer_new_with_capacity(
            4 * vscr_ratchet_common_hidden_SHARED_KEY_LEN + 4 * vscf_round5_kem_shared_key_len(self->round5, NULL));
    vsc_buffer_make_secure(shared_secret);

    vscr_status_t status = vscr_status_SUCCESS;

    vscr_ratchet_private_key_t ephemeral_private_key_first;

    vsc_buffer_t buff;
    vsc_buffer_init(&buff);
    vsc_buffer_use(&buff, ephemeral_private_key_first, sizeof(ephemeral_private_key_first));

    vscf_status_t f_status = vscf_random(self->rng, sizeof(ephemeral_private_key_first), &buff);

    vsc_buffer_delete(&buff);

    if (f_status != vscf_status_SUCCESS) {
        status = vscr_status_ERROR_RNG_FAILED;
        goto err;
    }

    int curve_status = curve25519_get_pubkey(ephemeral_public_key_first, ephemeral_private_key_first);

    if (curve_status != 0) {
        status = vscr_status_ERROR_CURVE25519;
        goto err;
    }

    curve_status = curve25519_key_exchange(vsc_buffer_unused_bytes(shared_secret), receiver_long_term_public_key_first,
            sender_identity_private_key_first);
    vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

    if (curve_status != 0) {
        status = vscr_status_ERROR_CURVE25519;
        goto err;
    }

    curve_status = curve25519_key_exchange(
            vsc_buffer_unused_bytes(shared_secret), receiver_identity_public_key_first, ephemeral_private_key_first);
    vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

    if (curve_status != 0) {
        status = vscr_status_ERROR_CURVE25519;
        goto err;
    }

    curve_status = curve25519_key_exchange(
            vsc_buffer_unused_bytes(shared_secret), receiver_long_term_public_key_first, ephemeral_private_key_first);
    vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

    if (curve_status != 0) {
        status = vscr_status_ERROR_CURVE25519;
        goto err;
    }

    if (receiver_has_one_time_key) {
        curve_status = curve25519_key_exchange(vsc_buffer_unused_bytes(shared_secret),
                receiver_one_time_public_key_first, ephemeral_private_key_first);
        vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

        if (curve_status != 0) {
            status = vscr_status_ERROR_CURVE25519;
            goto err;
        }
    }

    status = vscr_ratchet_xxdh_compute_initiator_pqc_shared_secret(self, sender_identity_private_key_second_signer,
            receiver_identity_public_key_second, receiver_long_term_public_key_second,
            receiver_one_time_public_key_second, encapsulated_key_1_ref, encapsulated_key_2_ref, encapsulated_key_3_ref,
            decapsulated_keys_signature_ref, shared_secret);

    if (status != vscr_status_SUCCESS) {
        goto err;
    }

    vscr_ratchet_xxdh_derive_key(vsc_buffer_data(shared_secret), shared_key);

err:
    vscr_zeroize(ephemeral_private_key_first, sizeof(ephemeral_private_key_first));
    vsc_buffer_destroy(&shared_secret);

    return status;
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_xxdh_compute_initiator_pqc_shared_secret(vscr_ratchet_xxdh_t *self,
        const vscf_impl_t *sender_identity_private_key_second_signer,
        const vscf_impl_t *receiver_identity_public_key_second, const vscf_impl_t *receiver_long_term_public_key_second,
        const vscf_impl_t *receiver_one_time_public_key_second, vsc_buffer_t **encapsulated_key_1_ref,
        vsc_buffer_t **encapsulated_key_2_ref, vsc_buffer_t **encapsulated_key_3_ref,
        vsc_buffer_t **decapsulated_keys_signature_ref, vsc_buffer_t *shared_secret) {

    vscr_status_t status = vscr_status_SUCCESS;

    size_t pqc_begin_index = vsc_buffer_len(shared_secret);

    if (receiver_identity_public_key_second != NULL) {
        status = vscr_ratchet_xxdh_encapsulate_pqc_key(
                self, receiver_identity_public_key_second, encapsulated_key_1_ref, shared_secret);

        if (status != vscr_status_SUCCESS) {
            goto err;
        }
    }

    if (receiver_long_term_public_key_second != NULL) {
        status = vscr_ratchet_xxdh_encapsulate_pqc_key(
                self, receiver_long_term_public_key_second, encapsulated_key_2_ref, shared_secret);

        if (status != vscr_status_SUCCESS) {
            goto err;
        }
    }

    if (receiver_one_time_public_key_second != NULL) {
        status = vscr_ratchet_xxdh_encapsulate_pqc_key(
                self, receiver_one_time_public_key_second, encapsulated_key_3_ref, shared_secret);

        if (status != vscr_status_SUCCESS) {
            goto err;
        }
    }

    if (sender_identity_private_key_second_signer != NULL) {
        size_t length = vsc_buffer_len(shared_secret);

        vsc_data_t pqc_shared_secret =
                vsc_data_slice_beg(vsc_buffer_data(shared_secret), pqc_begin_index, length - pqc_begin_index);
        VSCR_ASSERT(!vsc_data_is_empty(pqc_shared_secret));

        vsc_buffer_t *hash = vsc_buffer_new_with_capacity(vscf_sha512_DIGEST_LEN);
        vscf_sha512_hash(pqc_shared_secret, hash);

        size_t signature_len = vscf_falcon_signature_len(self->falcon, sender_identity_private_key_second_signer);

        *decapsulated_keys_signature_ref = vsc_buffer_new_with_capacity(signature_len);
        vscf_status_t f_status = vscf_falcon_sign_hash(self->falcon, sender_identity_private_key_second_signer,
                vscf_alg_id_SHA512, vsc_buffer_data(hash), *decapsulated_keys_signature_ref);

        vsc_buffer_destroy(&hash);

        if (f_status != vscf_status_SUCCESS) {
            // FIXME
            status = vscr_status_ERROR_CURVE25519;
            goto err;
        }
    }

err:
    return status;
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_xxdh_compute_responder_xxdh_secret(vscr_ratchet_xxdh_t *self,
        const vscr_ratchet_public_key_t sender_identity_public_key_first,
        const vscr_ratchet_private_key_t receiver_identity_private_key_first,
        const vscr_ratchet_private_key_t receiver_long_term_private_key_first, bool receiver_has_one_time_key,
        const vscr_ratchet_private_key_t receiver_one_time_private_key_first,
        const vscr_ratchet_public_key_t sender_ephemeral_public_key_first,
        const vscf_impl_t *sender_identity_public_key_second_verifier,
        const vscf_impl_t *receiver_identity_private_key_second,
        const vscf_impl_t *receiver_long_term_private_key_second,
        const vscf_impl_t *receiver_one_time_private_key_second, vsc_data_t encapsulated_key_1,
        vsc_data_t encapsulated_key_2, vsc_data_t encapsulated_key_3, vsc_data_t decapsulated_keys_signature,
        vscr_ratchet_symmetric_key_t shared_key) {

    vsc_buffer_t *shared_secret = vsc_buffer_new_with_capacity(
            4 * vscr_ratchet_common_hidden_SHARED_KEY_LEN + 4 * vscf_round5_kem_shared_key_len(self->round5, NULL));
    vsc_buffer_make_secure(shared_secret);

    vscr_status_t status = vscr_status_SUCCESS;

    int curve_status = curve25519_key_exchange(vsc_buffer_unused_bytes(shared_secret), sender_identity_public_key_first,
            receiver_long_term_private_key_first);
    vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

    if (curve_status != 0) {
        status = vscr_status_ERROR_CURVE25519;
        goto err;
    }

    curve_status = curve25519_key_exchange(vsc_buffer_unused_bytes(shared_secret), sender_ephemeral_public_key_first,
            receiver_identity_private_key_first);
    vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

    if (curve_status != 0) {
        status = vscr_status_ERROR_CURVE25519;
        goto err;
    }

    curve_status = curve25519_key_exchange(vsc_buffer_unused_bytes(shared_secret), sender_ephemeral_public_key_first,
            receiver_long_term_private_key_first);
    vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

    if (curve_status != 0) {
        status = vscr_status_ERROR_CURVE25519;
        goto err;
    }

    if (receiver_has_one_time_key) {
        curve_status = curve25519_key_exchange(vsc_buffer_unused_bytes(shared_secret),
                sender_ephemeral_public_key_first, receiver_one_time_private_key_first);
        vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

        if (curve_status != 0) {
            status = vscr_status_ERROR_CURVE25519;
            goto err;
        }
    }

    status = vscr_ratchet_xxdh_compute_responder_pqc_shared_secret(self, sender_identity_public_key_second_verifier,
            receiver_identity_private_key_second, receiver_long_term_private_key_second,
            receiver_one_time_private_key_second, encapsulated_key_1, encapsulated_key_2, encapsulated_key_3,
            decapsulated_keys_signature, shared_secret);

    if (status != vscr_status_SUCCESS) {
        goto err;
    }

    vscr_ratchet_xxdh_derive_key(vsc_buffer_data(shared_secret), shared_key);

err:
    vsc_buffer_destroy(&shared_secret);

    return status;
}

//
//  Z
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_xxdh_compute_responder_pqc_shared_secret(vscr_ratchet_xxdh_t *self,
        const vscf_impl_t *sender_identity_public_key_second_verifier,
        const vscf_impl_t *receiver_identity_private_key_second,
        const vscf_impl_t *receiver_long_term_private_key_second,
        const vscf_impl_t *receiver_one_time_private_key_second, vsc_data_t encapsulated_key_1,
        vsc_data_t encapsulated_key_2, vsc_data_t encapsulated_key_3, vsc_data_t decapsulated_keys_signature,
        vsc_buffer_t *shared_secret) {

    vscr_status_t status = vscr_status_SUCCESS;

    size_t pqc_begin_index = vsc_buffer_len(shared_secret);

    if (receiver_identity_private_key_second != NULL) {
        status = vscr_ratchet_xxdh_decapsulate_pqc_key(
                self, receiver_identity_private_key_second, encapsulated_key_1, shared_secret);

        if (status != vscr_status_SUCCESS) {
            goto err;
        }
    }

    if (receiver_long_term_private_key_second != NULL) {
        status = vscr_ratchet_xxdh_decapsulate_pqc_key(
                self, receiver_long_term_private_key_second, encapsulated_key_2, shared_secret);

        if (status != vscr_status_SUCCESS) {
            goto err;
        }
    }

    if (receiver_one_time_private_key_second != NULL) {
        status = vscr_ratchet_xxdh_decapsulate_pqc_key(
                self, receiver_one_time_private_key_second, encapsulated_key_3, shared_secret);

        if (status != vscr_status_SUCCESS) {
            goto err;
        }
    }
    if (sender_identity_public_key_second_verifier != NULL) {
        size_t length = vsc_buffer_len(shared_secret);

        vsc_data_t pqc_shared_secret =
                vsc_data_slice_beg(vsc_buffer_data(shared_secret), pqc_begin_index, length - pqc_begin_index);
        VSCR_ASSERT(!vsc_data_is_empty(pqc_shared_secret));

        vsc_buffer_t *hash = vsc_buffer_new_with_capacity(vscf_sha512_DIGEST_LEN);
        vscf_sha512_hash(pqc_shared_secret, hash);

        bool verified = vscf_falcon_verify_hash(self->falcon, sender_identity_public_key_second_verifier,
                vscf_alg_id_SHA512, vsc_buffer_data(hash), decapsulated_keys_signature);

        vsc_buffer_destroy(&hash);

        if (!verified) {
            // FIXME
            status = vscr_status_ERROR_CURVE25519;
            goto err;
        }
    }

err:
    return status;
}

VSCR_PUBLIC void
vscr_ratchet_xxdh_derive_key(vsc_data_t shared_secret, vscr_ratchet_symmetric_key_t shared_key) {

    vsc_buffer_t buffer;
    vsc_buffer_init(&buffer);
    vsc_buffer_use(&buffer, shared_key, vscr_ratchet_common_hidden_SHARED_KEY_LEN);

    vscf_hkdf_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    vscf_hkdf_set_info(hkdf, vsc_data(ratchet_kdf_root_info, sizeof(ratchet_kdf_root_info)));

    vscf_hkdf_derive(hkdf, shared_secret, vscr_ratchet_common_hidden_SHARED_KEY_LEN, &buffer);
    vscf_hkdf_destroy(&hkdf);

    vsc_buffer_delete(&buffer);
}
