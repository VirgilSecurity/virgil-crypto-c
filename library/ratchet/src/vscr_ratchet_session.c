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


//  @description
// --------------------------------------------------------------------------
//  Class for ratchet session between 2 participants
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_ratchet_session.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_session_defs.h"
#include "vscr_ratchet_xxdh.h"
#include "vscr_ratchet_defs.h"
#include "vscr_ratchet_message_defs.h"
#include "vscr_ratchet_skipped_messages_defs.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_key_info.h>
#include <virgil/crypto/foundation/vscf_compound_private_key.h>
#include <virgil/crypto/foundation/vscf_hybrid_private_key.h>
#include <virgil/crypto/foundation/vscf_private_key.h>
#include <virgil/crypto/foundation/vscf_compound_public_key.h>
#include <virgil/crypto/foundation/vscf_hybrid_public_key.h>
#include <virgil/crypto/foundation/vscf_public_key.h>
#include <virgil/crypto/foundation/vscf_raw_public_key.h>
#include <virgil/crypto/foundation/vscf_raw_private_key.h>
#include <virgil/crypto/foundation/vscf_key_info.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <vscr_RatchetSession.pb.h>
#include <vscr_RatchetMessage.pb.h>
#include <pb_decode.h>
#include <pb_encode.h>
#include <ed25519/ed25519.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_session_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_session_init_ctx(vscr_ratchet_session_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_session_cleanup_ctx(vscr_ratchet_session_t *self);

//
//  This method is called when interface 'random' was setup.
//
static void
vscr_ratchet_session_did_setup_rng(vscr_ratchet_session_t *self);

//
//  This method is called when interface 'random' was released.
//
static void
vscr_ratchet_session_did_release_rng(vscr_ratchet_session_t *self);

//
//  Return size of 'vscr_ratchet_session_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_session_ctx_size(void) {

    return sizeof(vscr_ratchet_session_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_session_init(vscr_ratchet_session_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_session_t));

    self->refcnt = 1;

    vscr_ratchet_session_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_session_cleanup(vscr_ratchet_session_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_ratchet_session_cleanup_ctx(self);

    vscr_ratchet_session_release_rng(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_session_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_session_t *
vscr_ratchet_session_new(void) {

    vscr_ratchet_session_t *self = (vscr_ratchet_session_t *) vscr_alloc(sizeof (vscr_ratchet_session_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_session_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCR_PUBLIC void
vscr_ratchet_session_delete(vscr_ratchet_session_t *self) {

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

    vscr_ratchet_session_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_session_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_session_destroy(vscr_ratchet_session_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_session_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_session_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_session_t *
vscr_ratchet_session_shallow_copy(vscr_ratchet_session_t *self) {

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
//  Random used to generate keys
//
//  Note, ownership is shared.
//
VSCR_PUBLIC void
vscr_ratchet_session_use_rng(vscr_ratchet_session_t *self, vscf_impl_t *rng) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT(self->rng == NULL);

    VSCR_ASSERT(vscf_random_is_implemented(rng));

    self->rng = vscf_impl_shallow_copy(rng);

    vscr_ratchet_session_did_setup_rng(self);
}

//
//  Random used to generate keys
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_session_take_rng(vscr_ratchet_session_t *self, vscf_impl_t *rng) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT(self->rng == NULL);

    VSCR_ASSERT(vscf_random_is_implemented(rng));

    self->rng = rng;

    vscr_ratchet_session_did_setup_rng(self);
}

//
//  Release dependency to the interface 'random'.
//
VSCR_PUBLIC void
vscr_ratchet_session_release_rng(vscr_ratchet_session_t *self) {

    VSCR_ASSERT_PTR(self);

    vscf_impl_destroy(&self->rng);

    vscr_ratchet_session_did_release_rng(self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_session_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_session_init_ctx(vscr_ratchet_session_t *self) {

    VSCR_ASSERT_PTR(self);
    self->received_first_response = false;
    self->is_initiator = false;
    self->ratchet = vscr_ratchet_new();
    self->key_utils = vscr_ratchet_key_utils_new();
    self->xxdh = vscr_ratchet_xxdh_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_session_cleanup_ctx(vscr_ratchet_session_t *self) {

    VSCR_ASSERT_PTR(self);

    vsc_buffer_destroy(&self->encapsulated_key_1);
    vsc_buffer_destroy(&self->encapsulated_key_2);
    vsc_buffer_destroy(&self->encapsulated_key_3);
    vsc_buffer_destroy(&self->decapsulated_keys_signature);

    vscr_ratchet_destroy(&self->ratchet);
    vscr_ratchet_key_utils_destroy(&self->key_utils);
    vscr_ratchet_xxdh_destroy(&self->xxdh);
}

//
//  This method is called when interface 'random' was setup.
//
static void
vscr_ratchet_session_did_setup_rng(vscr_ratchet_session_t *self) {

    VSCR_ASSERT_PTR(self);

    if (self->rng != NULL) {
        vscr_ratchet_use_rng(self->ratchet, self->rng);
        vscr_ratchet_xxdh_use_rng(self->xxdh, self->rng);
    }
}

//
//  This method is called when interface 'random' was released.
//
static void
vscr_ratchet_session_did_release_rng(vscr_ratchet_session_t *self) {

    VSCR_UNUSED(self);
}

//
//  Setups default dependencies:
//      - RNG: CTR DRBG
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_session_setup_defaults(vscr_ratchet_session_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(self->rng == NULL);

    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    vscf_status_t status = vscf_ctr_drbg_setup_defaults(rng);

    if (status != vscf_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&rng);
        return vscr_status_ERROR_RNG_FAILED;
    }

    vscr_ratchet_session_take_rng(self, vscf_ctr_drbg_impl(rng));

    return vscr_status_SUCCESS;
}

//
//  Initiates session
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_session_initiate(vscr_ratchet_session_t *self, const vscf_impl_t *sender_identity_private_key,
        vsc_data_t sender_identity_key_id, const vscf_impl_t *receiver_identity_public_key,
        vsc_data_t receiver_identity_key_id, vscf_impl_t *receiver_long_term_public_key,
        vsc_data_t receiver_long_term_key_id, vscf_impl_t *receiver_one_time_public_key,
        vsc_data_t receiver_one_time_key_id, bool enable_post_quantum) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->rng);
    VSCR_ASSERT_PTR(self->ratchet);
    VSCR_ASSERT_PTR(self->key_utils);

    VSCR_ASSERT_PTR(sender_identity_private_key);
    VSCR_ASSERT(vscf_private_key_is_implemented(sender_identity_private_key));
    VSCR_ASSERT(sender_identity_key_id.len == sizeof(self->sender_identity_key_id));

    VSCR_ASSERT_PTR(receiver_identity_public_key);
    VSCR_ASSERT(vscf_public_key_is_implemented(receiver_identity_public_key));
    VSCR_ASSERT(receiver_identity_key_id.len == sizeof(self->receiver_identity_key_id));

    VSCR_ASSERT_PTR(receiver_long_term_public_key);
    VSCR_ASSERT(vscf_public_key_is_implemented(receiver_long_term_public_key));
    VSCR_ASSERT(receiver_long_term_key_id.len == sizeof(self->receiver_long_term_key_id));

    if (receiver_one_time_public_key != NULL) {
        VSCR_ASSERT(vscf_public_key_is_implemented(receiver_one_time_public_key));
        VSCR_ASSERT(receiver_one_time_key_id.len == sizeof(self->receiver_one_time_key_id));
    }

    self->enable_post_quantum = enable_post_quantum;

    vscr_status_t status = vscr_status_SUCCESS;

    vscr_ratchet_private_key_t sender_identity_private_key_first;
    const vscf_impl_t *sender_identity_private_key_second = NULL, *sender_identity_private_key_second_signer = NULL;

    status = vscr_ratchet_key_utils_import_private_key(self->key_utils, sender_identity_private_key,
            &sender_identity_private_key_first, &sender_identity_private_key_second,
            &sender_identity_private_key_second_signer, enable_post_quantum, true);

    if (status != vscr_status_SUCCESS) {
        goto err1;
    }

    memcpy(self->sender_identity_key_id, sender_identity_key_id.bytes, sizeof(self->sender_identity_key_id));

    vscr_ratchet_public_key_t sender_identity_public_key_first;
    int curve25519_status = curve25519_get_pubkey(sender_identity_public_key_first, sender_identity_private_key_first);

    if (curve25519_status != 0) {
        status = vscr_status_ERROR_CURVE25519;
        goto err1;
    }

    vscr_ratchet_public_key_t receiver_identity_public_key_first;
    const vscf_impl_t *receiver_identity_public_key_second = NULL;

    status = vscr_ratchet_key_utils_import_public_key(self->key_utils, receiver_identity_public_key,
            &receiver_identity_public_key_first, &receiver_identity_public_key_second, NULL, enable_post_quantum, true);
    if (status != vscr_status_SUCCESS) {
        goto err1;
    }

    vscr_ratchet_public_key_t receiver_long_term_public_key_first;
    const vscf_impl_t *receiver_long_term_public_key_second = NULL;
    status = vscr_ratchet_key_utils_import_public_key(self->key_utils, receiver_long_term_public_key,
            &receiver_long_term_public_key_first, &receiver_long_term_public_key_second, NULL, enable_post_quantum,
            false);
    if (status != vscr_status_SUCCESS) {
        goto err1;
    }

    vscr_ratchet_public_key_t receiver_one_time_public_key_first;
    const vscf_impl_t *receiver_one_time_public_key_second = NULL;

    if (receiver_one_time_public_key != NULL) {
        status = vscr_ratchet_key_utils_import_public_key(self->key_utils, receiver_one_time_public_key,
                &receiver_one_time_public_key_first, &receiver_one_time_public_key_second, NULL, enable_post_quantum,
                false);
        if (status != vscr_status_SUCCESS) {
            goto err1;
        }

        self->receiver_has_one_time_key_first = true;
    } else {
        self->receiver_has_one_time_key_first = false;
        receiver_one_time_public_key_second = NULL;
    }

    vscr_ratchet_symmetric_key_t shared_key;

    status = vscr_ratchet_xxdh_compute_initiator_xxdh_secret(self->xxdh, sender_identity_private_key_first,
            receiver_identity_public_key_first, receiver_long_term_public_key_first,
            self->receiver_has_one_time_key_first, receiver_one_time_public_key_first,
            self->sender_ephemeral_public_key_first, sender_identity_private_key_second_signer,
            receiver_identity_public_key_second, receiver_long_term_public_key_second,
            receiver_one_time_public_key_second, &self->encapsulated_key_1, &self->encapsulated_key_2,
            &self->encapsulated_key_3, &self->decapsulated_keys_signature, shared_key);

    if (status != vscr_status_SUCCESS) {
        goto err1;
    }

    status = vscr_ratchet_initiate(self->ratchet, shared_key, receiver_long_term_public_key_first,
            receiver_long_term_public_key_second, enable_post_quantum);

    self->is_initiator = true;

err1:
    vscr_zeroize(sender_identity_private_key_first, sizeof(sender_identity_private_key_first));

    return status;
}

//
//  Responds to session initiation
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_session_respond(vscr_ratchet_session_t *self, vscf_impl_t *sender_identity_public_key,
        const vscf_impl_t *receiver_identity_private_key, const vscf_impl_t *receiver_long_term_private_key,
        const vscf_impl_t *receiver_one_time_private_key, const vscr_ratchet_message_t *message,
        bool enable_post_quantum) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->rng);
    VSCR_ASSERT_PTR(self->ratchet);
    VSCR_ASSERT_PTR(self->key_utils);

    VSCR_ASSERT_PTR(sender_identity_public_key);
    VSCR_ASSERT(vscf_public_key_is_implemented(sender_identity_public_key));
    VSCR_ASSERT_PTR(receiver_identity_private_key);
    VSCR_ASSERT(vscf_private_key_is_implemented(receiver_identity_private_key));
    VSCR_ASSERT_PTR(receiver_long_term_private_key);
    VSCR_ASSERT(vscf_private_key_is_implemented(receiver_long_term_private_key));

    if (receiver_one_time_private_key != NULL) {
        VSCR_ASSERT(vscf_private_key_is_implemented(receiver_long_term_private_key));
    }

    VSCR_ASSERT_PTR(message);

    self->enable_post_quantum = enable_post_quantum;

    vscr_status_t status = vscr_status_SUCCESS;

    if (!message->message_pb.has_prekey_message) {
        status = vscr_status_ERROR_BAD_MESSAGE_TYPE;
        goto err1;
    }

    const vscr_PrekeyMessage *prekey_message = &message->message_pb.prekey_message;

    vscr_ratchet_public_key_t sender_identity_public_key_first;
    const vscf_impl_t *sender_identity_public_key_second = NULL, *sender_identity_public_key_second_verifier = NULL;

    status = vscr_ratchet_key_utils_import_public_key(self->key_utils, sender_identity_public_key,
            &sender_identity_public_key_first, &sender_identity_public_key_second,
            &sender_identity_public_key_second_verifier, enable_post_quantum, true);

    if (status != vscr_status_SUCCESS) {
        goto err1;
    }

    vscr_ratchet_private_key_t receiver_identity_private_key_first;
    const vscf_impl_t *receiver_identity_private_key_second = NULL;

    status = vscr_ratchet_key_utils_import_private_key(self->key_utils, receiver_identity_private_key,
            &receiver_identity_private_key_first, &receiver_identity_private_key_second, NULL, enable_post_quantum,
            true);

    if (status != vscr_status_SUCCESS) {
        goto err2;
    }

    vscr_ratchet_private_key_t receiver_long_term_private_key_first;
    const vscf_impl_t *receiver_long_term_private_key_second = NULL;

    status = vscr_ratchet_key_utils_import_private_key(self->key_utils, receiver_long_term_private_key,
            &receiver_long_term_private_key_first, &receiver_long_term_private_key_second, NULL, enable_post_quantum,
            false);

    if (status != vscr_status_SUCCESS) {
        goto err3;
    }

    vscr_ratchet_private_key_t receiver_one_time_private_key_first;
    const vscf_impl_t *receiver_one_time_private_key_second = NULL;

    if (receiver_one_time_private_key != NULL) {
        self->receiver_has_one_time_key_first = true;

        status = vscr_ratchet_key_utils_import_private_key(self->key_utils, receiver_one_time_private_key,
                &receiver_one_time_private_key_first, &receiver_one_time_private_key_second, NULL, enable_post_quantum,
                false);

        if (status != vscr_status_SUCCESS) {
            goto err4;
        }
    } else {
        self->receiver_has_one_time_key_first = false;
        receiver_one_time_private_key_second = NULL;
    }

    vscr_ratchet_symmetric_key_t shared_key;

    status = vscr_ratchet_xxdh_compute_responder_xxdh_secret(self->xxdh, sender_identity_public_key_first,
            receiver_identity_private_key_first, receiver_long_term_private_key_first,
            self->receiver_has_one_time_key_first, receiver_one_time_private_key_first,
            prekey_message->sender_ephemeral_key, sender_identity_public_key_second_verifier,
            receiver_identity_private_key_second, receiver_long_term_private_key_second,
            receiver_one_time_private_key_second,
            vscr_ratchet_pb_utils_buffer_to_data(prekey_message->pqc_info.encapsulated_key1),
            vscr_ratchet_pb_utils_buffer_to_data(prekey_message->pqc_info.encapsulated_key2),
            vscr_ratchet_pb_utils_buffer_to_data(prekey_message->pqc_info.encapsulated_key3),
            vscr_ratchet_pb_utils_buffer_to_data(prekey_message->pqc_info.decapsulated_keys_signature), shared_key);

    if (status != vscr_status_SUCCESS) {
        goto err5;
    }

    status = vscr_ratchet_respond(self->ratchet, shared_key, receiver_long_term_private_key_first,
            receiver_long_term_private_key_second, &message->message_pb.regular_message, message->header_pb,
            enable_post_quantum);

    self->is_initiator = false;

err5:
    vscr_zeroize(shared_key, sizeof(shared_key));

err4:
    vscr_zeroize(receiver_one_time_private_key_first, sizeof(receiver_one_time_private_key_first));

err3:
    vscr_zeroize(receiver_long_term_private_key_first, sizeof(receiver_long_term_private_key_first));

err2:
    vscr_zeroize(receiver_identity_private_key_first, sizeof(receiver_identity_private_key_first));

err1:
    return status;
}

//
//  Returns flag that indicates is this session was initiated or responded
//
VSCR_PUBLIC bool
vscr_ratchet_session_is_initiator(vscr_ratchet_session_t *self) {

    return self->is_initiator;
}

//
//  Returns true if at least 1 response was successfully decrypted, false - otherwise
//
VSCR_PUBLIC bool
vscr_ratchet_session_received_first_response(vscr_ratchet_session_t *self) {

    return self->received_first_response;
}

//
//  Returns true if receiver had one time public key
//
VSCR_PUBLIC bool
vscr_ratchet_session_receiver_has_one_time_public_key(vscr_ratchet_session_t *self) {

    return self->receiver_has_one_time_key_first;
}

//
//  Encrypts data
//
VSCR_PUBLIC vscr_ratchet_message_t *
vscr_ratchet_session_encrypt(vscr_ratchet_session_t *self, vsc_data_t plain_text, vscr_error_t *error) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->rng);
    VSCR_ASSERT_PTR(self->ratchet);

    VSCR_ASSERT(vsc_data_is_valid(plain_text));

    vscr_ratchet_message_t *ratchet_message = NULL;

    if (plain_text.len > vscr_ratchet_common_MAX_PLAIN_TEXT_LEN) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_EXCEEDED_MAX_PLAIN_TEXT_LEN);
        goto err;
    }

    if (!self->is_initiator && !self->received_first_response) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_SESSION_IS_NOT_INITIALIZED);
        goto err;
    }

    ratchet_message = vscr_ratchet_message_new();

    vscr_RegularMessage *regular_message = &ratchet_message->message_pb.regular_message;

    if (self->received_first_response || !self->is_initiator) {
        ratchet_message->message_pb.has_prekey_message = false;
    } else {
        ratchet_message->message_pb.has_prekey_message = true;
        vscr_PrekeyMessage *prekey_message = &ratchet_message->message_pb.prekey_message;

        memcpy(prekey_message->sender_ephemeral_key, self->sender_ephemeral_public_key_first,
                sizeof(prekey_message->sender_ephemeral_key));
        memcpy(prekey_message->sender_identity_key_id, self->sender_identity_key_id,
                sizeof(prekey_message->sender_identity_key_id));
        memcpy(prekey_message->receiver_identity_key_id, self->receiver_identity_key_id,
                sizeof(prekey_message->receiver_identity_key_id));
        memcpy(prekey_message->receiver_long_term_key_id, self->receiver_long_term_key_id,
                sizeof(prekey_message->receiver_long_term_key_id));
        if (self->receiver_has_one_time_key_first) {
            prekey_message->has_receiver_one_time_key_id = true;
            memcpy(prekey_message->receiver_one_time_key_id, self->sender_identity_key_id,
                    sizeof(prekey_message->receiver_one_time_key_id));
        } else {
            prekey_message->has_receiver_one_time_key_id = false;
        }

        if (self->enable_post_quantum) {
            prekey_message->has_pqc_info = true;

            vscr_PrekeyMessagePqcInfo *pqc_info = &prekey_message->pqc_info;

            vscr_ratchet_pb_utils_serialize_buffer(self->encapsulated_key_1, &pqc_info->encapsulated_key1);
            vscr_ratchet_pb_utils_serialize_buffer(self->encapsulated_key_2, &pqc_info->encapsulated_key2);

            if (self->receiver_has_one_time_key_first) {
                vscr_ratchet_pb_utils_serialize_buffer(self->encapsulated_key_3, &pqc_info->encapsulated_key3);
            }
            vscr_ratchet_pb_utils_serialize_buffer(
                    self->decapsulated_keys_signature, &pqc_info->decapsulated_keys_signature);
        } else {
            prekey_message->has_pqc_info = false;
        }
    }

    vscr_status_t result = vscr_ratchet_encrypt(self->ratchet, plain_text, regular_message, ratchet_message->header_pb);

    if (result != vscr_status_SUCCESS) {
        VSCR_ERROR_SAFE_UPDATE(error, result);

        vscr_ratchet_message_destroy(&ratchet_message);

        return NULL;
    }

err:
    return ratchet_message;
}

//
//  Calculates size of buffer sufficient to store decrypted message
//
VSCR_PUBLIC size_t
vscr_ratchet_session_decrypt_len(vscr_ratchet_session_t *self, const vscr_ratchet_message_t *message) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->ratchet);
    VSCR_ASSERT_PTR(message);

    size_t cipher_text_len = message->message_pb.regular_message.cipher_text->size;

    VSCR_ASSERT(cipher_text_len <= vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN);

    return vscr_ratchet_decrypt_len(self->ratchet, cipher_text_len);
}

//
//  Decrypts message
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_session_decrypt(
        vscr_ratchet_session_t *self, const vscr_ratchet_message_t *message, vsc_buffer_t *plain_text) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->rng);
    VSCR_ASSERT_PTR(self->ratchet);

    VSCR_ASSERT_PTR(message);
    VSCR_ASSERT_PTR(plain_text);

    const vscr_RegularMessage *regular_message = &message->message_pb.regular_message;

    if (message->message_pb.has_prekey_message && self->is_initiator) {
        return vscr_status_ERROR_BAD_MESSAGE_TYPE;
    }

    VSCR_ASSERT(vsc_buffer_unused_len(plain_text) >= vscr_ratchet_session_decrypt_len(self, message));

    vscr_status_t result = vscr_ratchet_decrypt(self->ratchet, regular_message, message->header_pb, plain_text);

    if (result == vscr_status_SUCCESS)
        self->received_first_response = true;

    return result;
}

//
//  Serializes session to buffer
//
VSCR_PUBLIC vsc_buffer_t *
vscr_ratchet_session_serialize(vscr_ratchet_session_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_Session *session_pb = vscr_alloc(sizeof(vscr_Session));

    session_pb->version = vscr_ratchet_common_hidden_SESSION_VERSION;
    session_pb->received_first_response = self->received_first_response;
    session_pb->is_initiator = self->is_initiator;
    session_pb->enable_post_quantum = self->enable_post_quantum;
    session_pb->receiver_has_one_time_public_key = self->receiver_has_one_time_key_first;

    if (!self->received_first_response && self->is_initiator) {

        session_pb->has_sender_identity_key_id = true;
        session_pb->has_sender_ephemeral_key = true;
        session_pb->has_receiver_identity_key_id = true;
        session_pb->has_receiver_long_term_key_id = true;

        memcpy(session_pb->sender_identity_key_id, self->sender_identity_key_id,
                sizeof(session_pb->sender_identity_key_id));
        memcpy(session_pb->sender_ephemeral_key, self->sender_ephemeral_public_key_first,
                sizeof(session_pb->sender_ephemeral_key));
        memcpy(session_pb->receiver_identity_key_id, self->receiver_identity_key_id,
                sizeof(session_pb->receiver_identity_key_id));
        memcpy(session_pb->receiver_long_term_key_id, self->receiver_long_term_key_id,
                sizeof(session_pb->receiver_long_term_key_id));

        if (self->receiver_has_one_time_key_first) {
            session_pb->has_receiver_one_time_key_id = true;
            memcpy(session_pb->receiver_one_time_key_id, self->receiver_one_time_key_id,
                    sizeof(session_pb->receiver_one_time_key_id));
        }

        if (self->enable_post_quantum) {
            session_pb->has_pqc_info = true;
            vscr_ratchet_pb_utils_serialize_buffer(self->encapsulated_key_1, &session_pb->pqc_info.encapsulated_key1);
            vscr_ratchet_pb_utils_serialize_buffer(self->encapsulated_key_2, &session_pb->pqc_info.encapsulated_key2);

            if (self->receiver_has_one_time_key_first) {
                vscr_ratchet_pb_utils_serialize_buffer(
                        self->encapsulated_key_3, &session_pb->pqc_info.encapsulated_key3);
            }

            vscr_ratchet_pb_utils_serialize_buffer(
                    self->decapsulated_keys_signature, &session_pb->pqc_info.decapsulated_keys_signature);
        } else {
            session_pb->has_pqc_info = false;
        }
    } else {
        session_pb->has_pqc_info = false;
        session_pb->has_sender_identity_key_id = false;
        session_pb->has_sender_ephemeral_key = false;
        session_pb->has_receiver_identity_key_id = false;
        session_pb->has_receiver_long_term_key_id = false;
        session_pb->has_receiver_one_time_key_id = false;
    }

    vscr_ratchet_serialize(self->ratchet, &session_pb->ratchet);

    size_t len = 0;
    pb_get_encoded_size(&len, vscr_Session_fields, session_pb);

    vsc_buffer_t *output = vsc_buffer_new_with_capacity(len);
    vsc_buffer_make_secure(output);

    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_unused_bytes(output), vsc_buffer_unused_len(output));

    VSCR_ASSERT(pb_encode(&ostream, vscr_Session_fields, session_pb));
    vsc_buffer_inc_used(output, ostream.bytes_written);

    // FIXME: Free memory

    for (size_t j = 0; j < session_pb->ratchet.skipped_messages.keys_count; j++) {
        vscr_dealloc(session_pb->ratchet.skipped_messages.keys[j].message_keys);
    }

    vscr_zeroize(session_pb, sizeof(vscr_Session));
    vscr_dealloc(session_pb);

    return output;
}

//
//  Deserializes session from buffer.
//  NOTE: Deserialized session needs dependencies to be set. Check setup defaults
//
VSCR_PUBLIC vscr_ratchet_session_t *
vscr_ratchet_session_deserialize(vsc_data_t input, vscr_error_t *error) {

    VSCR_ASSERT(vsc_data_is_valid(input));

    if (input.len > vscr_ratchet_common_hidden_MAX_SESSION_LEN) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_PROTOBUF_DECODE);

        return NULL;
    }

    vscr_ratchet_session_t *session = NULL;
    vscr_Session *session_pb = vscr_alloc(sizeof(vscr_Session));

    pb_istream_t istream = pb_istream_from_buffer(input.bytes, input.len);

    bool pb_status = pb_decode(&istream, vscr_Session_fields, session_pb);

    if (!pb_status) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_PROTOBUF_DECODE);

        goto err;
    }

    if (!session_pb->received_first_response && session_pb->is_initiator) {
        if (!session_pb->has_sender_identity_key_id || !session_pb->has_sender_ephemeral_key ||
                !session_pb->has_receiver_identity_key_id || !session_pb->has_receiver_long_term_key_id) {
            VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_PROTOBUF_DECODE);

            goto err;
        }
    }

    // FIXME
    //    if (session_pb->enable_post_quantum) {
    //        if (!session_pb->has_pqc_info ||
    //                (session_pb->has_receiver_one_time_key_id != (session_pb->pqc_info.encapsulated_key3 != NULL))) {
    //            VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_PROTOBUF_DECODE);
    //
    //            goto err;
    //        }
    //    }

    session = vscr_ratchet_session_new();

    session->receiver_has_one_time_key_first = session_pb->receiver_has_one_time_public_key;
    session->received_first_response = session_pb->received_first_response;
    session->is_initiator = session_pb->is_initiator;
    session->enable_post_quantum = session_pb->enable_post_quantum;

    if (!session->received_first_response && session->is_initiator) {
        if (session_pb->receiver_has_one_time_public_key != session_pb->has_receiver_one_time_key_id) {
            VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_PROTOBUF_DECODE);

            goto err;
        }

        memcpy(session->sender_identity_key_id, session_pb->sender_identity_key_id,
                sizeof(session_pb->sender_identity_key_id));
        memcpy(session->sender_ephemeral_public_key_first, session_pb->sender_ephemeral_key,
                sizeof(session_pb->sender_ephemeral_key));
        memcpy(session->receiver_identity_key_id, session_pb->receiver_identity_key_id,
                sizeof(session_pb->receiver_identity_key_id));
        memcpy(session->receiver_long_term_key_id, session_pb->receiver_long_term_key_id,
                sizeof(session_pb->receiver_long_term_key_id));

        if (session_pb->has_receiver_one_time_key_id) {
            memcpy(session_pb->receiver_one_time_key_id, session->receiver_one_time_key_id,
                    sizeof(session_pb->receiver_one_time_key_id));
        }

        if (session->enable_post_quantum) {
            session->encapsulated_key_1 =
                    vscr_ratchet_pb_utils_deserialize_buffer(session_pb->pqc_info.encapsulated_key1);
            session->encapsulated_key_2 =
                    vscr_ratchet_pb_utils_deserialize_buffer(session_pb->pqc_info.encapsulated_key2);
            session->encapsulated_key_3 =
                    vscr_ratchet_pb_utils_deserialize_buffer(session_pb->pqc_info.encapsulated_key3);
            session->decapsulated_keys_signature =
                    vscr_ratchet_pb_utils_deserialize_buffer(session_pb->pqc_info.decapsulated_keys_signature);
        }
    }

    vscr_status_t status = vscr_ratchet_deserialize(&session_pb->ratchet, session->ratchet);

    if (status != vscf_status_SUCCESS) {
        vscr_ratchet_session_destroy(&session);
        goto err;
    }

err:
    if (pb_status) {
        pb_release(vscr_Session_fields, session_pb);
    }

    vscr_zeroize(session_pb, sizeof(vscr_Session));
    vscr_dealloc(session_pb);

    return session;
}
