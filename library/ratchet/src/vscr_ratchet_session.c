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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_ratchet_session.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_common.h"
#include "vscr_ratchet_message_defs.h"
#include "vscr_ratchet.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <RatchetSession.pb.h>
#include <RatchetMessage.pb.h>
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
//  Handle 'ratchet session' context.
//
struct vscr_ratchet_session_t {
    //
    //  Function do deallocate self context.
    //
    vscr_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    size_t refcnt;
    //
    //  Dependency to the interface 'random'.
    //
    vscf_impl_t *rng;

    bool is_initiator;

    vscr_ratchet_t *ratchet;

    bool received_first_response;

    byte sender_identity_public_key[vscr_ratchet_common_RATCHET_KEY_LENGTH];

    byte sender_ephemeral_public_key[vscr_ratchet_common_RATCHET_KEY_LENGTH];

    byte receiver_long_term_public_key[vscr_ratchet_common_RATCHET_KEY_LENGTH];

    bool receiver_has_one_time_public_key;

    byte receiver_one_time_public_key[vscr_ratchet_common_RATCHET_KEY_LENGTH];
};

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_session_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_session_init_ctx(vscr_ratchet_session_t *ratchet_session);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_session_cleanup_ctx(vscr_ratchet_session_t *ratchet_session);

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
vscr_ratchet_session_init(vscr_ratchet_session_t *ratchet_session) {

    VSCR_ASSERT_PTR(ratchet_session);

    vscr_zeroize(ratchet_session, sizeof(vscr_ratchet_session_t));

    ratchet_session->refcnt = 1;

    vscr_ratchet_session_init_ctx(ratchet_session);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_session_cleanup(vscr_ratchet_session_t *ratchet_session) {

    if (ratchet_session == NULL) {
        return;
    }

    if (ratchet_session->refcnt == 0) {
        return;
    }

    if (--ratchet_session->refcnt == 0) {
        vscr_ratchet_session_cleanup_ctx(ratchet_session);

        vscr_ratchet_session_release_rng(ratchet_session);

        vscr_zeroize(ratchet_session, sizeof(vscr_ratchet_session_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_session_t *
vscr_ratchet_session_new(void) {

    vscr_ratchet_session_t *ratchet_session = (vscr_ratchet_session_t *) vscr_alloc(sizeof (vscr_ratchet_session_t));
    VSCR_ASSERT_ALLOC(ratchet_session);

    vscr_ratchet_session_init(ratchet_session);

    ratchet_session->self_dealloc_cb = vscr_dealloc;

    return ratchet_session;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_session_delete(vscr_ratchet_session_t *ratchet_session) {

    if (ratchet_session == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = ratchet_session->self_dealloc_cb;

    vscr_ratchet_session_cleanup(ratchet_session);

    if (ratchet_session->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(ratchet_session);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_session_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_session_destroy(vscr_ratchet_session_t **ratchet_session_ref) {

    VSCR_ASSERT_PTR(ratchet_session_ref);

    vscr_ratchet_session_t *ratchet_session = *ratchet_session_ref;
    *ratchet_session_ref = NULL;

    vscr_ratchet_session_delete(ratchet_session);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_session_t *
vscr_ratchet_session_shallow_copy(vscr_ratchet_session_t *ratchet_session) {

    VSCR_ASSERT_PTR(ratchet_session);

    ++ratchet_session->refcnt;

    return ratchet_session;
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCR_PUBLIC void
vscr_ratchet_session_use_rng(vscr_ratchet_session_t *ratchet_session, vscf_impl_t *rng) {

    VSCR_ASSERT_PTR(ratchet_session);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT_PTR(ratchet_session->rng == NULL);

    VSCR_ASSERT(vscf_random_is_implemented(rng));

    ratchet_session->rng = vscf_impl_shallow_copy(rng);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_session_take_rng(vscr_ratchet_session_t *ratchet_session, vscf_impl_t *rng) {

    VSCR_ASSERT_PTR(ratchet_session);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT_PTR(ratchet_session->rng == NULL);

    VSCR_ASSERT(vscf_random_is_implemented(rng));

    ratchet_session->rng = rng;
}

//
//  Release dependency to the interface 'random'.
//
VSCR_PUBLIC void
vscr_ratchet_session_release_rng(vscr_ratchet_session_t *ratchet_session) {

    VSCR_ASSERT_PTR(ratchet_session);

    vscf_impl_destroy(&ratchet_session->rng);
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
vscr_ratchet_session_init_ctx(vscr_ratchet_session_t *ratchet_session) {

    VSCR_ASSERT_PTR(ratchet_session);
    ratchet_session->received_first_response = false;
    ratchet_session->is_initiator = false;
    ratchet_session->ratchet = vscr_ratchet_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_session_cleanup_ctx(vscr_ratchet_session_t *ratchet_session) {

    VSCR_ASSERT_PTR(ratchet_session);

    vscr_ratchet_destroy(&ratchet_session->ratchet);
}

VSCR_PUBLIC void
vscr_ratchet_session_setup_defaults(vscr_ratchet_session_t *ratchet_session) {

    VSCR_ASSERT_PTR(ratchet_session);
    VSCR_ASSERT(ratchet_session->rng == NULL);

    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng);
    vscr_ratchet_session_take_rng(ratchet_session, vscf_ctr_drbg_impl(rng));

    vscr_ratchet_setup_defaults(ratchet_session->ratchet);
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_session_initiate(vscr_ratchet_session_t *ratchet_session, vsc_data_t sender_identity_private_key,
        vsc_data_t receiver_identity_public_key, vsc_data_t receiver_long_term_public_key,
        vsc_data_t receiver_one_time_public_key) {

    VSCR_ASSERT_PTR(ratchet_session);

    VSCR_ASSERT(sender_identity_private_key.len == vscr_ratchet_common_RATCHET_KEY_LENGTH);
    VSCR_ASSERT(receiver_identity_public_key.len == vscr_ratchet_common_RATCHET_KEY_LENGTH);
    VSCR_ASSERT(receiver_long_term_public_key.len == vscr_ratchet_common_RATCHET_KEY_LENGTH);

    size_t shared_secret_count = 3;
    if (receiver_one_time_public_key.len != 0) {
        VSCR_ASSERT(receiver_one_time_public_key.len == vscr_ratchet_common_RATCHET_KEY_LENGTH);

        shared_secret_count = 4;
    }

    vscr_error_t status = vscr_SUCCESS;

    byte ephemeral_private_key[vscr_ratchet_common_RATCHET_KEY_LENGTH];
    byte ratchet_private_key[vscr_ratchet_common_RATCHET_KEY_LENGTH];

    vsc_buffer_t ephemeral_private_key_buf;
    vsc_buffer_init(&ephemeral_private_key_buf);
    vsc_buffer_use(&ephemeral_private_key_buf, ephemeral_private_key, sizeof(ephemeral_private_key));

    vscf_error_t f_status =
            vscf_random(ratchet_session->rng, vscr_ratchet_common_RATCHET_KEY_LENGTH, &ephemeral_private_key_buf);
    vsc_buffer_delete(&ephemeral_private_key_buf);

    if (f_status != vscf_SUCCESS) {
        status = vscr_error_RNG_FAILED;
        goto rng_err;
    }

    vsc_buffer_t ratchet_private_key_buf;
    vsc_buffer_init(&ratchet_private_key_buf);
    vsc_buffer_use(&ratchet_private_key_buf, ratchet_private_key, sizeof(ratchet_private_key));

    f_status = vscf_random(ratchet_session->rng, vscr_ratchet_common_RATCHET_KEY_LENGTH, &ratchet_private_key_buf);
    vsc_buffer_delete(&ratchet_private_key_buf);

    if (f_status != vscf_SUCCESS) {
        status = vscr_error_RNG_FAILED;
        goto rng_err;
    }

    byte shared_secret[4 * ED25519_DH_LEN];

    int curve_status = 0;
    curve_status = curve25519_key_exchange(
            shared_secret, receiver_long_term_public_key.bytes, sender_identity_private_key.bytes);

    if (curve_status != 0) {
        status = vscr_error_CURVE25519_ERROR;
        goto curve_err;
    }

    curve_status = curve25519_key_exchange(
            shared_secret + ED25519_DH_LEN, receiver_identity_public_key.bytes, ephemeral_private_key);

    if (curve_status != 0) {
        status = vscr_error_CURVE25519_ERROR;
        goto curve_err;
    }

    curve_status = curve25519_key_exchange(
            shared_secret + 2 * ED25519_DH_LEN, receiver_long_term_public_key.bytes, ephemeral_private_key);

    if (curve_status != 0) {
        status = vscr_error_CURVE25519_ERROR;
        goto curve_err;
    }

    if (receiver_one_time_public_key.len != 0) {
        curve_status = curve25519_key_exchange(
                shared_secret + 3 * ED25519_DH_LEN, receiver_one_time_public_key.bytes, ephemeral_private_key);

        if (curve_status != 0) {
            status = vscr_error_CURVE25519_ERROR;
            goto curve_err;
        }

        ratchet_session->receiver_has_one_time_public_key = true;
        memcpy(ratchet_session->receiver_one_time_public_key, receiver_one_time_public_key.bytes,
                receiver_one_time_public_key.len);
    } else {
        ratchet_session->receiver_has_one_time_public_key = false;
    }

    curve_status =
            curve25519_get_pubkey(ratchet_session->sender_identity_public_key, sender_identity_private_key.bytes);

    if (curve_status != 0) {
        status = vscr_error_CURVE25519_ERROR;
        goto curve_err;
    }

    curve_status = curve25519_get_pubkey(ratchet_session->sender_ephemeral_public_key, ephemeral_private_key);

    if (curve_status != 0) {
        status = vscr_error_CURVE25519_ERROR;
        goto curve_err;
    }

    memcpy(ratchet_session->receiver_long_term_public_key, receiver_long_term_public_key.bytes,
            receiver_long_term_public_key.len);

    status = vscr_ratchet_initiate(ratchet_session->ratchet,
            vsc_data(shared_secret, shared_secret_count * ED25519_DH_LEN),
            vsc_data(ratchet_private_key, sizeof(ratchet_private_key)));

    ratchet_session->is_initiator = true;

curve_err:
    vscr_zeroize(shared_secret, sizeof(shared_secret));

rng_err:
    vscr_zeroize(ephemeral_private_key, sizeof(ephemeral_private_key));
    vscr_zeroize(ratchet_private_key, sizeof(ratchet_private_key));

    return status;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_session_respond(vscr_ratchet_session_t *ratchet_session, vsc_data_t sender_identity_public_key,
        vsc_data_t receiver_identity_private_key, vsc_data_t receiver_long_term_private_key,
        vsc_data_t receiver_one_time_private_key, const vscr_ratchet_message_t *message) {

    VSCR_ASSERT_PTR(ratchet_session);
    VSCR_ASSERT(message->message_pb.has_prekey_message);
    VSCR_ASSERT(memcmp(message->message_pb.prekey_message.sender_identity_key, sender_identity_public_key.bytes,
                        sender_identity_public_key.len) == 0);

    VSCR_ASSERT(sender_identity_public_key.len == vscr_ratchet_common_RATCHET_KEY_LENGTH);
    VSCR_ASSERT(receiver_identity_private_key.len == vscr_ratchet_common_RATCHET_KEY_LENGTH);
    VSCR_ASSERT(receiver_long_term_private_key.len == vscr_ratchet_common_RATCHET_KEY_LENGTH);

    size_t shared_secret_count = 3;
    if (receiver_one_time_private_key.len != 0) {
        VSCR_ASSERT(receiver_one_time_private_key.len == vscr_ratchet_common_RATCHET_KEY_LENGTH);

        shared_secret_count = 4;
    }

    vscr_error_t status = vscr_SUCCESS;

    int curve_status = 0;

    byte shared_secret[4 * ED25519_DH_LEN];

    curve_status = curve25519_key_exchange(
            shared_secret, sender_identity_public_key.bytes, receiver_long_term_private_key.bytes);

    if (curve_status != 0) {
        status = vscr_error_CURVE25519_ERROR;
        goto curve_err;
    }

    curve_status = curve25519_key_exchange(shared_secret + ED25519_DH_LEN,
            message->message_pb.prekey_message.sender_ephemeral_key, receiver_identity_private_key.bytes);

    if (curve_status != 0) {
        status = vscr_error_CURVE25519_ERROR;
        goto curve_err;
    }

    curve_status = curve25519_key_exchange(shared_secret + 2 * ED25519_DH_LEN,
            message->message_pb.prekey_message.sender_ephemeral_key, receiver_long_term_private_key.bytes);

    if (curve_status != 0) {
        status = vscr_error_CURVE25519_ERROR;
        goto curve_err;
    }

    if (receiver_one_time_private_key.len != 0) {
        curve_status = curve25519_key_exchange(shared_secret + 3 * ED25519_DH_LEN,
                message->message_pb.prekey_message.sender_ephemeral_key, receiver_one_time_private_key.bytes);

        if (curve_status != 0) {
            status = vscr_error_CURVE25519_ERROR;
            goto curve_err;
        }

        ratchet_session->receiver_has_one_time_public_key = true;
        curve_status = curve25519_get_pubkey(
                ratchet_session->receiver_one_time_public_key, receiver_one_time_private_key.bytes);

        if (curve_status != 0) {
            status = vscr_error_CURVE25519_ERROR;
            goto curve_err;
        }
    } else {
        ratchet_session->receiver_has_one_time_public_key = false;
    }

    memcpy(ratchet_session->sender_identity_public_key, sender_identity_public_key.bytes,
            sender_identity_public_key.len);
    memcpy(ratchet_session->sender_ephemeral_public_key, message->message_pb.prekey_message.sender_ephemeral_key,
            sizeof(message->message_pb.prekey_message.sender_ephemeral_key));

    curve_status =
            curve25519_get_pubkey(ratchet_session->receiver_long_term_public_key, receiver_long_term_private_key.bytes);

    if (curve_status != 0) {
        status = vscr_error_CURVE25519_ERROR;
        goto curve_err;
    }

    status = vscr_ratchet_respond(ratchet_session->ratchet,
            vsc_data(shared_secret, shared_secret_count * ED25519_DH_LEN),
            &message->message_pb.prekey_message.regular_message);

    ratchet_session->is_initiator = false;

curve_err:
    vscr_zeroize(shared_secret, sizeof(shared_secret));

    return status;
}

VSCR_PUBLIC vscr_ratchet_message_t *
vscr_ratchet_session_encrypt(
        vscr_ratchet_session_t *ratchet_session, vsc_data_t plain_text, vscr_error_ctx_t *err_ctx) {

    VSCR_ASSERT_PTR(ratchet_session);
    VSCR_ASSERT(plain_text.len <= vscr_ratchet_common_MAX_PLAIN_TEXT_LEN);
    VSCR_ASSERT(ratchet_session->is_initiator || ratchet_session->received_first_response);

    vscr_ratchet_message_t *ratchet_message = vscr_ratchet_message_new();
    ratchet_message->message_pb.version = vscr_ratchet_common_RATCHET_MESSAGE_VERSION;
    RegularMessage *regular_message;

    if (ratchet_session->received_first_response) {
        ratchet_message->message_pb.has_regular_message = true;
        regular_message = &ratchet_message->message_pb.regular_message;

    } else {
        ratchet_message->message_pb.has_prekey_message = true;
        PrekeyMessage *prekey_message = &ratchet_message->message_pb.prekey_message;
        regular_message = &prekey_message->regular_message;

        prekey_message->version = vscr_ratchet_common_RATCHET_PROTOCOL_VERSION;

        memcpy(prekey_message->sender_identity_key, ratchet_session->sender_identity_public_key,
                sizeof(ratchet_session->sender_identity_public_key));

        memcpy(prekey_message->sender_ephemeral_key, ratchet_session->sender_ephemeral_public_key,
                sizeof(ratchet_session->sender_ephemeral_public_key));

        memcpy(prekey_message->receiver_long_term_key, ratchet_session->receiver_long_term_public_key,
                sizeof(ratchet_session->receiver_long_term_public_key));

        if (ratchet_session->receiver_has_one_time_public_key) {
            prekey_message->has_receiver_one_time_key = true;
            memcpy(prekey_message->receiver_one_time_key, ratchet_session->receiver_one_time_public_key,
                    sizeof(ratchet_session->receiver_one_time_public_key));
        } else {
            prekey_message->has_receiver_one_time_key = false;
        }
    }

    regular_message->cipher_text.arg =
            vsc_buffer_new_with_capacity(vscr_ratchet_encrypt_len(ratchet_session->ratchet, plain_text.len));

    vscr_error_t result = vscr_ratchet_encrypt(ratchet_session->ratchet, plain_text, regular_message);

    if (result != vscr_SUCCESS) {
        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, result);

        vscr_ratchet_message_destroy(&ratchet_message);

        return NULL;
    }

    return ratchet_message;
}

VSCR_PUBLIC size_t
vscr_ratchet_session_decrypt_len(vscr_ratchet_session_t *ratchet_session, const vscr_ratchet_message_t *message) {

    VSCR_UNUSED(ratchet_session);
    VSCR_ASSERT_PTR(message);

    size_t cipher_text_len = 0;

    if (message->message_pb.has_regular_message) {
        cipher_text_len = vsc_buffer_len(message->message_pb.regular_message.cipher_text.arg);
    } else if (message->message_pb.has_prekey_message) {
        cipher_text_len = vsc_buffer_len(message->message_pb.prekey_message.regular_message.cipher_text.arg);
    }

    VSCR_ASSERT(cipher_text_len <= vscr_ratchet_common_MAX_CIPHER_TEXT_LEN);

    return vscr_ratchet_decrypt_len(ratchet_session->ratchet, cipher_text_len);
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_session_decrypt(
        vscr_ratchet_session_t *ratchet_session, const vscr_ratchet_message_t *message, vsc_buffer_t *plain_text) {

    VSCR_ASSERT_PTR(ratchet_session);
    VSCR_ASSERT_PTR(message);
    VSCR_ASSERT_PTR(plain_text);

    const RegularMessage *regular_message = NULL;

    if (message->message_pb.has_regular_message) {
        regular_message = &message->message_pb.regular_message;
    } else if (message->message_pb.has_prekey_message) {
        regular_message = &message->message_pb.prekey_message.regular_message;
    }

    VSCR_ASSERT(vsc_buffer_unused_len(plain_text) >= vscr_ratchet_session_decrypt_len(ratchet_session, message));

    vscr_error_t result = vscr_ratchet_decrypt(ratchet_session->ratchet, regular_message, plain_text);

    if (result == vscr_SUCCESS)
        ratchet_session->received_first_response = true;

    return result;
}

VSCR_PUBLIC size_t
vscr_ratchet_session_serialize_len(vscr_ratchet_session_t *ratchet_session) {

    VSCR_UNUSED(ratchet_session);

    return Session_size;
}

VSCR_PUBLIC void
vscr_ratchet_session_serialize(vscr_ratchet_session_t *ratchet_session, vsc_buffer_t *output) {

    VSCR_ASSERT_PTR(ratchet_session);
    VSCR_ASSERT(vsc_buffer_unused_len(output) >= vscr_ratchet_session_serialize_len(ratchet_session));

    Session session_pb = Session_init_zero;

    session_pb.received_first_response = ratchet_session->received_first_response;
    session_pb.is_initiator = ratchet_session->is_initiator;

    memcpy(session_pb.sender_identity_key, ratchet_session->sender_identity_public_key,
            sizeof(ratchet_session->sender_identity_public_key));
    memcpy(session_pb.sender_ephemeral_key, ratchet_session->sender_ephemeral_public_key,
            sizeof(ratchet_session->sender_ephemeral_public_key));
    memcpy(session_pb.receiver_long_term_key, ratchet_session->receiver_long_term_public_key,
            sizeof(ratchet_session->receiver_long_term_public_key));

    if (ratchet_session->receiver_has_one_time_public_key) {
        session_pb.has_receiver_one_time_key = true;
        memcpy(session_pb.receiver_one_time_key, ratchet_session->receiver_one_time_public_key,
                sizeof(ratchet_session->receiver_one_time_public_key));
    } else {
        session_pb.has_receiver_one_time_key = false;
    }

    vscr_ratchet_serialize(ratchet_session->ratchet, &session_pb.ratchet);

    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_unused_bytes(output), vsc_buffer_capacity(output));

    VSCR_ASSERT(pb_encode(&ostream, Session_fields, &session_pb));
    vsc_buffer_inc_used(output, ostream.bytes_written);

    vscr_zeroize(&session_pb, sizeof(Session));
}

VSCR_PUBLIC vscr_ratchet_session_t *
vscr_ratchet_session_deserialize(vsc_data_t input, vscr_error_ctx_t *err_ctx) {

    VSCR_ASSERT(vsc_data_is_valid(input));

    if (input.len > Session_size) {
        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_error_PROTOBUF_DECODE_ERROR);

        return NULL;
    }

    Session session_pb = Session_init_zero;

    pb_istream_t istream = pb_istream_from_buffer(input.bytes, input.len);

    bool status = pb_decode(&istream, Session_fields, &session_pb);

    if (!status) {
        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_error_PROTOBUF_DECODE_ERROR);

        return NULL;
    }

    vscr_ratchet_session_t *session = vscr_ratchet_session_new();

    session->received_first_response = session_pb.received_first_response;
    session->is_initiator = session_pb.is_initiator;

    memcpy(session->sender_identity_public_key, session_pb.sender_identity_key, sizeof(session_pb.sender_identity_key));
    memcpy(session->sender_ephemeral_public_key, session_pb.sender_ephemeral_key,
            sizeof(session_pb.sender_ephemeral_key));
    memcpy(session->receiver_long_term_public_key, session_pb.receiver_long_term_key,
            sizeof(session_pb.receiver_long_term_key));

    if (session_pb.has_receiver_one_time_key) {
        session->receiver_has_one_time_public_key = true;
        memcpy(session->receiver_one_time_public_key, session_pb.receiver_one_time_key,
                sizeof(session_pb.receiver_one_time_key));
    } else {
        session->receiver_has_one_time_public_key = false;
    }

    vscr_ratchet_deserialize(&session_pb.ratchet, session->ratchet);

    vscr_zeroize(&session_pb, sizeof(Session));

    return session;
}
