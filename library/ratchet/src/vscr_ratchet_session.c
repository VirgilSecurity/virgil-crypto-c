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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_ratchet_session.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_rng.h"
#include "vscr_ratchet_session_defs.h"

#include <ed25519/ed25519.h>

// clang-format on
//  @end


#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <Message.pb.h>


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
        vscr_ratchet_session_release_ratchet(ratchet_session);

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
//  Setup dependency to the interface 'ratchet rng' with shared ownership.
//
VSCR_PUBLIC void
vscr_ratchet_session_use_rng(vscr_ratchet_session_t *ratchet_session, vscr_impl_t *rng) {

    VSCR_ASSERT_PTR(ratchet_session);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT_PTR(ratchet_session->rng == NULL);

    VSCR_ASSERT(vscr_ratchet_rng_is_implemented(rng));

    ratchet_session->rng = vscr_impl_shallow_copy(rng);
}

//
//  Setup dependency to the interface 'ratchet rng' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_session_take_rng(vscr_ratchet_session_t *ratchet_session, vscr_impl_t *rng) {

    VSCR_ASSERT_PTR(ratchet_session);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT_PTR(ratchet_session->rng == NULL);

    VSCR_ASSERT(vscr_ratchet_rng_is_implemented(rng));

    ratchet_session->rng = rng;
}

//
//  Release dependency to the interface 'ratchet rng'.
//
VSCR_PUBLIC void
vscr_ratchet_session_release_rng(vscr_ratchet_session_t *ratchet_session) {

    VSCR_ASSERT_PTR(ratchet_session);

    vscr_impl_destroy(&ratchet_session->rng);
}

//
//  Setup dependency to the class 'ratchet' with shared ownership.
//
VSCR_PUBLIC void
vscr_ratchet_session_use_ratchet(vscr_ratchet_session_t *ratchet_session, vscr_ratchet_t *ratchet) {

    VSCR_ASSERT_PTR(ratchet_session);
    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(ratchet_session->ratchet == NULL);

    ratchet_session->ratchet = vscr_ratchet_shallow_copy(ratchet);
}

//
//  Setup dependency to the class 'ratchet' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_session_take_ratchet(vscr_ratchet_session_t *ratchet_session, vscr_ratchet_t *ratchet) {

    VSCR_ASSERT_PTR(ratchet_session);
    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(ratchet_session->ratchet == NULL);

    ratchet_session->ratchet = ratchet;
}

//
//  Release dependency to the class 'ratchet'.
//
VSCR_PUBLIC void
vscr_ratchet_session_release_ratchet(vscr_ratchet_session_t *ratchet_session) {

    VSCR_ASSERT_PTR(ratchet_session);

    vscr_ratchet_destroy(&ratchet_session->ratchet);
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
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_session_cleanup_ctx(vscr_ratchet_session_t *ratchet_session) {

    VSCR_ASSERT_PTR(ratchet_session);

    vsc_buffer_destroy(&ratchet_session->sender_identity_public_key);
    vsc_buffer_destroy(&ratchet_session->sender_ephemeral_public_key);
    vsc_buffer_destroy(&ratchet_session->receiver_longterm_public_key);
    vsc_buffer_destroy(&ratchet_session->receiver_onetime_public_key);
}

VSCR_PUBLIC vscr_ratchet_session_t *
vscr_ratchet_session_new_with_members(bool received_first_response, vsc_buffer_t *sender_identity_public_key,
        vsc_buffer_t *sender_ephemeral_public_key, vsc_buffer_t *receiver_longterm_public_key,
        vsc_buffer_t *receiver_onetime_public_key, vscr_ratchet_t **ratchet_ref) {

    vscr_ratchet_session_t *ratchet_session = vscr_ratchet_session_new();

    ratchet_session->received_first_response = received_first_response;
    ratchet_session->sender_identity_public_key = sender_identity_public_key;
    ratchet_session->sender_ephemeral_public_key = sender_ephemeral_public_key;
    ratchet_session->receiver_longterm_public_key = receiver_longterm_public_key;
    ratchet_session->receiver_onetime_public_key = receiver_onetime_public_key;
    ratchet_session->ratchet = *ratchet_ref;
    *ratchet_ref = NULL;

    return ratchet_session;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_session_initiate(vscr_ratchet_session_t *ratchet_session, vsc_data_t sender_identity_private_key,
        vsc_data_t receiver_identity_public_key, vsc_buffer_t *receiver_long_term_public_key,
        vsc_buffer_t *receiver_one_time_public_key) {

    VSCR_ASSERT_PTR(ratchet_session);

    if (sender_identity_private_key.len != ED25519_KEY_LEN || receiver_identity_public_key.len != ED25519_KEY_LEN ||
            vsc_buffer_len(receiver_long_term_public_key) != ED25519_KEY_LEN) {

        return vscr_INVALID_ARGUMENTS;
    }

    size_t shared_secret_count = 3;
    if (receiver_one_time_public_key) {
        if (vsc_buffer_len(receiver_one_time_public_key) != ED25519_KEY_LEN) {

            return vscr_INVALID_ARGUMENTS;
        }

        shared_secret_count = 4;
    }

    vsc_buffer_t *ephemeral_private_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    vsc_buffer_make_secure(ephemeral_private_key);
    vscr_ratchet_rng_generate_random_data(ratchet_session->rng, ED25519_KEY_LEN, ephemeral_private_key);

    vsc_buffer_t *ratchet_private_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    vsc_buffer_make_secure(ratchet_private_key);
    vscr_ratchet_rng_generate_random_data(ratchet_session->rng, ED25519_KEY_LEN, ratchet_private_key);

    vsc_buffer_t *shared_secret = vsc_buffer_new_with_capacity(shared_secret_count * ED25519_DH_LEN);
    vsc_buffer_make_secure(shared_secret);

    // TODO: Add early quit logic
    unsigned int curve25519_status = 0;
    curve25519_status = (unsigned int)curve25519_key_exchange(vsc_buffer_unused_bytes(shared_secret),
            vsc_buffer_bytes(receiver_long_term_public_key), sender_identity_private_key.bytes);

    vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

    curve25519_status |= (unsigned int)curve25519_key_exchange(vsc_buffer_unused_bytes(shared_secret),
            receiver_identity_public_key.bytes, vsc_buffer_bytes(ephemeral_private_key));
    vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

    curve25519_status |= (unsigned int)curve25519_key_exchange(vsc_buffer_unused_bytes(shared_secret),
            vsc_buffer_bytes(receiver_long_term_public_key), vsc_buffer_bytes(ephemeral_private_key));
    vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

    if (receiver_one_time_public_key) {
        curve25519_status |= (unsigned int)curve25519_key_exchange(vsc_buffer_unused_bytes(shared_secret),
                vsc_buffer_bytes(receiver_one_time_public_key), vsc_buffer_bytes(ephemeral_private_key));
        vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

        ratchet_session->receiver_onetime_public_key = vsc_buffer_shallow_copy(receiver_one_time_public_key);
    }

    ratchet_session->sender_identity_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    curve25519_status |= (unsigned int)curve25519_get_pubkey(
            vsc_buffer_unused_bytes(ratchet_session->sender_identity_public_key), sender_identity_private_key.bytes);
    vsc_buffer_inc_used(ratchet_session->sender_identity_public_key, ED25519_KEY_LEN);

    ratchet_session->sender_ephemeral_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    curve25519_status |=
            (unsigned int)curve25519_get_pubkey(vsc_buffer_unused_bytes(ratchet_session->sender_ephemeral_public_key),
                    vsc_buffer_bytes(ephemeral_private_key));
    vsc_buffer_inc_used(ratchet_session->sender_ephemeral_public_key, ED25519_KEY_LEN);

    ratchet_session->receiver_longterm_public_key = vsc_buffer_shallow_copy(receiver_long_term_public_key);

    vscr_error_t result =
            vscr_ratchet_initiate(ratchet_session->ratchet, vsc_buffer_data(shared_secret), ratchet_private_key);

    vsc_buffer_destroy(&shared_secret);
    vsc_buffer_destroy(&ephemeral_private_key);
    vsc_buffer_destroy(&ratchet_private_key);

    return curve25519_status == 0 ? result : vscr_CURVE25519_ERROR;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_session_respond(vscr_ratchet_session_t *ratchet_session, vsc_buffer_t *sender_identity_public_key,
        vsc_buffer_t *sender_ephemeral_public_key, vsc_buffer_t *ratchet_public_key,
        vsc_buffer_t *receiver_identity_private_key, vsc_buffer_t *receiver_long_term_private_key,
        vsc_buffer_t *receiver_one_time_private_key, const RegularMessage *message) {

    VSCR_ASSERT_PTR(ratchet_session);

    if (vsc_buffer_len(sender_identity_public_key) != ED25519_KEY_LEN ||
            vsc_buffer_len(receiver_identity_private_key) != ED25519_KEY_LEN ||
            vsc_buffer_len(receiver_long_term_private_key) != ED25519_KEY_LEN) {

        return vscr_INVALID_ARGUMENTS;
    }

    size_t shared_secret_count = 3;
    if (receiver_one_time_private_key) {
        if (vsc_buffer_len(receiver_one_time_private_key) != ED25519_KEY_LEN) {

            return vscr_INVALID_ARGUMENTS;
        }

        shared_secret_count = 4;
    }

    // TODO: Add early quit logic
    unsigned int curve25519_status = 0;

    vsc_buffer_t *shared_secret = vsc_buffer_new_with_capacity(shared_secret_count * ED25519_DH_LEN);
    vsc_buffer_make_secure(shared_secret);

    curve25519_status |= (unsigned int)curve25519_key_exchange(vsc_buffer_unused_bytes(shared_secret),
            vsc_buffer_bytes(sender_identity_public_key), vsc_buffer_bytes(receiver_long_term_private_key));
    vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

    curve25519_status |= (unsigned int)curve25519_key_exchange(vsc_buffer_unused_bytes(shared_secret),
            vsc_buffer_bytes(sender_ephemeral_public_key), vsc_buffer_bytes(receiver_identity_private_key));
    vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

    curve25519_status |= (unsigned int)curve25519_key_exchange(vsc_buffer_unused_bytes(shared_secret),
            vsc_buffer_bytes(sender_ephemeral_public_key), vsc_buffer_bytes(receiver_long_term_private_key));
    vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

    if (receiver_one_time_private_key) {
        curve25519_status |= (unsigned int)curve25519_key_exchange(vsc_buffer_unused_bytes(shared_secret),
                vsc_buffer_bytes(sender_ephemeral_public_key), vsc_buffer_bytes(receiver_one_time_private_key));
        vsc_buffer_inc_used(shared_secret, ED25519_DH_LEN);

        ratchet_session->receiver_onetime_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
        curve25519_status |= (unsigned int)curve25519_get_pubkey(
                vsc_buffer_unused_bytes(ratchet_session->receiver_onetime_public_key),
                vsc_buffer_bytes(receiver_one_time_private_key));
        vsc_buffer_inc_used(ratchet_session->receiver_onetime_public_key, ED25519_KEY_LEN);
    }

    ratchet_session->sender_identity_public_key = vsc_buffer_shallow_copy(sender_identity_public_key);
    ratchet_session->sender_ephemeral_public_key = vsc_buffer_shallow_copy(sender_ephemeral_public_key);

    ratchet_session->receiver_longterm_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    curve25519_status |=
            (unsigned int)curve25519_get_pubkey(vsc_buffer_unused_bytes(ratchet_session->receiver_longterm_public_key),
                    vsc_buffer_bytes(receiver_long_term_private_key));
    vsc_buffer_inc_used(ratchet_session->receiver_longterm_public_key, ED25519_KEY_LEN);

    vscr_error_t status =
            vscr_ratchet_respond(ratchet_session->ratchet, vsc_buffer_data(shared_secret), ratchet_public_key, message);

    vsc_buffer_destroy(&shared_secret);

    if (status != vscr_SUCCESS)
        return status;

    if (curve25519_status != 0)
        return vscr_CURVE25519_ERROR;

    return vscr_SUCCESS;
}

VSCR_PUBLIC size_t
vscr_ratchet_session_encrypt_len(vscr_ratchet_session_t *ratchet_session, size_t plain_text_len) {

    VSCR_ASSERT_PTR(ratchet_session);

    size_t top_sequence_len = 1 + 3       /* SEQUENCE */
                              + 1 + 1 + 5 /* VERSION */
                              + 1 + 3 +
                              vscr_ratchet_encrypt_len(ratchet_session->ratchet, plain_text_len); /* message */

    if (!ratchet_session->received_first_response) {
        top_sequence_len += 1 + 1 + 5     /* version */
                            + 1 + 1 + 32  /* sender_identity_key */
                            + 1 + 1 + 32  /* sender_ephemeral_key */
                            + 1 + 1 + 32  /* receiver_long_term_key */
                            + 1 + 1 + 32; /* receiver_one_time_public_key */
    }

    return top_sequence_len;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_session_encrypt(
        vscr_ratchet_session_t *ratchet_session, vsc_data_t plain_text, vsc_buffer_t *cipher_text) {

    VSCR_ASSERT_PTR(ratchet_session);
    VSCR_ASSERT(
            vsc_buffer_unused_len(cipher_text) >= vscr_ratchet_session_encrypt_len(ratchet_session, plain_text.len));

    vscr_error_t result;

    Message ratchet_message = Message_init_zero;
    ratchet_message.version = vscr_ratchet_common_RATCHET_MESSAGE_VERSION;

    if (ratchet_session->received_first_response) {
        RegularMessage regular_message = RegularMessage_init_zero;
        bool status = true;

        result = vscr_ratchet_encrypt(ratchet_session->ratchet, plain_text, &regular_message);
        if (result == vscr_SUCCESS) {
            ratchet_message.which_message = Message_regular_message_tag;
            ratchet_message.message.regular_message = regular_message;

            pb_ostream_t ostream =
                    pb_ostream_from_buffer(vsc_buffer_unused_bytes(cipher_text), vsc_buffer_capacity(cipher_text));

            status = pb_encode(&ostream, Message_fields, &ratchet_message);

            if (!status) {
                result = vscr_PROTOBUF_ENCODE_ERROR;
            }

            vsc_buffer_inc_used(cipher_text, ostream.bytes_written);
        }
    } else {
        RegularMessage regular_message = RegularMessage_init_zero;

        result = vscr_ratchet_encrypt(ratchet_session->ratchet, plain_text, &regular_message);

        if (result == vscr_SUCCESS) {
            PrekeyMessage prekey_message = PrekeyMessage_init_zero;

            prekey_message.version = vscr_ratchet_common_RATCHET_PROTOCOL_VERSION;

            memcpy(prekey_message.sender_identity_key, ratchet_session->sender_identity_public_key->bytes,
                    ratchet_session->sender_identity_public_key->len);

            memcpy(prekey_message.sender_ephemeral_key, ratchet_session->sender_ephemeral_public_key->bytes,
                    ratchet_session->sender_ephemeral_public_key->len);

            memcpy(prekey_message.receiver_longterm_key, ratchet_session->receiver_longterm_public_key->bytes,
                    ratchet_session->receiver_longterm_public_key->len);

            memcpy(prekey_message.receiver_onetime_key, ratchet_session->receiver_onetime_public_key->bytes,
                    ratchet_session->receiver_onetime_public_key->len);

            prekey_message.regular_message = regular_message;

            ratchet_message.which_message = Message_prekey_message_tag;
            ratchet_message.message.prekey_message = prekey_message;

            pb_ostream_t ostream =
                    pb_ostream_from_buffer(vsc_buffer_unused_bytes(cipher_text), vsc_buffer_capacity(cipher_text));

            bool status = true;
            status = pb_encode(&ostream, Message_fields, &ratchet_message);

            if (!status) {
                result = vscr_PROTOBUF_ENCODE_ERROR;
            }

            vsc_buffer_inc_used(cipher_text, ostream.bytes_written);
        }
    }

    return result;
}

VSCR_PUBLIC size_t
vscr_ratchet_session_decrypt_len(vscr_ratchet_session_t *ratchet_session, const Message *message) {

    VSCR_UNUSED(ratchet_session);

    size_t len = 0;

    // FIXME
    if (message->which_message == Message_regular_message_tag) {
        len = vscr_ratchet_decrypt_len(ratchet_session->ratchet, message->message.regular_message.cipher_text.size);
    } else if (message->which_message == Message_prekey_message_tag) {
        len = vscr_ratchet_decrypt_len(
                ratchet_session->ratchet, message->message.prekey_message.regular_message.cipher_text.size);
    }

    return len;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_session_decrypt(vscr_ratchet_session_t *ratchet_session, Message *message, vsc_buffer_t *plain_text) {

    VSCR_ASSERT_PTR(ratchet_session);
    VSCR_ASSERT(vsc_buffer_unused_len(plain_text) >= vscr_ratchet_session_decrypt_len(ratchet_session, message));

    vscr_error_t result;

    if (message->which_message == Message_regular_message_tag) {
        result = vscr_ratchet_decrypt(ratchet_session->ratchet, &message->message.regular_message, plain_text);
    } else if (message->which_message == Message_prekey_message_tag) {
        vscr_error_ctx_t error;
        vscr_error_ctx_reset(&error);

        result = vscr_ratchet_decrypt(
                ratchet_session->ratchet, &message->message.prekey_message.regular_message, plain_text);
    } else {
        result = vscr_WRONG_MESSAGE_FORMAT;
    }

    if (result == vscr_SUCCESS)
        ratchet_session->received_first_response = true;

    return result;
}

VSCR_PUBLIC size_t
vscr_ratchet_session_serialize_len(vscr_ratchet_session_t *ratchet_session) {

    VSCR_ASSERT_PTR(ratchet_session);

    //  RATCHETSession ::= SEQUENCE {
    //       received first response BOOL,
    //       sender identity public key OCTET_STRING,
    //       sender ephemeral public key OCTET_STRING,
    //       receiver longterm public key OCTET_STRING,
    //       receiver onetime public key OCTET_STRING,
    //       ratchet OCTET_STRING }

    size_t top_sequence_len = 1 + 3                                                           /* SEQUENCE */
                              + 1 + 1 + 5                                                     /* INTEGER */
                              + 1 + 1 + 32                                                    /* KEY */
                              + 1 + 1 + 32                                                    /* KEY */
                              + 1 + 1 + 32                                                    /* KEY */
                              + 1 + 1 + 32                                                    /* KEY */
                              + 1 + 3 + vscr_ratchet_serialize_len(ratchet_session->ratchet); /* message */


    return top_sequence_len;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_session_serialize(vscr_ratchet_session_t *ratchet_session, vsc_buffer_t *output) {

    //  RATCHETSession ::= SEQUENCE {
    //       received first response BOOL,
    //       sender identity public key OCTET_STRING,
    //       sender ephemeral public key OCTET_STRING,
    //       receiver longterm public key OCTET_STRING,
    //       receiver onetime public key OCTET_STRING,
    //       ratchet OCTET_STRING }

    VSCR_ASSERT_PTR(ratchet_session);

    VSCR_ASSERT(vsc_buffer_unused_len(output) >= vscr_ratchet_session_serialize_len(ratchet_session));

    Session ratchet_session_value = Session_init_zero;

    ratchet_session_value.received_first_response = ratchet_session->received_first_response;

    memcpy(ratchet_session_value.sender_identity_key, ratchet_session->sender_identity_public_key->bytes,
            ratchet_session->sender_identity_public_key->len);

    memcpy(ratchet_session_value.sender_ephemeral_key, ratchet_session->sender_ephemeral_public_key->bytes,
            ratchet_session->sender_ephemeral_public_key->len);

    memcpy(ratchet_session_value.receiver_longterm_key, ratchet_session->receiver_longterm_public_key->bytes,
            ratchet_session->receiver_longterm_public_key->len);

    memcpy(ratchet_session_value.receiver_onetime_key, ratchet_session->receiver_onetime_public_key->bytes,
            ratchet_session->receiver_onetime_public_key->len);

    vsc_buffer_t *ratchet_buff = vsc_buffer_new_with_capacity(vscr_ratchet_serialize_len(ratchet_session->ratchet));
    vsc_buffer_make_secure(ratchet_buff);

    vscr_error_t status = vscr_ratchet_serialize(ratchet_session->ratchet, ratchet_buff);

    if (status != vscr_SUCCESS) {
        return status;
    }

    vsc_buffer_inc_used(ratchet_buff, vscr_ratchet_serialize_len(ratchet_session->ratchet));

    memcpy(ratchet_session_value.ratchet, ratchet_buff->bytes, ratchet_buff->len);

    vsc_buffer_destroy(&ratchet_buff);

    bool proto_status = true;
    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_unused_bytes(output), vsc_buffer_capacity(output));

    proto_status = pb_encode(&ostream, Session_fields, &ratchet_session);

    vsc_buffer_inc_used(output, ostream.bytes_written);

    if (!proto_status) {
        return vscr_PROTOBUF_ENCODE_ERROR;
    }

    return vscr_SUCCESS;
}

VSCR_PUBLIC vscr_ratchet_session_t *
vscr_ratchet_session_deserialize(vsc_data_t input, vscr_error_ctx_t *err_ctx) {

    //  RATCHETSession ::= SEQUENCE {
    //       received first response BOOL,
    //       sender identity public key OCTET_STRING,
    //       sender ephemeral public key OCTET_STRING,
    //       receiver longterm public key OCTET_STRING,
    //       receiver onetime public key OCTET_STRING,
    //       ratchet OCTET_STRING }

    VSCR_ASSERT(vsc_data_is_valid(input));

    Session ratchet_session_proto = Session_init_zero;

    bool status = true;
    pb_istream_t istream = pb_istream_from_buffer(input.bytes, input.len);

    status = pb_decode(&istream, Session_fields, &ratchet_session_proto);

    if (!status) {

        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_PROTOBUF_ENCODE_ERROR);

        return NULL;
    }

    vsc_buffer_t *sender_identity_public_key = vsc_buffer_new_with_data(
            vsc_data(ratchet_session_proto.sender_identity_key, sizeof(ratchet_session_proto.sender_identity_key)));
    vsc_buffer_t *sender_ephemeral_public_key = vsc_buffer_new_with_data(
            vsc_data(ratchet_session_proto.sender_ephemeral_key, sizeof(ratchet_session_proto.sender_ephemeral_key)));
    vsc_buffer_t *receiver_longterm_public_key = vsc_buffer_new_with_data(
            vsc_data(ratchet_session_proto.receiver_longterm_key, sizeof(ratchet_session_proto.receiver_longterm_key)));
    vsc_buffer_t *receiver_onetime_public_key = vsc_buffer_new_with_data(
            vsc_data(ratchet_session_proto.receiver_onetime_key, sizeof(ratchet_session_proto.receiver_onetime_key)));

    vsc_data_t ratchet_buff = vsc_data(ratchet_session_proto.ratchet, sizeof(ratchet_session_proto));

    vscr_ratchet_t *ratchet = vscr_ratchet_deserialize(ratchet_buff, err_ctx);

    if (err_ctx->error != vscr_SUCCESS) {
        vscr_ratchet_destroy(&ratchet);

        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_WRONG_MESSAGE_FORMAT);

        return NULL;
    }

    vscr_ratchet_session_t *ratchet_session = vscr_ratchet_session_new_with_members(
            ratchet_session_proto.received_first_response, sender_identity_public_key, sender_ephemeral_public_key,
            receiver_longterm_public_key, receiver_onetime_public_key,
            &ratchet); // FIXME

    return ratchet_session;
}
