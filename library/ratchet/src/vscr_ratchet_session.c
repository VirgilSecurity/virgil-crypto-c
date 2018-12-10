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

#include <virgil/crypto/foundation/vscf_asn1wr.h>
#include <virgil/crypto/foundation/vscf_asn1rd.h>
#include <ed25519/ed25519.h>

// clang-format on
//  @end

#include <virgil/crypto/common/private/vsc_buffer_defs.h>

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
vscr_ratchet_session_init_ctx(vscr_ratchet_session_t *ratchet_session_ctx);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_session_cleanup_ctx(vscr_ratchet_session_t *ratchet_session_ctx);

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
vscr_ratchet_session_init(vscr_ratchet_session_t *ratchet_session_ctx) {

    VSCR_ASSERT_PTR(ratchet_session_ctx);

    vscr_zeroize(ratchet_session_ctx, sizeof(vscr_ratchet_session_t));

    ratchet_session_ctx->refcnt = 1;

    vscr_ratchet_session_init_ctx(ratchet_session_ctx);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_session_cleanup(vscr_ratchet_session_t *ratchet_session_ctx) {

    if (ratchet_session_ctx == NULL) {
        return;
    }

    if (ratchet_session_ctx->refcnt == 0) {
        return;
    }

    if (--ratchet_session_ctx->refcnt == 0) {
        vscr_ratchet_session_cleanup_ctx(ratchet_session_ctx);

        vscr_ratchet_session_release_rng(ratchet_session_ctx);
        vscr_ratchet_session_release_ratchet(ratchet_session_ctx);

        vscr_zeroize(ratchet_session_ctx, sizeof(vscr_ratchet_session_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_session_t *
vscr_ratchet_session_new(void) {

    vscr_ratchet_session_t *ratchet_session_ctx = (vscr_ratchet_session_t *) vscr_alloc(sizeof (vscr_ratchet_session_t));
    VSCR_ASSERT_ALLOC(ratchet_session_ctx);

    vscr_ratchet_session_init(ratchet_session_ctx);

    ratchet_session_ctx->self_dealloc_cb = vscr_dealloc;

    return ratchet_session_ctx;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_session_delete(vscr_ratchet_session_t *ratchet_session_ctx) {

    if (ratchet_session_ctx == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = ratchet_session_ctx->self_dealloc_cb;

    vscr_ratchet_session_cleanup(ratchet_session_ctx);

    if (ratchet_session_ctx->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(ratchet_session_ctx);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_session_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_session_destroy(vscr_ratchet_session_t **ratchet_session_ctx_ref) {

    VSCR_ASSERT_PTR(ratchet_session_ctx_ref);

    vscr_ratchet_session_t *ratchet_session_ctx = *ratchet_session_ctx_ref;
    *ratchet_session_ctx_ref = NULL;

    vscr_ratchet_session_delete(ratchet_session_ctx);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_session_t *
vscr_ratchet_session_copy(vscr_ratchet_session_t *ratchet_session_ctx) {

    VSCR_ASSERT_PTR(ratchet_session_ctx);

    ++ratchet_session_ctx->refcnt;

    return ratchet_session_ctx;
}

//
//  Setup dependency to the interface 'ratchet rng' with shared ownership.
//
VSCR_PUBLIC void
vscr_ratchet_session_use_rng(vscr_ratchet_session_t *ratchet_session_ctx, vscr_impl_t *rng) {

    VSCR_ASSERT_PTR(ratchet_session_ctx);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT_PTR(ratchet_session_ctx->rng == NULL);

    VSCR_ASSERT(vscr_ratchet_rng_is_implemented(rng));

    ratchet_session_ctx->rng = vscr_impl_copy(rng);
}

//
//  Setup dependency to the interface 'ratchet rng' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_session_take_rng(vscr_ratchet_session_t *ratchet_session_ctx, vscr_impl_t *rng) {

    VSCR_ASSERT_PTR(ratchet_session_ctx);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT_PTR(ratchet_session_ctx->rng == NULL);

    VSCR_ASSERT(vscr_ratchet_rng_is_implemented(rng));

    ratchet_session_ctx->rng = rng;
}

//
//  Release dependency to the interface 'ratchet rng'.
//
VSCR_PUBLIC void
vscr_ratchet_session_release_rng(vscr_ratchet_session_t *ratchet_session_ctx) {

    VSCR_ASSERT_PTR(ratchet_session_ctx);

    vscr_impl_destroy(&ratchet_session_ctx->rng);
}

//
//  Setup dependency to the class 'ratchet' with shared ownership.
//
VSCR_PUBLIC void
vscr_ratchet_session_use_ratchet(vscr_ratchet_session_t *ratchet_session_ctx, vscr_ratchet_t *ratchet) {

    VSCR_ASSERT_PTR(ratchet_session_ctx);
    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(ratchet_session_ctx->ratchet == NULL);

    ratchet_session_ctx->ratchet = vscr_ratchet_copy(ratchet);
}

//
//  Setup dependency to the class 'ratchet' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_session_take_ratchet(vscr_ratchet_session_t *ratchet_session_ctx, vscr_ratchet_t *ratchet) {

    VSCR_ASSERT_PTR(ratchet_session_ctx);
    VSCR_ASSERT_PTR(ratchet);
    VSCR_ASSERT_PTR(ratchet_session_ctx->ratchet == NULL);

    ratchet_session_ctx->ratchet = ratchet;
}

//
//  Release dependency to the class 'ratchet'.
//
VSCR_PUBLIC void
vscr_ratchet_session_release_ratchet(vscr_ratchet_session_t *ratchet_session_ctx) {

    VSCR_ASSERT_PTR(ratchet_session_ctx);

    vscr_ratchet_destroy(&ratchet_session_ctx->ratchet);
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
vscr_ratchet_session_init_ctx(vscr_ratchet_session_t *ratchet_session_ctx) {

    VSCR_ASSERT_PTR(ratchet_session_ctx);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_session_cleanup_ctx(vscr_ratchet_session_t *ratchet_session_ctx) {

    VSCR_ASSERT_PTR(ratchet_session_ctx);

    vsc_buffer_destroy(&ratchet_session_ctx->sender_identity_public_key);
    vsc_buffer_destroy(&ratchet_session_ctx->sender_ephemeral_public_key);
    vsc_buffer_destroy(&ratchet_session_ctx->receiver_longterm_public_key);
    vsc_buffer_destroy(&ratchet_session_ctx->receiver_onetime_public_key);
}

VSCR_PUBLIC vscr_ratchet_session_t *
vscr_ratchet_session_new_with_members(bool received_first_response, vsc_buffer_t *sender_identity_public_key,
        vsc_buffer_t *sender_ephemeral_public_key, vsc_buffer_t *receiver_longterm_public_key,
        vsc_buffer_t *receiver_onetime_public_key, vscr_ratchet_t **ratchet_ref) {

    vscr_ratchet_session_t *ratchet_session_ctx = vscr_ratchet_session_new();

    ratchet_session_ctx->received_first_response = received_first_response;
    ratchet_session_ctx->sender_identity_public_key = sender_identity_public_key;
    ratchet_session_ctx->sender_ephemeral_public_key = sender_ephemeral_public_key;
    ratchet_session_ctx->receiver_longterm_public_key = receiver_longterm_public_key;
    ratchet_session_ctx->receiver_onetime_public_key = receiver_onetime_public_key;
    ratchet_session_ctx->ratchet = *ratchet_ref;
    *ratchet_ref = NULL;

    return ratchet_session_ctx;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_session_initiate(vscr_ratchet_session_t *ratchet_session_ctx, vsc_data_t sender_identity_private_key,
        vsc_data_t receiver_identity_public_key, vsc_buffer_t *receiver_long_term_public_key,
        vsc_buffer_t *receiver_one_time_public_key) {

    VSCR_ASSERT_PTR(ratchet_session_ctx);

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
    vscr_ratchet_rng_generate_random_data(ratchet_session_ctx->rng, ED25519_KEY_LEN, ephemeral_private_key);

    vsc_buffer_t *ratchet_private_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    vsc_buffer_make_secure(ratchet_private_key);
    vscr_ratchet_rng_generate_random_data(ratchet_session_ctx->rng, ED25519_KEY_LEN, ratchet_private_key);

    vsc_buffer_t *shared_secret = vsc_buffer_new_with_capacity(shared_secret_count * ED25519_DH_LEN);
    vsc_buffer_make_secure(shared_secret);

    // TODO: Add early quit logic
    unsigned int curve25519_status = 0;
    curve25519_status = (unsigned int)curve25519_key_exchange(vsc_buffer_ptr(shared_secret),
            vsc_buffer_bytes(receiver_long_term_public_key), sender_identity_private_key.bytes);

    vsc_buffer_reserve(shared_secret, ED25519_DH_LEN);

    curve25519_status |= (unsigned int)curve25519_key_exchange(
            vsc_buffer_ptr(shared_secret), receiver_identity_public_key.bytes, vsc_buffer_bytes(ephemeral_private_key));
    vsc_buffer_reserve(shared_secret, ED25519_DH_LEN);

    curve25519_status |= (unsigned int)curve25519_key_exchange(vsc_buffer_ptr(shared_secret),
            vsc_buffer_bytes(receiver_long_term_public_key), vsc_buffer_bytes(ephemeral_private_key));
    vsc_buffer_reserve(shared_secret, ED25519_DH_LEN);

    if (receiver_one_time_public_key) {
        curve25519_status |= (unsigned int)curve25519_key_exchange(vsc_buffer_ptr(shared_secret),
                vsc_buffer_bytes(receiver_one_time_public_key), vsc_buffer_bytes(ephemeral_private_key));
        vsc_buffer_reserve(shared_secret, ED25519_DH_LEN);

        ratchet_session_ctx->receiver_onetime_public_key = vsc_buffer_copy(receiver_one_time_public_key);
    }

    ratchet_session_ctx->sender_identity_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    curve25519_status |= (unsigned int)curve25519_get_pubkey(
            vsc_buffer_ptr(ratchet_session_ctx->sender_identity_public_key), sender_identity_private_key.bytes);
    vsc_buffer_reserve(ratchet_session_ctx->sender_identity_public_key, ED25519_KEY_LEN);

    ratchet_session_ctx->sender_ephemeral_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    curve25519_status |= (unsigned int)curve25519_get_pubkey(
            vsc_buffer_ptr(ratchet_session_ctx->sender_ephemeral_public_key), vsc_buffer_bytes(ephemeral_private_key));
    vsc_buffer_reserve(ratchet_session_ctx->sender_ephemeral_public_key, ED25519_KEY_LEN);

    ratchet_session_ctx->receiver_longterm_public_key = vsc_buffer_copy(receiver_long_term_public_key);

    vscr_error_t result =
            vscr_ratchet_initiate(ratchet_session_ctx->ratchet, vsc_buffer_data(shared_secret), ratchet_private_key);

    vsc_buffer_destroy(&shared_secret);
    vsc_buffer_destroy(&ephemeral_private_key);
    vsc_buffer_destroy(&ratchet_private_key);

    return curve25519_status == 0 ? result : vscr_CURVE25519_ERROR;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_session_respond(vscr_ratchet_session_t *ratchet_session_ctx, vsc_buffer_t *sender_identity_public_key,
        vsc_buffer_t *sender_ephemeral_public_key, vsc_buffer_t *ratchet_public_key,
        vsc_buffer_t *receiver_identity_private_key, vsc_buffer_t *receiver_long_term_private_key,
        vsc_buffer_t *receiver_one_time_private_key, const RegularMessage message) {

    VSCR_ASSERT_PTR(ratchet_session_ctx);

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

    curve25519_status |= (unsigned int)curve25519_key_exchange(vsc_buffer_ptr(shared_secret),
            vsc_buffer_bytes(sender_identity_public_key), vsc_buffer_bytes(receiver_long_term_private_key));
    vsc_buffer_reserve(shared_secret, ED25519_DH_LEN);

    curve25519_status |= (unsigned int)curve25519_key_exchange(vsc_buffer_ptr(shared_secret),
            vsc_buffer_bytes(sender_ephemeral_public_key), vsc_buffer_bytes(receiver_identity_private_key));
    vsc_buffer_reserve(shared_secret, ED25519_DH_LEN);

    curve25519_status |= (unsigned int)curve25519_key_exchange(vsc_buffer_ptr(shared_secret),
            vsc_buffer_bytes(sender_ephemeral_public_key), vsc_buffer_bytes(receiver_long_term_private_key));
    vsc_buffer_reserve(shared_secret, ED25519_DH_LEN);

    if (receiver_one_time_private_key) {
        curve25519_status |= (unsigned int)curve25519_key_exchange(vsc_buffer_ptr(shared_secret),
                vsc_buffer_bytes(sender_ephemeral_public_key), vsc_buffer_bytes(receiver_one_time_private_key));
        vsc_buffer_reserve(shared_secret, ED25519_DH_LEN);

        ratchet_session_ctx->receiver_onetime_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
        curve25519_status |=
                (unsigned int)curve25519_get_pubkey(vsc_buffer_ptr(ratchet_session_ctx->receiver_onetime_public_key),
                        vsc_buffer_bytes(receiver_one_time_private_key));
        vsc_buffer_reserve(ratchet_session_ctx->receiver_onetime_public_key, ED25519_KEY_LEN);
    }

    ratchet_session_ctx->sender_identity_public_key = vsc_buffer_copy(sender_identity_public_key);
    ratchet_session_ctx->sender_ephemeral_public_key = vsc_buffer_copy(sender_ephemeral_public_key);

    ratchet_session_ctx->receiver_longterm_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    curve25519_status |=
            (unsigned int)curve25519_get_pubkey(vsc_buffer_ptr(ratchet_session_ctx->receiver_longterm_public_key),
                    vsc_buffer_bytes(receiver_long_term_private_key));
    vsc_buffer_reserve(ratchet_session_ctx->receiver_longterm_public_key, ED25519_KEY_LEN);

    vscr_error_t status = vscr_ratchet_respond(ratchet_session_ctx->ratchet, vsc_buffer_data(shared_secret), ratchet_public_key, message);

    vsc_buffer_destroy(&shared_secret);

    if (status != vscr_SUCCESS)
        return status;

    if (curve25519_status != 0)
        return vscr_CURVE25519_ERROR;

    return vscr_SUCCESS;
}

VSCR_PUBLIC size_t
vscr_ratchet_session_encrypt_len(vscr_ratchet_session_t *ratchet_session_ctx, size_t plain_text_len) {

    VSCR_ASSERT_PTR(ratchet_session_ctx);

    // FIXME
    if (ratchet_session_ctx->received_first_response) {
        return vscr_ratchet_message_serialize_len(
                vscr_ratchet_encrypt_len(ratchet_session_ctx->ratchet, plain_text_len));
    } else {
        size_t top_sequence_len = 1 + 3 /* SEQUENCE */
                                  + 1 + 1 + 2 /* version */
                                  + 1 + 1 + 32 /* sender_identity_key */
                                  + 1 + 1 + 32 /* sender_ephemeral_key */
                                  + 1 + 1 + 32 /* receiver_long_term_key */
                                  + 1 + 1 + 32 /* receiver_one_time_public_key */
                                  + 1 + 3 + vscr_ratchet_encrypt_len(ratchet_session_ctx->ratchet, plain_text_len); /* message */

        return vscr_ratchet_message_serialize_len(top_sequence_len);
    }
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_session_encrypt(vscr_ratchet_session_t *ratchet_session_ctx, vsc_data_t plain_text,
        vsc_buffer_t *cipher_text) {

    VSCR_ASSERT_PTR(ratchet_session_ctx);
    VSCR_ASSERT(vsc_buffer_left(cipher_text) >= vscr_ratchet_session_encrypt_len(ratchet_session_ctx, plain_text.len));

    vscr_error_t result;

    if (ratchet_session_ctx->received_first_response) {
        size_t len = vscr_ratchet_encrypt_len(ratchet_session_ctx->ratchet, plain_text.len);

        vsc_buffer_t *cipher_buffer = vsc_buffer_new_with_capacity(len);

        RegularMessage regular_message = RegularMessage_init_zero;
        bool status = true;

        result = vscr_ratchet_encrypt(ratchet_session_ctx->ratchet, plain_text, &regular_message);
        if (result == vscr_SUCCESS) {

            pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_ptr(cipher_buffer),
                                                          vsc_buffer_capacity(cipher_buffer));

            status = pb_encode(&ostream, RegularMessage_fields, &regular_message);

            if (!status) {
                // FIXME
                result = vscr_ASN1_WRITE_ERROR;
            }

            vsc_buffer_reserve(cipher_buffer, ostream.bytes_written);

            if (result == vscr_SUCCESS) {
                vscr_ratchet_message_t *ratchet_message = vscr_ratchet_message_new_with_members(
                        vscr_ratchet_common_RATCHET_MESSAGE_VERSION, vscr_ratchet_message_TYPE_REGULAR, cipher_buffer);

                result = vscr_ratchet_message_serialize(ratchet_message, cipher_text);

                vscr_ratchet_message_destroy(&ratchet_message);
            }
        }

        vsc_buffer_destroy(&cipher_buffer);
    } else {
        size_t len = vscr_ratchet_encrypt_len(ratchet_session_ctx->ratchet, plain_text.len);
        vsc_buffer_t *cipher_buffer = vsc_buffer_new_with_capacity(len);

        RegularMessage regular_message = RegularMessage_init_zero;

        result = vscr_ratchet_encrypt(ratchet_session_ctx->ratchet, plain_text, &regular_message);

        if (result == vscr_SUCCESS) {
            PrekeyMessage prekey_message = PrekeyMessage_init_zero;

            prekey_message.version = vscr_ratchet_common_RATCHET_PROTOCOL_VERSION;

            memcpy(prekey_message.sender_identity_key, ratchet_session_ctx->sender_identity_public_key->bytes,
                    ratchet_session_ctx->sender_identity_public_key->len);

            memcpy(prekey_message.sender_ephemeral_key, ratchet_session_ctx->sender_ephemeral_public_key->bytes,
                   ratchet_session_ctx->sender_ephemeral_public_key->len);

            memcpy(prekey_message.receiver_long_term_key, ratchet_session_ctx->receiver_longterm_public_key->bytes,
                   ratchet_session_ctx->receiver_longterm_public_key->len);

            memcpy(prekey_message.receiver_one_time_key, ratchet_session_ctx->receiver_onetime_public_key->bytes,
                   ratchet_session_ctx->receiver_onetime_public_key->len);

            prekey_message.regular_message = regular_message;

            size_t top_sequence_len = 1 + 3 /* SEQUENCE */
                                      + 1 + 1 + 2 /* version */
                                      + 1 + 1 + 32 /* sender_identity_key */
                                      + 1 + 1 + 32 /* sender_ephemeral_key */
                                      + 1 + 1 + 32 /* receiver_long_term_key */
                                      + 1 + 1 + 32 /* receiver_one_time_public_key */
                                      + 1 + 3 + vsc_buffer_len(cipher_buffer); /* message */

            vsc_buffer_t *prekey_buffer = vsc_buffer_new_with_capacity(top_sequence_len);

            bool status = true;

            pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_ptr(prekey_buffer), vsc_buffer_capacity(prekey_buffer));

            status = pb_encode(&ostream, PrekeyMessage_fields, &prekey_message);

            if (!status) {
                // FIXME
                result = vscr_ASN1_WRITE_ERROR;
            }

            vsc_buffer_reserve(prekey_buffer, ostream.bytes_written);

            if (result == vscr_SUCCESS) {
                vscr_ratchet_message_t *ratchet_message = vscr_ratchet_message_new_with_members(
                        vscr_ratchet_common_RATCHET_MESSAGE_VERSION, vscr_ratchet_message_TYPE_PREKEY, prekey_buffer);

                result = vscr_ratchet_message_serialize(ratchet_message, cipher_text);

                vscr_ratchet_message_destroy(&ratchet_message);
            }

            vsc_buffer_destroy(&prekey_buffer);
        }

        vsc_buffer_destroy(&cipher_buffer);
    }

    return result;
}

VSCR_PUBLIC size_t
vscr_ratchet_session_decrypt_len(vscr_ratchet_session_t *ratchet_session_ctx, const vscr_ratchet_message_t *message) {

    VSCR_UNUSED(ratchet_session_ctx);
    VSCR_ASSERT_PTR(message);

    // TODO: Optimize
    return vsc_buffer_len(message->message);
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_session_decrypt(vscr_ratchet_session_t *ratchet_session_ctx, const vscr_ratchet_message_t *message,
        vsc_buffer_t *plain_text) {

    VSCR_ASSERT_PTR(ratchet_session_ctx);
    VSCR_ASSERT_PTR(message);
    VSCR_ASSERT(vsc_buffer_left(plain_text) >= vscr_ratchet_session_decrypt_len(ratchet_session_ctx, message));

    vscr_error_t result;

    if (message->type == vscr_ratchet_message_TYPE_REGULAR) {
        RegularMessage regular_message = RegularMessage_init_zero;

        bool status = true;

        pb_istream_t istream = pb_istream_from_buffer(vsc_buffer_data(message->message).bytes,
                vsc_buffer_data(message->message).len);

        status = pb_decode(&istream, RegularMessage_fields, &regular_message);

        if (status) {
            result = vscr_ratchet_decrypt(ratchet_session_ctx->ratchet, &regular_message, plain_text);
        } else {
            // FIXME
            result = vscr_ASN1_READ_ERROR;
        }
    } else if (message->type == vscr_ratchet_message_TYPE_PREKEY) {
        vscr_error_ctx_t error_ctx;
        vscr_error_ctx_reset(&error_ctx);

        PrekeyMessage prekey_message = PrekeyMessage_init_zero;
        bool status = true;

        pb_istream_t istream = pb_istream_from_buffer(vsc_buffer_data(message->message).bytes,
                vsc_buffer_data(message->message).len);

        status = pb_decode(&istream, PrekeyMessage_fields, &prekey_message);

        if (status) {
            result = vscr_ratchet_decrypt(
                    ratchet_session_ctx->ratchet, &prekey_message.regular_message, plain_text);
        } else {
            // FIXME
            result = vscr_ASN1_WRITE_ERROR;
        }
    } else {
        result = vscr_WRONG_MESSAGE_FORMAT;
    }

    if (result == vscr_SUCCESS)
        ratchet_session_ctx->received_first_response = true;

    return result;
}

VSCR_PUBLIC size_t
vscr_ratchet_session_serialize_len(vscr_ratchet_session_t *ratchet_session_ctx) {

    VSCR_ASSERT_PTR(ratchet_session_ctx);

    //  RATCHETSession ::= SEQUENCE {
    //       received first response BOOL,
    //       sender identity public key OCTET_STRING,
    //       sender ephemeral public key OCTET_STRING,
    //       receiver longterm public key OCTET_STRING,
    //       receiver onetime public key OCTET_STRING,
    //       ratchet OCTET_STRING }

    size_t top_sequence_len = 1 + 3 /* SEQUENCE */
                              + 1 + 1 + 2 /* INTEGER */
                              + 1 + 1 + 32 /* KEY */
                              + 1 + 1 + 32 /* KEY */
                              + 1 + 1 + 32 /* KEY */
                              + 1 + 1 + 32 /* KEY */
                              + 1 + 3 + vscr_ratchet_serialize_len(ratchet_session_ctx->ratchet); /* message */


    return top_sequence_len;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_session_serialize(vscr_ratchet_session_t *ratchet_session_ctx, vsc_buffer_t *output) {

    //  RATCHETSession ::= SEQUENCE {
    //       received first response BOOL,
    //       sender identity public key OCTET_STRING,
    //       sender ephemeral public key OCTET_STRING,
    //       receiver longterm public key OCTET_STRING,
    //       receiver onetime public key OCTET_STRING,
    //       ratchet OCTET_STRING }

    VSCR_ASSERT_PTR(ratchet_session_ctx);

    VSCR_ASSERT(vsc_buffer_left(output) >= vscr_ratchet_session_serialize_len(ratchet_session_ctx));

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(output), vsc_buffer_left(output));

    size_t top_sequence_len = 0;

    vsc_buffer_t *ratchet_buff = vsc_buffer_new_with_capacity(vscr_ratchet_serialize_len(ratchet_session_ctx->ratchet));
    vsc_buffer_make_secure(ratchet_buff);

    vscr_error_t status = vscr_ratchet_serialize(ratchet_session_ctx->ratchet, ratchet_buff);

    vsc_buffer_destroy(&ratchet_buff);

    if (status != vscr_SUCCESS) {
        vscf_asn1wr_destroy(&asn1wr);

        return status;
    }

    top_sequence_len += vscf_asn1wr_write_octet_str(asn1wr, vsc_buffer_data(ratchet_buff));

    top_sequence_len += vscf_asn1wr_write_octet_str(asn1wr, vsc_buffer_data(ratchet_session_ctx->receiver_onetime_public_key));

    top_sequence_len += vscf_asn1wr_write_octet_str(asn1wr, vsc_buffer_data(ratchet_session_ctx->receiver_longterm_public_key));

    top_sequence_len += vscf_asn1wr_write_octet_str(asn1wr, vsc_buffer_data(ratchet_session_ctx->sender_ephemeral_public_key));

    top_sequence_len += vscf_asn1wr_write_octet_str(asn1wr, vsc_buffer_data(ratchet_session_ctx->sender_identity_public_key));

    top_sequence_len += vscf_asn1wr_write_bool(asn1wr, ratchet_session_ctx->received_first_response);

    vscf_asn1wr_write_sequence(asn1wr, top_sequence_len);

    if (vscf_asn1wr_error(asn1wr) != vscf_SUCCESS) {
        vscf_asn1wr_destroy(&asn1wr);

        // FIXME
        return vscr_ASN1_WRITE_ERROR;
    }

    vsc_buffer_reserve(output, vscf_asn1wr_finish(asn1wr));

    vscf_asn1wr_destroy(&asn1wr);

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

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();

    vscf_asn1rd_reset(asn1rd, input);
    vscf_asn1rd_read_sequence(asn1rd);

    bool received_first_response = vscf_asn1rd_read_bool(asn1rd);

    size_t key_len = vscf_asn1rd_get_len(asn1rd);
    if (key_len != ED25519_KEY_LEN) {

        vscf_asn1rd_destroy(&asn1rd);

        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_WRONG_MESSAGE_FORMAT);

        return NULL;
    }
    vsc_data_t sender_identity_public_key = vscf_asn1rd_read_octet_str(asn1rd);

    key_len = vscf_asn1rd_get_len(asn1rd);
    if (key_len != ED25519_KEY_LEN) {

        vscf_asn1rd_destroy(&asn1rd);

        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_WRONG_MESSAGE_FORMAT);

        return NULL;
    }
    vsc_data_t sender_ephemeral_public_key = vscf_asn1rd_read_octet_str(asn1rd);

    key_len = vscf_asn1rd_get_len(asn1rd);
    if (key_len != ED25519_KEY_LEN) {

        vscf_asn1rd_destroy(&asn1rd);

        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_WRONG_MESSAGE_FORMAT);

        return NULL;
    }
    vsc_data_t receiver_longterm_public_key = vscf_asn1rd_read_octet_str(asn1rd);

    key_len = vscf_asn1rd_get_len(asn1rd);
    if (key_len != ED25519_KEY_LEN) {

        vscf_asn1rd_destroy(&asn1rd);

        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_WRONG_MESSAGE_FORMAT);

        return NULL;
    }
    vsc_data_t receiver_onetime_public_key = vscf_asn1rd_read_octet_str(asn1rd);

    size_t ratchet_len = vscf_asn1rd_get_len(asn1rd);
    if (ratchet_len > vscr_ratchet_session_MAX_RATCHET_LENGTH) {

        vscf_asn1rd_destroy(&asn1rd);

        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_WRONG_MESSAGE_FORMAT);

        return NULL;
    }
    vsc_data_t ratchet_buff = vscf_asn1rd_read_octet_str(asn1rd);

    vscr_ratchet_t *ratchet = vscr_ratchet_deserialize(ratchet_buff, err_ctx);

    if (err_ctx->error != vscr_SUCCESS) {
        vscf_asn1rd_destroy(&asn1rd);
        vscr_ratchet_destroy(&ratchet);

        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_WRONG_MESSAGE_FORMAT);

        return NULL;
    }

    if (vscf_asn1rd_error(asn1rd) != vscf_SUCCESS) {
        vscf_asn1rd_destroy(&asn1rd);
        vscr_ratchet_destroy(&ratchet);

        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_ASN1_READ_ERROR);

        return NULL;
    }


    vsc_buffer_new_with_data(sender_identity_public_key);


    vscr_ratchet_session_t *ratchet_session = vscr_ratchet_session_new_with_members(received_first_response,
            vsc_buffer_new_with_data(sender_identity_public_key), vsc_buffer_new_with_data(sender_ephemeral_public_key),
            vsc_buffer_new_with_data(receiver_longterm_public_key), vsc_buffer_new_with_data(receiver_onetime_public_key),
            &ratchet); // FIXME

    vscf_asn1rd_destroy(&asn1rd);

    return ratchet_session;
}
