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
//  Group chat encryption session.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_group_session.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_random.h"
#include "vscf_group_session_defs.h"
#include "vscf_ctr_drbg.h"
#include "vscf_ed25519.h"
#include "vscf_private_key.h"
#include "vscf_public_key.h"
#include "vscf_group_session_message_defs.h"
#include "vscf_group_session_message_internal.h"
#include "vscf_group_session_ticket_internal.h"

#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <vscf_GroupMessage.pb.h>
#include <pb_decode.h>
#include <pb_encode.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_group_session_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_group_session_init_ctx(vscf_group_session_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_group_session_cleanup_ctx(vscf_group_session_t *self);

//
//  This method is called when interface 'random' was setup.
//
static void
vscf_group_session_did_setup_rng(vscf_group_session_t *self);

//
//  This method is called when interface 'random' was released.
//
static void
vscf_group_session_did_release_rng(vscf_group_session_t *self);

//
//  Return size of 'vscf_group_session_t'.
//
VSCF_PUBLIC size_t
vscf_group_session_ctx_size(void) {

    return sizeof(vscf_group_session_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_group_session_init(vscf_group_session_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_group_session_t));

    self->refcnt = 1;

    vscf_group_session_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_group_session_cleanup(vscf_group_session_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_group_session_cleanup_ctx(self);

    vscf_group_session_release_rng(self);

    vscf_zeroize(self, sizeof(vscf_group_session_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_group_session_t *
vscf_group_session_new(void) {

    vscf_group_session_t *self = (vscf_group_session_t *) vscf_alloc(sizeof (vscf_group_session_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_group_session_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_group_session_delete(vscf_group_session_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCF_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCF_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_group_session_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_group_session_new ()'.
//
VSCF_PUBLIC void
vscf_group_session_destroy(vscf_group_session_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_group_session_t *self = *self_ref;
    *self_ref = NULL;

    vscf_group_session_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_group_session_t *
vscf_group_session_shallow_copy(vscf_group_session_t *self) {

    VSCF_ASSERT_PTR(self);

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Random
//
//  Note, ownership is shared.
//
VSCF_PUBLIC void
vscf_group_session_use_rng(vscf_group_session_t *self, vscf_impl_t *rng) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(rng);
    VSCF_ASSERT(self->rng == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(rng));

    self->rng = vscf_impl_shallow_copy(rng);

    vscf_group_session_did_setup_rng(self);
}

//
//  Random
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_group_session_take_rng(vscf_group_session_t *self, vscf_impl_t *rng) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(rng);
    VSCF_ASSERT(self->rng == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(rng));

    self->rng = rng;

    vscf_group_session_did_setup_rng(self);
}

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_group_session_release_rng(vscf_group_session_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->rng);

    vscf_group_session_did_release_rng(self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_group_session_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_group_session_init_ctx(vscf_group_session_t *self) {

    VSCF_ASSERT_PTR(self);

    self->cipher = vscf_message_cipher_new();
    self->padding = vscf_message_padding_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_group_session_cleanup_ctx(vscf_group_session_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_message_cipher_destroy(&self->cipher);
    vscf_message_padding_destroy(&self->padding);
    vscf_group_session_epoch_node_destroy(&self->last_epoch);
}

//
//  This method is called when interface 'random' was setup.
//
static void
vscf_group_session_did_setup_rng(vscf_group_session_t *self) {

    VSCF_ASSERT_PTR(self);

    if (self->rng) {
        vscf_message_padding_use_rng(self->padding, self->rng);
    }
}

//
//  This method is called when interface 'random' was released.
//
static void
vscf_group_session_did_release_rng(vscf_group_session_t *self) {

    VSCF_UNUSED(self);
}

//
//  Returns current epoch.
//
VSCF_PUBLIC uint32_t
vscf_group_session_get_current_epoch(const vscf_group_session_t *self) {

    VSCF_ASSERT_PTR(self);

    if (self->last_epoch == NULL) {
        return 0;
    }

    return self->last_epoch->value->epoch_number;
}

//
//  Setups default dependencies:
//  - RNG: CTR DRBG
//
VSCF_PUBLIC vscf_status_t
vscf_group_session_setup_defaults(vscf_group_session_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(self->rng == NULL);

    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    vscf_status_t status = vscf_ctr_drbg_setup_defaults(rng);

    if (status != vscf_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&rng);
        return vscf_status_ERROR_RANDOM_FAILED;
    }

    vscf_group_session_take_rng(self, vscf_ctr_drbg_impl(rng));

    return vscf_status_SUCCESS;
}

//
//  Returns session id.
//
VSCF_PUBLIC vsc_data_t
vscf_group_session_get_session_id(const vscf_group_session_t *self) {

    VSCF_ASSERT_PTR(self);

    if (self->last_epoch == NULL) {
        return vsc_data_empty();
    } else {
        return vsc_data(self->session_id, sizeof(self->session_id));
    }
}

//
//  Adds epoch. New epoch should be generated for member removal or proactive to rotate encryption key.
//  Epoch message should be encrypted and signed by trusted group chat member (admin).
//
VSCF_PUBLIC vscf_status_t
vscf_group_session_add_epoch(vscf_group_session_t *self, const vscf_group_session_message_t *message) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message);
    VSCF_ASSERT(message->message_pb.has_group_info);

    if (self->last_epoch &&
            memcmp(self->session_id, message->message_pb.group_info.session_id, sizeof(self->session_id)) != 0) {
        return vscf_status_ERROR_SESSION_ID_DOESNT_MATCH;
    }

    vscf_status_t status = vscf_status_SUCCESS;

    uint32_t msg_epoch = message->message_pb.group_info.epoch;

    if (self->last_epoch == NULL) {
        memcpy(self->session_id, message->message_pb.group_info.session_id, sizeof(self->session_id));
    }

    vscf_group_session_epoch_node_t *left = NULL, *right = NULL;

    left = self->last_epoch;

    while (left != NULL && left->value->epoch_number >= msg_epoch) {
        if (left->value->epoch_number == msg_epoch) {
            status = vscf_status_ERROR_DUPLICATE_EPOCH;
            goto err;
        }

        right = left;
        left = left->prev;
    }

    vscf_group_session_epoch_t *value = vscf_group_session_epoch_new();
    value->epoch_number = message->message_pb.group_info.epoch;
    memcpy(value->key, message->message_pb.group_info.key, sizeof(value->key));

    vscf_group_session_epoch_node_t *new_node = vscf_group_session_epoch_node_new();
    new_node->value = value;

    new_node->prev = left;
    new_node->next = right;

    if (right == NULL) {
        self->last_epoch = new_node;
    } else {
        right->prev = new_node;
    }

    if (left == NULL) {
        self->first_epoch = new_node;
    } else {
        left->next = new_node;
    }

    if (self->epochs_count == vscf_group_session_MAX_EPOCHS_COUNT) {
        VSCF_ASSERT_PTR(self->first_epoch);
        vscf_group_session_epoch_node_t *first = self->first_epoch;
        self->first_epoch = first->next;
        self->first_epoch->prev = NULL;
        vscf_group_session_epoch_node_destroy(&first);
    } else if (self->epochs_count < vscf_group_session_MAX_EPOCHS_COUNT) {
        self->epochs_count++;
    } else {
        VSCF_ASSERT(false);
    }

err:
    return status;
}

//
//  Encrypts data
//
VSCF_PUBLIC vscf_group_session_message_t *
vscf_group_session_encrypt(
        vscf_group_session_t *self, vsc_data_t plain_text, const vscf_impl_t *private_key, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->last_epoch);
    VSCF_ASSERT_PTR(private_key);
    VSCF_ASSERT(vsc_data_is_valid(plain_text));
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));

    // TODO: Support other key types?
    if (vscf_key_alg_id(private_key) != vscf_alg_id_ED25519) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_WRONG_KEY_TYPE);
        return NULL;
    }

    if (plain_text.len > vscf_group_session_MAX_PLAIN_TEXT_LEN) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_PLAIN_TEXT_TOO_LONG);
        return NULL;
    }

    vscf_status_t status;

    vsc_buffer_t *salt = vsc_buffer_new_with_capacity(vscf_group_session_SALT_SIZE);

    status = vscf_random(self->rng, vscf_group_session_SALT_SIZE, salt);

    if (status != vscf_status_SUCCESS) {
        goto err1;
    }

    vscf_group_session_message_t *msg = vscf_group_session_message_new();

    vscf_group_session_message_set_type(msg, vscf_group_msg_type_REGULAR);

    memcpy(msg->header_pb->salt, vsc_buffer_bytes(salt), sizeof(msg->header_pb->salt));
    memcpy(msg->header_pb->session_id, self->session_id, sizeof(msg->header_pb->session_id));
    msg->header_pb->epoch = self->last_epoch->value->epoch_number;

    pb_ostream_t header_stream = pb_ostream_from_buffer(
            msg->message_pb.regular_message.header.bytes, sizeof(msg->message_pb.regular_message.header));

    VSCF_ASSERT(pb_encode(&header_stream, vscf_RegularGroupMessageHeader_fields, msg->header_pb));

    msg->message_pb.regular_message.header.size = header_stream.bytes_written;

    size_t len = vscf_message_cipher_encrypt_len(self->cipher, vscf_message_padding_padded_len(plain_text.len));

    msg->message_pb.regular_message.cipher_text = vscf_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(len));

    vsc_buffer_t cipher_text;
    vsc_buffer_init(&cipher_text);
    vsc_buffer_use(&cipher_text, msg->message_pb.regular_message.cipher_text->bytes, len);

    status = vscf_message_cipher_pad_then_encrypt(self->cipher, self->padding, plain_text, self->last_epoch->value->key,
            vsc_buffer_bytes(salt),
            vsc_data(msg->message_pb.regular_message.header.bytes, msg->message_pb.regular_message.header.size),
            &cipher_text);

    msg->message_pb.regular_message.cipher_text->size = vsc_buffer_len(&cipher_text);

    if (status != vscf_status_SUCCESS) {
        goto err1;
    }

    vscf_ed25519_t *ed25519 = vscf_ed25519_new();

    size_t signature_len = vscf_ed25519_signature_len(ed25519, private_key);

    VSCF_ASSERT(sizeof(msg->message_pb.regular_message.signature) == signature_len);

    vsc_buffer_t signature;
    vsc_buffer_init(&signature);
    vsc_buffer_use(&signature, msg->message_pb.regular_message.signature, signature_len);

    status = vscf_ed25519_sign_hash(
            ed25519, private_key, vscf_alg_id_SHA512 /* FIXME */, vsc_buffer_data(&cipher_text), &signature);

    if (status != vscf_status_SUCCESS) {
        goto err2;
    }

err2:
    vsc_buffer_delete(&signature);
    vscf_ed25519_destroy(&ed25519);
    vsc_buffer_delete(&cipher_text);

err1:
    vsc_buffer_destroy(&salt);

    if (status != vscf_status_SUCCESS) {
        VSCF_ERROR_SAFE_UPDATE(error, status);
        vscf_group_session_message_destroy(&msg);
        return NULL;
    }

    return msg;
}

//
//  Calculates size of buffer sufficient to store decrypted message
//
VSCF_PUBLIC size_t
vscf_group_session_decrypt_len(vscf_group_session_t *self, const vscf_group_session_message_t *message) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message);
    VSCF_ASSERT(message->message_pb.has_regular_message);
    VSCF_ASSERT_PTR(message->header_pb);

    return vscf_message_cipher_decrypt_len(self->cipher, message->message_pb.regular_message.cipher_text->size);
}

//
//  Decrypts message
//
VSCF_PUBLIC vscf_status_t
vscf_group_session_decrypt(vscf_group_session_t *self, const vscf_group_session_message_t *message,
        const vscf_impl_t *public_key, vsc_buffer_t *plain_text) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT_PTR(message);
    VSCF_ASSERT(message->message_pb.has_regular_message);
    VSCF_ASSERT_PTR(message->header_pb);
    VSCF_ASSERT_PTR(plain_text);
    VSCF_ASSERT_PTR(self->last_epoch);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));

    // TODO: Support other key types?
    if (vscf_key_alg_id(public_key) != vscf_alg_id_ED25519) {
        return vscf_status_ERROR_WRONG_KEY_TYPE;
    }

    if (memcmp(self->session_id, message->header_pb->session_id, sizeof(self->session_id)) != 0) {
        return vscf_status_ERROR_SESSION_ID_DOESNT_MATCH;
    }

    uint32_t msg_epoch = message->header_pb->epoch;
    vscf_group_session_epoch_node_t *epoch = self->last_epoch;

    while (epoch != NULL && epoch->value->epoch_number > msg_epoch) {
        epoch = epoch->prev;
    }

    if (epoch == NULL || epoch->value->epoch_number != msg_epoch) {
        return vscf_status_ERROR_EPOCH_NOT_FOUND;
    }

    vscf_status_t status = vscf_status_SUCCESS;

    vscf_ed25519_t *ed25519 = vscf_ed25519_new();

    size_t signature_len = vscf_ed25519_signature_len(ed25519, public_key);

    VSCF_ASSERT(sizeof(message->message_pb.regular_message.signature) == signature_len);

    vsc_data_t signature = vsc_data(message->message_pb.regular_message.signature, signature_len);
    vsc_data_t digest = vsc_data(message->message_pb.regular_message.cipher_text->bytes,
            message->message_pb.regular_message.cipher_text->size);

    bool verified = vscf_ed25519_verify_hash(ed25519, public_key, vscf_alg_id_SHA512 /* FIXME */, digest, signature);

    if (!verified) {
        status = vscf_status_ERROR_INVALID_SIGNATURE;
        goto err;
    }

    status = vscf_message_cipher_decrypt_then_remove_pad(self->cipher,
            vsc_data(message->message_pb.regular_message.cipher_text->bytes,
                    message->message_pb.regular_message.cipher_text->size),
            epoch->value->key, message->header_pb->salt,
            vsc_data(message->message_pb.regular_message.header.bytes, message->message_pb.regular_message.header.size),
            plain_text);

err:
    vscf_ed25519_destroy(&ed25519);

    return status;
}

//
//  Creates ticket with new key for removing participants or proactive to rotate encryption key.
//
VSCF_PUBLIC vscf_group_session_ticket_t *
vscf_group_session_create_group_ticket(const vscf_group_session_t *self, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->last_epoch);

    vscf_group_session_ticket_t *ticket = vscf_group_session_ticket_new();
    vscf_group_session_ticket_use_rng(ticket, self->rng);

    vscf_status_t status = vscf_group_session_ticket_setup_ticket_internal(
            ticket, self->last_epoch->value->epoch_number + 1, vsc_data(self->session_id, sizeof(self->session_id)));

    if (status != vscf_status_SUCCESS) {
        VSCF_ERROR_SAFE_UPDATE(error, status);
        return NULL;
    }

    return ticket;
}
