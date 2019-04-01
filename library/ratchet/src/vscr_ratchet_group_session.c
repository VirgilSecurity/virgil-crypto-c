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

#include "vscr_ratchet_group_session.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_common_hidden.h"
#include "vscr_ratchet_group_message_defs.h"
#include "vscr_ratchet_keys.h"
#include "vscr_ratchet_group_participant_data.h"
#include "vscr_ratchet_key_utils.h"
#include "vscr_ratchet_cipher.h"
#include "vscr_ratchet_skipped_group_messages.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <RatchetGroupMessage.pb.h>
#include <pb_decode.h>
#include <pb_encode.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Handle 'ratchet group session' context.
//
struct vscr_ratchet_group_session_t {
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

    vscr_ratchet_key_utils_t *key_utils;

    vscr_ratchet_cipher_t *cipher;

    vscr_ratchet_skipped_group_messages_t *skipped_messages;

    bool is_owner;

    bool is_initialized;

    byte my_id[vscr_ratchet_common_PARTICIPANT_ID_LEN];

    byte my_private_key[vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH];

    byte owner_id[vscr_ratchet_common_PARTICIPANT_ID_LEN];

    vscr_ratchet_group_participant_data_t **participants;

    size_t participants_count;

    vscr_ratchet_group_participant_data_t *me;
};

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_group_session_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_group_session_init_ctx(vscr_ratchet_group_session_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_group_session_cleanup_ctx(vscr_ratchet_group_session_t *self);

//
//  This method is called when interface 'random' was setup.
//
static void
vscr_ratchet_group_session_did_setup_rng(vscr_ratchet_group_session_t *self);

//
//  This method is called when interface 'random' was released.
//
static void
vscr_ratchet_group_session_did_release_rng(vscr_ratchet_group_session_t *self);

static vscr_ratchet_group_participant_data_t *
vscr_ratchet_group_session_find_participant(vscr_ratchet_group_session_t *self,
        const byte id[vscr_ratchet_common_PARTICIPANT_ID_LEN]);

//
//  Return size of 'vscr_ratchet_group_session_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_group_session_ctx_size(void) {

    return sizeof(vscr_ratchet_group_session_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_group_session_init(vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_group_session_t));

    self->refcnt = 1;

    vscr_ratchet_group_session_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_group_session_cleanup(vscr_ratchet_group_session_t *self) {

    if (self == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscr_ratchet_group_session_cleanup_ctx(self);

        vscr_ratchet_group_session_release_rng(self);

        vscr_zeroize(self, sizeof(vscr_ratchet_group_session_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_group_session_t *
vscr_ratchet_group_session_new(void) {

    vscr_ratchet_group_session_t *self = (vscr_ratchet_group_session_t *) vscr_alloc(sizeof (vscr_ratchet_group_session_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_group_session_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_group_session_delete(vscr_ratchet_group_session_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscr_ratchet_group_session_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_group_session_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_group_session_destroy(vscr_ratchet_group_session_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_group_session_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_group_session_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_group_session_t *
vscr_ratchet_group_session_shallow_copy(vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);

    ++self->refcnt;

    return self;
}

//
//  Random used to generate keys
//
//  Note, ownership is shared.
//
VSCR_PUBLIC void
vscr_ratchet_group_session_use_rng(vscr_ratchet_group_session_t *self, vscf_impl_t *rng) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT(self->rng == NULL);

    VSCR_ASSERT(vscf_random_is_implemented(rng));

    self->rng = vscf_impl_shallow_copy(rng);

    vscr_ratchet_group_session_did_setup_rng(self);
}

//
//  Random used to generate keys
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_group_session_take_rng(vscr_ratchet_group_session_t *self, vscf_impl_t *rng) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT_PTR(self->rng == NULL);

    VSCR_ASSERT(vscf_random_is_implemented(rng));

    self->rng = rng;

    vscr_ratchet_group_session_did_setup_rng(self);
}

//
//  Release dependency to the interface 'random'.
//
VSCR_PUBLIC void
vscr_ratchet_group_session_release_rng(vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);

    vscf_impl_destroy(&self->rng);

    vscr_ratchet_group_session_did_release_rng(self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_group_session_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_group_session_init_ctx(vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);

    self->skipped_messages = vscr_ratchet_skipped_group_messages_new();
    self->key_utils = vscr_ratchet_key_utils_new();
    self->cipher = vscr_ratchet_cipher_new();
    self->is_initialized = false;
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_group_session_cleanup_ctx(vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);

    if (self->participants_count > 0) {
        for (size_t i = 0; i < self->participants_count; i++) {
            vscr_ratchet_group_participant_data_destroy(&self->participants[i]);
        }

        free(self->participants);
    }

    vscr_ratchet_key_utils_destroy(&self->key_utils);
    vscr_ratchet_cipher_destroy(&self->cipher);
    vscr_ratchet_group_participant_data_destroy(&self->me);
    vscr_ratchet_skipped_group_messages_destroy(&self->skipped_messages);
}

//
//  This method is called when interface 'random' was setup.
//
static void
vscr_ratchet_group_session_did_setup_rng(vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);

    if (self->rng) {
        vscr_ratchet_cipher_use_rng(self->cipher, self->rng);
    }
}

//
//  This method is called when interface 'random' was released.
//
static void
vscr_ratchet_group_session_did_release_rng(vscr_ratchet_group_session_t *self) {

    VSCR_UNUSED(self);
}

VSCR_PUBLIC bool
vscr_ratchet_group_session_is_initialized(const vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT(self);

    return self->is_initialized;
}

VSCR_PUBLIC bool
vscr_ratchet_group_session_is_owner(const vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT(self);

    return self->is_owner;
}

VSCR_PUBLIC vsc_data_t
vscr_ratchet_group_session_owner_id(const vscr_ratchet_group_session_t *self) {

    return vsc_data(self->owner_id, sizeof(self->owner_id));
}

//
//  Setups default dependencies:
//  - RNG: CTR DRBG
//  - Key serialization: DER PKCS8
//  - Symmetric cipher: AES256-GCM
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_group_session_setup_defaults(vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(self->rng == NULL);

    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    vscf_status_t status = vscf_ctr_drbg_setup_defaults(rng);

    if (status != vscf_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&rng);
        return vscr_status_ERROR_RNG_FAILED;
    }

    vscr_ratchet_group_session_take_rng(self, vscf_ctr_drbg_impl(rng));

    return vscr_status_SUCCESS;
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_group_session_setup_session(vscr_ratchet_group_session_t *self, vsc_data_t participant_id,
        vsc_data_t my_private_key, vsc_data_t owner_id, const vscr_ratchet_group_message_t *message) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->key_utils);
    VSCR_ASSERT_PTR(message);
    VSCR_ASSERT(message->message_pb.has_group_info);
    VSCR_ASSERT(participant_id.len == vscr_ratchet_common_PARTICIPANT_ID_LEN);
    VSCR_ASSERT(owner_id.len == vscr_ratchet_common_PARTICIPANT_ID_LEN);

    memcpy(self->my_id, participant_id.bytes, sizeof(self->my_id));
    memcpy(self->owner_id, owner_id.bytes, sizeof(self->owner_id));

    vscr_status_t status = vscr_status_SUCCESS;

    vscr_error_t error_ctx;
    vscr_error_reset(&error_ctx);

    vsc_buffer_t *my_private_key_raw =
            vscr_ratchet_key_utils_extract_ratchet_private_key(self->key_utils, my_private_key, &error_ctx);

    if (vscr_error_has_error(&error_ctx)) {
        status = vscr_error_status(&error_ctx);
        goto err;
    }

    memcpy(self->my_private_key, vsc_buffer_bytes(my_private_key_raw), sizeof(self->my_private_key));

    if (message->message_pb.group_info.participants_count > vscr_ratchet_common_MAX_PARTICIPANTS_COUNT) {
        return vscr_status_ERROR_TOO_MANY_PARTICIPANTS;
    }

    if (message->message_pb.group_info.participants_count < vscr_ratchet_common_MIN_PARTICIPANTS_COUNT) {
        return vscr_status_ERROR_TOO_FEW_PARTICIPANTS;
    }

    self->is_owner = (memcmp(self->my_id, owner_id.bytes, sizeof(self->my_id)) == 0);

    self->participants = vscr_alloc(
            (message->message_pb.group_info.participants_count - 1) * sizeof(vscr_ratchet_group_participant_data_t *));

    bool handled_myself = false;

    vscr_ratchet_skipped_group_messages_setup(
            self->skipped_messages, message->message_pb.group_info.participants_count);

    for (size_t i = 0; i < message->message_pb.group_info.participants_count; i++) {
        const ParticipantInfo *info = &message->message_pb.group_info.participants[i];

        vscr_ratchet_skipped_group_messages_add_participant(
                self->skipped_messages, message->message_pb.group_info.participants[i].id, i);

        vscr_ratchet_group_participant_data_t *data = vscr_ratchet_group_participant_data_new();

        data->chain_key = vscr_ratchet_chain_key_new();
        data->chain_key->index = 0;
        memcpy(data->chain_key->key, info->key, sizeof(data->chain_key->key));
        memcpy(data->participant_id, info->id, sizeof(data->participant_id));

        if (memcmp(data->participant_id, self->my_id, sizeof(data->participant_id)) == 0) {
            if (handled_myself) {
                status = vscr_status_ERROR_RNG_FAILED; // FIXME: Check for duplicates
                vscr_ratchet_group_participant_data_destroy(&data);
                goto err;
            }
            handled_myself = true;
            self->me = data;
        } else {
            self->participants[self->participants_count++] = data;
        }
    }

err:
    vsc_buffer_destroy(&my_private_key_raw);

    if (status == vscr_status_SUCCESS) {
        self->is_initialized = true;
    }

    return status;
}

//
//  Encrypts data
//
VSCR_PUBLIC vscr_ratchet_group_message_t *
vscr_ratchet_group_session_encrypt(vscr_ratchet_group_session_t *self, vsc_data_t plain_text, vscr_error_t *error) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->cipher);

    if (!self->is_initialized) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_CAN_T_ENCRYPT_YET);
        return NULL;
    }

    VSCR_ASSERT_PTR(self->me);

    vscr_ratchet_group_message_t *result = NULL;

    if (plain_text.len > vscr_ratchet_common_MAX_PLAIN_TEXT_LEN) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_EXCEEDED_MAX_PLAIN_TEXT_LEN);
        goto err;
    }

    vscr_ratchet_group_message_t *msg = vscr_ratchet_group_message_new();

    msg->message_pb.has_regular_message = true;
    msg->message_pb.regular_message.version = 1;
    // TODO: Sign message
    msg->message_pb.regular_message.counter = self->me->chain_key->index;
    memcpy(msg->message_pb.regular_message.sender_id, self->my_id, sizeof(self->my_id));

    vscr_ratchet_message_key_t *message_key = vscr_ratchet_keys_create_message_key(self->me->chain_key);
    vscr_ratchet_keys_advance_chain_key(self->me->chain_key);

    msg->message_pb.regular_message.cipher_text.arg =
            vsc_buffer_new_with_capacity(vscr_ratchet_cipher_encrypt_len(self->cipher, plain_text.len));

    vscr_status_t status =
            vscr_ratchet_cipher_encrypt(self->cipher, vsc_data(message_key->key, sizeof(message_key->key)), plain_text,
                    msg->message_pb.regular_message.cipher_text.arg);

    if (status != vscr_status_SUCCESS) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_CAN_T_ENCRYPT_YET);
        goto err2;
    }

    result = vscr_ratchet_group_message_shallow_copy(msg);

err2:
    vscr_ratchet_message_key_destroy(&message_key);

    vscr_ratchet_group_message_destroy(&msg);

err:
    return result;
}

//
//  Calculates size of buffer sufficient to store decrypted message
//
VSCR_PUBLIC size_t
vscr_ratchet_group_session_decrypt_len(
        vscr_ratchet_group_session_t *self, const vscr_ratchet_group_message_t *message) {

    //  TODO: This is STUB. Implement me.

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(message);

    return 5000;
}

//
//  Decrypts message
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_group_session_decrypt(
        vscr_ratchet_group_session_t *self, const vscr_ratchet_group_message_t *message, vsc_buffer_t *plain_text) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->cipher);
    VSCR_ASSERT_PTR(message);
    VSCR_ASSERT_PTR(plain_text);
    VSCR_ASSERT(vscr_ratchet_group_message_get_type(message) == vscr_group_msg_type_REGULAR);

    const RegularGroupMessage *group_message = &message->message_pb.regular_message;

    // TODO: Check version

    if (memcmp(group_message->sender_id, self->my_id, sizeof(self->my_id)) == 0) {
        return vscr_status_ERROR_CANNOT_DECRYPT_OWN_MESSAGES;
    }

    // TODO: Check signature

    vscr_ratchet_group_participant_data_t *participant =
            vscr_ratchet_group_session_find_participant(self, group_message->sender_id);

    if (!participant) {
        return vscr_status_ERROR_SENDER_NOT_FOUND;
    }

    if (participant->chain_key->index > group_message->counter) {
        vscr_ratchet_message_key_t *skipped_message_key = vscr_ratchet_skipped_group_messages_find_key(
                self->skipped_messages, group_message->sender_id, group_message->counter);

        if (!skipped_message_key) {
            return vscr_status_ERROR_SKIPPED_MESSAGE_MISSING;
        } else {
            vscr_status_t result = vscr_ratchet_cipher_decrypt(self->cipher,
                    vsc_data(skipped_message_key->key, sizeof(skipped_message_key->key)),
                    vsc_buffer_data(group_message->cipher_text.arg), plain_text);

            if (result != vscr_status_SUCCESS) {
                return result;
            }

            vscr_ratchet_skipped_group_messages_delete_key(
                    self->skipped_messages, group_message->sender_id, skipped_message_key);

            return vscr_status_SUCCESS;
        }
    }

    // Too many lost messages
    if (group_message->counter - participant->chain_key->index > vscr_ratchet_common_hidden_MAX_MESSAGE_GAP) {
        return vscr_status_ERROR_TOO_MANY_LOST_MESSAGES;
    }

    vscr_ratchet_chain_key_t *new_chain_key = vscr_ratchet_chain_key_new();
    vscr_ratchet_chain_key_clone(participant->chain_key, new_chain_key);

    while (new_chain_key->index < group_message->counter) {
        vscr_ratchet_keys_advance_chain_key(new_chain_key);
    }

    vscr_ratchet_message_key_t *message_key = vscr_ratchet_keys_create_message_key(new_chain_key);

    vscr_status_t result =
            vscr_ratchet_cipher_decrypt(self->cipher, vsc_data(message_key->key, sizeof(message_key->key)),
                    vsc_buffer_data(group_message->cipher_text.arg), plain_text);

    vscr_ratchet_chain_key_destroy(&new_chain_key);
    vscr_ratchet_message_key_destroy(&message_key);

    while (participant->chain_key->index < group_message->counter) {
        vscr_ratchet_message_key_t *skipped_message_key = vscr_ratchet_keys_create_message_key(participant->chain_key);
        if (participant->chain_key->index == UINT32_MAX) {
            vscr_ratchet_message_key_destroy(&skipped_message_key);
            return vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN;
        }
        vscr_ratchet_keys_advance_chain_key(participant->chain_key);
        vscr_ratchet_skipped_group_messages_add_key(
                self->skipped_messages, group_message->sender_id, skipped_message_key);
    }

    if (participant->chain_key->index == UINT32_MAX) {
        return vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN;
    }

    vscr_ratchet_keys_advance_chain_key(participant->chain_key);

    return result;
}

static vscr_ratchet_group_participant_data_t *
vscr_ratchet_group_session_find_participant(
        vscr_ratchet_group_session_t *self, const byte id[vscr_ratchet_common_PARTICIPANT_ID_LEN]) {

    VSCR_ASSERT_PTR(self);

    for (size_t i = 0; i < self->participants_count; i++) {
        vscr_ratchet_group_participant_data_t *participant = self->participants[i];

        if (memcmp(participant->participant_id, id, sizeof(participant->participant_id)) == 0) {
            return participant;
        }
    }

    return NULL;
}
