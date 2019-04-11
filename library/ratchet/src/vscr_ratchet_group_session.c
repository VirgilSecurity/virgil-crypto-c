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
//  Ratchet group session.
// --------------------------------------------------------------------------


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
#include "vscr_ratchet_group_ticket_defs.h"
#include "vscr_ratchet_keys.h"
#include "vscr_ratchet_group_participant_data.h"
#include "vscr_ratchet_key_utils.h"
#include "vscr_ratchet_cipher.h"
#include "vscr_ratchet_skipped_group_message_key_root_node.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <RatchetGroupMessage.pb.h>
#include <pb_decode.h>
#include <pb_encode.h>
#include <ed25519/ed25519.h>
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

    vscr_ratchet_skipped_group_message_key_root_node_t **skipped_messages;

    bool is_initialized;

    bool is_private_key_set;

    bool is_id_set;

    byte my_id[vscr_ratchet_common_PARTICIPANT_ID_LEN];

    vscr_ratchet_group_participant_data_t *me;

    byte my_private_key[vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH];

    vscr_ratchet_group_participant_data_t **participants;

    size_t participants_count;
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

static size_t
vscr_ratchet_group_session_find_participant(vscr_ratchet_group_session_t *self,
        const byte id[vscr_ratchet_common_PARTICIPANT_ID_LEN]);

static void
vscr_ratchet_group_session_copy_data_from_participant_pb(vscr_ratchet_group_participant_data_t *participant,
        const MessageParticipantInfo *info);

static void
vscr_ratchet_group_session_copy_data_from_participant_class(MessageParticipantInfo *info,
        const vscr_ratchet_group_participant_data_t *participant);

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

    self->key_utils = vscr_ratchet_key_utils_new();
    self->cipher = vscr_ratchet_cipher_new();
    self->me = vscr_ratchet_group_participant_data_new();
    self->is_initialized = false;
    self->is_private_key_set = false;
    self->is_id_set = false;
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
            vscr_ratchet_skipped_group_message_key_root_node_destroy(&self->skipped_messages[i]);
        }

        vscr_dealloc(self->participants);
        vscr_dealloc(self->skipped_messages);
    }

    vscr_ratchet_group_participant_data_destroy(&self->me);
    vscr_ratchet_key_utils_destroy(&self->key_utils);
    vscr_ratchet_cipher_destroy(&self->cipher);
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

//
//  Shows whether session was initialized.
//
VSCR_PUBLIC bool
vscr_ratchet_group_session_is_initialized(const vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);

    return self->is_initialized;
}

//
//  Shows whether identity private key was set.
//
VSCR_PUBLIC bool
vscr_ratchet_group_session_is_private_key_set(const vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);

    return self->is_private_key_set;
}

//
//  Shows whether identity private key was set.
//
VSCR_PUBLIC bool
vscr_ratchet_group_session_is_id_set(const vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);

    return self->is_id_set;
}

//
//  Setups default dependencies:
//  - RNG: CTR DRBG
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

//
//  Sets identity private key.
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_group_session_set_private_key(vscr_ratchet_group_session_t *self, vsc_data_t my_private_key) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->key_utils);

    vscr_error_t error_ctx;
    vscr_error_reset(&error_ctx);

    vsc_buffer_t *my_private_key_raw = vscr_ratchet_key_utils_extract_ratchet_private_key(
            self->key_utils, my_private_key, true, false, false, &error_ctx);

    if (vscr_error_has_error(&error_ctx)) {
        goto err;
    }

    memcpy(self->my_private_key, vsc_buffer_bytes(my_private_key_raw), sizeof(self->my_private_key));
    self->is_private_key_set = true;

err:
    vsc_buffer_destroy(&my_private_key_raw);

    return vscr_error_status(&error_ctx);
}

//
//  Sets identity private key.
//
VSCR_PUBLIC void
vscr_ratchet_group_session_set_id(vscr_ratchet_group_session_t *self, vsc_data_t my_id) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(my_id.len == vscr_ratchet_common_PARTICIPANT_ID_LEN);

    memcpy(self->my_id, my_id.bytes, sizeof(self->my_id));

    self->is_id_set = true;
}

//
//  Sets up session. Identity private key should be set separately.
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_group_session_setup_session(
        vscr_ratchet_group_session_t *self, const vscr_ratchet_group_message_t *message) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->key_utils);
    VSCR_ASSERT_PTR(message);
    VSCR_ASSERT(!message->message_pb.has_remove_members_info); // TODO

    VSCR_ASSERT(self->is_id_set);
    VSCR_ASSERT(self->is_private_key_set);

    bool first_setup = message->message_pb.has_start_group_info;

    const MessageGroupInfo *msg_info;

    if (first_setup) {
        msg_info = &message->message_pb.start_group_info;
    } else {
        VSCR_ASSERT(self->is_initialized);
        msg_info = &message->message_pb.add_members_info;
    }

    if (self->participants_count + msg_info->participants_count > vscr_ratchet_common_MAX_PARTICIPANTS_COUNT) {
        return vscr_status_ERROR_TOO_MANY_PARTICIPANTS;
    }

    bool i_participate = false;
    for (size_t i = 0; i < msg_info->participants_count; i++) {
        const MessageParticipantInfo *info = &msg_info->participants[i];

        if (memcmp(info->id, self->my_id, sizeof(self->my_id)) == 0) {
            i_participate = true;
            break;
        }
    }

    if (first_setup && !i_participate) {
        return vscr_status_ERROR_USER_IS_NOT_PRESENT_IN_GROUP_MESSAGE;
    }

    VSCR_ASSERT(msg_info->participants_count > 1);

    vscr_ratchet_group_participant_data_t **old_participants = self->participants;
    vscr_ratchet_skipped_group_message_key_root_node_t **old_skipped = self->skipped_messages;
    self->participants = vscr_alloc((self->participants_count + msg_info->participants_count - 1) *
                                    sizeof(vscr_ratchet_group_participant_data_t *));
    self->skipped_messages = vscr_alloc((self->participants_count + msg_info->participants_count - 1) *
                                        sizeof(vscr_ratchet_skipped_group_message_key_root_node_t *));

    if (old_participants) {
        for (size_t i = 0; i < self->participants_count; i++) {
            self->participants[i] = old_participants[i];
            self->skipped_messages[i] = old_skipped[i];
        }

        vscr_dealloc(old_participants);
        vscr_dealloc(old_skipped);
    }

    for (size_t i = 0; i < msg_info->participants_count; i++) {
        const MessageParticipantInfo *info = &msg_info->participants[i];

        vscr_ratchet_group_participant_data_t **target;

        if (memcmp(info->id, self->my_id, sizeof(self->my_id)) == 0) {
            target = &self->me;
        } else {
            target = &self->participants[self->participants_count];
            *target = vscr_ratchet_group_participant_data_new();

            self->skipped_messages[self->participants_count] = vscr_ratchet_skipped_group_message_key_root_node_new();
            memcpy(self->skipped_messages[self->participants_count]->id, info->id,
                    sizeof(self->skipped_messages[self->participants_count]->id));
            self->participants_count++;
        }

        vscr_ratchet_group_session_copy_data_from_participant_pb(*target, info);
    }

    self->is_initialized = true;

    return vscr_status_SUCCESS;
}

//
//  Encrypts data
//
VSCR_PUBLIC vscr_ratchet_group_message_t *
vscr_ratchet_group_session_encrypt(vscr_ratchet_group_session_t *self, vsc_data_t plain_text, vscr_error_t *error) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->cipher);
    VSCR_ASSERT_PTR(self->me);
    VSCR_ASSERT(self->is_initialized);
    VSCR_ASSERT(self->is_id_set);
    VSCR_ASSERT(self->is_private_key_set);

    vscr_ratchet_group_message_t *result = NULL;

    if (plain_text.len > vscr_ratchet_common_MAX_PLAIN_TEXT_LEN) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_EXCEEDED_MAX_PLAIN_TEXT_LEN);
        goto err;
    }

    vscr_ratchet_group_message_t *msg = vscr_ratchet_group_message_new();

    msg->message_pb.has_regular_message = true;
    msg->message_pb.regular_message.version = 1;

    ed25519_sign(msg->message_pb.regular_message.signature, self->my_private_key, plain_text.bytes, plain_text.len);

    msg->message_pb.regular_message.counter = self->me->chain_key->index;
    memcpy(msg->message_pb.regular_message.sender_id, self->me->id, sizeof(self->me->id));

    vscr_ratchet_message_key_t *message_key = vscr_ratchet_keys_create_message_key(self->me->chain_key);
    vscr_ratchet_keys_advance_chain_key(self->me->chain_key);

    msg->message_pb.regular_message.cipher_text.arg =
            vsc_buffer_new_with_capacity(vscr_ratchet_cipher_encrypt_len(self->cipher, plain_text.len));

    vscr_status_t status =
            vscr_ratchet_cipher_encrypt(self->cipher, vsc_data(message_key->key, sizeof(message_key->key)), plain_text,
                    msg->message_pb.regular_message.cipher_text.arg);

    if (status != vscr_status_SUCCESS) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_SESSION_IS_NOT_INITIALIZED);
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

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->cipher);
    VSCR_ASSERT_PTR(message);
    VSCR_ASSERT(message->message_pb.has_regular_message);

    return vscr_ratchet_cipher_decrypt_len(
            self->cipher, vsc_buffer_len(message->message_pb.regular_message.cipher_text.arg));
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
    VSCR_ASSERT(self->is_initialized);
    VSCR_ASSERT(self->is_id_set);
    VSCR_ASSERT(self->is_private_key_set);

    const RegularGroupMessage *group_message = &message->message_pb.regular_message;

    // TODO: Check version

    if (memcmp(group_message->sender_id, self->me->id, sizeof(self->me->id)) == 0) {
        return vscr_status_ERROR_CANNOT_DECRYPT_OWN_MESSAGES;
    }

    size_t sender = vscr_ratchet_group_session_find_participant(self, group_message->sender_id);

    if (sender == self->participants_count) {
        return vscr_status_ERROR_SENDER_NOT_FOUND;
    }

    vscr_ratchet_group_participant_data_t *participant = self->participants[sender];
    vscr_ratchet_skipped_group_message_key_root_node_t *skipped_root = self->skipped_messages[sender];

    VSCR_ASSERT(participant);
    VSCR_ASSERT(skipped_root);

    if (participant->chain_key->index > group_message->counter) {
        vscr_ratchet_message_key_t *skipped_message_key =
                vscr_ratchet_skipped_group_message_key_root_node_find_key(skipped_root, group_message->counter);

        if (!skipped_message_key) {
            return vscr_status_ERROR_SKIPPED_MESSAGE_MISSING;
        } else {
            vscr_status_t result = vscr_ratchet_cipher_decrypt(self->cipher,
                    vsc_data(skipped_message_key->key, sizeof(skipped_message_key->key)),
                    vsc_buffer_data(group_message->cipher_text.arg), plain_text);

            if (result != vscr_status_SUCCESS) {
                return result;
            }

            vscr_ratchet_skipped_group_message_key_root_node_delete_key(skipped_root, skipped_message_key);

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

    if (result != vscr_status_SUCCESS) {
        goto err;
    }

    int ed_result = ed25519_verify(
            group_message->signature, participant->pub_key, vsc_buffer_bytes(plain_text), vsc_buffer_len(plain_text));

    if (ed_result != 0) {
        result = vscr_status_ERROR_INVALID_SIGNATURE;
        goto err;
    }

    while (participant->chain_key->index < group_message->counter) {
        vscr_ratchet_message_key_t *skipped_message_key = vscr_ratchet_keys_create_message_key(participant->chain_key);
        if (participant->chain_key->index == UINT32_MAX) {
            vscr_ratchet_message_key_destroy(&skipped_message_key);
            return vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN;
        }
        vscr_ratchet_keys_advance_chain_key(participant->chain_key);
        vscr_ratchet_skipped_group_message_key_root_node_add_key(skipped_root, skipped_message_key);
    }

    if (participant->chain_key->index == UINT32_MAX) {
        return vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN;
    }

    vscr_ratchet_keys_advance_chain_key(participant->chain_key);

err:
    vscr_ratchet_chain_key_destroy(&new_chain_key);
    vscr_ratchet_message_key_destroy(&message_key);

    return result;
}

static size_t
vscr_ratchet_group_session_find_participant(
        vscr_ratchet_group_session_t *self, const byte id[vscr_ratchet_common_PARTICIPANT_ID_LEN]) {

    VSCR_ASSERT_PTR(self);

    for (size_t i = 0; i < self->participants_count; i++) {
        vscr_ratchet_group_participant_data_t *participant = self->participants[i];

        if (memcmp(participant->id, id, sizeof(participant->id)) == 0) {
            return i;
        }
    }

    return self->participants_count;
}

//
//  Calculates size of buffer sufficient to store session
//
VSCR_PUBLIC size_t
vscr_ratchet_group_session_serialize_len(vscr_ratchet_group_session_t *self) {

    VSCR_UNUSED(self);

    return GroupSession_size;
}

//
//  Serializes session to buffer
//
VSCR_PUBLIC void
vscr_ratchet_group_session_serialize(vscr_ratchet_group_session_t *self, vsc_buffer_t *output) {

    VSCR_ASSERT(self);
    VSCR_ASSERT(self->me);
    VSCR_ASSERT(vsc_buffer_unused_len(output) >= vscr_ratchet_group_session_serialize_len(self));
    VSCR_ASSERT(self->is_initialized);

    GroupSession session_pb = GroupSession_init_zero;

    session_pb.participants_count = self->participants_count;
    session_pb.skipped_messages_count = self->participants_count;

    for (size_t i = 0; i < self->participants_count; i++) {
        vscr_ratchet_group_participant_data_serialize(self->participants[i], &session_pb.participants[i]);
        vscr_ratchet_skipped_group_message_key_root_node_serialize(
                self->skipped_messages[i], &session_pb.skipped_messages[i]);
    }

    vscr_ratchet_group_participant_data_serialize(self->me, &session_pb.me);

    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_unused_bytes(output), vsc_buffer_capacity(output));

    VSCR_ASSERT(pb_encode(&ostream, GroupSession_fields, &session_pb));
    vsc_buffer_inc_used(output, ostream.bytes_written);

    vscr_zeroize(&session_pb, sizeof(Session));
}

//
//  Deserializes session from buffer.
//  NOTE: Deserialized session needs dependencies to be set. Check setup defaults
//
VSCR_PUBLIC vscr_ratchet_group_session_t *
vscr_ratchet_group_session_deserialize(vsc_data_t input, vscr_error_t *error) {

    VSCR_ASSERT(vsc_data_is_valid(input));

    if (input.len > GroupSession_size) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_PROTOBUF_DECODE);

        return NULL;
    }

    vscr_ratchet_group_session_t *session = NULL;
    GroupSession session_pb = GroupSession_init_zero;

    pb_istream_t istream = pb_istream_from_buffer(input.bytes, input.len);

    bool status = pb_decode(&istream, GroupSession_fields, &session_pb);

    if (!status || session_pb.skipped_messages_count != session_pb.participants_count) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_PROTOBUF_DECODE);

        goto err;
    }

    session = vscr_ratchet_group_session_new();

    session->is_initialized = true;
    session->is_id_set = true;

    vscr_ratchet_group_participant_data_deserialize(&session_pb.me, session->me);
    session->participants_count = session_pb.participants_count;
    session->participants = vscr_alloc(session_pb.participants_count * sizeof(vscr_ratchet_group_participant_data_t *));
    session->skipped_messages =
            vscr_alloc(session_pb.participants_count * sizeof(vscr_ratchet_skipped_group_message_key_root_node_t *));

    for (size_t i = 0; i < session_pb.participants_count; i++) {
        session->participants[i] = vscr_ratchet_group_participant_data_new();
        vscr_ratchet_group_participant_data_deserialize(&session_pb.participants[i], session->participants[i]);

        session->skipped_messages[i] = vscr_ratchet_skipped_group_message_key_root_node_new();
        vscr_ratchet_skipped_group_message_key_root_node_deserialize(
                &session_pb.skipped_messages[i], session->skipped_messages[i]);
    }

err:
    vscr_zeroize(&session_pb, sizeof(Session));

    return session;
}

static void
vscr_ratchet_group_session_copy_data_from_participant_pb(
        vscr_ratchet_group_participant_data_t *participant, const MessageParticipantInfo *info) {

    memcpy(participant->id, info->id, sizeof(participant->id));
    memcpy(participant->pub_key, info->pub_key, sizeof(participant->pub_key));
    memcpy(participant->chain_key->key, info->key, sizeof(participant->chain_key->key));
    participant->chain_key->index = info->index;
}

static void
vscr_ratchet_group_session_copy_data_from_participant_class(
        MessageParticipantInfo *info, const vscr_ratchet_group_participant_data_t *participant) {

    memcpy(info->id, participant->id, sizeof(info->id));
    memcpy(info->pub_key, participant->pub_key, sizeof(info->pub_key));
    memcpy(info->key, participant->chain_key->key, sizeof(info->key));
    info->index = participant->chain_key->index;
}

VSCR_PUBLIC vscr_ratchet_group_ticket_t *
vscr_ratchet_group_session_create_group_ticket_for_adding_members(const vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(self->is_initialized);

    vscr_ratchet_group_ticket_t *ticket = vscr_ratchet_group_ticket_new();

    MessageGroupInfo *info = &ticket->msg_start->message_pb.start_group_info;
    info->participants_count = self->participants_count + 1;

    vscr_ratchet_group_session_copy_data_from_participant_class(&info->participants[0], self->me);
    for (size_t i = 0; i < self->participants_count; i++) {
        vscr_ratchet_group_session_copy_data_from_participant_class(&info->participants[i + 1], self->participants[i]);
    }

    return ticket;
}

VSCR_PUBLIC vscr_ratchet_group_ticket_t *
vscr_ratchet_group_session_create_group_ticket_for_adding_or_removing_members(
        const vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(self->is_initialized);

    return NULL;
}
