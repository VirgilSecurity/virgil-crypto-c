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
#include "vscr_ratchet_padding.h"
#include "vscr_ratchet_skipped_group_message_key_root_node.h"
#include "vscr_ratchet_group_participant_epoch.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <RatchetGroupMessage.pb.h>
#include <pb_decode.h>
#include <pb_encode.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
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

    vscr_ratchet_padding_t *padding;

    vscr_ratchet_skipped_group_message_key_root_node_t **skipped_messages;

    bool is_initialized;

    bool is_private_key_set;

    bool is_id_set;

    byte session_id[vscr_ratchet_common_SESSION_ID_LEN];

    byte my_id[vscr_ratchet_common_PARTICIPANT_ID_LEN];

    vscr_ratchet_group_participant_epoch_t *my_epoch;

    byte my_public_key[vscr_ratchet_common_hidden_RATCHET_KEY_LEN];

    byte my_private_key[vscr_ratchet_common_hidden_RATCHET_KEY_LEN];

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
vscr_ratchet_group_session_update_participant(vscr_ratchet_group_participant_data_t *participant, size_t epoch,
        const MessageParticipantInfo *info);

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
    self->padding = vscr_ratchet_padding_new();
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

    vscr_ratchet_group_participant_epoch_destroy(&self->my_epoch);
    vscr_ratchet_key_utils_destroy(&self->key_utils);
    vscr_ratchet_cipher_destroy(&self->cipher);
    vscr_ratchet_padding_destroy(&self->padding);
}

//
//  This method is called when interface 'random' was setup.
//
static void
vscr_ratchet_group_session_did_setup_rng(vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);

    if (self->rng) {
        vscr_ratchet_padding_use_rng(self->padding, self->rng);
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

VSCR_PUBLIC size_t
vscr_ratchet_group_session_get_current_epoch(const vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->my_epoch);
    VSCR_ASSERT(self->is_initialized);

    return self->my_epoch->epoch;
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

    if (ed25519_get_pubkey(self->my_public_key, self->my_private_key) != 0) {
        error_ctx.status = vscr_status_ERROR_ED25519;
    }

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

VSCR_PUBLIC vsc_data_t
vscr_ratchet_group_session_get_my_id(const vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(self->is_id_set);

    return vsc_data(self->my_id, sizeof(self->my_id));
}

VSCR_PUBLIC vsc_data_t
vscr_ratchet_group_session_get_id(const vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(self->is_initialized);

    return vsc_data(self->session_id, sizeof(self->session_id));
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
    VSCR_ASSERT(message->message_pb.has_group_info);

    VSCR_ASSERT(self->is_id_set);
    VSCR_ASSERT(self->is_private_key_set);

    const MessageGroupInfo *msg_info = &message->message_pb.group_info;

    if (self->is_initialized) {
        if (memcmp(self->session_id, msg_info->session_id, sizeof(self->session_id)) != 0) {
            return vscr_status_ERROR_SESSION_ID_MISMATCH;
        }
    } else {
        memcpy(self->session_id, msg_info->session_id, sizeof(self->session_id));
    }

    MessageGroupInfo_Type type = message->message_pb.group_info.type;

    if (type == MessageGroupInfo_Type_ADD) {
        VSCR_ASSERT(self->is_initialized);
        if (msg_info->epoch != self->my_epoch->epoch) {
            return vscr_status_ERROR_EPOCH_MISMATCH;
        }
    } else if (self->is_initialized && self->my_epoch->epoch + 1 != msg_info->epoch) {
        return vscr_status_ERROR_EPOCH_MISMATCH;
    }

    size_t new_size = 0;

    switch (type) {
    case MessageGroupInfo_Type_ADD:
        new_size = self->participants_count + msg_info->participants_count;
        break;

    case MessageGroupInfo_Type_START:
    case MessageGroupInfo_Type_CHANGE:
        new_size = msg_info->participants_count;
        break;

    default:
        VSCR_ASSERT(false);
    }

    if (new_size > vscr_ratchet_common_MAX_PARTICIPANTS_COUNT) {
        return vscr_status_ERROR_TOO_MANY_PARTICIPANTS;
    }

    if (new_size < vscr_ratchet_common_MIN_PARTICIPANTS_COUNT) {
        return vscr_status_ERROR_TOO_FEW_PARTICIPANTS;
    }

    bool i_participate = false;
    for (size_t i = 0; i < msg_info->participants_count; i++) {
        const MessageParticipantInfo *info = &msg_info->participants[i];

        if (memcmp(info->id, self->my_id, sizeof(self->my_id)) == 0) {
            i_participate = true;
            break;
        }
    }

    if (!self->is_initialized && !i_participate) {
        return vscr_status_ERROR_USER_IS_NOT_PRESENT_IN_GROUP_MESSAGE;
    }

    VSCR_ASSERT(type == MessageGroupInfo_Type_ADD || msg_info->participants_count > 1);

    if (type == MessageGroupInfo_Type_ADD) {
        for (size_t i = 0; i < msg_info->participants_count; i++) {
            const MessageParticipantInfo *info = &msg_info->participants[i];

            for (size_t j = 0; j < self->participants_count; j++) {
                // Previously existed participant
                if (memcmp(info->id, self->participants[j]->id, sizeof(info->id)) == 0) {
                    return vscr_status_ERROR_DUPLICATE_ID;
                }
            }
        }
    }

    size_t len = new_size;

    if (i_participate) {
        // Except me
        len--;
    }

    if (type == MessageGroupInfo_Type_ADD || (type == MessageGroupInfo_Type_CHANGE && self->participants_count > 0)) {
        vscr_ratchet_group_participant_data_t **old_participants = self->participants;
        vscr_ratchet_skipped_group_message_key_root_node_t **old_skipped = self->skipped_messages;
        size_t old_count = self->participants_count;
        self->participants_count = 0;

        self->participants = vscr_alloc(len * sizeof(vscr_ratchet_group_participant_data_t *));
        self->skipped_messages = vscr_alloc(len * sizeof(vscr_ratchet_skipped_group_message_key_root_node_t *));

        if (type == MessageGroupInfo_Type_ADD) {
            for (size_t i = 0; i < old_count; i++, self->participants_count++) {
                self->participants[i] = old_participants[i];
                old_participants[i] = NULL;
                self->skipped_messages[i] = old_skipped[i];
                old_skipped[i] = NULL;
            }
        } else {
            for (size_t i = 0; i < old_count; i++) {
                bool deleted_participant = true;

                for (size_t j = 0; j < msg_info->participants_count; j++) {
                    const MessageParticipantInfo *info = &msg_info->participants[j];

                    if (memcmp(info->id, old_participants[i]->id, sizeof(info->id)) == 0) {
                        self->participants[self->participants_count] = old_participants[i];
                        old_participants[i] = NULL;
                        self->skipped_messages[self->participants_count] = old_skipped[i];
                        old_skipped[i] = NULL;

                        vscr_ratchet_group_session_update_participant(
                                self->participants[self->participants_count], msg_info->epoch, info);

                        self->participants_count++;

                        deleted_participant = false;

                        break;
                    }
                }

                if (deleted_participant) {
                    vscr_ratchet_group_participant_data_destroy(&old_participants[i]);
                    vscr_ratchet_skipped_group_message_key_root_node_destroy(&old_skipped[i]);
                }
            }
        }

        vscr_dealloc(old_participants);
        vscr_dealloc(old_skipped);
    } else {
        self->participants = vscr_alloc(len * sizeof(vscr_ratchet_group_participant_data_t *));
        self->skipped_messages = vscr_alloc(len * sizeof(vscr_ratchet_skipped_group_message_key_root_node_t *));
    }

    for (size_t i = 0; i < msg_info->participants_count; i++) {
        const MessageParticipantInfo *info = &msg_info->participants[i];

        if (memcmp(info->id, self->my_id, sizeof(self->my_id)) == 0) {
            VSCR_ASSERT(type != MessageGroupInfo_Type_ADD);

            vscr_ratchet_group_participant_epoch_destroy(&self->my_epoch);

            vscr_ratchet_group_participant_epoch_t *new_epoch = vscr_ratchet_group_participant_epoch_new();

            new_epoch->epoch = msg_info->epoch;

            // FIXME
            VSCR_ASSERT(info->index == 0);

            new_epoch->chain_key->index = info->index;
            memcpy(new_epoch->chain_key->key, info->key, sizeof(new_epoch->chain_key->key));

            self->my_epoch = new_epoch;
        } else {
            bool should_add = true;
            if (type == MessageGroupInfo_Type_CHANGE) {
                for (size_t j = 0; j < self->participants_count; j++) {
                    // Previously existed participant
                    if (memcmp(info->id, self->participants[j]->id, sizeof(info->id)) == 0) {
                        should_add = false;
                    }
                }
            }

            if (should_add) {
                self->participants[self->participants_count] = vscr_ratchet_group_participant_data_new();

                self->skipped_messages[self->participants_count] =
                        vscr_ratchet_skipped_group_message_key_root_node_new();
                memcpy(self->skipped_messages[self->participants_count]->id, info->id,
                        sizeof(self->skipped_messages[self->participants_count]->id));

                vscr_ratchet_group_session_update_participant(
                        self->participants[self->participants_count], msg_info->epoch, info);

                self->participants_count++;
            } else {
                continue;
            }
        }
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
    VSCR_ASSERT_PTR(self->my_epoch);
    VSCR_ASSERT(self->is_initialized);
    VSCR_ASSERT(self->is_id_set);
    VSCR_ASSERT(self->is_private_key_set);

    if (plain_text.len > vscr_ratchet_common_MAX_PLAIN_TEXT_LEN) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_EXCEEDED_MAX_PLAIN_TEXT_LEN);
        return NULL;
    }

    vscr_status_t status = vscr_status_SUCCESS;

    vscr_ratchet_group_message_t *msg = vscr_ratchet_group_message_new();
    vscr_ratchet_group_message_set_type(msg, vscr_group_msg_type_REGULAR);

    RegularGroupMessage *regular_message = &msg->message_pb.regular_message;

    regular_message->version = 1;

    msg->header_pb->epoch = self->my_epoch->epoch;

    msg->header_pb->counter = self->my_epoch->chain_key->index;
    memcpy(msg->header_pb->sender_id, self->my_id, sizeof(self->my_id));

    vscr_ratchet_message_key_t *message_key = vscr_ratchet_keys_create_message_key(self->my_epoch->chain_key);
    vscr_ratchet_keys_advance_chain_key(self->my_epoch->chain_key);

    regular_message->cipher_text.arg =
            vsc_buffer_new_with_capacity(vscr_ratchet_cipher_encrypt_len(self->cipher, plain_text.len));

    pb_ostream_t ostream = pb_ostream_from_buffer(regular_message->header, sizeof(regular_message->header));

    VSCR_ASSERT(pb_encode(&ostream, RegularGroupMessageHeader_fields, msg->header_pb));

    status = vscr_ratchet_cipher_encrypt(self->cipher, vsc_data(message_key->key, sizeof(message_key->key)), plain_text,
            vsc_data(regular_message->header, sizeof(regular_message->header)), regular_message->cipher_text.arg);

    if (status != vscr_status_SUCCESS) {
        status = vscr_status_ERROR_SESSION_IS_NOT_INITIALIZED;
        goto err;
    }

    int ed_status = ed25519_sign(regular_message->signature, self->my_private_key,
            vsc_buffer_bytes(regular_message->cipher_text.arg), vsc_buffer_len(regular_message->cipher_text.arg));

    if (ed_status != 0) {
        status = vscr_status_ERROR_ED25519;
        goto err;
    }

err:
    if (status != vscr_status_SUCCESS) {
        VSCR_ERROR_SAFE_UPDATE(error, status);
        vscr_ratchet_group_message_destroy(&msg);
    }

    vscr_ratchet_message_key_destroy(&message_key);

    return msg;
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
    const RegularGroupMessageHeader *header = message->header_pb;

    // TODO: Check version

    if (memcmp(header->sender_id, self->my_id, sizeof(self->my_id)) == 0) {
        return vscr_status_ERROR_CANNOT_DECRYPT_OWN_MESSAGES;
    }

    size_t sender = vscr_ratchet_group_session_find_participant(self, header->sender_id);

    if (sender == self->participants_count) {
        return vscr_status_ERROR_SENDER_NOT_FOUND;
    }

    vscr_ratchet_group_participant_data_t *participant = self->participants[sender];
    vscr_ratchet_skipped_group_message_key_root_node_t *skipped_root = self->skipped_messages[sender];

    VSCR_ASSERT(participant);
    VSCR_ASSERT(skipped_root);

    int ed_status = ed25519_verify(group_message->signature, participant->pub_key,
            vsc_buffer_bytes(group_message->cipher_text.arg), vsc_buffer_len(group_message->cipher_text.arg));

    if (ed_status != 0) {
        return ed_status == 1 ? vscr_status_ERROR_ED25519 : vscr_status_ERROR_INVALID_SIGNATURE;
    }

    vscr_ratchet_group_participant_epoch_t *epoch =
            vscr_ratchet_group_participant_data_find_epoch(participant, header->epoch);

    if (!epoch) {
        return vscr_status_ERROR_EPOCH_NOT_FOUND;
    }

    // TODO: Add old epoches removal

    if (epoch->chain_key->index > header->counter) {
        vscr_ratchet_message_key_t *skipped_message_key =
                vscr_ratchet_skipped_group_message_key_root_node_find_key(skipped_root, header->epoch, header->counter);

        if (!skipped_message_key) {
            return vscr_status_ERROR_SKIPPED_MESSAGE_MISSING;
        } else {
            vscr_status_t result = vscr_ratchet_cipher_decrypt(self->cipher,
                    vsc_data(skipped_message_key->key, sizeof(skipped_message_key->key)),
                    vsc_buffer_data(group_message->cipher_text.arg),
                    vsc_data(group_message->header, sizeof(group_message->header)), plain_text);

            if (result != vscr_status_SUCCESS) {
                return result;
            }

            vscr_ratchet_skipped_group_message_key_root_node_delete_key(skipped_root, skipped_message_key);

            return vscr_status_SUCCESS;
        }
    }

    // Too many lost messages
    if (header->counter - epoch->chain_key->index > vscr_ratchet_common_hidden_MAX_MESSAGE_GAP) {
        return vscr_status_ERROR_TOO_MANY_LOST_MESSAGES;
    }

    vscr_ratchet_chain_key_t *new_chain_key = vscr_ratchet_chain_key_new();
    vscr_ratchet_chain_key_clone(epoch->chain_key, new_chain_key);

    while (new_chain_key->index < header->counter) {
        vscr_ratchet_keys_advance_chain_key(new_chain_key);
    }

    vscr_ratchet_message_key_t *message_key = vscr_ratchet_keys_create_message_key(new_chain_key);

    vscr_status_t result = vscr_ratchet_cipher_decrypt(self->cipher,
            vsc_data(message_key->key, sizeof(message_key->key)), vsc_buffer_data(group_message->cipher_text.arg),
            vsc_data(group_message->header, sizeof(group_message->header)), plain_text);

    if (result != vscr_status_SUCCESS) {
        goto err;
    }

    while (epoch->chain_key->index < header->counter) {
        vscr_ratchet_skipped_group_message_key_t *skipped_message_key = vscr_ratchet_skipped_group_message_key_new();
        skipped_message_key->epoch = header->epoch;
        skipped_message_key->message_key = vscr_ratchet_keys_create_message_key(epoch->chain_key);
        if (epoch->chain_key->index == UINT32_MAX) {
            vscr_ratchet_skipped_group_message_key_destroy(&skipped_message_key);
            return vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN;
        }
        vscr_ratchet_keys_advance_chain_key(epoch->chain_key);
        vscr_ratchet_skipped_group_message_key_root_node_add_key(skipped_root, skipped_message_key);
    }

    if (epoch->chain_key->index == UINT32_MAX) {
        return vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN;
    }

    vscr_ratchet_keys_advance_chain_key(epoch->chain_key);

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

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->my_epoch);
    VSCR_ASSERT(vsc_buffer_unused_len(output) >= vscr_ratchet_group_session_serialize_len(self));
    VSCR_ASSERT(self->is_initialized);
    VSCR_ASSERT(self->is_id_set);

    GroupSession session_pb = GroupSession_init_zero;

    session_pb.participants_count = self->participants_count;
    session_pb.skipped_messages_count = self->participants_count;
    memcpy(session_pb.session_id, self->session_id, sizeof(session_pb.session_id));
    memcpy(session_pb.my_id, self->my_id, sizeof(session_pb.my_id));

    for (size_t i = 0; i < self->participants_count; i++) {
        vscr_ratchet_group_participant_data_serialize(self->participants[i], &session_pb.participants[i]);
        vscr_ratchet_skipped_group_message_key_root_node_serialize(
                self->skipped_messages[i], &session_pb.skipped_messages[i]);
    }

    vscr_ratchet_group_participant_epoch_serialize(self->my_epoch, &session_pb.my_epoch);

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

    memcpy(session->session_id, session_pb.session_id, sizeof(session->session_id));
    memcpy(session->my_id, session_pb.my_id, sizeof(session->my_id));

    session->my_epoch = vscr_ratchet_group_participant_epoch_new();
    vscr_ratchet_group_participant_epoch_deserialize(&session_pb.my_epoch, session->my_epoch);
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
vscr_ratchet_group_session_update_participant(
        vscr_ratchet_group_participant_data_t *participant, size_t epoch, const MessageParticipantInfo *info) {

    // FIXME
    VSCR_ASSERT(vscr_ratchet_group_participant_data_find_epoch(participant, epoch) == NULL);

    vscr_ratchet_group_participant_epoch_t *new_epoch =
            vscr_ratchet_group_participant_data_add_epoch(participant, epoch);
    VSCR_ASSERT_PTR(new_epoch);

    memcpy(participant->id, info->id, sizeof(participant->id));
    memcpy(participant->pub_key, info->pub_key, sizeof(participant->pub_key));
    memcpy(new_epoch->chain_key->key, info->key, sizeof(new_epoch->chain_key->key));
    new_epoch->chain_key->index = info->index;
}

VSCR_PUBLIC vscr_ratchet_group_ticket_t *
vscr_ratchet_group_session_create_group_ticket_for_adding_members(const vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->my_epoch);
    VSCR_ASSERT(self->is_initialized);

    vscr_ratchet_group_ticket_t *ticket = vscr_ratchet_group_ticket_new();
    vscr_ratchet_group_ticket_use_rng(ticket, self->rng);

    vscr_ratchet_group_ticket_setup_ticket_internal(
            ticket, self->my_epoch->epoch, false, vsc_data(self->session_id, sizeof(self->session_id)));

    vscr_status_t status = vscr_ratchet_group_ticket_add_existing_participant(
            ticket, self->my_id, self->my_public_key, self->my_epoch->chain_key);
    VSCR_ASSERT(status == vscr_status_SUCCESS);

    for (size_t i = 0; i < self->participants_count; i++) {
        vscr_ratchet_group_participant_data_t *participant = self->participants[i];
        vscr_ratchet_group_participant_epoch_t *current_epoch = participant->epoches[participant->epoch_count - 1];
        VSCR_ASSERT(current_epoch->epoch == self->my_epoch->epoch);
        status = vscr_ratchet_group_ticket_add_existing_participant(
                ticket, participant->id, participant->pub_key, current_epoch->chain_key);
        // Should not return errors here
        VSCR_ASSERT(status == vscr_status_SUCCESS);
    }

    return ticket;
}

VSCR_PUBLIC vscr_ratchet_group_ticket_t *
vscr_ratchet_group_session_create_group_ticket_for_adding_or_removing_members(
        const vscr_ratchet_group_session_t *self, vscr_error_t *error) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(self->is_initialized);

    vscr_ratchet_group_ticket_t *ticket = vscr_ratchet_group_ticket_new();

    vscr_ratchet_group_ticket_use_rng(ticket, self->rng);
    vscr_ratchet_group_ticket_setup_ticket_internal(
            ticket, self->my_epoch->epoch + 1, true, vsc_data(self->session_id, sizeof(self->session_id)));

    vscr_status_t status =
            vscr_ratchet_group_ticket_add_existing_participant(ticket, self->my_id, self->my_public_key, NULL);

    if (status != vscr_status_SUCCESS) {
        goto err;
    }

    for (size_t i = 0; i < self->participants_count; i++) {
        vscr_ratchet_group_participant_data_t *participant = self->participants[i];
        status =
                vscr_ratchet_group_ticket_add_existing_participant(ticket, participant->id, participant->pub_key, NULL);

        if (status != vscr_status_SUCCESS) {
            goto err;
        }
    }

err:
    if (status != vscr_status_SUCCESS) {
        VSCR_ERROR_SAFE_UPDATE(error, status);
        vscr_ratchet_group_ticket_destroy(&ticket);
    }

    return ticket;
}
