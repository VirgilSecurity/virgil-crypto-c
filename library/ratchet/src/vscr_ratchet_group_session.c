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
#include "vscr_ratchet_group_session_defs.h"
#include "vscr_ratchet_group_message_defs.h"
#include "vscr_ratchet_group_message_internal.h"
#include "vscr_ratchet_group_ticket_defs.h"
#include "vscr_ratchet_group_ticket_internal.h"
#include "vscr_ratchet_group_participants_info_defs.h"
#include "vscr_ratchet_group_participants_ids_defs.h"
#include "vscr_ratchet_keys.h"
#include "vscr_ratchet_group_participant_epoch.h"
#include "vscr_ratchet_group_participant.h"
#include "vscr_ratchet_group_participant_info.h"

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

static vscr_status_t
vscr_ratchet_group_session_check_session_consistency(vscr_ratchet_group_session_t *self,
        const vscr_ratchet_group_message_t *message,
        const vscr_ratchet_group_participants_info_t *participants) VSCR_NODISCARD;

static uint32_t
vscr_ratchet_group_session_find_participant(vscr_ratchet_group_session_t *self, const vscr_ratchet_participant_id_t id);

static vscr_status_t
vscr_ratchet_group_session_generate_skipped_keys(vscr_ratchet_group_session_t *self,
        vscr_ratchet_group_participant_epoch_t *epoch, uint32_t counter) VSCR_NODISCARD;

static void
vscr_ratchet_group_session_update_participant(vscr_ratchet_group_participant_t *participant, uint32_t epoch,
        const vscr_ratchet_symmetric_key_t root_key, const vscr_ratchet_group_participant_info_t *info);

static void
vscr_ratchet_group_session_add_new_participant(vscr_ratchet_group_session_t *self, uint32_t epoch,
        const vscr_ratchet_symmetric_key_t root_key, const vscr_ratchet_group_participant_info_t *info);

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
//  Random
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
//  Random
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
    self->is_my_id_set = false;
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
            vscr_ratchet_group_participant_destroy(&self->participants[i]);
        }

        vscr_dealloc(self->participants);
    }

    vscr_ratchet_chain_key_destroy(&self->my_chain_key);
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
//  Shows whether my id was set.
//
VSCR_PUBLIC bool
vscr_ratchet_group_session_is_my_id_set(const vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);

    return self->is_my_id_set;
}

//
//  Returns current epoch.
//
VSCR_PUBLIC uint32_t
vscr_ratchet_group_session_get_current_epoch(const vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->my_chain_key);
    VSCR_ASSERT(self->is_initialized);

    return self->my_epoch;
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
    VSCR_ASSERT(vsc_data_is_valid(my_private_key));

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
//  Sets my id. Should be 32 byte
//
VSCR_PUBLIC void
vscr_ratchet_group_session_set_my_id(vscr_ratchet_group_session_t *self, vsc_data_t my_id) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(vsc_data_is_valid(my_id));
    VSCR_ASSERT(my_id.len == vscr_ratchet_common_PARTICIPANT_ID_LEN);

    memcpy(self->my_id, my_id.bytes, sizeof(self->my_id));

    self->is_my_id_set = true;
}

//
//  Returns my id.
//
VSCR_PUBLIC vsc_data_t
vscr_ratchet_group_session_get_my_id(const vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(self->is_my_id_set);

    return vsc_data(self->my_id, sizeof(self->my_id));
}

//
//  Returns session id.
//
VSCR_PUBLIC vsc_data_t
vscr_ratchet_group_session_get_session_id(const vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(self->is_initialized);

    return vsc_data(self->session_id, sizeof(self->session_id));
}

//
//  Returns number of participants.
//
VSCR_PUBLIC uint32_t
vscr_ratchet_group_session_get_participants_count(const vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);

    return self->participants_count;
}

static vscr_status_t
vscr_ratchet_group_session_check_session_consistency(vscr_ratchet_group_session_t *self,
        const vscr_ratchet_group_message_t *message, const vscr_ratchet_group_participants_info_t *participants) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->key_utils);
    VSCR_ASSERT_PTR(message);
    VSCR_ASSERT(message->message_pb.has_group_info);
    VSCR_ASSERT(self->is_my_id_set);
    VSCR_ASSERT(self->is_private_key_set);

    const MessageGroupInfo *group_info = &message->message_pb.group_info;

    if (participants->count + 1 > vscr_ratchet_common_MAX_PARTICIPANTS_COUNT) {
        return vscr_status_ERROR_TOO_MANY_PARTICIPANTS;
    }

    if (participants->count + 1 < vscr_ratchet_common_MIN_PARTICIPANTS_COUNT) {
        return vscr_status_ERROR_TOO_FEW_PARTICIPANTS;
    }

    if (self->my_chain_key && (self->my_epoch >= group_info->epoch + vscr_ratchet_common_hidden_MAX_EPOCHS_COUNT ||
                                      self->my_epoch == group_info->epoch)) {
        return vscr_status_ERROR_EPOCH_MISMATCH;
    }

    // Compare participants in session and in message
    bool i_participate = false;
    for (size_t i = 0; i < participants->count; i++) {
        const vscr_ratchet_group_participant_info_t *info = participants->participants[i];

        if (memcmp(info->id, self->my_id, sizeof(self->my_id)) == 0) {
            i_participate = true;
            break;
        }
    }

    // I should be in participants list
    if (i_participate) {
        return vscr_status_ERROR_MYSELF_IS_INCLUDED_IN_INFO;
    }

    // Updating session
    if (self->is_initialized) {
        // Received message has another session id
        if (memcmp(self->session_id, group_info->session_id, sizeof(self->session_id)) != 0) {
            return vscr_status_ERROR_SESSION_ID_MISMATCH;
        }
    }

    return vscr_status_SUCCESS;
}

//
//  Sets up session.
//  Use this method when you have newer epoch message and know all participants info.
//  NOTE: Identity private key and my id should be set separately.
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_group_session_setup_session_state(vscr_ratchet_group_session_t *self,
        const vscr_ratchet_group_message_t *message, const vscr_ratchet_group_participants_info_t *participants) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->key_utils);
    VSCR_ASSERT_PTR(message);
    VSCR_ASSERT_PTR(participants);
    VSCR_ASSERT(message->message_pb.has_group_info);
    VSCR_ASSERT(self->is_my_id_set);
    VSCR_ASSERT(self->is_private_key_set);

    vscr_status_t status = vscr_ratchet_group_session_check_session_consistency(self, message, participants);

    if (status != vscr_status_SUCCESS) {
        return status;
    }

    const MessageGroupInfo *group_info = &message->message_pb.group_info;

    // Set session id
    memcpy(self->session_id, group_info->session_id, sizeof(self->session_id));

    size_t len = participants->count;

    // Save old participants, decide which participants should be removed
    if (self->participants_count > 0) {
        vscr_ratchet_group_participant_t **old_participants = self->participants;
        size_t old_count = self->participants_count;
        self->participants_count = 0;

        self->participants = vscr_alloc(len * sizeof(vscr_ratchet_group_participant_t *));

        // Save old participants
        for (size_t i = 0; i < old_count; i++) {
            const vscr_ratchet_group_participant_info_t *info = NULL;

            for (size_t j = 0; j < participants->count; j++) {
                if (memcmp(participants->participants[j]->id, old_participants[i]->info.id,
                            sizeof(participants->participants[j]->id)) == 0) {
                    info = participants->participants[j];
                    break;
                }
            }

            if (info) {
                size_t index = self->participants_count;
                self->participants[index] = old_participants[i];
                old_participants[i] = NULL;

                if (self->my_epoch < group_info->epoch) {
                    vscr_ratchet_group_session_update_participant(
                            self->participants[index], group_info->epoch, group_info->key, info);
                }

                self->participants_count++;
            } else {
                vscr_ratchet_group_participant_destroy(&old_participants[i]);
            }
        }

        vscr_dealloc(old_participants);
    } else {
        self->participants = vscr_alloc(len * sizeof(vscr_ratchet_group_participant_t *));
    }

    if (self->my_chain_key) {
        size_t shift = group_info->epoch - self->my_epoch;

        for (size_t j = 0; j < shift - 1; j++) {
            self->messages_count[j] = 0;
        }

        for (size_t j = vscr_ratchet_common_hidden_MAX_SKIPPED_EPOCHS_COUNT - 1; j >= shift; j--) {
            self->messages_count[j] = self->messages_count[j - shift];
        }

        self->messages_count[shift - 1] = self->my_chain_key->index;
    }

    vscr_ratchet_chain_key_destroy(&self->my_chain_key);

    self->my_epoch = group_info->epoch;
    ;
    self->my_chain_key = vscr_ratchet_key_utils_derive_participant_key(group_info->key, self->my_id);

    for (size_t i = 0; i < participants->count; i++) {
        const vscr_ratchet_group_participant_info_t *info = participants->participants[i];

        if (vscr_ratchet_group_session_find_participant(self, info->id) == self->participants_count) {
            // Only new participants are here
            vscr_ratchet_group_session_add_new_participant(self, group_info->epoch, group_info->key, info);
        }
    }

    self->is_initialized = true;

    return vscr_status_SUCCESS;
}

//
//  Sets up session.
//  Use this method when you have message with next epoch, and you know how participants set was changed.
//  NOTE: Identity private key and my id should be set separately.
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_group_session_update_session_state(vscr_ratchet_group_session_t *self,
        const vscr_ratchet_group_message_t *message, const vscr_ratchet_group_participants_info_t *add_participants,
        const vscr_ratchet_group_participants_ids_t *remove_participants) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->key_utils);
    VSCR_ASSERT_PTR(message);
    VSCR_ASSERT_PTR(add_participants);
    VSCR_ASSERT_PTR(remove_participants);
    VSCR_ASSERT(message->message_pb.has_group_info);
    VSCR_ASSERT(self->is_my_id_set);
    VSCR_ASSERT(self->is_private_key_set);
    VSCR_ASSERT(self->is_initialized);
    VSCR_ASSERT_PTR(self->my_chain_key);
    VSCR_ASSERT(self->my_epoch + 1 == message->message_pb.group_info.epoch);

    for (size_t j = 0; j < remove_participants->count; j++) {
        if (memcmp(self->my_id, remove_participants->ids[j], vscr_ratchet_common_PARTICIPANT_ID_LEN) == 0) {
            return vscr_status_ERROR_CANNOT_REMOVE_MYSELF;
        }

        for (size_t i = 0; i < add_participants->count; i++) {
            if (memcmp(add_participants->participants[i]->id, remove_participants->ids[j],
                        vscr_ratchet_common_PARTICIPANT_ID_LEN) == 0) {
                return vscr_status_ERROR_SIMULTANEOUS_GROUP_USER_OPERATION;
            }
        }
    }

    if (self->participants_count + add_participants->count + 1 <
            remove_participants->count + vscr_ratchet_common_MIN_PARTICIPANTS_COUNT) {
        return vscr_status_ERROR_TOO_FEW_PARTICIPANTS;
    }

    if (self->participants_count + add_participants->count + 1 >
            vscr_ratchet_common_MAX_PARTICIPANTS_COUNT + remove_participants->count) {
        return vscr_status_ERROR_TOO_MANY_PARTICIPANTS;
    }

    vscr_ratchet_group_participants_info_t *info = vscr_ratchet_group_participants_info_new_size(
            self->participants_count + add_participants->count - remove_participants->count);

    for (size_t i = 0; i < self->participants_count; i++) {
        bool removed_participant = false;

        for (size_t j = 0; j < remove_participants->count; j++) {
            if (memcmp(self->participants[i]->info.id, remove_participants->ids[j],
                        vscr_ratchet_common_PARTICIPANT_ID_LEN) == 0) {
                removed_participant = true;
                break;
            }
        }

        if (removed_participant) {
            continue;
        }

        vscr_ratchet_group_participant_info_t *old_participant = vscr_ratchet_group_participant_info_new();

        memcpy(old_participant->id, self->participants[i]->info.id, vscr_ratchet_common_PARTICIPANT_ID_LEN);
        memcpy(old_participant->pub_key, self->participants[i]->info.pub_key, vscr_ratchet_common_hidden_KEY_LEN);

        info->participants[info->count++] = old_participant;
    }

    for (size_t i = 0; i < add_participants->count; i++) {
        vscr_ratchet_group_participant_info_t *new_participant = vscr_ratchet_group_participant_info_new();

        memcpy(new_participant->id, add_participants->participants[i]->id, vscr_ratchet_common_PARTICIPANT_ID_LEN);
        memcpy(new_participant->pub_key, add_participants->participants[i]->pub_key,
                vscr_ratchet_common_hidden_KEY_LEN);

        info->participants[info->count++] = new_participant;
    }

    vscr_status_t status = vscr_ratchet_group_session_setup_session_state(self, message, info);

    vscr_ratchet_group_participants_info_destroy(&info);

    return status;
}

//
//  Encrypts data
//
VSCR_PUBLIC vscr_ratchet_group_message_t *
vscr_ratchet_group_session_encrypt(vscr_ratchet_group_session_t *self, vsc_data_t plain_text, vscr_error_t *error) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->cipher);
    VSCR_ASSERT_PTR(self->my_chain_key);
    VSCR_ASSERT_PTR(self->my_chain_key);
    VSCR_ASSERT(self->is_initialized);
    VSCR_ASSERT(self->is_my_id_set);
    VSCR_ASSERT(self->is_private_key_set);
    VSCR_ASSERT(vsc_data_is_valid(plain_text));

    if (plain_text.len > vscr_ratchet_common_MAX_PLAIN_TEXT_LEN) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_EXCEEDED_MAX_PLAIN_TEXT_LEN);
        return NULL;
    }

    vscr_status_t status = vscr_status_SUCCESS;

    vscr_ratchet_group_message_t *msg = vscr_ratchet_group_message_new();
    vscr_ratchet_group_message_set_type(msg, vscr_group_msg_type_REGULAR);

    RegularGroupMessage *regular_message = &msg->message_pb.regular_message;

    msg->header_pb->epoch = self->my_epoch;
    msg->header_pb->counter = self->my_chain_key->index;
    memcpy(msg->header_pb->sender_id, self->my_id, sizeof(self->my_id));

    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_SKIPPED_EPOCHS_COUNT; i++) {
        msg->header_pb->prev_epochs_msgs[i] = self->messages_count[i];
    }

    vscr_ratchet_message_key_t *message_key = vscr_ratchet_keys_create_message_key(self->my_chain_key);

    if (self->my_chain_key->index == UINT32_MAX) {
        vscr_ratchet_message_key_destroy(&message_key);
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN);
        return NULL;
    }
    vscr_ratchet_keys_advance_chain_key(self->my_chain_key);

    regular_message->cipher_text.arg = vsc_buffer_new_with_capacity(
            vscr_ratchet_cipher_encrypt_len(self->cipher, vscr_ratchet_padding_padded_len(plain_text.len)));

    pb_ostream_t ostream = pb_ostream_from_buffer(regular_message->header.bytes, sizeof(regular_message->header.bytes));

    VSCR_ASSERT(pb_encode(&ostream, RegularGroupMessageHeader_fields, msg->header_pb));
    regular_message->header.size = ostream.bytes_written;

    status = vscr_ratchet_cipher_pad_then_encrypt(self->cipher, self->padding, plain_text, message_key,
            vsc_data(regular_message->header.bytes, regular_message->header.size), regular_message->cipher_text.arg);

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
    VSCR_ASSERT(self->is_my_id_set);
    VSCR_ASSERT(self->is_private_key_set);

    const RegularGroupMessage *group_message = &message->message_pb.regular_message;
    const RegularGroupMessageHeader *header = message->header_pb;

    if (memcmp(header->sender_id, self->my_id, sizeof(self->my_id)) == 0) {
        return vscr_status_ERROR_CANNOT_DECRYPT_OWN_MESSAGES;
    }

    size_t sender = vscr_ratchet_group_session_find_participant(self, header->sender_id);

    if (sender == self->participants_count) {
        return vscr_status_ERROR_SENDER_NOT_FOUND;
    }

    vscr_ratchet_group_participant_t *participant = self->participants[sender];

    VSCR_ASSERT_PTR(participant);

    int ed_status = ed25519_verify(group_message->signature, participant->info.pub_key,
            vsc_buffer_bytes(group_message->cipher_text.arg), vsc_buffer_len(group_message->cipher_text.arg));

    if (ed_status != 0) {
        return ed_status == 1 ? vscr_status_ERROR_ED25519 : vscr_status_ERROR_INVALID_SIGNATURE;
    }

    // Check epoch is out of range
    if (self->my_epoch < header->epoch ||
            self->my_epoch >= header->epoch + vscr_ratchet_common_hidden_MAX_EPOCHS_COUNT) {
        return vscr_status_ERROR_EPOCH_NOT_FOUND;
    }

    vscr_ratchet_group_participant_epoch_t *epoch =
            vscr_ratchet_group_participant_find_epoch(participant, header->epoch);

    if (!epoch) {
        return vscr_status_ERROR_EPOCH_NOT_FOUND;
    }

    // New message
    if (epoch->chain_key && epoch->chain_key->index <= header->counter) {

        // Too many lost messages
        if (header->counter - epoch->chain_key->index > vscr_ratchet_common_hidden_MAX_MESSAGE_GAP) {
            return vscr_status_ERROR_TOO_MANY_LOST_MESSAGES;
        }

        vscr_ratchet_chain_key_t *new_chain_key = vscr_ratchet_chain_key_new();
        vscr_ratchet_chain_key_clone(epoch->chain_key, new_chain_key);

        while (new_chain_key->index < header->counter) {
            if (epoch->chain_key->index == UINT32_MAX) {
                return vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN;
            }

            vscr_ratchet_keys_advance_chain_key(new_chain_key);
        }

        vscr_ratchet_message_key_t *message_key = vscr_ratchet_keys_create_message_key(new_chain_key);

        vscr_status_t result = vscr_ratchet_cipher_decrypt_then_remove_pad(self->cipher,
                vsc_buffer_data(group_message->cipher_text.arg), message_key,
                vsc_data(group_message->header.bytes, group_message->header.size), plain_text);

        vscr_ratchet_message_key_destroy(&message_key);
        vscr_ratchet_chain_key_destroy(&new_chain_key);

        if (result != vscr_status_SUCCESS) {
            return result;
        }

        result = vscr_ratchet_group_session_generate_skipped_keys(self, epoch, header->counter);

        if (result != vscr_status_SUCCESS) {
            return result;
        }

        for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_SKIPPED_EPOCHS_COUNT; i++) {
            if (header->epoch < i + 1) {
                break;
            }

            vscr_ratchet_group_participant_epoch_t *old_epoch =
                    vscr_ratchet_group_participant_find_epoch(participant, header->epoch - i - 1);

            if (!old_epoch || !old_epoch->chain_key) {
                continue;
            }

            result = vscr_ratchet_group_session_generate_skipped_keys(self, old_epoch, header->prev_epochs_msgs[i]);

            if (result != vscr_status_SUCCESS) {
                return result;
            }

            vscr_ratchet_chain_key_destroy(&old_epoch->chain_key);
        }

        if (epoch->chain_key->index == UINT32_MAX) {
            return vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN;
        }

        vscr_ratchet_keys_advance_chain_key(epoch->chain_key);

        return vscr_status_SUCCESS;
    } else {
        vscr_ratchet_message_key_t *message_key =
                vscr_ratchet_skipped_messages_root_node_find_key(epoch->skipped_messages, header->counter);

        if (!message_key) {
            return vscr_status_ERROR_SKIPPED_MESSAGE_MISSING;
        } else {
            vscr_status_t result = vscr_ratchet_cipher_decrypt_then_remove_pad(self->cipher,
                    vsc_buffer_data(group_message->cipher_text.arg), message_key,
                    vsc_data(group_message->header.bytes, group_message->header.size), plain_text);

            if (result != vscr_status_SUCCESS) {
                return result;
            }

            vscr_ratchet_skipped_messages_root_node_delete_key(epoch->skipped_messages, message_key);

            return result;
        }
    }
}

static uint32_t
vscr_ratchet_group_session_find_participant(
        vscr_ratchet_group_session_t *self, const vscr_ratchet_participant_id_t id) {

    VSCR_ASSERT_PTR(self);

    for (size_t i = 0; i < self->participants_count; i++) {
        vscr_ratchet_group_participant_t *participant = self->participants[i];

        if (memcmp(participant->info.id, id, sizeof(participant->info.id)) == 0) {
            return i;
        }
    }

    return self->participants_count;
}

//
//  Serializes session to buffer
//  NOTE: Session changes its state every encrypt/decrypt operations. Be sure to save it.
//
VSCR_PUBLIC vsc_buffer_t *
vscr_ratchet_group_session_serialize(const vscr_ratchet_group_session_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->my_chain_key);
    VSCR_ASSERT(self->is_initialized);
    VSCR_ASSERT(self->is_my_id_set);

    GroupSession *session_pb = vscr_alloc(sizeof(GroupSession));

    session_pb->version = vscr_ratchet_common_hidden_GROUP_SESSION_VERSION;
    session_pb->participants_count = self->participants_count;
    memcpy(session_pb->session_id, self->session_id, sizeof(session_pb->session_id));
    memcpy(session_pb->my_id, self->my_id, sizeof(session_pb->my_id));
    vscr_ratchet_chain_key_serialize(self->my_chain_key, &session_pb->my_chain_key);
    session_pb->my_epoch = self->my_epoch;

    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_SKIPPED_EPOCHS_COUNT; i++) {
        session_pb->messages_count[i] = self->messages_count[i];
    }

    if (self->participants_count) {
        session_pb->participants = vscr_alloc(self->participants_count * sizeof(ParticipantData));
    }
    for (size_t i = 0; i < self->participants_count; i++) {
        vscr_ratchet_group_participant_serialize(self->participants[i], &session_pb->participants[i]);
    }

    size_t len = 0;
    pb_get_encoded_size(&len, GroupSession_fields, session_pb);

    vsc_buffer_t *output = vsc_buffer_new_with_capacity(len);
    vsc_buffer_make_secure(output);

    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_unused_bytes(output), vsc_buffer_capacity(output));

    VSCR_ASSERT(pb_encode(&ostream, GroupSession_fields, session_pb));
    vsc_buffer_inc_used(output, ostream.bytes_written);

    for (size_t i = 0; i < self->participants_count; i++) {
        for (size_t j = 0; j < vscr_ratchet_common_hidden_MAX_EPOCHS_COUNT; j++) {
            vscr_dealloc(session_pb->participants[i].epochs[j].message_keys);
        }
    }

    vscr_dealloc(session_pb->participants);

    vscr_zeroize(session_pb, sizeof(GroupSession));
    vscr_dealloc(session_pb);

    return output;
}

//
//  Deserializes session from buffer.
//  NOTE: Deserialized session needs dependencies to be set.
//  You should set separately:
//      - rng
//      - my private key
//
VSCR_PUBLIC vscr_ratchet_group_session_t *
vscr_ratchet_group_session_deserialize(vsc_data_t input, vscr_error_t *error) {

    VSCR_ASSERT(vsc_data_is_valid(input));

    if (input.len > vscr_ratchet_common_hidden_MAX_GROUP_SESSION_LEN) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_PROTOBUF_DECODE);

        return NULL;
    }

    vscr_ratchet_group_session_t *session = NULL;
    GroupSession *session_pb = vscr_alloc(sizeof(GroupSession));

    pb_istream_t istream = pb_istream_from_buffer(input.bytes, input.len);

    bool status = pb_decode(&istream, GroupSession_fields, session_pb);

    if (!status) {
        VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_PROTOBUF_DECODE);

        goto err;
    }

    session = vscr_ratchet_group_session_new();

    session->is_initialized = true;
    session->is_my_id_set = true;

    memcpy(session->session_id, session_pb->session_id, sizeof(session->session_id));
    memcpy(session->my_id, session_pb->my_id, sizeof(session->my_id));

    session->my_epoch = session_pb->my_epoch;
    session->my_chain_key = vscr_ratchet_chain_key_new();
    vscr_ratchet_chain_key_deserialize(&session_pb->my_chain_key, session->my_chain_key);

    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_SKIPPED_EPOCHS_COUNT; i++) {
        session->messages_count[i] = session_pb->messages_count[i];
    }

    session->participants_count = session_pb->participants_count;
    session->participants = vscr_alloc(session_pb->participants_count * sizeof(vscr_ratchet_group_participant_t *));
    memset(session->participants, 0, session_pb->participants_count * sizeof(vscr_ratchet_group_participant_t *));

    for (size_t i = 0; i < session_pb->participants_count; i++) {
        session->participants[i] = vscr_ratchet_group_participant_new();
        vscr_ratchet_group_participant_deserialize(&session_pb->participants[i], session->participants[i]);
    }

err:
    pb_release(GroupSession_fields, session_pb);
    vscr_zeroize(session_pb, sizeof(GroupSession));
    vscr_dealloc(session_pb);

    return session;
}

static vscr_status_t
vscr_ratchet_group_session_generate_skipped_keys(
        vscr_ratchet_group_session_t *self, vscr_ratchet_group_participant_epoch_t *epoch, uint32_t counter) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(epoch);
    VSCR_ASSERT_PTR(epoch->chain_key);

    while (epoch->chain_key->index < counter) {
        vscr_ratchet_message_key_t *message_key = vscr_ratchet_keys_create_message_key(epoch->chain_key);
        if (epoch->chain_key->index == UINT32_MAX) {
            vscr_ratchet_message_key_destroy(&message_key);
            return vscr_status_ERROR_TOO_MANY_MESSAGES_FOR_RECEIVER_CHAIN;
        }
        vscr_ratchet_keys_advance_chain_key(epoch->chain_key);
        vscr_ratchet_skipped_messages_root_node_add_key(epoch->skipped_messages, message_key);
    }

    return vscr_status_SUCCESS;
}

static void
vscr_ratchet_group_session_update_participant(vscr_ratchet_group_participant_t *participant, uint32_t epoch,
        const vscr_ratchet_symmetric_key_t root_key, const vscr_ratchet_group_participant_info_t *info) {

    VSCR_ASSERT_PTR(participant);
    VSCR_ASSERT_PTR(info);

    vscr_ratchet_group_participant_epoch_t *found_epoch = vscr_ratchet_group_participant_find_epoch(participant, epoch);
    VSCR_ASSERT(!found_epoch);

    vscr_ratchet_chain_key_t *chain_key = vscr_ratchet_key_utils_derive_participant_key(root_key, info->id);
    vscr_ratchet_group_participant_add_epoch(participant, epoch, &chain_key);
}

static void
vscr_ratchet_group_session_add_new_participant(vscr_ratchet_group_session_t *self, uint32_t epoch,
        const vscr_ratchet_symmetric_key_t root_key, const vscr_ratchet_group_participant_info_t *info) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(info);

    vscr_ratchet_group_participant_t *participant = vscr_ratchet_group_participant_new();
    self->participants[self->participants_count++] = participant;

    memcpy(participant->info.id, info->id, sizeof(participant->info.id));
    memcpy(participant->info.pub_key, info->pub_key, sizeof(participant->info.pub_key));

    vscr_ratchet_group_session_update_participant(participant, epoch, root_key, info);
}

//
//  Creates ticket with new key for adding or removing participants.
//
VSCR_PUBLIC vscr_ratchet_group_ticket_t *
vscr_ratchet_group_session_create_group_ticket(const vscr_ratchet_group_session_t *self, vscr_error_t *error) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->my_chain_key);
    VSCR_ASSERT(self->is_initialized);

    vscr_ratchet_group_ticket_t *ticket = vscr_ratchet_group_ticket_new();
    vscr_ratchet_group_ticket_use_rng(ticket, self->rng);

    vscr_status_t status = vscr_ratchet_group_ticket_setup_ticket_internal(
            ticket, self->my_epoch + 1, vsc_data(self->session_id, sizeof(self->session_id)));

    if (status != vscr_status_SUCCESS) {
        VSCR_ERROR_SAFE_UPDATE(error, status);
        return NULL;
    }

    return ticket;
}
