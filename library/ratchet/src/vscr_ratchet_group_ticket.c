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
//  Group ticket used to start group session.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_ratchet_group_ticket.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_group_ticket_defs.h"
#include "vscr_ratchet_chain_key.h"
#include "vscr_ratchet_group_message_defs.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>
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
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_group_ticket_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_group_ticket_init_ctx(vscr_ratchet_group_ticket_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_group_ticket_cleanup_ctx(vscr_ratchet_group_ticket_t *self);

static void
vscr_ratchet_group_ticket_add_participant_to_msg(MessageGroupInfo *msg_info, vsc_data_t participant_id,
        vsc_data_t public_key, vsc_data_t key, size_t index);

//
//  Return size of 'vscr_ratchet_group_ticket_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_group_ticket_ctx_size(void) {

    return sizeof(vscr_ratchet_group_ticket_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_group_ticket_init(vscr_ratchet_group_ticket_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_group_ticket_t));

    self->refcnt = 1;

    vscr_ratchet_group_ticket_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_group_ticket_cleanup(vscr_ratchet_group_ticket_t *self) {

    if (self == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscr_ratchet_group_ticket_cleanup_ctx(self);

        vscr_ratchet_group_ticket_release_rng(self);

        vscr_zeroize(self, sizeof(vscr_ratchet_group_ticket_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_group_ticket_t *
vscr_ratchet_group_ticket_new(void) {

    vscr_ratchet_group_ticket_t *self = (vscr_ratchet_group_ticket_t *) vscr_alloc(sizeof (vscr_ratchet_group_ticket_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_group_ticket_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_group_ticket_delete(vscr_ratchet_group_ticket_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscr_ratchet_group_ticket_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_group_ticket_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_group_ticket_destroy(vscr_ratchet_group_ticket_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_group_ticket_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_group_ticket_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_group_ticket_t *
vscr_ratchet_group_ticket_shallow_copy(vscr_ratchet_group_ticket_t *self) {

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
vscr_ratchet_group_ticket_use_rng(vscr_ratchet_group_ticket_t *self, vscf_impl_t *rng) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT(self->rng == NULL);

    VSCR_ASSERT(vscf_random_is_implemented(rng));

    self->rng = vscf_impl_shallow_copy(rng);
}

//
//  Random used to generate keys
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_group_ticket_take_rng(vscr_ratchet_group_ticket_t *self, vscf_impl_t *rng) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT_PTR(self->rng == NULL);

    VSCR_ASSERT(vscf_random_is_implemented(rng));

    self->rng = rng;
}

//
//  Release dependency to the interface 'random'.
//
VSCR_PUBLIC void
vscr_ratchet_group_ticket_release_rng(vscr_ratchet_group_ticket_t *self) {

    VSCR_ASSERT_PTR(self);

    vscf_impl_destroy(&self->rng);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_group_ticket_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_group_ticket_init_ctx(vscr_ratchet_group_ticket_t *self) {

    VSCR_ASSERT_PTR(self);

    self->key_utils = vscr_ratchet_key_utils_new();
    self->epoch_change = true;
    self->full_msg = vscr_ratchet_group_message_new();

    vscr_ratchet_group_message_set_type(self->full_msg, vscr_group_msg_type_START_GROUP);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_group_ticket_cleanup_ctx(vscr_ratchet_group_ticket_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_ratchet_group_message_destroy(&self->complementary_msg);
    vscr_ratchet_group_message_destroy(&self->full_msg);
    vscr_ratchet_key_utils_destroy(&self->key_utils);
}

//
//  Setups default dependencies:
//  - RNG: CTR DRBG
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_group_ticket_setup_defaults(vscr_ratchet_group_ticket_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(self->rng == NULL);

    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    vscf_status_t status = vscf_ctr_drbg_setup_defaults(rng);

    if (status != vscf_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&rng);
        return vscr_status_ERROR_RNG_FAILED;
    }

    vscr_ratchet_group_ticket_take_rng(self, vscf_ctr_drbg_impl(rng));

    return vscr_status_SUCCESS;
}

VSCR_PRIVATE void
vscr_ratchet_group_ticket_setup_ticket(vscr_ratchet_group_ticket_t *self, size_t epoch, bool epoch_change) {

    VSCR_ASSERT_PTR(self);

    self->epoch_change = epoch_change;

    self->full_msg->message_pb.group_info.epoch = epoch;
    self->full_msg->message_pb.group_info.type =
            epoch_change ? MessageGroupInfo_Type_CHANGE : MessageGroupInfo_Type_START;

    if (!epoch_change) {
        self->complementary_msg = vscr_ratchet_group_message_new();
        vscr_ratchet_group_message_set_type(self->complementary_msg, vscr_group_msg_type_ADD_MEMBERS);
        self->complementary_msg->message_pb.group_info.epoch = epoch;
    }
}

//
//  Adds participant to chat.
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_group_ticket_add_new_participant(
        vscr_ratchet_group_ticket_t *self, vsc_data_t participant_id, vsc_data_t public_key) {

    // TODO: Check for duplicates

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->rng);

    VSCR_ASSERT(participant_id.len == vscr_ratchet_common_PARTICIPANT_ID_LEN);

    vscr_status_t status = vscr_status_SUCCESS;

    vscr_error_t error_ctx;
    vscr_error_reset(&error_ctx);

    vsc_buffer_t *pub_key = vscr_ratchet_key_utils_extract_ratchet_public_key(
            self->key_utils, public_key, true, false, false, &error_ctx);

    if (error_ctx.status != vscr_status_SUCCESS) {
        status = error_ctx.status;
        goto err1;
    }

    vsc_buffer_t *key = vsc_buffer_new_with_capacity(vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LEN);
    vsc_buffer_make_secure(key);

    vscf_status_t f_status = vscf_random(self->rng, vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LEN, key);

    if (f_status != vscf_status_SUCCESS) {
        status = vscr_status_ERROR_RNG_FAILED;
        goto err2;
    }

    vscr_ratchet_group_ticket_add_participant_to_msg(
            &self->full_msg->message_pb.group_info, participant_id, vsc_buffer_data(pub_key), vsc_buffer_data(key), 0);

    if (!self->epoch_change) {
        vscr_ratchet_group_ticket_add_participant_to_msg(&self->complementary_msg->message_pb.group_info,
                participant_id, vsc_buffer_data(pub_key), vsc_buffer_data(key), 0);
    }

err2:
    vsc_buffer_destroy(&key);

err1:
    vsc_buffer_destroy(&pub_key);

    return status;
}

VSCR_PRIVATE vscr_status_t
vscr_ratchet_group_ticket_add_existing_participant(vscr_ratchet_group_ticket_t *self,
        const byte id[vscr_ratchet_common_PARTICIPANT_ID_LEN], const byte pub_key[32], const void *chain_key) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->rng);

    vscr_status_t status = vscr_status_SUCCESS;

    const vscr_ratchet_chain_key_t *chain_key_ref;
    vscr_ratchet_chain_key_t new_chain_key;
    vscr_ratchet_chain_key_init(&new_chain_key);

    if (self->epoch_change) {
        vsc_buffer_t key;
        vsc_buffer_init(&key);
        vsc_buffer_use(&key, new_chain_key.key, sizeof(new_chain_key.key));

        vscf_status_t f_status = vscf_random(self->rng, vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LEN, &key);
        vsc_buffer_delete(&key);

        if (f_status != vscf_status_SUCCESS) {
            status = vscr_status_ERROR_RNG_FAILED;
            goto err;
        }

        chain_key_ref = &new_chain_key;
    } else {
        VSCR_UNUSED(new_chain_key);
        chain_key_ref = chain_key;
    }

    vscr_ratchet_group_ticket_add_participant_to_msg(&self->full_msg->message_pb.group_info,
            vsc_data(id, vscr_ratchet_common_PARTICIPANT_ID_LEN),
            vsc_data(pub_key, vscr_ratchet_common_hidden_RATCHET_KEY_LEN),
            vsc_data(chain_key_ref->key, sizeof(chain_key_ref->key)), chain_key_ref->index);

err:
    vscr_ratchet_chain_key_delete(&new_chain_key);

    return status;
}

static void
vscr_ratchet_group_ticket_add_participant_to_msg(
        MessageGroupInfo *msg_info, vsc_data_t participant_id, vsc_data_t public_key, vsc_data_t key, size_t index) {

    VSCR_ASSERT_PTR(msg_info);
    VSCR_ASSERT(participant_id.len == vscr_ratchet_common_PARTICIPANT_ID_LEN);
    VSCR_ASSERT(public_key.len == vscr_ratchet_common_hidden_RATCHET_KEY_LEN);
    VSCR_ASSERT(key.len == vscr_ratchet_common_hidden_RATCHET_SHARED_KEY_LEN);

    MessageParticipantInfo *info = &msg_info->participants[msg_info->participants_count];

    info->version = 1;
    info->index = index;
    memcpy(info->id, participant_id.bytes, sizeof(info->id));
    memcpy(info->pub_key, public_key.bytes, sizeof(info->pub_key));
    memcpy(info->key, key.bytes, sizeof(info->key));

    msg_info->participants_count++;
}

//
//  Remove participant from chat.
//
VSCR_PUBLIC vscr_status_t
vscr_ratchet_group_ticket_remove_participant(vscr_ratchet_group_ticket_t *self, vsc_data_t participant_id) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(self->epoch_change);
    VSCR_ASSERT(participant_id.len == vscr_ratchet_common_PARTICIPANT_ID_LEN);

    MessageGroupInfo *msg_info = &self->full_msg->message_pb.group_info;

    size_t i = 0;

    for (; i < msg_info->participants_count; i++) {
        if (memcmp(msg_info->participants[i].id, participant_id.bytes, participant_id.len) == 0) {
            break;
        }
    }

    if (i == msg_info->participants_count) {
        return vscr_status_ERROR_PARTICIPANT_NOT_FOUND;
    }

    msg_info->participants_count--;
    for (size_t j = i; j < msg_info->participants_count; j++) {
        // TODO: Optimize?
        memcpy(&msg_info->participants[j], &msg_info->participants[j + 1], sizeof(MessageParticipantInfo));
    }

    vscr_zeroize(&msg_info->participants[msg_info->participants_count], sizeof(MessageParticipantInfo));

    return vscr_status_SUCCESS;
}

//
//  Generates message that should be sent to all participants using secure channel.
//
VSCR_PUBLIC const vscr_ratchet_group_message_t *
vscr_ratchet_group_ticket_get_complementary_ticket_message(const vscr_ratchet_group_ticket_t *self) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(!self->epoch_change);

    return self->complementary_msg;
}

//
//  Generates message that should be sent to all participants using secure channel.
//
VSCR_PUBLIC const vscr_ratchet_group_message_t *
vscr_ratchet_group_ticket_get_full_ticket_message(const vscr_ratchet_group_ticket_t *self) {

    VSCR_ASSERT_PTR(self);

    return self->full_msg;
}
