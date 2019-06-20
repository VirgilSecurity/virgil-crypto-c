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

#include "vscf_group_session.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_random.h"
#include "vscf_group_session_defs.h"
#include "vscf_ctr_drbg.h"
#include "vscf_group_session_message_defs.h"
#include "vscf_group_session_message_internal.h"
#include "vscf_group_session_ticket_internal.h"

#include <GroupMessage.pb.h>
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
}

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_group_session_release_rng(vscf_group_session_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->rng);
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
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_group_session_cleanup_ctx(vscf_group_session_t *self) {

    VSCF_ASSERT_PTR(self);
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
    //  TODO: Check if is_initialized

    return vsc_data(self->session_id, sizeof(self->session_id));
}

VSCF_PUBLIC vscf_status_t
vscf_group_session_add_epoch(vscf_group_session_t *self, const vscf_group_session_message_t *message) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message);
    VSCF_ASSERT(message->message_pb.has_group_info);

    //  TODO: Add checks
    //  TODO: Add max number of epoches limit
    //  TODO: Set session_id if not initialized

    vscf_group_session_epoch_t *value = vscf_group_session_epoch_new();
    value->epoch_number = message->message_pb.group_info.epoch;
    memcpy(value->key, message->message_pb.group_info.key, sizeof(value->key));

    vscf_group_session_epoch_node_t *new_node = vscf_group_session_epoch_node_new();

    new_node->value = value;
    new_node->prev = self->last_epoch;

    self->last_epoch = new_node;

    return vscf_status_SUCCESS;
}

//
//  Encrypts data
//
VSCF_PUBLIC vscf_group_session_message_t *
vscf_group_session_encrypt(vscf_group_session_t *self, vsc_data_t plain_text, vsc_data_t private_key,
        vsc_data_t sender_id, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->last_epoch);
    VSCF_ASSERT(vsc_data_is_valid(sender_id));
    VSCF_ASSERT(vsc_data_is_valid(private_key));
    VSCF_ASSERT(vsc_data_is_valid(plain_text));

    vscf_group_session_message_t *msg = vscf_group_session_message_new();

    vscf_group_session_message_set_type(msg, vscf_group_msg_type_REGULAR);

    memcpy(msg->header_pb->session_id, self->session_id, sizeof(msg->header_pb->session_id));
    VSCF_ASSERT(sender_id.len == sizeof(msg->header_pb->sender_id));
    memcpy(msg->header_pb->sender_id, sender_id.bytes, sizeof(msg->header_pb->sender_id));
    msg->header_pb->epoch = self->last_epoch->value->epoch_number;

    pb_ostream_t header_stream = pb_ostream_from_buffer(
            msg->message_pb.regular_message.header.bytes, sizeof(msg->message_pb.regular_message.header));

    VSCF_ASSERT(pb_encode(&header_stream, RegularGroupMessageHeader_fields, msg->header_pb));

    msg->message_pb.regular_message.header.size = header_stream.bytes_written;

    VSCF_UNUSED(error);

    return msg;
}

//
//  Calculates size of buffer sufficient to store decrypted message
//
VSCF_PUBLIC size_t
vscf_group_session_decrypt_len(vscf_group_session_t *self, const vscf_group_session_message_t *message) {

    //  TODO: Check if session_id match
    //  TODO: This is STUB. Implement me.
    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(message);

    return 0;
}

//
//  Decrypts message
//
VSCF_PUBLIC vscf_status_t
vscf_group_session_decrypt(vscf_group_session_t *self, const vscf_group_session_message_t *message,
        vsc_data_t public_key, vsc_data_t sender_id, vsc_buffer_t *plain_text) {

    //  TODO: This is STUB. Implement me.
    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(public_key));
    VSCF_ASSERT(vsc_data_is_valid(sender_id));
    VSCF_ASSERT_PTR(message);
    VSCF_ASSERT_PTR(plain_text);

    return vscf_status_SUCCESS;
}

//
//  Creates ticket with new key for adding or removing participants.
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
