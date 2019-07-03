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
//  Group ticket used to start group session, remove participants or proactive to rotate encryption key.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_group_session_ticket.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_group_session_ticket_internal.h"
#include "vscf_random.h"
#include "vscf_group_session_ticket_defs.h"
#include "vscf_group_session_message_defs.h"
#include "vscf_group_session_message_internal.h"
#include "vscf_ctr_drbg.h"

#include <virgil/crypto/common/private/vsc_buffer_defs.h>
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
//  Note, this method is called automatically when method vscf_group_session_ticket_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_group_session_ticket_init_ctx(vscf_group_session_ticket_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_group_session_ticket_cleanup_ctx(vscf_group_session_ticket_t *self);

static void
vscf_group_session_ticket_set_session_id(vscf_group_session_ticket_t *self, vsc_data_t session_id);

static vscf_status_t
vscf_group_session_ticket_generate_key(vscf_group_session_ticket_t *self) VSCF_NODISCARD;

//
//  Return size of 'vscf_group_session_ticket_t'.
//
VSCF_PUBLIC size_t
vscf_group_session_ticket_ctx_size(void) {

    return sizeof(vscf_group_session_ticket_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_group_session_ticket_init(vscf_group_session_ticket_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_group_session_ticket_t));

    self->refcnt = 1;

    vscf_group_session_ticket_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_group_session_ticket_cleanup(vscf_group_session_ticket_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_group_session_ticket_cleanup_ctx(self);

    vscf_group_session_ticket_release_rng(self);

    vscf_zeroize(self, sizeof(vscf_group_session_ticket_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_group_session_ticket_t *
vscf_group_session_ticket_new(void) {

    vscf_group_session_ticket_t *self = (vscf_group_session_ticket_t *) vscf_alloc(sizeof (vscf_group_session_ticket_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_group_session_ticket_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_group_session_ticket_delete(vscf_group_session_ticket_t *self) {

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

    vscf_group_session_ticket_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_group_session_ticket_new ()'.
//
VSCF_PUBLIC void
vscf_group_session_ticket_destroy(vscf_group_session_ticket_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_group_session_ticket_t *self = *self_ref;
    *self_ref = NULL;

    vscf_group_session_ticket_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_group_session_ticket_t *
vscf_group_session_ticket_shallow_copy(vscf_group_session_ticket_t *self) {

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
//  Random used to generate keys
//
//  Note, ownership is shared.
//
VSCF_PUBLIC void
vscf_group_session_ticket_use_rng(vscf_group_session_ticket_t *self, vscf_impl_t *rng) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(rng);
    VSCF_ASSERT(self->rng == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(rng));

    self->rng = vscf_impl_shallow_copy(rng);
}

//
//  Random used to generate keys
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_group_session_ticket_take_rng(vscf_group_session_ticket_t *self, vscf_impl_t *rng) {

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
vscf_group_session_ticket_release_rng(vscf_group_session_ticket_t *self) {

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
//  Note, this method is called automatically when method vscf_group_session_ticket_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_group_session_ticket_init_ctx(vscf_group_session_ticket_t *self) {

    VSCF_ASSERT_PTR(self);

    self->msg = vscf_group_session_message_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_group_session_ticket_cleanup_ctx(vscf_group_session_ticket_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_group_session_message_destroy(&self->msg);
}

//
//  Setups default dependencies:
//  - RNG: CTR DRBG
//
VSCF_PUBLIC vscf_status_t
vscf_group_session_ticket_setup_defaults(vscf_group_session_ticket_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(self->rng == NULL);

    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    vscf_status_t status = vscf_ctr_drbg_setup_defaults(rng);

    if (status != vscf_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&rng);
        return vscf_status_ERROR_RANDOM_FAILED;
    }

    vscf_group_session_ticket_take_rng(self, vscf_ctr_drbg_impl(rng));

    return vscf_status_SUCCESS;
}

VSCF_PUBLIC vscf_status_t
vscf_group_session_ticket_setup_ticket_internal(
        vscf_group_session_ticket_t *self, uint32_t epoch, vsc_data_t session_id) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->rng);

    vscf_group_session_message_set_type(self->msg, vscf_group_msg_type_GROUP_INFO);

    vscf_group_session_ticket_set_session_id(self, session_id);
    self->msg->message_pb.group_info.epoch = epoch;

    return vscf_group_session_ticket_generate_key(self);
}

//
//  Set this ticket to start new group session.
//
VSCF_PUBLIC vscf_status_t
vscf_group_session_ticket_setup_ticket_as_new(vscf_group_session_ticket_t *self, vsc_data_t session_id) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->rng);

    vscf_group_session_message_set_type(self->msg, vscf_group_msg_type_GROUP_INFO);

    vscf_group_session_ticket_set_session_id(self, session_id);

    vscf_status_t status = vscf_group_session_ticket_generate_key(self);

    return status;
}

static void
vscf_group_session_ticket_set_session_id(vscf_group_session_ticket_t *self, vsc_data_t session_id) {

    VSCF_ASSERT(self);
    VSCF_ASSERT(session_id.len == sizeof(vscf_group_session_id_t));

    memcpy(self->msg->message_pb.group_info.session_id, session_id.bytes, session_id.len);
}

static vscf_status_t
vscf_group_session_ticket_generate_key(vscf_group_session_ticket_t *self) {

    VSCF_ASSERT(self);
    VSCF_ASSERT(self->rng);

    vsc_buffer_t root_key;
    vsc_buffer_init(&root_key);
    vsc_buffer_use(&root_key, self->msg->message_pb.group_info.key, sizeof(vscf_group_session_symmetric_key_t));

    vscf_status_t f_status = vscf_random(self->rng, sizeof(vscf_group_session_symmetric_key_t), &root_key);

    vsc_buffer_delete(&root_key);

    if (f_status != vscf_status_SUCCESS) {
        return vscf_status_ERROR_RANDOM_FAILED;
    }

    return vscf_status_SUCCESS;
}

//
//  Returns message that should be sent to all participants using secure channel.
//
VSCF_PUBLIC const vscf_group_session_message_t *
vscf_group_session_ticket_get_ticket_message(const vscf_group_session_ticket_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->msg);

    return self->msg;
}
