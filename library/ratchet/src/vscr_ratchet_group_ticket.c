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

#include "vscr_ratchet_group_ticket.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_common_hidden.h"
#include "vscr_ratchet_message_defs.h"
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
//  Handle 'ratchet group ticket' context.
//
struct vscr_ratchet_group_ticket_t {
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

    vscr_ratchet_group_message_t *msg;
};

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

    self->msg = vscr_ratchet_group_message_new();
    GroupMessage msg = GroupMessage_init_zero;
    self->msg->message_pb = msg;
    self->msg->message_pb.has_group_info = true;
    self->msg->message_pb.version = 1;
    self->msg->message_pb.group_info.version = 1;
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_group_ticket_cleanup_ctx(vscr_ratchet_group_ticket_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_ratchet_group_message_destroy(&self->msg);
}

//
//  Setups default dependencies:
//  - RNG: CTR DRBG
//  - Key serialization: DER PKCS8
//  - Symmetric cipher: AES256-GCM
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

VSCR_PUBLIC vscr_status_t
vscr_ratchet_group_ticket_set_credentials(vscr_ratchet_group_ticket_t *self, vsc_data_t participant_id) {

    VSCR_ASSERT_PTR(self);

    return vscr_ratchet_group_ticket_add_participant(self, participant_id);
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_group_ticket_add_participant(vscr_ratchet_group_ticket_t *self, vsc_data_t participant_id) {

    VSCR_ASSERT_PTR(self);

    VSCR_ASSERT(participant_id.len == vscr_ratchet_common_PARTICIPANT_ID_LEN);

    ParticipantInfo *info =
            &self->msg->message_pb.group_info.participants[self->msg->message_pb.group_info.participants_count];

    info->version = 1;
    memcpy(info->id, participant_id.bytes, sizeof(info->id));

    vsc_buffer_t key;
    vsc_buffer_init(&key);

    vsc_buffer_use(&key, info->key, sizeof(info->key));

    vscf_status_t status = vscf_random(self->rng, sizeof(info->key), &key);

    vsc_buffer_cleanup(&key);

    if (status != vscf_status_SUCCESS) {
        return vscr_status_ERROR_RNG_FAILED;
    }

    self->msg->message_pb.group_info.participants_count++;

    return vscr_status_SUCCESS;
}

VSCR_PUBLIC const vscr_ratchet_group_message_t *
vscr_ratchet_group_ticket_generate_ticket(const vscr_ratchet_group_ticket_t *self) {

    VSCR_ASSERT_PTR(self);

    return self->msg;
}
