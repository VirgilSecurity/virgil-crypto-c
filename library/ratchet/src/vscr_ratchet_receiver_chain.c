//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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

#include "vscr_ratchet_receiver_chain.h"
#include "vscr_memory.h"
#include "vscr_assert.h"

#include <ed25519/ed25519.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_receiver_chain_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_receiver_chain_init_ctx(vscr_ratchet_receiver_chain_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_receiver_chain_cleanup_ctx(vscr_ratchet_receiver_chain_t *self);

//
//  Return size of 'vscr_ratchet_receiver_chain_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_receiver_chain_ctx_size(void) {

    return sizeof(vscr_ratchet_receiver_chain_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_receiver_chain_init(vscr_ratchet_receiver_chain_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_receiver_chain_t));

    self->refcnt = 1;

    vscr_ratchet_receiver_chain_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_receiver_chain_cleanup(vscr_ratchet_receiver_chain_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_ratchet_receiver_chain_cleanup_ctx(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_receiver_chain_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_receiver_chain_t *
vscr_ratchet_receiver_chain_new(void) {

    vscr_ratchet_receiver_chain_t *self = (vscr_ratchet_receiver_chain_t *) vscr_alloc(sizeof (vscr_ratchet_receiver_chain_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_receiver_chain_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCR_PUBLIC void
vscr_ratchet_receiver_chain_delete(const vscr_ratchet_receiver_chain_t *self) {

    vscr_ratchet_receiver_chain_t *local_self = (vscr_ratchet_receiver_chain_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSCR_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSCR_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vscr_ratchet_receiver_chain_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_receiver_chain_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_receiver_chain_destroy(vscr_ratchet_receiver_chain_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_receiver_chain_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_receiver_chain_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_receiver_chain_t *
vscr_ratchet_receiver_chain_shallow_copy(vscr_ratchet_receiver_chain_t *self) {

    VSCR_ASSERT_PTR(self);

    #if defined(VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSCR_PUBLIC const vscr_ratchet_receiver_chain_t *
vscr_ratchet_receiver_chain_shallow_copy_const(const vscr_ratchet_receiver_chain_t *self) {

    return vscr_ratchet_receiver_chain_shallow_copy((vscr_ratchet_receiver_chain_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_receiver_chain_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_receiver_chain_init_ctx(vscr_ratchet_receiver_chain_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_ratchet_chain_key_init(&self->chain_key);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_receiver_chain_cleanup_ctx(vscr_ratchet_receiver_chain_t *self) {

    VSCR_ASSERT_PTR(self);

    vscf_impl_destroy(&self->public_key_second);
}

VSCR_PUBLIC void
vscr_ratchet_receiver_chain_serialize(
        const vscr_ratchet_receiver_chain_t *self, vscr_ReceiverChain *receiver_chain_pb) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(receiver_chain_pb);

    memcpy(receiver_chain_pb->public_key_id, self->public_key_id, sizeof(self->public_key_id));
    memcpy(receiver_chain_pb->public_key_first, self->public_key_first, sizeof(receiver_chain_pb->public_key_first));
    vscr_ratchet_chain_key_serialize(&self->chain_key, &receiver_chain_pb->chain_key);

    if (self->public_key_second != NULL) {
        vscr_ratchet_pb_utils_serialize_public_key(self->public_key_second, &receiver_chain_pb->public_key_second);
    }
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_receiver_chain_deserialize(const vscr_ReceiverChain *receiver_chain_pb,
        vscr_ratchet_receiver_chain_t *receiver_chain, vscf_round5_t *round5) {

    VSCR_ASSERT_PTR(round5);
    VSCR_ASSERT_PTR(receiver_chain);
    VSCR_ASSERT_PTR(receiver_chain_pb);

    vscr_status_t status = vscr_status_SUCCESS;

    memcpy(receiver_chain->public_key_id, receiver_chain_pb->public_key_id, sizeof(receiver_chain_pb->public_key_id));
    memcpy(receiver_chain->public_key_first, receiver_chain_pb->public_key_first,
            sizeof(receiver_chain_pb->public_key_first));
    vscr_ratchet_chain_key_deserialize(&receiver_chain_pb->chain_key, &receiver_chain->chain_key);

    if (receiver_chain_pb->public_key_second != NULL) {
        status = vscr_ratchet_pb_utils_deserialize_public_key(
                round5, receiver_chain_pb->public_key_second, &receiver_chain->public_key_second);
        if (status != vscr_status_SUCCESS) {
            goto err;
        }
    }

err:
    return status;
}
