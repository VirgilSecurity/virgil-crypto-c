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

#include "vscr_ratchet_receiver_chains.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_common_hidden.h"
#include "vscr_ratchet_chain_key.h"
#include "vscr_ratchet_receiver_chain_list_node.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Handle 'ratchet receiver chains' context.
//
struct vscr_ratchet_receiver_chains_t {
    //
    //  Function do deallocate self context.
    //
    vscr_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    size_t refcnt;

    vscr_ratchet_receiver_chain_list_node_t *chains;
};

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_receiver_chains_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_receiver_chains_init_ctx(vscr_ratchet_receiver_chains_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_receiver_chains_cleanup_ctx(vscr_ratchet_receiver_chains_t *self);

//
//  Return size of 'vscr_ratchet_receiver_chains_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_receiver_chains_ctx_size(void) {

    return sizeof(vscr_ratchet_receiver_chains_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_receiver_chains_init(vscr_ratchet_receiver_chains_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_receiver_chains_t));

    self->refcnt = 1;

    vscr_ratchet_receiver_chains_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_receiver_chains_cleanup(vscr_ratchet_receiver_chains_t *self) {

    if (self == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscr_ratchet_receiver_chains_cleanup_ctx(self);

        vscr_zeroize(self, sizeof(vscr_ratchet_receiver_chains_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_receiver_chains_t *
vscr_ratchet_receiver_chains_new(void) {

    vscr_ratchet_receiver_chains_t *self = (vscr_ratchet_receiver_chains_t *) vscr_alloc(sizeof (vscr_ratchet_receiver_chains_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_receiver_chains_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_receiver_chains_delete(vscr_ratchet_receiver_chains_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscr_ratchet_receiver_chains_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_receiver_chains_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_receiver_chains_destroy(vscr_ratchet_receiver_chains_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_receiver_chains_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_receiver_chains_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_receiver_chains_t *
vscr_ratchet_receiver_chains_shallow_copy(vscr_ratchet_receiver_chains_t *self) {

    VSCR_ASSERT_PTR(self);

    ++self->refcnt;

    return self;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_receiver_chains_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_receiver_chains_init_ctx(vscr_ratchet_receiver_chains_t *self) {

    VSCR_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_receiver_chains_cleanup_ctx(vscr_ratchet_receiver_chains_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_ratchet_receiver_chain_list_node_t *node = self->chains;

    while (node) {
        vscr_ratchet_receiver_chain_list_node_t *next = node->next;
        vscr_ratchet_receiver_chain_list_node_destroy(&node);
        node = next;
    }
}

VSCR_PUBLIC vscr_ratchet_receiver_chain_t *
vscr_ratchet_receiver_chains_first_chain(vscr_ratchet_receiver_chains_t *self) {

    VSCR_ASSERT_PTR(self);

    if (self->chains) {
        return self->chains->value;
    }

    return NULL;
}

VSCR_PUBLIC vscr_ratchet_receiver_chain_t *
vscr_ratchet_receiver_chains_find_chain(vscr_ratchet_receiver_chains_t *self, vsc_data_t ratchet_public_key) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(ratchet_public_key.len == vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH);

    vscr_ratchet_receiver_chain_list_node_t *chain_list_node = self->chains;

    while (chain_list_node) {
        if (!memcmp(ratchet_public_key.bytes, chain_list_node->value->public_key,
                    vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH)) {
            return chain_list_node->value;
        }
        chain_list_node = chain_list_node->next;
    }

    return NULL;
}

VSCR_PUBLIC vscr_ratchet_receiver_chain_t *
vscr_ratchet_receiver_chains_add_chain(
        vscr_ratchet_receiver_chains_t *self, vscr_ratchet_receiver_chain_t *receiver_chain) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(receiver_chain);

    vscr_ratchet_receiver_chain_list_node_t *receiver_chain_list_node = vscr_ratchet_receiver_chain_list_node_new();
    receiver_chain_list_node->value = vscr_ratchet_receiver_chain_shallow_copy(receiver_chain);
    receiver_chain_list_node->next = self->chains;
    self->chains = receiver_chain_list_node;

    if (!self->chains->next) {
        return receiver_chain_list_node->value;
    }

    size_t chains_count = 2;
    while (receiver_chain_list_node->next->next) {
        chains_count += 1;
        receiver_chain_list_node = receiver_chain_list_node->next;
    }

    VSCR_ASSERT(chains_count <= vscr_ratchet_common_hidden_MAX_RECEIVERS_CHAINS);

    if (chains_count == vscr_ratchet_common_hidden_MAX_RECEIVERS_CHAINS) {
        vscr_ratchet_receiver_chain_list_node_destroy(&receiver_chain_list_node->next);
    }

    return receiver_chain_list_node->value;
}

VSCR_PUBLIC void
vscr_ratchet_receiver_chains_delete_next_chain_if_possible(
        vscr_ratchet_receiver_chains_t *self, vscr_ratchet_receiver_chain_t *chain, size_t prev_chain_count) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(chain);

    if (prev_chain_count == 0)
        return;

    vscr_ratchet_receiver_chain_list_node_t *node = self->chains;

    while (node) {
        if (node->value == chain) {
            if (node->next && node->next->value->chain_key.index == prev_chain_count) {
                vscr_ratchet_receiver_chain_list_node_t *to_delete = node->next;
                node->next = node->next->next;

                to_delete->next = NULL;
                vscr_ratchet_receiver_chain_list_node_destroy(&to_delete);
            }

            return;
        }

        node = node->next;
    }

    VSCR_ASSERT(false);
}

VSCR_PUBLIC void
vscr_ratchet_receiver_chains_serialize(vscr_ratchet_receiver_chains_t *self, ReceiverChains *receiver_chains_pb) {

    VSCR_ASSERT_PTR(self);

    vscr_ratchet_receiver_chain_list_node_t *receiver_chain = self->chains;

    pb_size_t chains_count = 0;
    while (receiver_chain) {
        vscr_ratchet_receiver_chain_serialize(receiver_chain->value, &receiver_chains_pb->chains[chains_count]);

        chains_count++;
        receiver_chains_pb->chains_count = chains_count;
        receiver_chain = receiver_chain->next;
    }
}

VSCR_PUBLIC void
vscr_ratchet_receiver_chains_deserialize(
        ReceiverChains *receiver_chains_pb, vscr_ratchet_receiver_chains_t *receiver_chains) {

    VSCR_ASSERT_PTR(receiver_chains_pb);
    VSCR_ASSERT_PTR(receiver_chains);

    for (pb_size_t i = receiver_chains_pb->chains_count; i > 0; i--) {
        vscr_ratchet_receiver_chain_t *receiver_chain = vscr_ratchet_receiver_chain_new();

        vscr_ratchet_receiver_chain_deserialize(&receiver_chains_pb->chains[i - 1], receiver_chain);

        vscr_ratchet_receiver_chains_add_chain(receiver_chains, receiver_chain);

        vscr_ratchet_receiver_chain_destroy(&receiver_chain);
    }
}
