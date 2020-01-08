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

#include "vscr_ratchet_skipped_messages.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_skipped_messages_defs.h"
#include "vscr_ratchet_chain_key.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_skipped_messages_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_skipped_messages_init_ctx(vscr_ratchet_skipped_messages_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_skipped_messages_cleanup_ctx(vscr_ratchet_skipped_messages_t *self);

//
//  Return size of 'vscr_ratchet_skipped_messages_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_skipped_messages_ctx_size(void) {

    return sizeof(vscr_ratchet_skipped_messages_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_skipped_messages_init(vscr_ratchet_skipped_messages_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_skipped_messages_t));

    self->refcnt = 1;

    vscr_ratchet_skipped_messages_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_skipped_messages_cleanup(vscr_ratchet_skipped_messages_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_ratchet_skipped_messages_cleanup_ctx(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_skipped_messages_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_skipped_messages_t *
vscr_ratchet_skipped_messages_new(void) {

    vscr_ratchet_skipped_messages_t *self = (vscr_ratchet_skipped_messages_t *) vscr_alloc(sizeof (vscr_ratchet_skipped_messages_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_skipped_messages_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCR_PUBLIC void
vscr_ratchet_skipped_messages_delete(vscr_ratchet_skipped_messages_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCR_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCR_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCR_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscr_ratchet_skipped_messages_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_skipped_messages_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_skipped_messages_destroy(vscr_ratchet_skipped_messages_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_skipped_messages_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_skipped_messages_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_skipped_messages_t *
vscr_ratchet_skipped_messages_shallow_copy(vscr_ratchet_skipped_messages_t *self) {

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


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_skipped_messages_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_skipped_messages_init_ctx(vscr_ratchet_skipped_messages_t *self) {

    VSCR_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_skipped_messages_cleanup_ctx(vscr_ratchet_skipped_messages_t *self) {

    VSCR_ASSERT_PTR(self);

    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_SKIPPED_DH; i++) {
        vscr_ratchet_skipped_messages_root_node_destroy(&self->root_nodes[i]);
    }
}

VSCR_PUBLIC vscr_ratchet_message_key_t *
vscr_ratchet_skipped_messages_find_key(
        const vscr_ratchet_skipped_messages_t *self, uint32_t counter, const vscr_ratchet_public_key_t public_key) {

    VSCR_ASSERT_PTR(self);

    size_t i = vscr_ratchet_skipped_messages_find_public_key(self, public_key);

    if (i == self->roots_count) {
        return NULL;
    }

    vscr_ratchet_message_key_node_t *node = self->root_nodes[i]->first;

    while (node) {
        if (counter == node->value->index) {
            return node->value;
        }

        node = node->next;
    }

    return NULL;
}

VSCR_PUBLIC uint32_t
vscr_ratchet_skipped_messages_find_public_key(
        const vscr_ratchet_skipped_messages_t *self, const vscr_ratchet_public_key_t public_key) {

    VSCR_ASSERT_PTR(self);

    size_t i = 0;
    for (; i < self->roots_count; i++) {
        if (memcmp(self->public_keys[i], public_key, sizeof(self->public_keys[i])) == 0) {
            break;
        }
    }

    return i;
}

VSCR_PUBLIC void
vscr_ratchet_skipped_messages_delete_key(vscr_ratchet_skipped_messages_t *self,
        const vscr_ratchet_public_key_t public_key, vscr_ratchet_message_key_t *message_key) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(message_key);

    size_t i = vscr_ratchet_skipped_messages_find_public_key(self, public_key);

    if (i == self->roots_count) {
        VSCR_ASSERT(false);
    }

    vscr_ratchet_skipped_messages_root_node_delete_key(self->root_nodes[i], message_key);
}

VSCR_PUBLIC void
vscr_ratchet_skipped_messages_add_public_key(
        vscr_ratchet_skipped_messages_t *self, const vscr_ratchet_public_key_t public_key) {

    size_t index = vscr_ratchet_skipped_messages_find_public_key(self, public_key);

    if (index != self->roots_count) {
        VSCR_ASSERT(false);
    }

    if (self->roots_count == vscr_ratchet_common_hidden_MAX_SKIPPED_DH) {
        vscr_ratchet_skipped_messages_root_node_destroy(
                &self->root_nodes[vscr_ratchet_common_hidden_MAX_SKIPPED_DH - 1]);
    }

    for (size_t i = vscr_ratchet_common_hidden_MAX_SKIPPED_DH - 1; i > 0; i--) {
        self->root_nodes[i] = self->root_nodes[i - 1];
        memcpy(self->public_keys[i], self->public_keys[i - 1], sizeof(self->public_keys[i]));
    }

    self->root_nodes[0] = vscr_ratchet_skipped_messages_root_node_new();
    memcpy(self->public_keys[0], public_key, sizeof(self->public_keys[0]));

    if (self->roots_count < vscr_ratchet_common_hidden_MAX_SKIPPED_DH) {
        self->roots_count++;
    }
}

VSCR_PUBLIC void
vscr_ratchet_skipped_messages_add_key(vscr_ratchet_skipped_messages_t *self, const vscr_ratchet_public_key_t public_key,
        vscr_ratchet_message_key_t *message_key) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(message_key);

    size_t i = vscr_ratchet_skipped_messages_find_public_key(self, public_key);

    VSCR_ASSERT(i != vscr_ratchet_common_hidden_MAX_SKIPPED_DH);

    vscr_ratchet_skipped_messages_root_node_add_key(self->root_nodes[i], message_key);
}

VSCR_PUBLIC void
vscr_ratchet_skipped_messages_serialize(
        const vscr_ratchet_skipped_messages_t *self, vscr_SkippedMessages *skipped_messages_pb) {

    VSCR_ASSERT_PTR(self);

    skipped_messages_pb->keys_count = self->roots_count;

    for (size_t i = 0; i < self->roots_count; i++) {

        vscr_SkippedMessageKey *root_pb = &skipped_messages_pb->keys[i];

        memcpy(root_pb->public_key, self->public_keys[i], sizeof(root_pb->public_key));

        vscr_ratchet_skipped_messages_root_node_serialize(
                self->root_nodes[i], &root_pb->message_keys, &root_pb->message_keys_count);
    }
}

VSCR_PUBLIC void
vscr_ratchet_skipped_messages_deserialize(
        const vscr_SkippedMessages *skipped_messages_pb, vscr_ratchet_skipped_messages_t *skipped_messages) {

    VSCR_ASSERT_PTR(skipped_messages_pb);
    VSCR_ASSERT_PTR(skipped_messages);

    skipped_messages->roots_count = skipped_messages_pb->keys_count;

    for (pb_size_t i = 0; i < skipped_messages_pb->keys_count; i++) {
        vscr_ratchet_skipped_messages_root_node_t *root = vscr_ratchet_skipped_messages_root_node_new();

        const vscr_SkippedMessageKey *root_pb = &skipped_messages_pb->keys[i];
        memcpy(skipped_messages->public_keys[i], root_pb->public_key, sizeof(skipped_messages->public_keys[i]));

        vscr_ratchet_skipped_messages_root_node_deserialize(root_pb->message_keys, root_pb->message_keys_count, root);

        skipped_messages->root_nodes[i] = root;
    }
}
