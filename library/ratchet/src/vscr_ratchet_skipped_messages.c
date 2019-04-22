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

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscr_ratchet_skipped_messages_cleanup_ctx(self);

        vscr_zeroize(self, sizeof(vscr_ratchet_skipped_messages_t));
    }
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
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_skipped_messages_delete(vscr_ratchet_skipped_messages_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscr_ratchet_skipped_messages_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
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
        const vscr_ratchet_skipped_messages_t *self, size_t counter, const vscr_ratchet_public_key_t public_key) {

    VSCR_ASSERT_PTR(self);

    size_t i = vscr_ratchet_skipped_messages_find_public_key(self, public_key);

    if (i == vscr_ratchet_common_hidden_MAX_SKIPPED_DH) {
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

VSCR_PUBLIC size_t
vscr_ratchet_skipped_messages_find_public_key(
        const vscr_ratchet_skipped_messages_t *self, const vscr_ratchet_public_key_t public_key) {

    VSCR_ASSERT_PTR(self);

    size_t i = 0;
    for (; i < vscr_ratchet_common_hidden_MAX_SKIPPED_DH; i++) {
        if (self->root_nodes[i] &&
                memcmp(self->root_nodes[i]->public_key, public_key, sizeof(self->root_nodes[i]->public_key)) == 0) {
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

    if (i == vscr_ratchet_common_hidden_MAX_SKIPPED_DH) {
        VSCR_ASSERT(false);
    }

    vscr_ratchet_skipped_messages_root_node_t *root = self->root_nodes[i];

    vscr_ratchet_message_key_node_t *prev = NULL;
    vscr_ratchet_message_key_node_t *node = root->first;

    for (size_t j = 0; j < root->count; j++) {
        if (node->value == message_key) {
            if (prev) {
                prev->next = node->next;
            }

            if (node->next) {
                node->next->prev = prev;
            }

            if (node == root->first) {
                root->first = node->next;
            }

            if (node == root->last) {
                root->last = node->prev;
            }

            node->next = NULL;
            vscr_ratchet_message_key_node_destroy(&node);

            root->count--;

            return;
        }

        prev = node;
        node = node->next;
    }

    // Element not found
    VSCR_ASSERT(false);
}

VSCR_PUBLIC void
vscr_ratchet_skipped_messages_add_public_key(
        vscr_ratchet_skipped_messages_t *self, const vscr_ratchet_public_key_t public_key) {

    size_t i = vscr_ratchet_skipped_messages_find_public_key(self, public_key);

    if (i != vscr_ratchet_common_hidden_MAX_SKIPPED_DH) {
        VSCR_ASSERT(false);
    }

    vscr_ratchet_skipped_messages_root_node_destroy(&self->root_nodes[vscr_ratchet_common_hidden_MAX_SKIPPED_DH - 1]);

    for (i = vscr_ratchet_common_hidden_MAX_SKIPPED_DH - 1; i > 0; i--) {
        self->root_nodes[i] = self->root_nodes[i - 1];
    }

    self->root_nodes[0] = vscr_ratchet_skipped_messages_root_node_new();

    memcpy(self->root_nodes[0]->public_key, public_key, sizeof(self->root_nodes[0]->public_key));
}

VSCR_PUBLIC void
vscr_ratchet_skipped_messages_add_key(vscr_ratchet_skipped_messages_t *self, const vscr_ratchet_public_key_t public_key,
        vscr_ratchet_message_key_t *message_key) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(message_key);

    size_t i = vscr_ratchet_skipped_messages_find_public_key(self, public_key);

    VSCR_ASSERT(i != vscr_ratchet_common_hidden_MAX_SKIPPED_DH);

    vscr_ratchet_skipped_messages_root_node_t *root = self->root_nodes[i];

    vscr_ratchet_message_key_node_t *node = vscr_ratchet_message_key_node_new();
    node->value = message_key;
    node->next = root->first;

    vscr_ratchet_message_key_node_t *prev_first = root->first;

    root->first = node;

    if (prev_first) {
        prev_first->prev = node;
    } else {
        root->last = node;
    }

    if (root->count == vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES) {
        vscr_ratchet_message_key_node_t *last = root->last;
        root->last = last->prev;
        root->last->next = NULL;

        vscr_ratchet_message_key_node_destroy(&last);
    } else {
        root->count++;
    }
}

VSCR_PUBLIC void
vscr_ratchet_skipped_messages_serialize(
        const vscr_ratchet_skipped_messages_t *self, SkippedMessages *skipped_messages_pb) {

    VSCR_ASSERT_PTR(self);

    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_SKIPPED_DH; i++) {

        const vscr_ratchet_skipped_messages_root_node_t *root = self->root_nodes[i];

        if (!root) {
            continue;
        }

        SkippedMessageKey *root_pb = &skipped_messages_pb->keys[skipped_messages_pb->keys_count++];

        root_pb->index = i;

        memcpy(root_pb->public_key, root->public_key, sizeof(root_pb->public_key));

        root_pb->message_keys_count = root->count;

        const vscr_ratchet_message_key_node_t *node = root->first;

        for (size_t j = 0; j < root->count; j++) {
            vscr_ratchet_message_key_serialize(node->value, &root_pb->message_keys[j]);
            node = node->next;
        }
    }
}

VSCR_PUBLIC void
vscr_ratchet_skipped_messages_deserialize(
        SkippedMessages *skipped_messages_pb, vscr_ratchet_skipped_messages_t *skipped_messages) {

    VSCR_ASSERT_PTR(skipped_messages_pb);
    VSCR_ASSERT_PTR(skipped_messages);

    for (pb_size_t i = 0; i < skipped_messages_pb->keys_count; i++) {
        vscr_ratchet_skipped_messages_root_node_t *root = vscr_ratchet_skipped_messages_root_node_new();
        SkippedMessageKey *root_pb = &skipped_messages_pb->keys[i];
        memcpy(root->public_key, root_pb->public_key, sizeof(root->public_key));

        skipped_messages->root_nodes[root_pb->index] = root;

        vscr_ratchet_message_key_node_t *prev = NULL;

        root->count = root_pb->message_keys_count;

        for (pb_size_t j = 0; j < root_pb->message_keys_count; j++) {
            vscr_ratchet_message_key_t *message_key = vscr_ratchet_message_key_new();

            vscr_ratchet_message_key_deserialize(&root_pb->message_keys[j], message_key);

            vscr_ratchet_message_key_node_t *key_node = vscr_ratchet_message_key_node_new();

            key_node->value = message_key;
            key_node->prev = prev;

            if (prev) {
                prev->next = key_node;
            } else {
                root->first = key_node;
            }

            prev = key_node;

            if (j == root_pb->message_keys_count - 1) {
                root->last = key_node;
            }
        }
    }
}
