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
#include "vscr_ratchet_common_hidden.h"
#include "vscr_ratchet_chain_key.h"
#include "vscr_ratchet_skipped_message_key_list_node.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Handle 'ratchet skipped messages' context.
//
struct vscr_ratchet_skipped_messages_t {
    //
    //  Function do deallocate self context.
    //
    vscr_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    size_t refcnt;

    vscr_ratchet_skipped_message_key_list_node_t *keys;
};

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

    vscr_ratchet_skipped_message_key_list_node_destroy(&self->keys);
}

VSCR_PUBLIC vscr_ratchet_skipped_message_key_t *
vscr_ratchet_skipped_messages_find_key(
        vscr_ratchet_skipped_messages_t *self, size_t counter, vsc_data_t ratchet_public_key) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT(ratchet_public_key.len == vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH);

    vscr_ratchet_skipped_message_key_list_node_t *skipped_message_key_list_node = self->keys;

    while (skipped_message_key_list_node) {
        if (counter == skipped_message_key_list_node->value->message_key->index &&
                !memcmp(ratchet_public_key.bytes, skipped_message_key_list_node->value->public_key,
                        vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH)) {
            return skipped_message_key_list_node->value;
        }
        skipped_message_key_list_node = skipped_message_key_list_node->next;
    }

    return NULL;
}

VSCR_PUBLIC void
vscr_ratchet_skipped_messages_delete_key(
        vscr_ratchet_skipped_messages_t *self, vscr_ratchet_skipped_message_key_t *skipped_message_key) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(skipped_message_key);

    vscr_ratchet_skipped_message_key_list_node_t *skipped_message_key_list_node_prev = NULL;
    vscr_ratchet_skipped_message_key_list_node_t *skipped_message_key_list_node = self->keys;

    while (skipped_message_key_list_node) {
        if (skipped_message_key_list_node->value == skipped_message_key) {
            if (skipped_message_key_list_node_prev) {
                skipped_message_key_list_node_prev->next = skipped_message_key_list_node->next;
            } else {
                self->keys = skipped_message_key_list_node->next;
            }

            skipped_message_key_list_node->next = NULL;
            vscr_ratchet_skipped_message_key_list_node_destroy(&skipped_message_key_list_node);

            return;
        }

        skipped_message_key_list_node_prev = skipped_message_key_list_node;
        skipped_message_key_list_node = skipped_message_key_list_node->next;
    }

    // Element not found
    VSCR_ASSERT(false);
}

VSCR_PUBLIC void
vscr_ratchet_skipped_messages_add_key(
        vscr_ratchet_skipped_messages_t *self, vscr_ratchet_skipped_message_key_t *skipped_message_key) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(skipped_message_key);

    vscr_ratchet_skipped_message_key_list_node_t *skipped_message_key_list_node =
            vscr_ratchet_skipped_message_key_list_node_new();
    skipped_message_key_list_node->value = skipped_message_key;
    skipped_message_key_list_node->next = self->keys;
    self->keys = skipped_message_key_list_node;

    if (!self->keys->next) {

        return;
    }

    size_t msgs_count = 2;
    while (skipped_message_key_list_node->next->next) {
        msgs_count += 1;
        skipped_message_key_list_node = skipped_message_key_list_node->next;
    }

    VSCR_ASSERT(msgs_count <= vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES + 1);

    if (msgs_count == vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES + 1) {
        vscr_ratchet_skipped_message_key_list_node_destroy(&skipped_message_key_list_node->next);
    }
}

VSCR_PUBLIC void
vscr_ratchet_skipped_messages_serialize(vscr_ratchet_skipped_messages_t *self, SkippedMessages *skipped_messages_pb) {

    VSCR_ASSERT_PTR(self);

    pb_size_t skipped_count = 0;

    vscr_ratchet_skipped_message_key_list_node_t *skipped_message_key = self->keys;

    while (skipped_message_key) {
        vscr_ratchet_skipped_message_key_serialize(
                skipped_message_key->value, &skipped_messages_pb->keys[skipped_count]);

        skipped_count++;
        skipped_messages_pb->keys_count = skipped_count;
        skipped_message_key = skipped_message_key->next;
    }
}

VSCR_PUBLIC void
vscr_ratchet_skipped_messages_deserialize(
        SkippedMessages *skipped_messages_pb, vscr_ratchet_skipped_messages_t *skipped_messages) {

    VSCR_ASSERT_PTR(skipped_messages_pb);
    VSCR_ASSERT_PTR(skipped_messages);

    for (pb_size_t i = skipped_messages_pb->keys_count; i > 0; i--) {
        vscr_ratchet_skipped_message_key_t *skipped_message_key = vscr_ratchet_skipped_message_key_new();

        vscr_ratchet_skipped_message_key_deserialize(&skipped_messages_pb->keys[i - 1], skipped_message_key);

        vscr_ratchet_skipped_messages_add_key(skipped_messages, skipped_message_key);

        vscr_ratchet_skipped_message_key_destroy(&skipped_message_key);
    }
}
