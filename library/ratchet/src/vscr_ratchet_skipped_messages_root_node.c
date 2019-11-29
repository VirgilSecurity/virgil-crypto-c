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

#include "vscr_ratchet_skipped_messages_root_node.h"
#include "vscr_memory.h"
#include "vscr_assert.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_skipped_messages_root_node_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_skipped_messages_root_node_init_ctx(vscr_ratchet_skipped_messages_root_node_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_skipped_messages_root_node_cleanup_ctx(vscr_ratchet_skipped_messages_root_node_t *self);

//
//  Return size of 'vscr_ratchet_skipped_messages_root_node_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_skipped_messages_root_node_ctx_size(void) {

    return sizeof(vscr_ratchet_skipped_messages_root_node_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_skipped_messages_root_node_init(vscr_ratchet_skipped_messages_root_node_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_skipped_messages_root_node_t));

    self->refcnt = 1;

    vscr_ratchet_skipped_messages_root_node_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_skipped_messages_root_node_cleanup(vscr_ratchet_skipped_messages_root_node_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_ratchet_skipped_messages_root_node_cleanup_ctx(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_skipped_messages_root_node_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_skipped_messages_root_node_t *
vscr_ratchet_skipped_messages_root_node_new(void) {

    vscr_ratchet_skipped_messages_root_node_t *self = (vscr_ratchet_skipped_messages_root_node_t *) vscr_alloc(sizeof (vscr_ratchet_skipped_messages_root_node_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_skipped_messages_root_node_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCR_PUBLIC void
vscr_ratchet_skipped_messages_root_node_delete(vscr_ratchet_skipped_messages_root_node_t *self) {

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

    vscr_ratchet_skipped_messages_root_node_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_skipped_messages_root_node_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_skipped_messages_root_node_destroy(vscr_ratchet_skipped_messages_root_node_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_skipped_messages_root_node_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_skipped_messages_root_node_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_skipped_messages_root_node_t *
vscr_ratchet_skipped_messages_root_node_shallow_copy(vscr_ratchet_skipped_messages_root_node_t *self) {

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
//  Note, this method is called automatically when method vscr_ratchet_skipped_messages_root_node_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_skipped_messages_root_node_init_ctx(vscr_ratchet_skipped_messages_root_node_t *self) {

    VSCR_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_skipped_messages_root_node_cleanup_ctx(vscr_ratchet_skipped_messages_root_node_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_ratchet_message_key_node_destroy(&self->first);
}

VSCR_PUBLIC vscr_ratchet_message_key_t *
vscr_ratchet_skipped_messages_root_node_find_key(const vscr_ratchet_skipped_messages_root_node_t *self,
        uint32_t counter) {

    VSCR_ASSERT_PTR(self);

    vscr_ratchet_message_key_node_t *node = self->first;

    while (node) {
        if (counter == node->value->index) {
            return node->value;
        }

        node = node->next;
    }

    return NULL;
}

VSCR_PUBLIC void
vscr_ratchet_skipped_messages_root_node_delete_key(vscr_ratchet_skipped_messages_root_node_t *self,
        vscr_ratchet_message_key_t *message_key) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(message_key);

    vscr_ratchet_message_key_node_t *prev = NULL;
    vscr_ratchet_message_key_node_t *node = self->first;

    for (size_t j = 0; j < self->count; j++) {
        if (node->value == message_key) {
            if (prev) {
                prev->next = node->next;
            }

            if (node->next) {
                node->next->prev = prev;
            }

            if (node == self->first) {
                self->first = node->next;
            }

            if (node == self->last) {
                self->last = node->prev;
            }

            node->next = NULL;
            vscr_ratchet_message_key_node_destroy(&node);

            self->count--;

            return;
        }

        prev = node;
        node = node->next;
    }

    // Element not found
    VSCR_ASSERT(false);
}

VSCR_PUBLIC void
vscr_ratchet_skipped_messages_root_node_add_key(vscr_ratchet_skipped_messages_root_node_t *self,
        vscr_ratchet_message_key_t *message_key) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(message_key);

    vscr_ratchet_message_key_node_t *node = vscr_ratchet_message_key_node_new();
    node->value = message_key;
    node->next = self->first;

    vscr_ratchet_message_key_node_t *prev_first = self->first;

    self->first = node;

    if (prev_first) {
        prev_first->prev = node;
    } else {
        self->last = node;
    }

    if (self->count == vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES) {
        vscr_ratchet_message_key_node_t *last = self->last;
        self->last = last->prev;
        self->last->next = NULL;

        vscr_ratchet_message_key_node_destroy(&last);
    } else {
        self->count++;
    }
}

VSCR_PUBLIC void
vscr_ratchet_skipped_messages_root_node_serialize(const vscr_ratchet_skipped_messages_root_node_t *self,
        vscr_MessageKey **skipped_messages_pb, pb_size_t *count) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(skipped_messages_pb);
    VSCR_ASSERT_PTR(count);

    *count = self->count;

    if (self->count) {
        *skipped_messages_pb = vscr_alloc(self->count * sizeof(vscr_MessageKey));
    }

    vscr_ratchet_message_key_node_t *node = self->first;

    for (size_t i = 0; i < self->count; i++, node = node->next) {
        vscr_ratchet_message_key_serialize(node->value, &(*skipped_messages_pb)[i]);
    }
}

VSCR_PUBLIC void
vscr_ratchet_skipped_messages_root_node_deserialize(const vscr_MessageKey *skipped_messages_pb, pb_size_t count,
        vscr_ratchet_skipped_messages_root_node_t *skipped_messages) {

    if (count != 0) {
        VSCR_ASSERT_PTR(skipped_messages_pb);
    }
    VSCR_ASSERT_PTR(skipped_messages);

    vscr_ratchet_message_key_node_t *prev = NULL;

    skipped_messages->count = count;

    for (pb_size_t j = 0; j < count; j++) {
        vscr_ratchet_message_key_t *message_key = vscr_ratchet_message_key_new();

        vscr_ratchet_message_key_deserialize(&skipped_messages_pb[j], message_key);

        vscr_ratchet_message_key_node_t *key_node = vscr_ratchet_message_key_node_new();

        key_node->value = message_key;
        key_node->prev = prev;

        if (prev) {
            prev->next = key_node;
        } else {
            skipped_messages->first = key_node;
        }

        prev = key_node;

        if (j == skipped_messages->count - 1) {
            skipped_messages->last = key_node;
        }
    }
}
