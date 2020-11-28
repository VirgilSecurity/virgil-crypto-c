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


//  @description
// --------------------------------------------------------------------------
//  Handles a list of "card" class objects.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_card_list.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_card_list_private.h"
#include "vssc_card_list_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_card_list_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_card_list_init_ctx(vssc_card_list_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_card_list_cleanup_ctx(vssc_card_list_t *self);

//
//  Return size of 'vssc_card_list_t'.
//
VSSC_PUBLIC size_t
vssc_card_list_ctx_size(void) {

    return sizeof(vssc_card_list_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_card_list_init(vssc_card_list_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_card_list_t));

    self->refcnt = 1;

    vssc_card_list_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_card_list_cleanup(vssc_card_list_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_card_list_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_card_list_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_card_list_t *
vssc_card_list_new(void) {

    vssc_card_list_t *self = (vssc_card_list_t *) vssc_alloc(sizeof (vssc_card_list_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_card_list_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_card_list_delete(const vssc_card_list_t *self) {

    vssc_card_list_t *local_self = (vssc_card_list_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSSC_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSSC_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vssc_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vssc_card_list_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_card_list_new ()'.
//
VSSC_PUBLIC void
vssc_card_list_destroy(vssc_card_list_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_card_list_t *self = *self_ref;
    *self_ref = NULL;

    vssc_card_list_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_card_list_t *
vssc_card_list_shallow_copy(vssc_card_list_t *self) {

    VSSC_ASSERT_PTR(self);

    #if defined(VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSSC_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSC_PUBLIC const vssc_card_list_t *
vssc_card_list_shallow_copy_const(const vssc_card_list_t *self) {

    return vssc_card_list_shallow_copy((vssc_card_list_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_card_list_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_card_list_init_ctx(vssc_card_list_t *self) {

    VSSC_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_card_list_cleanup_ctx(vssc_card_list_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_card_list_clear(self);
}

//
//  Add new item to the list.
//  Note, ownership is transfered.
//
VSSC_PUBLIC void
vssc_card_list_add(vssc_card_list_t *self, vssc_card_t **card_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_PTR(card_ref);
    VSSC_ASSERT_PTR(*card_ref);

    if (NULL == self->item) {
        self->item = *card_ref;
        *card_ref = NULL;
    } else {
        if (NULL == self->next) {
            self->next = vssc_card_list_new();
            self->next->prev = self;
        }
        vssc_card_list_add(self->next, card_ref);
    }
}

//
//  Remove current node.
//
VSSC_PRIVATE void
vssc_card_list_remove_self(vssc_card_list_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_card_destroy(&self->item);
    if (self->next) {
        vssc_card_list_t *next = self->next;
        self->item = next->item;
        self->next = next->next;
        next->next = NULL; //  prevent chain destruction
        next->item = NULL;
        next->prev = NULL;
        vssc_card_list_destroy(&next);
    }
}

//
//  Return true if given list has item.
//
VSSC_PUBLIC bool
vssc_card_list_has_item(const vssc_card_list_t *self) {

    VSSC_ASSERT_PTR(self);

    return self->item != NULL;
}

//
//  Return list item.
//
VSSC_PUBLIC const vssc_card_t *
vssc_card_list_item(const vssc_card_list_t *self) {

    VSSC_ASSERT_PTR(self);

    return self->item;
}

//
//  Return true if list has next item.
//
VSSC_PUBLIC bool
vssc_card_list_has_next(const vssc_card_list_t *self) {

    VSSC_ASSERT_PTR(self);

    return self->next != NULL;
}

//
//  Return next list node if exists, or NULL otherwise.
//
VSSC_PUBLIC const vssc_card_list_t *
vssc_card_list_next(const vssc_card_list_t *self) {

    VSSC_ASSERT_PTR(self);

    return self->next;
}

//
//  Return true if list has previous item.
//
VSSC_PUBLIC bool
vssc_card_list_has_prev(const vssc_card_list_t *self) {

    VSSC_ASSERT_PTR(self);

    return self->prev != NULL;
}

//
//  Return previous list node if exists, or NULL otherwise.
//
VSSC_PUBLIC const vssc_card_list_t *
vssc_card_list_prev(const vssc_card_list_t *self) {

    VSSC_ASSERT_PTR(self);

    return self->prev;
}

//
//  Remove all items.
//
VSSC_PUBLIC void
vssc_card_list_clear(vssc_card_list_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_card_destroy(&self->item);
    vssc_card_list_destroy(&self->next);
}

//
//  Find first card with it's identity.
//
VSSC_PUBLIC const vssc_card_t *
vssc_card_list_find_with_identity(const vssc_card_list_t *self, vsc_str_t identity, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(identity));

    for (const vssc_card_list_t *it = self; (it != NULL) && (it->item != NULL); it = it->next) {

        const vssc_card_t *card = it->item;

        vsc_str_t candidate_identity = vssc_card_identity(card);

        if (vsc_str_icase_equal(candidate_identity, identity)) {
            return card;
        }
    }

    VSSC_ERROR_SAFE_UPDATE(error, vssc_status_NOT_FOUND);

    return NULL;
}

//
//  Find card with it's identifier.
//
VSSC_PUBLIC const vssc_card_t *
vssc_card_list_find_with_identifier(const vssc_card_list_t *self, vsc_str_t identifier, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(identifier));

    for (const vssc_card_list_t *it = self; (it != NULL) && (it->item != NULL); it = it->next) {

        const vssc_card_t *card = it->item;

        vsc_str_t candidate_identifier = vssc_card_identifier(card);

        if (vsc_str_icase_equal(candidate_identifier, identifier)) {
            return card;
        }
    }

    VSSC_ERROR_SAFE_UPDATE(error, vssc_status_NOT_FOUND);

    return NULL;
}
