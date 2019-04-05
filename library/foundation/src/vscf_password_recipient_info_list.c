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
//  Handles a list of "password recipient info" class objects.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_password_recipient_info_list.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_password_recipient_info_list_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_password_recipient_info_list_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_password_recipient_info_list_init_ctx(vscf_password_recipient_info_list_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_password_recipient_info_list_cleanup_ctx(vscf_password_recipient_info_list_t *self);

//
//  Return size of 'vscf_password_recipient_info_list_t'.
//
VSCF_PUBLIC size_t
vscf_password_recipient_info_list_ctx_size(void) {

    return sizeof(vscf_password_recipient_info_list_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_password_recipient_info_list_init(vscf_password_recipient_info_list_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_password_recipient_info_list_t));

    self->refcnt = 1;

    vscf_password_recipient_info_list_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_password_recipient_info_list_cleanup(vscf_password_recipient_info_list_t *self) {

    if (self == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscf_password_recipient_info_list_cleanup_ctx(self);

        vscf_zeroize(self, sizeof(vscf_password_recipient_info_list_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_password_recipient_info_list_t *
vscf_password_recipient_info_list_new(void) {

    vscf_password_recipient_info_list_t *self = (vscf_password_recipient_info_list_t *) vscf_alloc(sizeof (vscf_password_recipient_info_list_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_password_recipient_info_list_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCF_PUBLIC void
vscf_password_recipient_info_list_delete(vscf_password_recipient_info_list_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_password_recipient_info_list_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_password_recipient_info_list_new ()'.
//
VSCF_PUBLIC void
vscf_password_recipient_info_list_destroy(vscf_password_recipient_info_list_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_password_recipient_info_list_t *self = *self_ref;
    *self_ref = NULL;

    vscf_password_recipient_info_list_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_password_recipient_info_list_t *
vscf_password_recipient_info_list_shallow_copy(vscf_password_recipient_info_list_t *self) {

    VSCF_ASSERT_PTR(self);

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
//  Note, this method is called automatically when method vscf_password_recipient_info_list_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_password_recipient_info_list_init_ctx(vscf_password_recipient_info_list_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_password_recipient_info_list_cleanup_ctx(vscf_password_recipient_info_list_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_password_recipient_info_destroy(&self->item);
    vscf_password_recipient_info_list_destroy(&self->next);
}

//
//  Add new item to the list.
//  Note, ownership is transfered.
//
VSCF_PUBLIC void
vscf_password_recipient_info_list_add(vscf_password_recipient_info_list_t *self,
        vscf_password_recipient_info_t **password_recipient_info_ref) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(password_recipient_info_ref);
    VSCF_ASSERT_PTR(*password_recipient_info_ref);

    if (NULL == self->item) {
        self->item = *password_recipient_info_ref;
        *password_recipient_info_ref = NULL;
    } else {
        if (NULL == self->next) {
            self->next = vscf_password_recipient_info_list_new();
            self->next->prev = self;
        }
        vscf_password_recipient_info_list_add(self->next, password_recipient_info_ref);
    }
}

//
//  Return true if given list has item.
//
VSCF_PUBLIC bool
vscf_password_recipient_info_list_has_item(const vscf_password_recipient_info_list_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->item != NULL;
}

//
//  Return list item.
//
VSCF_PUBLIC const vscf_password_recipient_info_t *
vscf_password_recipient_info_list_item(const vscf_password_recipient_info_list_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->item);

    return self->item;
}

//
//  Return true if list has next item.
//
VSCF_PUBLIC bool
vscf_password_recipient_info_list_has_next(const vscf_password_recipient_info_list_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->next != NULL;
}

//
//  Return next list node if exists, or NULL otherwise.
//
VSCF_PUBLIC vscf_password_recipient_info_list_t *
vscf_password_recipient_info_list_next(const vscf_password_recipient_info_list_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->next;
}

//
//  Return true if list has previous item.
//
VSCF_PUBLIC bool
vscf_password_recipient_info_list_has_prev(const vscf_password_recipient_info_list_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->prev != NULL;
}

//
//  Return previous list node if exists, or NULL otherwise.
//
VSCF_PUBLIC vscf_password_recipient_info_list_t *
vscf_password_recipient_info_list_prev(const vscf_password_recipient_info_list_t *self) {

    VSCF_ASSERT_PTR(self);

    return self->prev;
}

//
//  Remove all items.
//
VSCF_PUBLIC void
vscf_password_recipient_info_list_clear(vscf_password_recipient_info_list_t *self) {

    vscf_password_recipient_info_destroy(&self->item);
    vscf_password_recipient_info_list_destroy(&self->next);
}
