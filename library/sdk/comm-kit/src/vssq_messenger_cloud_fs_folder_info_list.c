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
//  Handles a list of "messenger cloud fs folder info" class objects.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssq_messenger_cloud_fs_folder_info_list.h"
#include "vssq_memory.h"
#include "vssq_assert.h"
#include "vssq_messenger_cloud_fs_folder_info_list_private.h"
#include "vssq_messenger_cloud_fs_folder_info_list_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_cloud_fs_folder_info_list_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_cloud_fs_folder_info_list_init_ctx(vssq_messenger_cloud_fs_folder_info_list_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_cloud_fs_folder_info_list_cleanup_ctx(vssq_messenger_cloud_fs_folder_info_list_t *self);

//
//  Return size of 'vssq_messenger_cloud_fs_folder_info_list_t'.
//
VSSQ_PUBLIC size_t
vssq_messenger_cloud_fs_folder_info_list_ctx_size(void) {

    return sizeof(vssq_messenger_cloud_fs_folder_info_list_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_info_list_init(vssq_messenger_cloud_fs_folder_info_list_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_zeroize(self, sizeof(vssq_messenger_cloud_fs_folder_info_list_t));

    self->refcnt = 1;

    vssq_messenger_cloud_fs_folder_info_list_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_info_list_cleanup(vssq_messenger_cloud_fs_folder_info_list_t *self) {

    if (self == NULL) {
        return;
    }

    vssq_messenger_cloud_fs_folder_info_list_cleanup_ctx(self);

    vssq_zeroize(self, sizeof(vssq_messenger_cloud_fs_folder_info_list_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_folder_info_list_t *
vssq_messenger_cloud_fs_folder_info_list_new(void) {

    vssq_messenger_cloud_fs_folder_info_list_t *self = (vssq_messenger_cloud_fs_folder_info_list_t *) vssq_alloc(sizeof (vssq_messenger_cloud_fs_folder_info_list_t));
    VSSQ_ASSERT_ALLOC(self);

    vssq_messenger_cloud_fs_folder_info_list_init(self);

    self->self_dealloc_cb = vssq_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_info_list_delete(const vssq_messenger_cloud_fs_folder_info_list_t *self) {

    vssq_messenger_cloud_fs_folder_info_list_t *local_self = (vssq_messenger_cloud_fs_folder_info_list_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSSQ_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSSQ_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vssq_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vssq_messenger_cloud_fs_folder_info_list_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssq_messenger_cloud_fs_folder_info_list_new ()'.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_info_list_destroy(vssq_messenger_cloud_fs_folder_info_list_t **self_ref) {

    VSSQ_ASSERT_PTR(self_ref);

    vssq_messenger_cloud_fs_folder_info_list_t *self = *self_ref;
    *self_ref = NULL;

    vssq_messenger_cloud_fs_folder_info_list_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSQ_PUBLIC vssq_messenger_cloud_fs_folder_info_list_t *
vssq_messenger_cloud_fs_folder_info_list_shallow_copy(vssq_messenger_cloud_fs_folder_info_list_t *self) {

    VSSQ_ASSERT_PTR(self);

    #if defined(VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSSQ_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_folder_info_list_t *
vssq_messenger_cloud_fs_folder_info_list_shallow_copy_const(const vssq_messenger_cloud_fs_folder_info_list_t *self) {

    return vssq_messenger_cloud_fs_folder_info_list_shallow_copy((vssq_messenger_cloud_fs_folder_info_list_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssq_messenger_cloud_fs_folder_info_list_init() is called.
//  Note, that context is already zeroed.
//
static void
vssq_messenger_cloud_fs_folder_info_list_init_ctx(vssq_messenger_cloud_fs_folder_info_list_t *self) {

    VSSQ_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssq_messenger_cloud_fs_folder_info_list_cleanup_ctx(vssq_messenger_cloud_fs_folder_info_list_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_messenger_cloud_fs_folder_info_list_clear(self);
}

//
//  Add new item to the list.
//  Note, ownership is retained.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_info_list_add(
        vssq_messenger_cloud_fs_folder_info_list_t *self, vssq_messenger_cloud_fs_folder_info_t *folder_info) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_PTR(folder_info);

    if (NULL == self->item) {
        self->item = vssq_messenger_cloud_fs_folder_info_shallow_copy(folder_info);
    } else {
        if (NULL == self->next) {
            self->next = vssq_messenger_cloud_fs_folder_info_list_new();
            self->next->prev = self;
        }
        vssq_messenger_cloud_fs_folder_info_list_add(self->next, folder_info);
    }
}

//
//  Add new item to the list.
//  Note, ownership is transfered.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_info_list_add_disown(
        vssq_messenger_cloud_fs_folder_info_list_t *self, vssq_messenger_cloud_fs_folder_info_t **folder_info_ref) {

    VSSQ_ASSERT_PTR(self);
    VSSQ_ASSERT_REF(folder_info_ref);

    if (NULL == self->item) {
        self->item = *folder_info_ref;
        *folder_info_ref = NULL;
    } else {
        if (NULL == self->next) {
            self->next = vssq_messenger_cloud_fs_folder_info_list_new();
            self->next->prev = self;
        }
        vssq_messenger_cloud_fs_folder_info_list_add_disown(self->next, folder_info_ref);
    }
}

//
//  Remove current node.
//
VSSQ_PRIVATE void
vssq_messenger_cloud_fs_folder_info_list_remove_self(vssq_messenger_cloud_fs_folder_info_list_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_messenger_cloud_fs_folder_info_delete(self->item);
    self->item = NULL;
    if (self->next) {
        vssq_messenger_cloud_fs_folder_info_list_t *next = self->next;
        self->item = next->item;
        self->next = next->next;
        next->next = NULL; //  prevent chain destruction
        next->item = NULL;
        next->prev = NULL;
        vssq_messenger_cloud_fs_folder_info_list_destroy(&next);
    }
}

//
//  Return true if given list has item.
//
VSSQ_PUBLIC bool
vssq_messenger_cloud_fs_folder_info_list_has_item(const vssq_messenger_cloud_fs_folder_info_list_t *self) {

    VSSQ_ASSERT_PTR(self);

    return self->item != NULL;
}

//
//  Return list item.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_folder_info_t *
vssq_messenger_cloud_fs_folder_info_list_item(const vssq_messenger_cloud_fs_folder_info_list_t *self) {

    VSSQ_ASSERT_PTR(self);

    return self->item;
}

//
//  Return true if list has next item.
//
VSSQ_PUBLIC bool
vssq_messenger_cloud_fs_folder_info_list_has_next(const vssq_messenger_cloud_fs_folder_info_list_t *self) {

    VSSQ_ASSERT_PTR(self);

    return self->next != NULL;
}

//
//  Return next list node if exists, or NULL otherwise.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_folder_info_list_t *
vssq_messenger_cloud_fs_folder_info_list_next(const vssq_messenger_cloud_fs_folder_info_list_t *self) {

    VSSQ_ASSERT_PTR(self);

    return self->next;
}

//
//  Return true if list has previous item.
//
VSSQ_PUBLIC bool
vssq_messenger_cloud_fs_folder_info_list_has_prev(const vssq_messenger_cloud_fs_folder_info_list_t *self) {

    VSSQ_ASSERT_PTR(self);

    return self->prev != NULL;
}

//
//  Return previous list node if exists, or NULL otherwise.
//
VSSQ_PUBLIC const vssq_messenger_cloud_fs_folder_info_list_t *
vssq_messenger_cloud_fs_folder_info_list_prev(const vssq_messenger_cloud_fs_folder_info_list_t *self) {

    VSSQ_ASSERT_PTR(self);

    return self->prev;
}

//
//  Remove all items.
//
VSSQ_PUBLIC void
vssq_messenger_cloud_fs_folder_info_list_clear(vssq_messenger_cloud_fs_folder_info_list_t *self) {

    VSSQ_ASSERT_PTR(self);

    vssq_messenger_cloud_fs_folder_info_delete(self->item);
    self->item = NULL;
    vssq_messenger_cloud_fs_folder_info_list_destroy(&self->next);
}
