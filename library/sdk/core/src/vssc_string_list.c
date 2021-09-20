//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2021 Virgil Security, Inc.
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
//  Handles a list of "string" class objects.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_string_list.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_string_list_private.h"
#include "vssc_string_list_defs.h"

#include <virgil/crypto/common/vsc_str_buffer.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_string_list_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_string_list_init_ctx(vssc_string_list_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_string_list_cleanup_ctx(vssc_string_list_t *self);

//
//  Return size of 'vssc_string_list_t'.
//
VSSC_PUBLIC size_t
vssc_string_list_ctx_size(void) {

    return sizeof(vssc_string_list_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_string_list_init(vssc_string_list_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_string_list_t));

    self->refcnt = 1;

    vssc_string_list_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_string_list_cleanup(vssc_string_list_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_string_list_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_string_list_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_string_list_t *
vssc_string_list_new(void) {

    vssc_string_list_t *self = (vssc_string_list_t *) vssc_alloc(sizeof (vssc_string_list_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_string_list_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_string_list_delete(const vssc_string_list_t *self) {

    vssc_string_list_t *local_self = (vssc_string_list_t *)self;

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

    vssc_string_list_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_string_list_new ()'.
//
VSSC_PUBLIC void
vssc_string_list_destroy(vssc_string_list_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_string_list_t *self = *self_ref;
    *self_ref = NULL;

    vssc_string_list_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_string_list_t *
vssc_string_list_shallow_copy(vssc_string_list_t *self) {

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
VSSC_PUBLIC const vssc_string_list_t *
vssc_string_list_shallow_copy_const(const vssc_string_list_t *self) {

    return vssc_string_list_shallow_copy((vssc_string_list_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_string_list_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_string_list_init_ctx(vssc_string_list_t *self) {

    VSSC_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_string_list_cleanup_ctx(vssc_string_list_t *self) {

    VSSC_ASSERT_PTR(self);

    vsc_str_buffer_delete(self->item);
    vssc_string_list_destroy(&self->next);
}

//
//  Add new item to the list.
//
VSSC_PUBLIC void
vssc_string_list_add(vssc_string_list_t *self, vsc_str_t str) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid(str));

    vsc_str_buffer_t *str_buffer = vsc_str_buffer_new_with_str(str);
    vssc_string_list_add_disown(self, &str_buffer);
}

//
//  Add new item to the list.
//  Note, string buffer is copied.
//
VSSC_PUBLIC void
vssc_string_list_add_copy(vssc_string_list_t *self, const vsc_str_buffer_t *str_buffer) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_buffer_is_valid(str_buffer));

    if (NULL == self->item) {
        self->item = vsc_str_buffer_shallow_copy_const(str_buffer);
    } else {
        if (NULL == self->next) {
            self->next = vssc_string_list_new();
            self->next->prev = self;
        }
        vssc_string_list_add_copy(self->next, str_buffer);
    }
}

//
//  Add new item to the list.
//  Note, ownership is transferred.
//
VSSC_PUBLIC void
vssc_string_list_add_disown(vssc_string_list_t *self, vsc_str_buffer_t **str_buffer_ref) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT_REF(str_buffer_ref);
    VSSC_ASSERT(vsc_str_buffer_is_valid(*str_buffer_ref));

    if (NULL == self->item) {
        self->item = *str_buffer_ref;
        *str_buffer_ref = NULL;
    } else {
        if (NULL == self->next) {
            self->next = vssc_string_list_new();
            self->next->prev = self;
        }
        vssc_string_list_add_disown(self->next, str_buffer_ref);
    }
}

//
//  Remove current node.
//
VSSC_PRIVATE void
vssc_string_list_remove_self(vssc_string_list_t *self) {

    VSSC_ASSERT_PTR(self);

    vsc_str_buffer_delete(self->item);
    if (self->next) {
        vssc_string_list_t *next = self->next;
        self->item = next->item;
        self->next = next->next;
        next->next = NULL; //  prevent chain destruction
        next->item = NULL;
        next->prev = NULL;
        vssc_string_list_destroy(&next);
    }
}

//
//  Return true if given list has item.
//
VSSC_PUBLIC bool
vssc_string_list_has_item(const vssc_string_list_t *self) {

    VSSC_ASSERT_PTR(self);

    return vsc_str_buffer_is_valid(self->item);
}

//
//  Return list item.
//
VSSC_PUBLIC vsc_str_t
vssc_string_list_item(const vssc_string_list_t *self) {

    VSSC_ASSERT_PTR(self);

    return vsc_str_buffer_str(self->item);
}

//
//  Return true if list has next item.
//
VSSC_PUBLIC bool
vssc_string_list_has_next(const vssc_string_list_t *self) {

    VSSC_ASSERT_PTR(self);

    return self->next != NULL;
}

//
//  Return next list node if exists, or NULL otherwise.
//
VSSC_PUBLIC const vssc_string_list_t *
vssc_string_list_next(const vssc_string_list_t *self) {

    VSSC_ASSERT_PTR(self);

    return self->next;
}

//
//  Return true if list has previous item.
//
VSSC_PUBLIC bool
vssc_string_list_has_prev(const vssc_string_list_t *self) {

    VSSC_ASSERT_PTR(self);

    return self->prev != NULL;
}

//
//  Return previous list node if exists, or NULL otherwise.
//
VSSC_PUBLIC const vssc_string_list_t *
vssc_string_list_prev(const vssc_string_list_t *self) {

    VSSC_ASSERT_PTR(self);

    return self->prev;
}

//
//  Remove all items.
//
VSSC_PUBLIC void
vssc_string_list_clear(vssc_string_list_t *self) {

    VSSC_ASSERT_PTR(self);

    vsc_str_buffer_delete(self->item);
    self->item = NULL;
    vssc_string_list_destroy(&self->next);
}

//
//  Return number of items within list.
//
VSSC_PUBLIC size_t
vssc_string_list_count(const vssc_string_list_t *self) {

    size_t count = 0;

    for (const vssc_string_list_t *it = self; (it != NULL) && (it->item != NULL); it = it->next) {
        ++count;
    }

    return count;
}

//
//  Return true if list contains a given value.
//
VSSC_PUBLIC bool
vssc_string_list_contains(const vssc_string_list_t *self, vsc_str_t str) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid(str));

    for (const vssc_string_list_t *it = self; (it != NULL) && (it->item != NULL); it = it->next) {

        if (vsc_str_equal(vsc_str_buffer_str(it->item), str)) {
            return true;
        }
    }

    return false;
}
