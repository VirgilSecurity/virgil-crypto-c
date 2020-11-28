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
//  Handles a list of map's list of key-value pairs.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_string_map_bucket.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_string_map_bucket_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_string_map_bucket_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_string_map_bucket_init_ctx(vssc_string_map_bucket_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_string_map_bucket_cleanup_ctx(vssc_string_map_bucket_t *self);

//
//  Return size of 'vssc_string_map_bucket_t'.
//
VSSC_PUBLIC size_t
vssc_string_map_bucket_ctx_size(void) {

    return sizeof(vssc_string_map_bucket_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_string_map_bucket_init(vssc_string_map_bucket_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_string_map_bucket_t));

    self->refcnt = 1;

    vssc_string_map_bucket_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_string_map_bucket_cleanup(vssc_string_map_bucket_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_string_map_bucket_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_string_map_bucket_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_string_map_bucket_t *
vssc_string_map_bucket_new(void) {

    vssc_string_map_bucket_t *self = (vssc_string_map_bucket_t *) vssc_alloc(sizeof (vssc_string_map_bucket_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_string_map_bucket_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_string_map_bucket_delete(const vssc_string_map_bucket_t *self) {

    vssc_string_map_bucket_t *local_self = (vssc_string_map_bucket_t *)self;

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

    vssc_string_map_bucket_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_string_map_bucket_new ()'.
//
VSSC_PUBLIC void
vssc_string_map_bucket_destroy(vssc_string_map_bucket_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_string_map_bucket_t *self = *self_ref;
    *self_ref = NULL;

    vssc_string_map_bucket_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_string_map_bucket_t *
vssc_string_map_bucket_shallow_copy(vssc_string_map_bucket_t *self) {

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
VSSC_PUBLIC const vssc_string_map_bucket_t *
vssc_string_map_bucket_shallow_copy_const(const vssc_string_map_bucket_t *self) {

    return vssc_string_map_bucket_shallow_copy((vssc_string_map_bucket_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_string_map_bucket_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_string_map_bucket_init_ctx(vssc_string_map_bucket_t *self) {

    VSSC_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_string_map_bucket_cleanup_ctx(vssc_string_map_bucket_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_string_map_bucket_clear(self);
}

//
//  Add key-value pair to the bucket.
//
VSSC_PUBLIC void
vssc_string_map_bucket_put(vssc_string_map_bucket_t *self, vsc_str_t key, vsc_str_t value) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(key));
    VSSC_ASSERT(vsc_str_is_valid(value));

    for (vssc_string_map_bucket_t *it = self; (it != NULL); it = it->next) {

        if (NULL == it->key) {
            // Insert values to the last empty bucket.
            it->key = vsc_str_buffer_new_with_str(key);
            it->value = vsc_str_buffer_new_with_str(value);

        } else if (vsc_str_equal(vsc_str_buffer_str(it->key), key)) {
            // Rewrite value for the same key.
            vsc_str_buffer_destroy(&it->value);
            it->value = vsc_str_buffer_new_with_str(value);
        } else if (NULL == it->next) {
            //  Create the last empty bucket.
            it->next = vssc_string_map_bucket_new();
            it->next->prev = it;
        }

        // Go to the next bucket.
    }
}

//
//  Remove all items.
//
VSSC_PUBLIC void
vssc_string_map_bucket_clear(vssc_string_map_bucket_t *self) {

    VSSC_ASSERT_PTR(self);

    vsc_str_buffer_destroy(&self->key);
    vsc_str_buffer_destroy(&self->value);
    vssc_string_map_bucket_destroy(&self->next);
}

//
//  Find value for a given key.
//
VSSC_PUBLIC vsc_str_t
vssc_string_map_bucket_find(const vssc_string_map_bucket_t *self, vsc_str_t key, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(key));

    for (const vssc_string_map_bucket_t *it = self; (it != NULL) && (it->key != NULL); it = it->next) {

        vsc_str_t candidate_key = vsc_str_buffer_str(it->key);

        if (vsc_str_equal(candidate_key, key)) {
            return vsc_str_buffer_str(it->value);
        }
    }

    VSSC_ERROR_SAFE_UPDATE(error, vssc_status_NOT_FOUND);

    return vsc_str_empty();
}
