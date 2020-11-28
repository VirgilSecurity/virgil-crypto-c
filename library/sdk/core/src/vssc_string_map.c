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
//  Handles a map: key=string, value=string.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vssc_string_map.h"
#include "vssc_memory.h"
#include "vssc_assert.h"
#include "vssc_string_map_defs.h"
#include "vssc_string_list_private.h"
#include "vssc_string_map_bucket_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Private integral constants.
//
enum {
    vssc_string_map_CAPACITY_DEFAULT = 50
};

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_string_map_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_string_map_init_ctx(vssc_string_map_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_string_map_cleanup_ctx(vssc_string_map_t *self);

//
//  Create an optimal map.
//
static void
vssc_string_map_init_ctx_with_capacity(vssc_string_map_t *self, size_t capacity);

//
//  Calculates bucket index based on a given key.
//
static size_t
vssc_string_map_calculate_bucket_index(const vssc_string_map_t *self, vsc_str_t key);

//
//  Calculates a hash code for a given key.
//
static size_t
vssc_string_map_hash_code(vsc_str_t key);

//
//  Return size of 'vssc_string_map_t'.
//
VSSC_PUBLIC size_t
vssc_string_map_ctx_size(void) {

    return sizeof(vssc_string_map_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSSC_PUBLIC void
vssc_string_map_init(vssc_string_map_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_string_map_t));

    self->refcnt = 1;

    vssc_string_map_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSSC_PUBLIC void
vssc_string_map_cleanup(vssc_string_map_t *self) {

    if (self == NULL) {
        return;
    }

    vssc_string_map_cleanup_ctx(self);

    vssc_zeroize(self, sizeof(vssc_string_map_t));
}

//
//  Allocate context and perform it's initialization.
//
VSSC_PUBLIC vssc_string_map_t *
vssc_string_map_new(void) {

    vssc_string_map_t *self = (vssc_string_map_t *) vssc_alloc(sizeof (vssc_string_map_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_string_map_init(self);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Create an optimal map.
//
VSSC_PUBLIC void
vssc_string_map_init_with_capacity(vssc_string_map_t *self, size_t capacity) {

    VSSC_ASSERT_PTR(self);

    vssc_zeroize(self, sizeof(vssc_string_map_t));

    self->refcnt = 1;

    vssc_string_map_init_ctx_with_capacity(self, capacity);
}

//
//  Allocate class context and perform it's initialization.
//  Create an optimal map.
//
VSSC_PUBLIC vssc_string_map_t *
vssc_string_map_new_with_capacity(size_t capacity) {

    vssc_string_map_t *self = (vssc_string_map_t *) vssc_alloc(sizeof (vssc_string_map_t));
    VSSC_ASSERT_ALLOC(self);

    vssc_string_map_init_with_capacity(self, capacity);

    self->self_dealloc_cb = vssc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSSC_PUBLIC void
vssc_string_map_delete(const vssc_string_map_t *self) {

    vssc_string_map_t *local_self = (vssc_string_map_t *)self;

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

    vssc_string_map_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vssc_string_map_new ()'.
//
VSSC_PUBLIC void
vssc_string_map_destroy(vssc_string_map_t **self_ref) {

    VSSC_ASSERT_PTR(self_ref);

    vssc_string_map_t *self = *self_ref;
    *self_ref = NULL;

    vssc_string_map_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSSC_PUBLIC vssc_string_map_t *
vssc_string_map_shallow_copy(vssc_string_map_t *self) {

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
VSSC_PUBLIC const vssc_string_map_t *
vssc_string_map_shallow_copy_const(const vssc_string_map_t *self) {

    return vssc_string_map_shallow_copy((vssc_string_map_t *)self);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vssc_string_map_init() is called.
//  Note, that context is already zeroed.
//
static void
vssc_string_map_init_ctx(vssc_string_map_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_string_map_init_ctx_with_capacity(self, vssc_string_map_CAPACITY_DEFAULT);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vssc_string_map_cleanup_ctx(vssc_string_map_t *self) {

    VSSC_ASSERT_PTR(self);

    for (size_t index = 0; index < self->capacity; ++index) {
        vssc_string_map_bucket_destroy(&(self->buckets[index]));
    }

    vssc_dealloc(self->buckets);
}

//
//  Create an optimal map.
//
static void
vssc_string_map_init_ctx_with_capacity(vssc_string_map_t *self, size_t capacity) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(0 < capacity && capacity <= vssc_string_map_CAPACITY_MAX);


    self->buckets = vssc_alloc(sizeof(vssc_string_map_bucket_t) * capacity);
    self->capacity = capacity;
}

//
//  Put a new pair to the map.
//
VSSC_PUBLIC void
vssc_string_map_put(vssc_string_map_t *self, vsc_str_t key, vsc_str_t value) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(key));
    VSSC_ASSERT(vsc_str_is_valid(value));

    const size_t bucket_index = vssc_string_map_calculate_bucket_index(self, key);
    if (NULL == self->buckets[bucket_index]) {
        self->buckets[bucket_index] = vssc_string_map_bucket_new();
    }

    vssc_string_map_bucket_put(self->buckets[bucket_index], key, value);
}

//
//  Return a value of the given key, or error.
//
VSSC_PUBLIC vsc_str_t
vssc_string_map_get(const vssc_string_map_t *self, vsc_str_t key, vssc_error_t *error) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(key));

    const size_t bucket_index = vssc_string_map_calculate_bucket_index(self, key);
    if (NULL == self->buckets[bucket_index]) {
        VSSC_ERROR_SAFE_UPDATE(error, vssc_status_NOT_FOUND);
        return vsc_str_empty();
    }

    return vssc_string_map_bucket_find(self->buckets[bucket_index], key, error);
}

//
//  Return true if value of the given key exists.
//
VSSC_PUBLIC bool
vssc_string_map_contains(const vssc_string_map_t *self, vsc_str_t key) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(key));

    vssc_error_t error;
    vssc_error_reset(&error);

    vsc_str_t value = vssc_string_map_get(self, key, &error);
    VSSC_UNUSED(value);

    return !vssc_error_has_error(&error);
    ;
}

//
//  Return map keys.
//
VSSC_PUBLIC vssc_string_list_t *
vssc_string_map_keys(const vssc_string_map_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_string_list_t *keys = vssc_string_list_new();

    for (size_t pos = 0; pos < self->capacity; ++pos) {
        for (vssc_string_map_bucket_t *bucket = self->buckets[pos]; (bucket != NULL) && (bucket->key != NULL);
                bucket = bucket->next) {
            vssc_string_list_add_copy(keys, bucket->key);
        }
    }

    return keys;
}

//
//  Return map values.
//
VSSC_PUBLIC vssc_string_list_t *
vssc_string_map_values(const vssc_string_map_t *self) {

    VSSC_ASSERT_PTR(self);

    vssc_string_list_t *values = vssc_string_list_new();

    for (size_t pos = 0; pos < self->capacity; ++pos) {
        for (vssc_string_map_bucket_t *bucket = self->buckets[pos]; (bucket != NULL) && (bucket->value != NULL);
                bucket = bucket->next) {
            vssc_string_list_add_copy(values, bucket->value);
        }
    }

    return values;
}

//
//  Calculates bucket index based on a given key.
//
static size_t
vssc_string_map_calculate_bucket_index(const vssc_string_map_t *self, vsc_str_t key) {

    VSSC_ASSERT_PTR(self);
    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(key));

    const size_t hash_code = vssc_string_map_hash_code(key);
    const size_t bucket_index = hash_code % self->capacity;

    return bucket_index;
}

//
//  Calculates a hash code for a given key.
//
static size_t
vssc_string_map_hash_code(vsc_str_t key) {

    VSSC_ASSERT(vsc_str_is_valid_and_non_empty(key));

    const size_t prime1 = 7;
    const size_t prime2 = 31;

    size_t result = prime1;

    for (size_t pos = 0; pos < key.len; ++pos) {
        result = prime2 * result + key.chars[pos];
    }

    return result;
}
