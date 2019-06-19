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
//  Encapsulates fixed byte array with variable effective data length.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsc_buffer.h"
#include "vsc_memory.h"
#include "vsc_assert.h"
#include "vsc_buffer_defs.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsc_buffer_init() is called.
//  Note, that context is already zeroed.
//
static void
vsc_buffer_init_ctx(vsc_buffer_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsc_buffer_cleanup_ctx(vsc_buffer_t *self);

//
//  Allocate inner buffer of given capacity.
//
static void
vsc_buffer_init_ctx_with_capacity(vsc_buffer_t *self, size_t capacity);

//
//  Allocate inner buffer buffer as copy of given data.
//
static void
vsc_buffer_init_ctx_with_data(vsc_buffer_t *self, vsc_data_t data);

//
//  Return size of 'vsc_buffer_t'.
//
VSC_PUBLIC size_t
vsc_buffer_ctx_size(void) {

    return sizeof(vsc_buffer_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSC_PUBLIC void
vsc_buffer_init(vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    vsc_zeroize(self, sizeof(vsc_buffer_t));

    self->refcnt = 1;

    vsc_buffer_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSC_PUBLIC void
vsc_buffer_cleanup(vsc_buffer_t *self) {

    if (self == NULL) {
        return;
    }

    vsc_buffer_cleanup_ctx(self);

    vsc_zeroize(self, sizeof(vsc_buffer_t));
}

//
//  Allocate context and perform it's initialization.
//
VSC_PUBLIC vsc_buffer_t *
vsc_buffer_new(void) {

    vsc_buffer_t *self = (vsc_buffer_t *) vsc_alloc(sizeof (vsc_buffer_t));
    VSC_ASSERT_ALLOC(self);

    vsc_buffer_init(self);

    self->self_dealloc_cb = vsc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Allocate inner buffer of given capacity.
//
VSC_PUBLIC void
vsc_buffer_init_with_capacity(vsc_buffer_t *self, size_t capacity) {

    VSC_ASSERT_PTR(self);

    vsc_zeroize(self, sizeof(vsc_buffer_t));

    self->refcnt = 1;

    vsc_buffer_init_ctx_with_capacity(self, capacity);
}

//
//  Allocate class context and perform it's initialization.
//  Allocate inner buffer of given capacity.
//
VSC_PUBLIC vsc_buffer_t *
vsc_buffer_new_with_capacity(size_t capacity) {

    vsc_buffer_t *self = (vsc_buffer_t *) vsc_alloc(sizeof (vsc_buffer_t));
    VSC_ASSERT_ALLOC(self);

    vsc_buffer_init_with_capacity(self, capacity);

    self->self_dealloc_cb = vsc_dealloc;

    return self;
}

//
//  Perform initialization of pre-allocated context.
//  Allocate inner buffer buffer as copy of given data.
//
VSC_PUBLIC void
vsc_buffer_init_with_data(vsc_buffer_t *self, vsc_data_t data) {

    VSC_ASSERT_PTR(self);

    vsc_zeroize(self, sizeof(vsc_buffer_t));

    self->refcnt = 1;

    vsc_buffer_init_ctx_with_data(self, data);
}

//
//  Allocate class context and perform it's initialization.
//  Allocate inner buffer buffer as copy of given data.
//
VSC_PUBLIC vsc_buffer_t *
vsc_buffer_new_with_data(vsc_data_t data) {

    vsc_buffer_t *self = (vsc_buffer_t *) vsc_alloc(sizeof (vsc_buffer_t));
    VSC_ASSERT_ALLOC(self);

    vsc_buffer_init_with_data(self, data);

    self->self_dealloc_cb = vsc_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSC_PUBLIC void
vsc_buffer_delete(vsc_buffer_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    size_t new_counter = old_counter > 0 ? old_counter - 1 : old_counter;
    #if defined(VSC_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSC_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        new_counter = old_counter > 0 ? old_counter - 1 : old_counter;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if ((new_counter > 0) || (0 == old_counter)) {
        return;
    }

    vsc_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vsc_buffer_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsc_buffer_new ()'.
//
VSC_PUBLIC void
vsc_buffer_destroy(vsc_buffer_t **self_ref) {

    VSC_ASSERT_PTR(self_ref);

    vsc_buffer_t *self = *self_ref;
    *self_ref = NULL;

    vsc_buffer_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSC_PUBLIC vsc_buffer_t *
vsc_buffer_shallow_copy(vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    #if defined(VSC_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSC_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
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
//  Note, this method is called automatically when method vsc_buffer_init() is called.
//  Note, that context is already zeroed.
//
static void
vsc_buffer_init_ctx(vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);
    self->is_reverse = false;
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsc_buffer_cleanup_ctx(vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    if (self->is_secure && self->is_owner) {
        vsc_buffer_erase(self);
    }

    if (self->bytes != NULL && self->bytes_dealloc_cb != NULL) {
        self->bytes_dealloc_cb(self->bytes);
    }
}

//
//  Allocate inner buffer of given capacity.
//
static void
vsc_buffer_init_ctx_with_capacity(vsc_buffer_t *self, size_t capacity) {

    VSC_ASSERT_PTR(self);

    self->bytes = (byte *)vsc_alloc(capacity);
    VSC_ASSERT_ALLOC(self->bytes);

    self->capacity = capacity;
    self->bytes_dealloc_cb = vsc_dealloc;
    self->is_owner = true;
}

//
//  Allocate inner buffer buffer as copy of given data.
//
static void
vsc_buffer_init_ctx_with_data(vsc_buffer_t *self, vsc_data_t data) {

    VSC_ASSERT_PTR(self);

    vsc_buffer_init_ctx_with_capacity(self, data.len);
    memcpy(self->bytes, data.bytes, data.len);
    self->len = data.len;
    self->is_owner = true;
}

//
//  Returns true if buffer has no data written.
//
VSC_PUBLIC bool
vsc_buffer_is_empty(const vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT(vsc_buffer_is_valid(self));

    return 0 == self->len;
}

//
//  Returns true if buffer written data is located at the buffer ending.
//
VSC_PUBLIC bool
vsc_buffer_is_reverse(const vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);
    return self->is_reverse;
}

//
//  Return true if buffers are equal.
//
VSC_PUBLIC bool
vsc_buffer_equal(const vsc_buffer_t *self, const vsc_buffer_t *rhs) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT_PTR(rhs);
    VSC_ASSERT(vsc_buffer_is_valid(self));
    VSC_ASSERT(vsc_buffer_is_valid(rhs));

    bool is_equal = vsc_data_equal(vsc_buffer_data(self), vsc_buffer_data(rhs));
    return is_equal;
}

//
//  Perform constant-time buffers comparison.
//  The time depends on the given length but not on the buffer data.
//  Return true if given buffers are equal.
//
VSC_PUBLIC bool
vsc_buffer_secure_equal(const vsc_buffer_t *self, const vsc_buffer_t *rhs) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT_PTR(rhs);
    VSC_ASSERT(vsc_buffer_is_valid(self));
    VSC_ASSERT(vsc_buffer_is_valid(rhs));

    bool is_equal = vsc_data_secure_equal(vsc_buffer_data(self), vsc_buffer_data(rhs));
    return is_equal;
}

//
//  Allocates inner buffer with a given capacity.
//  Precondition: buffer is initialized.
//  Precondition: buffer does not hold any bytes.
//  Postcondition: inner buffer is allocated.
//
VSC_PUBLIC void
vsc_buffer_alloc(vsc_buffer_t *self, size_t capacity) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT(capacity > 0);
    VSC_ASSERT(NULL == self->bytes);

    self->bytes = (byte *)vsc_alloc(capacity);
    VSC_ASSERT_ALLOC(self->bytes);

    self->capacity = capacity;
    self->len = 0;
    self->bytes_dealloc_cb = vsc_dealloc;
}

//
//  Release inner buffer.
//
VSC_PUBLIC void
vsc_buffer_release(vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    if (self->is_secure && self->is_owner) {
        vsc_buffer_erase(self);
    }

    if (self->bytes != NULL && self->bytes_dealloc_cb != NULL) {
        self->bytes_dealloc_cb(self->bytes);
    }

    self->bytes = NULL;
    self->bytes_dealloc_cb = NULL;
    self->is_owner = 0;
}

//
//  Use given data as output buffer.
//  Client side is responsible for data deallocation.
//  Precondition: buffer is initialized.
//  Precondition: buffer does not hold any bytes.
//
VSC_PUBLIC void
vsc_buffer_use(vsc_buffer_t *self, byte *bytes, size_t bytes_len) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT_PTR(bytes);
    VSC_ASSERT(bytes_len > 0);
    VSC_ASSERT(NULL == self->bytes);

    self->bytes = bytes;
    self->capacity = bytes_len;
    self->len = 0;
    self->bytes_dealloc_cb = NULL;
    self->is_owner = false;
}

//
//  Use given data as output buffer.
//  Buffer is responsible for data deallocation.
//  Precondition: buffer is initialized.
//  Precondition: buffer does not hold any bytes.
//
VSC_PUBLIC void
vsc_buffer_take(vsc_buffer_t *self, byte *bytes, size_t bytes_len, vsc_dealloc_fn dealloc_cb) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT_PTR(bytes);
    VSC_ASSERT(bytes_len > 0);
    VSC_ASSERT_PTR(dealloc_cb);
    VSC_ASSERT(NULL == self->bytes);

    self->bytes = bytes;
    self->capacity = bytes_len;
    self->len = 0;
    self->bytes_dealloc_cb = dealloc_cb;
    self->is_owner = true;
}

//
//  Tell buffer that it holds sensitive that must be erased
//  in a secure manner during destruction.
//
VSC_PUBLIC void
vsc_buffer_make_secure(vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    self->is_secure = true;
}

//
//  Change the way buffer content is interpreted.
//
//  If true - assume that written data is located at the buffer ending.
//  If false - assume that written data is located at the buffer beginning.
//
//  Note, that buffer is not empty and if new mode differs then data
//  will be moved to the appropriate place.
//
VSC_PUBLIC void
vsc_buffer_switch_reverse_mode(vsc_buffer_t *self, bool is_reverse) {

    VSC_ASSERT_PTR(self);

    if (self->is_reverse == is_reverse) {
        return;
    }

    if (self->is_reverse) {
        // Was reverse, so data from the end should be moved to the begin.
        memmove(self->bytes, self->bytes + self->capacity - self->len, self->len);
    } else {
        // Was straight, so data from the begin should be moved to the end.
        memmove(self->bytes + self->capacity - self->len, self->bytes, self->len);
    }

    self->is_reverse = is_reverse;
}

//
//  Returns true if buffer full.
//
VSC_PUBLIC bool
vsc_buffer_is_full(const vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT(vsc_buffer_is_valid(self));

    return self->len == self->capacity;
}

//
//  Returns true if buffer is configured and has valid internal states.
//
VSC_PUBLIC bool
vsc_buffer_is_valid(const vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);

    return (self->bytes != NULL) && (self->len <= self->capacity);
}

//
//  Returns underlying buffer bytes.
//
VSC_PUBLIC const byte *
vsc_buffer_bytes(const vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT(vsc_buffer_is_valid(self));

    return self->bytes;
}

//
//  Returns underlying buffer bytes as object.
//
VSC_PUBLIC vsc_data_t
vsc_buffer_data(const vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT(vsc_buffer_is_valid(self));

    if (self->is_reverse) {
        return vsc_data(self->bytes + self->capacity - self->len, self->len);
    } else {
        return vsc_data(self->bytes, self->len);
    }
}

//
//  Returns buffer capacity.
//
VSC_PUBLIC size_t
vsc_buffer_capacity(const vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT(vsc_buffer_is_valid(self));

    return self->capacity;
}

//
//  Returns buffer length - length of bytes actually used.
//
VSC_PUBLIC size_t
vsc_buffer_len(const vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT(vsc_buffer_is_valid(self));

    return self->len;
}

//
//  Returns length of the bytes that are not in use yet.
//
VSC_PUBLIC size_t
vsc_buffer_unused_len(const vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT(vsc_buffer_is_valid(self));

    return (size_t)(self->capacity - self->len);
}

//
//  Returns writable pointer to the buffer first element.
//
VSC_PUBLIC byte *
vsc_buffer_begin(vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT(vsc_buffer_is_valid(self));

    return self->bytes;
}

//
//  Returns pointer to the first unused byte in the buffer.
//
VSC_PUBLIC byte *
vsc_buffer_unused_bytes(vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT(vsc_buffer_is_valid(self));

    if (self->is_reverse) {
        return self->bytes;
    } else {
        return self->bytes + self->len;
    }
}

//
//  Increase used bytes by given length.
//
VSC_PUBLIC void
vsc_buffer_inc_used(vsc_buffer_t *self, size_t len) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT(len <= vsc_buffer_unused_len(self));

    self->len += len;
}

//
//  Decrease used bytes by given length.
//
VSC_PUBLIC void
vsc_buffer_dec_used(vsc_buffer_t *self, size_t len) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT(len <= self->len);

    self->len -= len;
}

//
//  Copy null-terminated string to the buffer.
//
VSC_PUBLIC void
vsc_buffer_write_str(vsc_buffer_t *self, const char *str) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT(vsc_buffer_is_valid(self));
    VSC_ASSERT_PTR(str);

    size_t str_len = strlen(str);
    VSC_ASSERT(str_len <= vsc_buffer_unused_len(self));

    size_t write_len = str_len > vsc_buffer_unused_len(self) ? vsc_buffer_unused_len(self) : str_len;

    if (self->is_reverse) {
        memcpy(vsc_buffer_unused_bytes(self) - write_len + 1, (const byte *)str, write_len);
    } else {
        memcpy(vsc_buffer_unused_bytes(self), (const byte *)str, write_len);
    }

    self->len += write_len;
}

//
//  Copy data to the buffer.
//
VSC_PUBLIC void
vsc_buffer_write_data(vsc_buffer_t *self, vsc_data_t data) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT(vsc_buffer_is_valid(self));
    VSC_ASSERT(vsc_data_is_valid(data));
    VSC_ASSERT(data.len <= vsc_buffer_unused_len(self));

    size_t write_len = data.len > vsc_buffer_unused_len(self) ? vsc_buffer_unused_len(self) : data.len;

    if (self->is_reverse) {
        memcpy(vsc_buffer_unused_bytes(self) - write_len + 1, data.bytes, write_len);
    } else {
        memcpy(vsc_buffer_unused_bytes(self), data.bytes, write_len);
    }

    self->len += write_len;
}

//
//  Reset to the initial state.
//  After reset inner buffer can be re-used.
//
VSC_PUBLIC void
vsc_buffer_reset(vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT(vsc_buffer_is_valid(self));

    self->len = 0;
    self->is_reverse = false;
}

//
//  Zeroing buffer in secure manner.
//  And reset it to the initial state.
//
VSC_PUBLIC void
vsc_buffer_erase(vsc_buffer_t *self) {

    VSC_ASSERT_PTR(self);
    VSC_ASSERT(vsc_buffer_is_valid(self));

    self->len = 0;

    vsc_erase(self->bytes, self->capacity);
    vsc_buffer_reset(self);
}
