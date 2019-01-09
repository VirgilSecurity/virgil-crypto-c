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
vsc_buffer_init_ctx(vsc_buffer_t *buffer);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsc_buffer_cleanup_ctx(vsc_buffer_t *buffer);

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
vsc_buffer_init(vsc_buffer_t *buffer) {

    VSC_ASSERT_PTR(buffer);

    vsc_zeroize(buffer, sizeof(vsc_buffer_t));

    buffer->refcnt = 1;

    vsc_buffer_init_ctx(buffer);
}

//
//  Release all inner resources including class dependencies.
//
VSC_PUBLIC void
vsc_buffer_cleanup(vsc_buffer_t *buffer) {

    if (buffer == NULL) {
        return;
    }

    if (buffer->refcnt == 0) {
        return;
    }

    if (--buffer->refcnt == 0) {
        vsc_buffer_cleanup_ctx(buffer);

        vsc_zeroize(buffer, sizeof(vsc_buffer_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSC_PUBLIC vsc_buffer_t *
vsc_buffer_new(void) {

    vsc_buffer_t *buffer = (vsc_buffer_t *) vsc_alloc(sizeof (vsc_buffer_t));
    VSC_ASSERT_ALLOC(buffer);

    vsc_buffer_init(buffer);

    buffer->self_dealloc_cb = vsc_dealloc;

    return buffer;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSC_PUBLIC void
vsc_buffer_delete(vsc_buffer_t *buffer) {

    if (buffer == NULL) {
        return;
    }

    vsc_dealloc_fn self_dealloc_cb = buffer->self_dealloc_cb;

    vsc_buffer_cleanup(buffer);

    if (buffer->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(buffer);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsc_buffer_new ()'.
//
VSC_PUBLIC void
vsc_buffer_destroy(vsc_buffer_t **buffer_ref) {

    VSC_ASSERT_PTR(buffer_ref);

    vsc_buffer_t *buffer = *buffer_ref;
    *buffer_ref = NULL;

    vsc_buffer_delete(buffer);
}

//
//  Copy given class context by increasing reference counter.
//
VSC_PUBLIC vsc_buffer_t *
vsc_buffer_shallow_copy(vsc_buffer_t *buffer) {

    VSC_ASSERT_PTR(buffer);

    ++buffer->refcnt;

    return buffer;
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
vsc_buffer_init_ctx(vsc_buffer_t *buffer) {

    VSC_UNUSED(buffer);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsc_buffer_cleanup_ctx(vsc_buffer_t *buffer) {

    VSC_ASSERT_PTR(buffer);

    if (buffer->is_secure && buffer->is_owner) {
        vsc_buffer_erase(buffer);
    }

    if (buffer->bytes != NULL && buffer->bytes_dealloc_cb != NULL) {
        buffer->bytes_dealloc_cb(buffer->bytes);
    }
}

//
//  Allocate context and underlying byte array.
//
VSC_PUBLIC vsc_buffer_t *
vsc_buffer_new_with_capacity(size_t capacity) {

    vsc_buffer_t *buffer = (vsc_buffer_t *)vsc_alloc(sizeof(vsc_buffer_t) + capacity);
    VSC_ASSERT_ALLOC(buffer);

    vsc_buffer_init(buffer);

    buffer->bytes = (byte *)(buffer) + sizeof(vsc_buffer_t);
    buffer->capacity = capacity;
    buffer->self_dealloc_cb = vsc_dealloc;
    buffer->is_owner = true;

    return buffer;
}

//
//  Create buffer with copied bytes from given data.
//
VSC_PUBLIC vsc_buffer_t *
vsc_buffer_new_with_data(vsc_data_t data) {

    VSC_ASSERT_PTR(vsc_data_is_valid(data));

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(data.len);
    memcpy(buffer->bytes, data.bytes, data.len);
    buffer->len = data.len;
    buffer->is_owner = true;

    return buffer;
}

//
//  Returns true if buffer has no data written.
//
VSC_PUBLIC bool
vsc_buffer_is_empty(const vsc_buffer_t *buffer) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT(vsc_buffer_is_valid(buffer));

    return 0 == buffer->len;
}

//
//  Return true if buffers are equal.
//
VSC_PUBLIC bool
vsc_buffer_equal(const vsc_buffer_t *buffer, const vsc_buffer_t *rhs) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT_PTR(rhs);
    VSC_ASSERT(vsc_buffer_is_valid(buffer));
    VSC_ASSERT(vsc_buffer_is_valid(rhs));

    if (buffer->len != rhs->len) {
        return false;
    }

    bool is_equal = memcmp(buffer->bytes, rhs->bytes, rhs->len) == 0;
    return is_equal;
}

//
//  Allocates inner buffer with a given capacity.
//  Precondition: buffer is initialized.
//  Precondition: buffer does not hold any bytes.
//  Postcondition: inner buffer is allocated.
//
VSC_PUBLIC void
vsc_buffer_alloc(vsc_buffer_t *buffer, size_t capacity) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT(capacity > 0);
    VSC_ASSERT(NULL == buffer->bytes);

    buffer->bytes = (byte *)vsc_alloc(capacity);
    VSC_ASSERT_ALLOC(buffer->bytes);

    buffer->capacity = capacity;
    buffer->len = 0;
    buffer->bytes_dealloc_cb = vsc_dealloc;
}

//
//  Use given data as output buffer.
//  Client side is responsible for data deallocation.
//  Precondition: buffer is initialized.
//  Precondition: buffer does not hold any bytes.
//
VSC_PUBLIC void
vsc_buffer_use(vsc_buffer_t *buffer, byte *bytes, size_t bytes_len) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT_PTR(bytes);
    VSC_ASSERT(bytes_len > 0);
    VSC_ASSERT(NULL == buffer->bytes);

    buffer->bytes = bytes;
    buffer->capacity = bytes_len;
    buffer->len = 0;
    buffer->bytes_dealloc_cb = NULL;
    buffer->is_owner = false;
}

//
//  Use given data as output buffer.
//  Buffer is responsible for data deallocation.
//  Precondition: buffer is initialized.
//  Precondition: buffer does not hold any bytes.
//
VSC_PUBLIC void
vsc_buffer_take(vsc_buffer_t *buffer, byte *bytes, size_t bytes_len, vsc_dealloc_fn dealloc_cb) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT_PTR(bytes);
    VSC_ASSERT(bytes_len > 0);
    VSC_ASSERT_PTR(dealloc_cb);
    VSC_ASSERT(NULL == buffer->bytes);

    buffer->bytes = bytes;
    buffer->capacity = bytes_len;
    buffer->len = 0;
    buffer->bytes_dealloc_cb = dealloc_cb;
    buffer->is_owner = true;
}

//
//  Tell buffer that it holds sensitive that must be erased
//  in a secure manner during destruction.
//
VSC_PUBLIC void
vsc_buffer_make_secure(vsc_buffer_t *buffer) {

    VSC_ASSERT_PTR(buffer);

    buffer->is_secure = true;
}

//
//  Returns true if buffer full.
//
VSC_PUBLIC bool
vsc_buffer_is_full(const vsc_buffer_t *buffer) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT(vsc_buffer_is_valid(buffer));

    return buffer->len == buffer->capacity;
}

//
//  Returns true if buffer is configured and has valid internal states.
//
VSC_PUBLIC bool
vsc_buffer_is_valid(const vsc_buffer_t *buffer) {

    VSC_ASSERT_PTR(buffer);

    return (buffer->bytes != NULL) && (buffer->len <= buffer->capacity);
}

//
//  Returns underlying buffer bytes.
//
VSC_PUBLIC const byte *
vsc_buffer_bytes(const vsc_buffer_t *buffer) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT(vsc_buffer_is_valid(buffer));

    return buffer->bytes;
}

//
//  Returns underlying buffer bytes as object.
//
VSC_PUBLIC vsc_data_t
vsc_buffer_data(const vsc_buffer_t *buffer) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT(vsc_buffer_is_valid(buffer));

    return vsc_data(buffer->bytes, buffer->len);
}

//
//  Returns buffer capacity.
//
VSC_PUBLIC size_t
vsc_buffer_capacity(const vsc_buffer_t *buffer) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT(vsc_buffer_is_valid(buffer));

    return buffer->capacity;
}

//
//  Returns buffer length - length of bytes actually used.
//
VSC_PUBLIC size_t
vsc_buffer_len(const vsc_buffer_t *buffer) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT(vsc_buffer_is_valid(buffer));

    return buffer->len;
}

//
//  Returns length of the bytes that are not in use yet.
//
VSC_PUBLIC size_t
vsc_buffer_unused_len(const vsc_buffer_t *buffer) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT(vsc_buffer_is_valid(buffer));

    return (size_t)(buffer->capacity - buffer->len);
}

//
//  Returns writable pointer to the buffer first element.
//
VSC_PUBLIC byte *
vsc_buffer_begin(vsc_buffer_t *buffer) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT(vsc_buffer_is_valid(buffer));

    return buffer->bytes;
}

//
//  Returns pointer to the first unused byte in the buffer.
//
VSC_PUBLIC byte *
vsc_buffer_unused_bytes(vsc_buffer_t *buffer) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT(vsc_buffer_is_valid(buffer));

    return buffer->bytes + buffer->len;
}

//
//  Increase used bytes by given length.
//
VSC_PUBLIC void
vsc_buffer_inc_used(vsc_buffer_t *buffer, size_t len) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT(len <= vsc_buffer_unused_len(buffer));

    buffer->len += len;
}

//
//  Decrease used bytes by given length.
//
VSC_PUBLIC void
vsc_buffer_dec_used(vsc_buffer_t *buffer, size_t len) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT(len <= buffer->len);

    buffer->len -= len;
}

//
//  Copy null-terminated string to the buffer.
//
VSC_PUBLIC void
vsc_buffer_write_str(vsc_buffer_t *buffer, const char *str) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT(vsc_buffer_is_valid(buffer));
    VSC_ASSERT_PTR(str);

    size_t str_len = strlen(str);
    VSC_ASSERT(str_len <= vsc_buffer_unused_len(buffer));

    size_t write_len = str_len > vsc_buffer_unused_len(buffer) ? vsc_buffer_unused_len(buffer) : str_len;

    memcpy(vsc_buffer_unused_bytes(buffer), (const byte *)str, write_len);

    buffer->len += write_len;
}

//
//  Copy data to the buffer.
//
VSC_PUBLIC void
vsc_buffer_write_data(vsc_buffer_t *buffer, vsc_data_t data) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT(vsc_buffer_is_valid(buffer));
    VSC_ASSERT(vsc_data_is_valid(data));
    VSC_ASSERT(data.len <= vsc_buffer_unused_len(buffer));

    size_t write_len = data.len > vsc_buffer_unused_len(buffer) ? vsc_buffer_unused_len(buffer) : data.len;

    memcpy(vsc_buffer_unused_bytes(buffer), data.bytes, write_len);

    buffer->len += write_len;
}

//
//  Reset to the initial state.
//  After reset inner buffer can be re-used.
//
VSC_PUBLIC void
vsc_buffer_reset(vsc_buffer_t *buffer) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT(vsc_buffer_is_valid(buffer));

    buffer->len = 0;
}

//
//  Zeroing buffer in secure manner.
//  And reset it to the initial state.
//
VSC_PUBLIC void
vsc_buffer_erase(vsc_buffer_t *buffer) {

    VSC_ASSERT_PTR(buffer);
    VSC_ASSERT(vsc_buffer_is_valid(buffer));

    buffer->len = 0;

    vsc_erase(buffer->bytes, buffer->capacity);
    vsc_buffer_reset(buffer);
}
