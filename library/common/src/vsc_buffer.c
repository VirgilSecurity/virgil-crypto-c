//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2018 Virgil Security Inc.
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
vsc_buffer_init_ctx(vsc_buffer_t *buffer_ctx);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsc_buffer_cleanup_ctx(vsc_buffer_t *buffer_ctx);

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
vsc_buffer_init(vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);

    vsc_zeroize(buffer_ctx, sizeof(vsc_buffer_t));

    buffer_ctx->refcnt = 1;

    vsc_buffer_init_ctx(buffer_ctx);
}

//
//  Release all inner resources including class dependencies.
//
VSC_PUBLIC void
vsc_buffer_cleanup(vsc_buffer_t *buffer_ctx) {

    if (buffer_ctx == NULL) {
        return;
    }

    if (buffer_ctx->refcnt == 0) {
        return;
    }

    if (--buffer_ctx->refcnt == 0) {
        vsc_buffer_cleanup_ctx(buffer_ctx);

        vsc_zeroize(buffer_ctx, sizeof(vsc_buffer_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSC_PUBLIC vsc_buffer_t *
vsc_buffer_new(void) {

    vsc_buffer_t *buffer_ctx = (vsc_buffer_t *) vsc_alloc(sizeof (vsc_buffer_t));
    VSC_ASSERT_ALLOC(buffer_ctx);

    vsc_buffer_init(buffer_ctx);

    buffer_ctx->self_dealloc_cb = vsc_dealloc;

    return buffer_ctx;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSC_PUBLIC void
vsc_buffer_delete(vsc_buffer_t *buffer_ctx) {

    if (buffer_ctx == NULL) {
        return;
    }

    vsc_dealloc_fn self_dealloc_cb = buffer_ctx->self_dealloc_cb;

    vsc_buffer_cleanup(buffer_ctx);

    if (buffer_ctx->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(buffer_ctx);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsc_buffer_new ()'.
//
VSC_PUBLIC void
vsc_buffer_destroy(vsc_buffer_t **buffer_ctx_ref) {

    VSC_ASSERT_PTR(buffer_ctx_ref);

    vsc_buffer_t *buffer_ctx = *buffer_ctx_ref;
    *buffer_ctx_ref = NULL;

    vsc_buffer_delete(buffer_ctx);
}

//
//  Copy given class context by increasing reference counter.
//
VSC_PUBLIC vsc_buffer_t *
vsc_buffer_copy(vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);

    ++buffer_ctx->refcnt;

    return buffer_ctx;
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
vsc_buffer_init_ctx(vsc_buffer_t *buffer_ctx) {

    VSC_UNUSED(buffer_ctx);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsc_buffer_cleanup_ctx(vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);

    if (buffer_ctx->bytes != NULL) {
        if (buffer_ctx->is_secure) {
            vsc_buffer_erase(buffer_ctx);
        }

        if (buffer_ctx->bytes_dealloc_cb != NULL) {
            buffer_ctx->bytes_dealloc_cb(buffer_ctx->bytes);
        }
    }
}

//
//  Allocate context and underlying byte array.
//
VSC_PUBLIC vsc_buffer_t *
vsc_buffer_new_with_capacity(size_t capacity) {

    vsc_buffer_t *buffer_ctx = (vsc_buffer_t *)vsc_alloc(sizeof(vsc_buffer_t) + capacity);
    VSC_ASSERT_ALLOC(buffer_ctx);

    vsc_buffer_init(buffer_ctx);

    buffer_ctx->bytes = (byte *)(buffer_ctx) + sizeof(vsc_buffer_t);
    buffer_ctx->capacity = capacity;
    buffer_ctx->self_dealloc_cb = vsc_dealloc;

    return buffer_ctx;
}

//
//  Create buffer with copied bytes from given data.
//
VSC_PUBLIC vsc_buffer_t *
vsc_buffer_new_with_data(vsc_data_t data) {

    VSC_ASSERT_PTR(vsc_data_is_valid(data));

    vsc_buffer_t *buffer_ctx = vsc_buffer_new_with_capacity(data.len);
    memcpy(buffer_ctx->bytes, data.bytes, data.len);
    buffer_ctx->len = data.len;

    return buffer_ctx;
}

//
//  Returns true if buffer has no data written.
//
VSC_PUBLIC bool
vsc_buffer_is_empty(const vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));

    return 0 == buffer_ctx->len;
}

//
//  Return true if buffers are equal.
//
VSC_PUBLIC bool
vsc_buffer_equal(const vsc_buffer_t *buffer_ctx, const vsc_buffer_t *rhs) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT_PTR(rhs);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));
    VSC_ASSERT(vsc_buffer_is_valid(rhs));

    if (buffer_ctx->len != rhs->len) {
        return false;
    }

    bool is_equal = memcmp(buffer_ctx->bytes, rhs->bytes, rhs->len) == 0;
    return is_equal;
}

//
//  Allocates inner buffer with a given capacity.
//  Precondition: buffer is initialized.
//  Precondition: buffer does not hold any bytes.
//  Postcondition: inner buffer is allocated.
//
VSC_PUBLIC void
vsc_buffer_alloc(vsc_buffer_t *buffer_ctx, size_t capacity) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(capacity > 0);
    VSC_ASSERT(NULL == buffer_ctx->bytes);

    buffer_ctx->bytes = (byte *)vsc_alloc(capacity);
    VSC_ASSERT_ALLOC(buffer_ctx->bytes);

    buffer_ctx->capacity = capacity;
    buffer_ctx->len = 0;
    buffer_ctx->bytes_dealloc_cb = vsc_dealloc;
}

//
//  Use given data as output buffer.
//  Client side is responsible for data deallocation.
//  Precondition: buffer is initialized.
//  Precondition: buffer does not hold any bytes.
//
VSC_PUBLIC void
vsc_buffer_use(vsc_buffer_t *buffer_ctx, byte *bytes, size_t bytes_len) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT_PTR(bytes);
    VSC_ASSERT(bytes_len > 0);
    VSC_ASSERT(NULL == buffer_ctx->bytes);

    buffer_ctx->bytes = bytes;
    buffer_ctx->capacity = bytes_len;
    buffer_ctx->len = 0;
    buffer_ctx->bytes_dealloc_cb = NULL;
}

//
//  Use given data as output buffer.
//  Buffer is responsible for data deallocation.
//  Precondition: buffer is initialized.
//  Precondition: buffer does not hold any bytes.
//
VSC_PUBLIC void
vsc_buffer_take(vsc_buffer_t *buffer_ctx, byte *bytes, size_t bytes_len, vsc_dealloc_fn dealloc_cb) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT_PTR(bytes);
    VSC_ASSERT(bytes_len > 0);
    VSC_ASSERT_PTR(dealloc_cb);
    VSC_ASSERT(NULL == buffer_ctx->bytes);

    buffer_ctx->bytes = bytes;
    buffer_ctx->capacity = bytes_len;
    buffer_ctx->len = 0;
    buffer_ctx->bytes_dealloc_cb = dealloc_cb;
}

//
//  Tell buffer that it holds sensitive that must be erased
//  in a secure manner during destruction.
//
VSC_PUBLIC void
vsc_buffer_make_secure(vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);

    buffer_ctx->is_secure = true;
}

//
//  Returns true if buffer full.
//
VSC_PUBLIC bool
vsc_buffer_is_full(const vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));

    return buffer_ctx->len == buffer_ctx->capacity;
}

//
//  Returns true if buffer is configured and has valid internal states.
//
VSC_PUBLIC bool
vsc_buffer_is_valid(const vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);

    return (buffer_ctx->bytes != NULL) && (buffer_ctx->len <= buffer_ctx->capacity);
}

//
//  Returns underlying buffer bytes.
//
VSC_PUBLIC const byte *
vsc_buffer_bytes(const vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));

    return buffer_ctx->bytes;
}

//
//  Returns underlying buffer bytes as object.
//
VSC_PUBLIC vsc_data_t
vsc_buffer_data(const vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));

    return vsc_data(buffer_ctx->bytes, buffer_ctx->len);
}

//
//  Returns buffer capacity.
//
VSC_PUBLIC size_t
vsc_buffer_capacity(const vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));

    return buffer_ctx->capacity;
}

//
//  Returns buffer length - length of bytes actually used.
//
VSC_PUBLIC size_t
vsc_buffer_len(const vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));

    return buffer_ctx->len;
}

//
//  Returns length of left bytes - bytes that are not in use yet.
//
VSC_PUBLIC size_t
vsc_buffer_left(const vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));

    return (size_t)(buffer_ctx->capacity - buffer_ctx->len);
}

//
//  Returns pointer to the current wirte position.
//
VSC_PUBLIC byte *
vsc_buffer_ptr(vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));

    return buffer_ctx->bytes + buffer_ctx->len;
}

//
//  Returns writable pointer to the buffer first element.
//
VSC_PUBLIC byte *
vsc_buffer_begin(vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));

    return buffer_ctx->bytes;
}

//
//  Increase used bytes by given length.
//
VSC_PUBLIC void
vsc_buffer_reserve(vsc_buffer_t *buffer_ctx, size_t len) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(len <= vsc_buffer_left(buffer_ctx));

    buffer_ctx->len += len;
}

//
//  Increase used bytes by given length.
//
VSC_PUBLIC void
vsc_buffer_increase_used_bytes(vsc_buffer_t *buffer_ctx, size_t len) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(len <= vsc_buffer_left(buffer_ctx));

    buffer_ctx->len += len;
}

//
//  Decrease used bytes by given length.
//
VSC_PUBLIC void
vsc_buffer_decrease_used_bytes(vsc_buffer_t *buffer_ctx, size_t len) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(len <= buffer_ctx->len);

    buffer_ctx->len -= len;
}

//
//  Copy null-terminated string to the buffer.
//
VSC_PUBLIC void
vsc_buffer_write_str(vsc_buffer_t *buffer_ctx, const char *str) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));
    VSC_ASSERT_PTR(str);

    size_t str_len = strlen(str);
    VSC_ASSERT(str_len <= vsc_buffer_left(buffer_ctx));

    size_t write_len = str_len > vsc_buffer_left(buffer_ctx) ? vsc_buffer_left(buffer_ctx) : str_len;

    memcpy(vsc_buffer_ptr(buffer_ctx), (const byte *)str, write_len);

    buffer_ctx->len += write_len;
}

//
//  Copy data to the buffer.
//
VSC_PUBLIC void
vsc_buffer_write_data(vsc_buffer_t *buffer_ctx, vsc_data_t data) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));
    VSC_ASSERT(vsc_data_is_valid(data));
    VSC_ASSERT(data.len <= vsc_buffer_left(buffer_ctx));

    size_t write_len = data.len > vsc_buffer_left(buffer_ctx) ? vsc_buffer_left(buffer_ctx) : data.len;

    memcpy(vsc_buffer_ptr(buffer_ctx), data.bytes, write_len);

    buffer_ctx->len += write_len;
}

//
//  Reset to the initial state.
//  After reset inner buffer can be re-used.
//
VSC_PUBLIC void
vsc_buffer_reset(vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));

    buffer_ctx->len = 0;
}

//
//  Zeroing buffer in secure manner.
//
VSC_PUBLIC void
vsc_buffer_erase(vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));

    buffer_ctx->len = 0;

    vsc_erase(buffer_ctx->bytes, buffer_ctx->capacity);
}
