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
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Return size of 'vsc_buffer_t'.
//
VSC_PUBLIC size_t
vsc_buffer_ctx_size(void) {

    return sizeof(vsc_buffer_t);
}

//
//  Allocate context and perform it's initialization.
//
VSC_PUBLIC vsc_buffer_t *
vsc_buffer_new(void) {

    vsc_buffer_t *buffer_ctx = (vsc_buffer_t *) vsc_alloc(sizeof (vsc_buffer_t));
    if (NULL == buffer_ctx) {
        return NULL;
    }

    if (vsc_buffer_init(buffer_ctx) != vsc_SUCCESS) {
        vsc_dealloc(buffer_ctx);
        return NULL;
    }

    buffer_ctx->self_dealloc_cb = vsc_dealloc;

    return buffer_ctx;
}

//
//  Release all inner resorces and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSC_PUBLIC void
vsc_buffer_delete(vsc_buffer_t *buffer_ctx) {

    if (NULL == buffer_ctx) {
        return;
    }

    vsc_buffer_cleanup(buffer_ctx);

    if (buffer_ctx->self_dealloc_cb != NULL) {
         buffer_ctx->self_dealloc_cb(buffer_ctx);
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


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform initialization of pre-allocated context.
//
VSC_PUBLIC vsc_error_t
vsc_buffer_init(vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);

    vsc_zeroize(buffer_ctx, sizeof(vsc_buffer_t));

    return vsc_SUCCESS;
}

//
//  Release all inner resources.
//
VSC_PUBLIC void
vsc_buffer_cleanup(vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    if (buffer_ctx->bytes != NULL && buffer_ctx->bytes_dealloc_cb != NULL) {
        buffer_ctx->bytes_dealloc_cb(buffer_ctx->bytes);
    }
    buffer_ctx->bytes = NULL;
    buffer_ctx->capacity = 0;
    buffer_ctx->len = 0;
    buffer_ctx->bytes_dealloc_cb = NULL;
}

//
//  Allocate context and underlying byte array.
//
VSC_PUBLIC vsc_buffer_t *
vsc_buffer_new_with_capacity(size_t capacity) {

    vsc_buffer_t *buffer_ctx = (vsc_buffer_t *)vsc_alloc(sizeof(vsc_buffer_t) + capacity);
    if (NULL == buffer_ctx) {
        return NULL;
    }

    if (vsc_buffer_init(buffer_ctx) != vsc_SUCCESS) {
        vsc_dealloc(buffer_ctx);
        return NULL;
    }

    buffer_ctx->bytes = (byte *)(buffer_ctx) + sizeof(vsc_buffer_t);
    buffer_ctx->capacity = capacity;
    buffer_ctx->self_dealloc_cb = vsc_dealloc;
    buffer_ctx->bytes_dealloc_cb = NULL;

    return buffer_ctx;
}

//
//  Allocates inner buffer with a given capacity.
//  Precondition: buffer is initialized.
//  Precondition: buffer does not hold any bytes.
//
VSC_PUBLIC vsc_error_t
vsc_buffer_alloc(vsc_buffer_t *buffer_ctx, size_t capacity) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(capacity > 0);
    VSC_ASSERT(NULL == buffer_ctx->bytes);

    buffer_ctx->bytes = (byte *)vsc_alloc(capacity);
    if (NULL == buffer_ctx->bytes) {
        return vsc_error_NO_MEMORY;
    }

    buffer_ctx->capacity = capacity;
    buffer_ctx->len = 0;
    buffer_ctx->bytes_dealloc_cb = vsc_dealloc;

    return vsc_SUCCESS;
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
//  Returns true if buffer full.
//
VSC_PUBLIC bool
vsc_buffer_is_full(vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));

    return buffer_ctx->len == buffer_ctx->capacity;
}

//
//  Returns true if buffer is configured and has valid internal states.
//
VSC_PUBLIC bool
vsc_buffer_is_valid(vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);

    return (buffer_ctx->bytes != NULL) && (buffer_ctx->capacity > 0) && (buffer_ctx->len <= buffer_ctx->capacity);
}

//
//  Returns underlying buffer bytes.
//
VSC_PUBLIC const byte *
vsc_buffer_bytes(vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));

    return buffer_ctx->bytes;
}

//
//  Returns underlying buffer bytes as object.
//
VSC_PUBLIC vsc_data_t
vsc_buffer_data(vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));

    return vsc_data(buffer_ctx->bytes, buffer_ctx->len);
}

//
//  Returns buffer capacity.
//
VSC_PUBLIC size_t
vsc_buffer_capacity(vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));

    return buffer_ctx->capacity;
}

//
//  Returns buffer length - length of bytes actually used.
//
VSC_PUBLIC size_t
vsc_buffer_len(vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));

    return buffer_ctx->len;
}

//
//  Returns length of available bytes - bytes that are not in use yet.
//
VSC_PUBLIC size_t
vsc_buffer_available_len(vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));

    return (size_t)(buffer_ctx->capacity - buffer_ctx->len);
}

//
//  Returns pointer to the first available byte to be written.
//
VSC_PUBLIC byte *
vsc_buffer_available_ptr(vsc_buffer_t *buffer_ctx) {

    VSC_ASSERT_PTR(buffer_ctx);
    VSC_ASSERT(vsc_buffer_is_valid(buffer_ctx));
    VSC_ASSERT(!vsc_buffer_is_full(buffer_ctx));

    return buffer_ctx->bytes + buffer_ctx->len;
}
