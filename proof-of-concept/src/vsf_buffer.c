//  Copyright (c) 2015-2018 Virgil Security Inc.
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


#include "vsf_buffer.h"
#include "vsf_buffer_api.h"
#include "vsf_impl.h"
#include "vsf_memory.h"
#include "vsf_assert.h"

//  Return buffer.
VSF_PUBLIC const byte *
vsf_buffer_data (void *impl) {
    vsf_buffer_t *buffer = vsf_buffer_variable(impl);
    VSF_ASSERT (buffer);

    return buffer->data;
}

//  Return whole buffer size.
VSF_PUBLIC size_t
vsf_buffer_size (void *impl) {
    vsf_buffer_t *buffer = vsf_buffer_variable(impl);
    VSF_ASSERT (buffer);

    return buffer->size;
}

//  Return number of bytes that is actually are used within buffer.
VSF_PUBLIC size_t
vsf_buffer_used_size (void *impl) {
    vsf_buffer_t *buffer = vsf_buffer_variable(impl);
    VSF_ASSERT (buffer);

    return buffer->used_size;
}

//  Setup new buffer and keep ownership.
//  Precondition: object has no buffer.
VSF_PUBLIC void
vsf_buffer_use (void *impl, byte* data, size_t data_size) {
    vsf_buffer_t *buffer = vsf_buffer_variable(impl);
    VSF_ASSERT (buffer);
    VSF_ASSERT (buffer->data == NULL);
    VSF_ASSERT (data);
    VSF_ASSERT (data_size > 0);

    buffer->data = data;
    buffer->size = data_size;
    buffer->used_size = 0;
    buffer->dealloc_fn = NULL;
}

//  Setup new buffer and transfer ownership.
//  Precondition: object has no buffer.
VSF_PUBLIC void
vsf_buffer_take (void *impl, byte** data_ref, size_t data_size, vsf_dealloc_fn dealloc_fn) {
    vsf_buffer_t *buffer = vsf_buffer_variable(impl);
    VSF_ASSERT (buffer);
    VSF_ASSERT (buffer->data == NULL);
    VSF_ASSERT (data_ref);
    VSF_ASSERT (*data_ref);
    VSF_ASSERT (data_size > 0);

    byte* data = *data_ref;
    *data_ref = NULL;

    buffer->data = data;
    buffer->size = data_size;
    buffer->used_size = 0;
    buffer->dealloc_fn = dealloc_fn;
}

//  Cleanup buffer.
VSF_PUBLIC void
vsf_buffer_cleanup (void *impl) {
    vsf_buffer_t *buffer = vsf_buffer_variable(impl);
    VSF_ASSERT (buffer);

    if (buffer->data == NULL) {
        return;
    }

    vsf_zeroize_s (buffer->data, buffer->size);
}

//  Release buffer.
//  If buffer was not defined, than do nothing.
VSF_PUBLIC void
vsf_buffer_release (void *impl) {
    vsf_buffer_t *buffer = vsf_buffer_variable(impl);
    VSF_ASSERT (buffer);

    if (buffer->data == NULL) {
        return;
    }

    if (buffer->dealloc_fn) {
        buffer->dealloc_fn (buffer->data);
    }

    vsf_zeroize (buffer, sizeof (vsf_buffer_t));
}

//  Return mixin state object.
VSF_PRIVATE vsf_buffer_t *
vsf_buffer_variable(void* impl) {
    VSF_ASSERT (impl);

    const vsf_buffer_api_t *api = vsf_buffer_api (impl);
    VSF_ASSERT (api);

    VSF_ASSERT (api->buffer);
    return api->buffer (impl);
}

//  Calculate required buffer size.
VSF_PUBLIC size_t
vsf_buffer_calc_size (void *impl) {
    VSF_ASSERT (impl);

    const vsf_buffer_api_t *api = vsf_buffer_api (impl);
    VSF_ASSERT (api);

    VSF_ASSERT (api->calc_size);
    return api->calc_size (impl);
}

VSF_PUBLIC const vsf_buffer_api_t*
vsf_buffer_api (void *impl) {
    VSF_ASSERT (impl);
    return (const vsf_buffer_api_t*) vsf_api (impl, vsf_api_tag_BUFFER);
}
