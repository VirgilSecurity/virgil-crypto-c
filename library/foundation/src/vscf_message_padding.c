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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_message_padding.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_random.h"
#include "vscf_message_padding_defs.h"

#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <pb_decode.h>
#include <pb_encode.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_message_padding_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_message_padding_init_ctx(vscf_message_padding_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_message_padding_cleanup_ctx(vscf_message_padding_t *self);

//
//  Return size of 'vscf_message_padding_t'.
//
VSCF_PUBLIC size_t
vscf_message_padding_ctx_size(void) {

    return sizeof(vscf_message_padding_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_message_padding_init(vscf_message_padding_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_message_padding_t));

    self->refcnt = 1;

    vscf_message_padding_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_message_padding_cleanup(vscf_message_padding_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_message_padding_cleanup_ctx(self);

    vscf_message_padding_release_rng(self);

    vscf_zeroize(self, sizeof(vscf_message_padding_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_message_padding_t *
vscf_message_padding_new(void) {

    vscf_message_padding_t *self = (vscf_message_padding_t *) vscf_alloc(sizeof (vscf_message_padding_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_message_padding_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_message_padding_delete(vscf_message_padding_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCF_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCF_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_message_padding_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_message_padding_new ()'.
//
VSCF_PUBLIC void
vscf_message_padding_destroy(vscf_message_padding_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_message_padding_t *self = *self_ref;
    *self_ref = NULL;

    vscf_message_padding_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_message_padding_t *
vscf_message_padding_shallow_copy(vscf_message_padding_t *self) {

    VSCF_ASSERT_PTR(self);

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_message_padding_use_rng(vscf_message_padding_t *self, vscf_impl_t *rng) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(rng);
    VSCF_ASSERT(self->rng == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(rng));

    self->rng = vscf_impl_shallow_copy(rng);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_message_padding_take_rng(vscf_message_padding_t *self, vscf_impl_t *rng) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(rng);
    VSCF_ASSERT(self->rng == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(rng));

    self->rng = rng;
}

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_message_padding_release_rng(vscf_message_padding_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->rng);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_message_padding_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_message_padding_init_ctx(vscf_message_padding_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_message_padding_cleanup_ctx(vscf_message_padding_t *self) {

    VSCF_ASSERT_PTR(self);
}

VSCF_PUBLIC size_t
vscf_message_padding_padded_len(size_t plain_text_len) {

    size_t full_size = plain_text_len + vscf_message_padding_PADDING_SIZE_LEN;

    size_t factor = full_size / vscf_message_padding_PADDING_FACTOR + 1;

    return factor * vscf_message_padding_PADDING_FACTOR;
}

VSCF_PUBLIC vscf_status_t
vscf_message_padding_add_padding(vscf_message_padding_t *self, vsc_buffer_t *plain_text) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->rng);
    VSCF_ASSERT_PTR(plain_text);

    size_t initial_len = vsc_buffer_len(plain_text);
    uint32_t padded_len = (uint32_t)vscf_message_padding_padded_len(vsc_buffer_len(plain_text));

    VSCF_ASSERT(vsc_buffer_capacity(plain_text) >= padded_len);

    size_t rest_len = padded_len - vsc_buffer_len(plain_text) - vscf_message_padding_PADDING_SIZE_LEN;

    VSCF_ASSERT(rest_len != 0);

    vscf_status_t status = vscf_random(self->rng, rest_len, plain_text);

    if (status != vscf_status_SUCCESS) {
        return vscf_status_ERROR_RANDOM_FAILED;
    }

    VSCF_ASSERT(vsc_buffer_unused_len(plain_text) == vscf_message_padding_PADDING_SIZE_LEN);

    pb_ostream_t stream =
            pb_ostream_from_buffer(vsc_buffer_unused_bytes(plain_text), vscf_message_padding_PADDING_SIZE_LEN);

    bool pb_res = pb_encode_fixed32(&stream, &initial_len);

    VSCF_ASSERT(pb_res);

    vsc_buffer_inc_used(plain_text, vscf_message_padding_PADDING_SIZE_LEN);

    return vscf_status_SUCCESS;
}

VSCF_PUBLIC vscf_status_t
vscf_message_padding_remove_padding(vsc_data_t decrypted_text, vsc_buffer_t *buffer) {

    VSCF_ASSERT_PTR(buffer);
    VSCF_ASSERT(vsc_data_is_valid(decrypted_text));

    if (decrypted_text.len < vscf_message_padding_PADDING_SIZE_LEN) {
        return vscf_status_ERROR_INVALID_PADDING;
    }

    uint32_t plain_text_len = 0;

    pb_istream_t stream =
            pb_istream_from_buffer(vsc_data_slice_end(decrypted_text, 0, vscf_message_padding_PADDING_SIZE_LEN).bytes,
                    vscf_message_padding_PADDING_SIZE_LEN);

    bool pb_res = pb_decode_fixed32(&stream, &plain_text_len);

    if (!pb_res) {
        return vscf_status_ERROR_INVALID_PADDING;
    }

    if (plain_text_len >= decrypted_text.len - vscf_message_padding_PADDING_SIZE_LEN) {
        return vscf_status_ERROR_INVALID_PADDING;
    }

    if (vsc_buffer_unused_len(buffer) < plain_text_len) {
        return vscf_status_ERROR_INVALID_PADDING;
    }

    vsc_buffer_write_data(buffer, vsc_data_slice_beg(decrypted_text, 0, plain_text_len));

    return vscf_status_SUCCESS;
}
