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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscr_ratchet_padding.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_padding_defs.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_padding_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_padding_init_ctx(vscr_ratchet_padding_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_padding_cleanup_ctx(vscr_ratchet_padding_t *self);

//
//  Return size of 'vscr_ratchet_padding_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_padding_ctx_size(void) {

    return sizeof(vscr_ratchet_padding_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_padding_init(vscr_ratchet_padding_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_padding_t));

    self->refcnt = 1;

    vscr_ratchet_padding_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_padding_cleanup(vscr_ratchet_padding_t *self) {

    if (self == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscr_ratchet_padding_cleanup_ctx(self);

        vscr_ratchet_padding_release_rng(self);

        vscr_zeroize(self, sizeof(vscr_ratchet_padding_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_padding_t *
vscr_ratchet_padding_new(void) {

    vscr_ratchet_padding_t *self = (vscr_ratchet_padding_t *) vscr_alloc(sizeof (vscr_ratchet_padding_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_padding_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_padding_delete(vscr_ratchet_padding_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscr_ratchet_padding_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_padding_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_padding_destroy(vscr_ratchet_padding_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_padding_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_padding_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_padding_t *
vscr_ratchet_padding_shallow_copy(vscr_ratchet_padding_t *self) {

    VSCR_ASSERT_PTR(self);

    ++self->refcnt;

    return self;
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCR_PUBLIC void
vscr_ratchet_padding_use_rng(vscr_ratchet_padding_t *self, vscf_impl_t *rng) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT(self->rng == NULL);

    VSCR_ASSERT(vscf_random_is_implemented(rng));

    self->rng = vscf_impl_shallow_copy(rng);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_padding_take_rng(vscr_ratchet_padding_t *self, vscf_impl_t *rng) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT_PTR(self->rng == NULL);

    VSCR_ASSERT(vscf_random_is_implemented(rng));

    self->rng = rng;
}

//
//  Release dependency to the interface 'random'.
//
VSCR_PUBLIC void
vscr_ratchet_padding_release_rng(vscr_ratchet_padding_t *self) {

    VSCR_ASSERT_PTR(self);

    vscf_impl_destroy(&self->rng);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_padding_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_padding_init_ctx(vscr_ratchet_padding_t *self) {

    VSCR_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_padding_cleanup_ctx(vscr_ratchet_padding_t *self) {

    VSCR_ASSERT_PTR(self);
}

VSCR_PUBLIC size_t
vscr_ratchet_padding_padded_len(size_t plain_text_len) {

    size_t full_size = plain_text_len + vscr_ratchet_padding_PADDING_SIZE_LEN;

    size_t factor = full_size / vscr_ratchet_padding_PADDING_FACTOR + 1;

    return factor * vscr_ratchet_padding_PADDING_FACTOR;
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_padding_add_padding(vscr_ratchet_padding_t *self, vsc_buffer_t *plain_text) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->rng);
    VSCR_ASSERT_PTR(plain_text);

    size_t initial_len = vsc_buffer_len(plain_text);
    uint32_t padded_len = (uint32_t)vscr_ratchet_padding_padded_len(vsc_buffer_len(plain_text));

    VSCR_ASSERT(vsc_buffer_capacity(plain_text) >= padded_len);

    size_t rest_len = padded_len - vsc_buffer_len(plain_text) - vscr_ratchet_padding_PADDING_SIZE_LEN;

    VSCR_ASSERT(rest_len != 0);

    vscf_status_t status = vscf_random(self->rng, rest_len, plain_text);

    if (status != vscf_status_SUCCESS) {
        return vscr_status_ERROR_RNG_FAILED;
    }

    VSCR_ASSERT(vsc_buffer_unused_len(plain_text) == vscr_ratchet_padding_PADDING_SIZE_LEN);

    pb_ostream_t stream =
            pb_ostream_from_buffer(vsc_buffer_unused_bytes(plain_text), vscr_ratchet_padding_PADDING_SIZE_LEN);

    bool pb_res = pb_encode_fixed32(&stream, &initial_len);

    VSCR_ASSERT(pb_res);

    vsc_buffer_inc_used(plain_text, vscr_ratchet_padding_PADDING_SIZE_LEN);

    return vscr_status_SUCCESS;
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_padding_remove_padding(vsc_data_t decrypted_text, vsc_buffer_t *buffer) {

    if (decrypted_text.len < vscr_ratchet_padding_PADDING_SIZE_LEN) {
        return vscr_status_ERROR_INVALID_PADDING;
    }

    uint32_t plain_text_len = 0;

    pb_istream_t stream =
            pb_istream_from_buffer(vsc_data_slice_end(decrypted_text, 0, vscr_ratchet_padding_PADDING_SIZE_LEN).bytes,
                    vscr_ratchet_padding_PADDING_SIZE_LEN);

    bool pb_res = pb_decode_fixed32(&stream, &plain_text_len);

    if (!pb_res) {
        return vscr_status_ERROR_INVALID_PADDING;
    }

    if (plain_text_len >= decrypted_text.len - vscr_ratchet_padding_PADDING_SIZE_LEN) {
        return vscr_status_ERROR_INVALID_PADDING;
    }

    if (vsc_buffer_unused_len(buffer) < plain_text_len) {
        return vscr_status_ERROR_INVALID_PADDING;
    }

    vsc_buffer_write_data(buffer, vsc_data_slice_beg(decrypted_text, 0, plain_text_len));

    return vscr_status_SUCCESS;
}
