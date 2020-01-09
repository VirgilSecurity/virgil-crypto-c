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
//  This module contains 'random padding' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_random_padding.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_alg_info.h"
#include "vscf_simple_alg_info.h"
#include "vscf_random.h"
#include "vscf_random_padding_defs.h"
#include "vscf_random_padding_internal.h"

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
//  Private integral constants.
//
enum {
    vscf_random_padding_PADDING_SIZE_LEN = 4,
    vscf_random_padding_PADDING_LEN_MIN = vscf_random_padding_PADDING_SIZE_LEN + 1
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_random_padding_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_random_padding_init_ctx(vscf_random_padding_t *self) {

    VSCF_ASSERT_PTR(self);

    self->padding_frame = vscf_padding_params_DEFAULT_FRAME;
    self->padding_frame_max = vscf_padding_params_DEFAULT_FRAME_MAX;
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_random_padding_cleanup_ctx(vscf_random_padding_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_tail_filter_destroy(&self->tail_filter);
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_random_padding_alg_id(const vscf_random_padding_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_alg_id_RANDOM_PADDING;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_random_padding_produce_alg_info(const vscf_random_padding_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_RANDOM_PADDING));
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_random_padding_restore_alg_info(vscf_random_padding_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_RANDOM_PADDING);

    return vscf_status_SUCCESS;
}

//
//  Set new padding parameters.
//
VSCF_PUBLIC void
vscf_random_padding_configure(vscf_random_padding_t *self, const vscf_padding_params_t *params) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(params);

    const size_t padding_frame = vscf_padding_params_frame(params);
    const size_t padding_frame_max = vscf_padding_params_frame_max(params);

    self->padding_frame = padding_frame;
    self->padding_frame_max = padding_frame_max;
}

//
//  Return length in bytes of a data with a padding.
//
VSCF_PUBLIC size_t
vscf_random_padding_padded_data_len(const vscf_random_padding_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);

    const size_t full_size = data_len + vscf_random_padding_PADDING_SIZE_LEN;
    const size_t factor = full_size / self->padding_frame + 1;
    const size_t padded_data_len = factor * self->padding_frame;

    return padded_data_len;
}

//
//  Return an actual number of padding in bytes.
//  Note, this method might be called right before "finish data processing".
//
VSCF_PUBLIC size_t
vscf_random_padding_len(const vscf_random_padding_t *self) {

    VSCF_ASSERT_PTR(self);


    const size_t padding_len = self->padding_frame -
                               (self->unpadded_len + vscf_random_padding_PADDING_SIZE_LEN) % self->padding_frame +
                               vscf_random_padding_PADDING_SIZE_LEN;

    return padding_len;
}

//
//  Return a maximum number of padding in bytes.
//
VSCF_PUBLIC size_t
vscf_random_padding_len_max(const vscf_random_padding_t *self) {

    VSCF_ASSERT_PTR(self);

    const size_t padding_len_max = self->padding_frame + vscf_random_padding_PADDING_SIZE_LEN;

    return padding_len_max;
}

//
//  Prepare the algorithm to process data.
//
VSCF_PUBLIC void
vscf_random_padding_start_data_processing(vscf_random_padding_t *self) {

    VSCF_ASSERT_PTR(self);

    self->unpadded_len = 0;
}

//
//  Only data length is needed to produce padding later.
//  Return data that should be further proceeded.
//
VSCF_PUBLIC vsc_data_t
vscf_random_padding_process_data(vscf_random_padding_t *self, vsc_data_t data) {

    VSCF_ASSERT_PTR(self);

    self->unpadded_len += data.len;
    self->unpadded_len %= self->padding_frame;

    return data;
}

//
//  Accomplish data processing and return padding.
//
VSCF_PUBLIC vscf_status_t
vscf_random_padding_finish_data_processing(vscf_random_padding_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_random_padding_len(self));

    const size_t total_padding_len = vscf_random_padding_len(self);
    VSCF_ASSERT_SAFE(total_padding_len > vscf_random_padding_PADDING_SIZE_LEN);
    const uint32_t padding_len = (uint32_t)total_padding_len - vscf_random_padding_PADDING_SIZE_LEN;

    const vscf_status_t rng_status = vscf_random(self->random, padding_len, out);
    if (rng_status != vscf_status_SUCCESS) {
        return vscf_status_ERROR_RANDOM_FAILED;
    }

    pb_ostream_t stream = pb_ostream_from_buffer(vsc_buffer_unused_bytes(out), vscf_random_padding_PADDING_SIZE_LEN);

    const bool pb_res = pb_encode_fixed32(&stream, &padding_len);
    VSCF_ASSERT(pb_res);
    vsc_buffer_inc_used(out, vscf_random_padding_PADDING_SIZE_LEN);


    return vscf_status_SUCCESS;
}

//
//  Prepare the algorithm to process padded data.
//
VSCF_PUBLIC void
vscf_random_padding_start_padded_data_processing(vscf_random_padding_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->tail_filter) {
        self->tail_filter = vscf_tail_filter_new();
    }

    vscf_tail_filter_reset(self->tail_filter, self->padding_frame_max + vscf_random_padding_PADDING_SIZE_LEN);
}

//
//  Process padded data.
//  Return filtered data without padding.
//
VSCF_PUBLIC void
vscf_random_padding_process_padded_data(vscf_random_padding_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->tail_filter);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= data.len);

    vscf_tail_filter_process(self->tail_filter, data, out);
}

//
//  Return length in bytes required hold output of the method
//  "finish padded data processing".
//
VSCF_PUBLIC size_t
vscf_random_padding_finish_padded_data_processing_out_len(const vscf_random_padding_t *self) {

    VSCF_ASSERT_PTR(self);

    vsc_data_t padding = vscf_tail_filter_tail(self->tail_filter);

    return padding.len;
}

//
//  Accomplish padded data processing and return left data without a padding.
//
VSCF_PUBLIC vscf_status_t
vscf_random_padding_finish_padded_data_processing(vscf_random_padding_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->tail_filter);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_random_padding_finish_padded_data_processing_out_len(self));

    vsc_data_t padding = vscf_tail_filter_tail(self->tail_filter);

    if (padding.len < (vscf_random_padding_PADDING_SIZE_LEN + 1)) {
        return vscf_status_ERROR_INVALID_PADDING;
    }

    uint32_t padding_len = 0;
    const vsc_data_t padding_size_data = vsc_data_slice_end(padding, 0, vscf_random_padding_PADDING_SIZE_LEN);
    pb_istream_t stream = pb_istream_from_buffer(padding_size_data.bytes, padding_size_data.len);
    const bool pb_res = pb_decode_fixed32(&stream, &padding_len);

    if (!pb_res) {
        return vscf_status_ERROR_INVALID_PADDING;
    }

    const size_t total_padding_len = padding_len + vscf_random_padding_PADDING_SIZE_LEN;
    if (padding.len < total_padding_len) {
        return vscf_status_ERROR_INVALID_PADDING;
    }

    vsc_data_t data = vsc_data_slice_beg(padding, 0, padding.len - total_padding_len);
    vsc_buffer_write_data(out, data);

    return vscf_status_SUCCESS;
}
