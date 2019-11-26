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
//  This module contains 'padding cipher' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_padding_cipher.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_alg.h"
#include "vscf_alg_info.h"
#include "vscf_decrypt.h"
#include "vscf_encrypt.h"
#include "vscf_padding_cipher_alg_info.h"
#include "vscf_alg_factory.h"
#include "vscf_random.h"
#include "vscf_cipher.h"
#include "vscf_padding_cipher_defs.h"
#include "vscf_padding_cipher_internal.h"
#include "vscf_error.h"

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
    vscf_padding_cipher_PADDING_SIZE_LEN = 4,
    vscf_padding_cipher_PADDING_LEN_MIN = vscf_padding_cipher_PADDING_SIZE_LEN + 1
};

//
//  Return padding length (without encoded length) based on
//  an unpadded plaintext length.
//
static size_t
vscf_padding_cipher_padding_len(const vscf_padding_cipher_t *self, size_t unpadded_len);

//
//  Return total plaintext length with padding.
//
static size_t
vscf_padding_cipher_padded_len(const vscf_padding_cipher_t *self, size_t data_len);

//
//  Generate padding.
//  Padding length is derived from the given data length.
//
static vsc_buffer_t *
vscf_padding_cipher_generate_padding(vscf_padding_cipher_t *self, size_t data_len, vscf_error_t *error);

//
//  Return data slice without padding.
//
static vsc_data_t
vscf_padding_cipher_trim_padding(vsc_data_t data, vscf_error_t *error);

static vscf_status_t
vscf_padding_cipher_finish_encryption(vscf_padding_cipher_t *self, vsc_buffer_t *out) VSCF_NODISCARD;

static vscf_status_t
vscf_padding_cipher_finish_decryption(vscf_padding_cipher_t *self, vsc_buffer_t *out) VSCF_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_padding_cipher_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_padding_cipher_init_ctx(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    self->padding_frame = vscf_padding_cipher_PADDING_FRAME_DEFAULT;
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_padding_cipher_cleanup_ctx(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_tail_filter_destroy(&self->tail_filter);
}

//
//  Setup padding frame in bytes.
//  The padding frame defines the multiplicator of data length.
//
VSCF_PUBLIC void
vscf_padding_cipher_set_padding_frame(vscf_padding_cipher_t *self, size_t padding_frame) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT((vscf_padding_cipher_PADDING_FRAME_MIN <= padding_frame) &&
                (padding_frame <= vscf_padding_cipher_PADDING_FRAME_MAX));

    self->padding_frame = padding_frame;
}

//
//  Return padding length (without encoded length) based on
//  an unpadded plaintext length.
//
static size_t
vscf_padding_cipher_padding_len(const vscf_padding_cipher_t *self, size_t unpadded_len) {

    VSCF_ASSERT_PTR(self);

    const size_t padding_len =
            self->padding_frame - (unpadded_len + vscf_padding_cipher_PADDING_SIZE_LEN) % self->padding_frame;

    return padding_len;
}

//
//  Return total plaintext length with padding.
//
static size_t
vscf_padding_cipher_padded_len(const vscf_padding_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);

    const size_t full_size = data_len + vscf_padding_cipher_PADDING_SIZE_LEN;

    const size_t factor = full_size / self->padding_frame + 1;

    return factor * self->padding_frame;
}

//
//  Generate padding.
//  Padding length is derived from the given data length.
//
static vsc_buffer_t *
vscf_padding_cipher_generate_padding(vscf_padding_cipher_t *self, size_t data_len, vscf_error_t *error) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);


    const uint32_t padding_len = (uint32_t)vscf_padding_cipher_padding_len(self, data_len);
    const size_t total_padding_len = padding_len + vscf_padding_cipher_PADDING_SIZE_LEN;

    vsc_buffer_t *padding = vsc_buffer_new_with_capacity(total_padding_len);
    const vscf_status_t status = vscf_random(self->random, padding_len, padding);

    if (status != vscf_status_SUCCESS) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_RANDOM_FAILED);
        vsc_buffer_destroy(&padding);
        return NULL;
    }

    pb_ostream_t stream =
            pb_ostream_from_buffer(vsc_buffer_unused_bytes(padding), vscf_padding_cipher_PADDING_SIZE_LEN);

    const bool pb_res = pb_encode_fixed32(&stream, &padding_len);
    VSCF_ASSERT(pb_res);
    vsc_buffer_inc_used(padding, vscf_padding_cipher_PADDING_SIZE_LEN);

    vsc_buffer_make_secure(padding);

    return padding;
}

//
//  Return data slice without padding.
//
static vsc_data_t
vscf_padding_cipher_trim_padding(vsc_data_t data, vscf_error_t *error) {

    VSCF_ASSERT(vsc_data_is_valid(data));

    if (data.len < (vscf_padding_cipher_PADDING_SIZE_LEN + 1)) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_INVALID_PADDING);
        return vsc_data_empty();
    }

    uint32_t padding_len = 0;
    const vsc_data_t padding_size_data = vsc_data_slice_end(data, 0, vscf_padding_cipher_PADDING_SIZE_LEN);
    pb_istream_t stream = pb_istream_from_buffer(padding_size_data.bytes, padding_size_data.len);
    const bool pb_res = pb_decode_fixed32(&stream, &padding_len);

    if (!pb_res) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_INVALID_PADDING);
        return vsc_data_empty();
    }

    const size_t total_padding_len = padding_len + vscf_padding_cipher_PADDING_SIZE_LEN;
    if (data.len < total_padding_len) {
        VSCF_ERROR_SAFE_UPDATE(error, vscf_status_ERROR_INVALID_PADDING);
        return vsc_data_empty();
    }

    vsc_data_t trimmed_data = vsc_data_slice_beg(data, 0, data.len - total_padding_len);

    return trimmed_data;
}

static vscf_status_t
vscf_padding_cipher_finish_encryption(vscf_padding_cipher_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(out);

    vscf_error_t error;
    vscf_error_reset(&error);

    vsc_buffer_t *padding = vscf_padding_cipher_generate_padding(self, self->unpadded_len, &error);
    if (NULL == padding) {
        return vscf_error_status(&error);
    }

    vscf_cipher_update(self->cipher, vsc_buffer_data(padding), out);
    vsc_buffer_destroy(&padding);

    const vscf_status_t status = vscf_cipher_finish(self->cipher, out);

    return status;
}

static vscf_status_t
vscf_padding_cipher_finish_decryption(vscf_padding_cipher_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->tail_filter);
    VSCF_ASSERT_PTR(out);

    const size_t buffer_capacity = vscf_cipher_decrypted_out_len(self->cipher, 0);
    vsc_buffer_t *buffer = vscf_tail_filter_provide_buffer(self->tail_filter, buffer_capacity);
    const vscf_status_t status = vscf_cipher_finish(self->cipher, buffer);

    if (status != vscf_status_SUCCESS) {
        vscf_tail_filter_release(self->tail_filter);
        return status;
    }

    vscf_tail_filter_process_buffer(self->tail_filter, out);

    vscf_error_t error;
    vscf_error_reset(&error);

    vsc_data_t data = vscf_padding_cipher_trim_padding(vscf_tail_filter_tail(self->tail_filter), &error);
    if (vscf_error_has_error(&error)) {
        vscf_tail_filter_release(self->tail_filter);
        return vscf_error_status(&error);
    }

    vsc_buffer_write_data(out, data);
    vscf_tail_filter_release(self->tail_filter);

    return vscf_status_SUCCESS;
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_padding_cipher_alg_id(const vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_alg_id_PADDING_CIPHER;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_padding_cipher_produce_alg_info(const vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    vscf_impl_t *underlying_cipher_alg_info = vscf_alg_produce_alg_info(self->cipher);
    vscf_padding_cipher_alg_info_t *alg_info =
            vscf_padding_cipher_alg_info_new_with_members(&underlying_cipher_alg_info, self->padding_frame);

    return vscf_padding_cipher_alg_info_impl(alg_info);
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_padding_cipher_restore_alg_info(vscf_padding_cipher_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_PADDING_CIPHER);
    VSCF_ASSERT(vscf_impl_tag(alg_info) == vscf_impl_tag_PADDING_CIPHER_ALG_INFO);

    const vscf_padding_cipher_alg_info_t *cipher_alg_info = (const vscf_padding_cipher_alg_info_t *)alg_info;
    const vscf_impl_t *underlying_cipher_alg_info = vscf_padding_cipher_alg_info_underlying_cipher(cipher_alg_info);
    const size_t padding_frame = vscf_padding_cipher_alg_info_padding_frame(cipher_alg_info);

    if (padding_frame < vscf_padding_cipher_PADDING_FRAME_MIN ||
            padding_frame > vscf_padding_cipher_PADDING_FRAME_MAX) {
        return vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
    }

    vscf_impl_t *underlying_cipher = vscf_alg_factory_create_cipher_from_info(underlying_cipher_alg_info);
    if (NULL == underlying_cipher) {
        return vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
    }

    vscf_padding_cipher_release_cipher(self);
    vscf_padding_cipher_take_cipher(self, underlying_cipher);
    vscf_padding_cipher_set_padding_frame(self, padding_frame);

    return vscf_status_SUCCESS;
}

//
//  Encrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_padding_cipher_encrypt(vscf_padding_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_padding_cipher_encrypted_len(self, data.len));

    vscf_padding_cipher_start_encryption(self);
    vscf_padding_cipher_update(self, data, out);
    const vscf_status_t status = vscf_padding_cipher_finish(self, out);

    return status;
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_padding_cipher_encrypted_len(vscf_padding_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    const size_t padded_len = vscf_padding_cipher_padded_len(self, data_len);
    const size_t len = vscf_encrypt_encrypted_len(self->cipher, padded_len);
    return len;
}

//
//  Precise length calculation of encrypted data.
//
VSCF_PUBLIC size_t
vscf_padding_cipher_precise_encrypted_len(vscf_padding_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    const size_t padded_len = vscf_padding_cipher_padded_len(self, data_len);
    const size_t len = vscf_encrypt_precise_encrypted_len(self->cipher, padded_len);
    return len;
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_padding_cipher_decrypt(vscf_padding_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_padding_cipher_decrypted_len(self, data.len));

    vscf_padding_cipher_start_decryption(self);
    vscf_padding_cipher_update(self, data, out);
    const vscf_status_t status = vscf_padding_cipher_finish(self, out);

    return status;
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_padding_cipher_decrypted_len(vscf_padding_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    const size_t len =
            vscf_padding_cipher_decrypted_out_len(self, data_len) + vscf_padding_cipher_decrypted_out_len(self, 0);
    return len;
}

//
//  Return cipher's nonce length or IV length in bytes,
//  or 0 if nonce is not required.
//
VSCF_PUBLIC size_t
vscf_padding_cipher_nonce_len(const vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    return vscf_cipher_info_nonce_len(self->cipher);
}

//
//  Return cipher's key length in bytes.
//
VSCF_PUBLIC size_t
vscf_padding_cipher_key_len(const vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    return vscf_cipher_info_key_len(self->cipher);
}

//
//  Return cipher's key length in bits.
//
VSCF_PUBLIC size_t
vscf_padding_cipher_key_bitlen(const vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    return vscf_cipher_info_key_bitlen(self->cipher);
}

//
//  Return cipher's block length in bytes.
//
VSCF_PUBLIC size_t
vscf_padding_cipher_block_len(const vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    return vscf_cipher_info_block_len(self->cipher);
}

//
//  Setup IV or nonce.
//
VSCF_PUBLIC void
vscf_padding_cipher_set_nonce(vscf_padding_cipher_t *self, vsc_data_t nonce) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    vscf_cipher_set_nonce(self->cipher, nonce);
}

//
//  Set cipher encryption / decryption key.
//
VSCF_PUBLIC void
vscf_padding_cipher_set_key(vscf_padding_cipher_t *self, vsc_data_t key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    vscf_cipher_set_key(self->cipher, key);
}

//
//  Return cipher's current state.
//
VSCF_PRIVATE vscf_cipher_state_t
vscf_padding_cipher_state(const vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    return vscf_cipher_state(self->cipher);
}

//
//  Start sequential encryption.
//
VSCF_PUBLIC void
vscf_padding_cipher_start_encryption(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    self->unpadded_len = 0;
    vscf_cipher_start_encryption(self->cipher);
}

//
//  Start sequential decryption.
//
VSCF_PUBLIC void
vscf_padding_cipher_start_decryption(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    if (NULL == self->tail_filter) {
        self->tail_filter = vscf_tail_filter_new();
    }

    vscf_tail_filter_reset(self->tail_filter, self->padding_frame + vscf_padding_cipher_PADDING_SIZE_LEN);
    vscf_cipher_start_decryption(self->cipher);
}

//
//  Process encryption or decryption of the given data chunk.
//
VSCF_PUBLIC void
vscf_padding_cipher_update(vscf_padding_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_padding_cipher_out_len(self, data.len));
    VSCF_ASSERT(vscf_cipher_state(self->cipher) != vscf_cipher_state_INITIAL);

    if (vscf_cipher_state(self->cipher) == vscf_cipher_state_ENCRYPTION) {
        self->unpadded_len += data.len;
        self->unpadded_len %= self->padding_frame;
        vscf_cipher_update(self->cipher, data, out);
    } else {
        VSCF_ASSERT_PTR(self->tail_filter);
        const size_t buffer_capacity = vscf_cipher_encrypted_out_len(self->cipher, data.len);
        vsc_buffer_t *buffer = vscf_tail_filter_provide_buffer(self->tail_filter, buffer_capacity);
        vscf_cipher_update(self->cipher, data, buffer);
        vscf_tail_filter_process_buffer(self->tail_filter, out);
    }
}

//
//  Return buffer length required to hold an output of the methods
//  "update" or "finish" in an current mode.
//  Pass zero length to define buffer length of the method "finish".
//
VSCF_PUBLIC size_t
vscf_padding_cipher_out_len(vscf_padding_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT(vscf_cipher_state(self->cipher) != vscf_cipher_state_INITIAL);

    if (vscf_cipher_state(self->cipher) == vscf_cipher_state_ENCRYPTION) {
        return vscf_padding_cipher_encrypted_out_len(self, data_len);
    } else {
        return vscf_padding_cipher_decrypted_out_len(self, data_len);
    }
}

//
//  Return buffer length required to hold an output of the methods
//  "update" or "finish" in an encryption mode.
//  Pass zero length to define buffer length of the method "finish".
//
VSCF_PUBLIC size_t
vscf_padding_cipher_encrypted_out_len(vscf_padding_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT(vscf_cipher_state(self->cipher) == vscf_cipher_state_ENCRYPTION);

    if (data_len > 0) {
        const size_t len = vscf_cipher_encrypted_out_len(self->cipher, data_len);
        return len;
    }

    const size_t padding_len =
            vscf_padding_cipher_padding_len(self, self->unpadded_len) + vscf_padding_cipher_PADDING_SIZE_LEN;
    const size_t len =
            vscf_cipher_encrypted_out_len(self->cipher, padding_len) + vscf_cipher_encrypted_out_len(self->cipher, 0);
    return len;
}

//
//  Return buffer length required to hold an output of the methods
//  "update" or "finish" in an decryption mode.
//  Pass zero length to define buffer length of the method "finish".
//
VSCF_PUBLIC size_t
vscf_padding_cipher_decrypted_out_len(vscf_padding_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    const size_t len = vscf_cipher_decrypted_out_len(self->cipher, data_len);
    return len;
}

//
//  Accomplish encryption or decryption process.
//
VSCF_PUBLIC vscf_status_t
vscf_padding_cipher_finish(vscf_padding_cipher_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    if (vscf_cipher_state(self->cipher) == vscf_cipher_state_ENCRYPTION) {
        return vscf_padding_cipher_finish_encryption(self, out);
    } else {
        return vscf_padding_cipher_finish_decryption(self, out);
    }
}
