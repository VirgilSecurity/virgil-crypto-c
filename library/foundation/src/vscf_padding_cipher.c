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
#include "vscf_cipher.h"
#include "vscf_padding.h"
#include "vscf_padding_cipher_defs.h"
#include "vscf_padding_cipher_internal.h"

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
//  Reset buffer. Ensures capacity is enough.
//
static void
vscf_padding_cipher_reset_buffer(vsc_buffer_t *buffer, size_t capacity);

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

    self->padding_buffer = vsc_buffer_new();
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_padding_cipher_cleanup_ctx(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vsc_buffer_destroy(&self->padding_buffer);
}

//
//  Return underlying cipher.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_padding_cipher_get_cipher(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    return self->cipher;
}

//
//  Return underlying padding.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_padding_cipher_get_padding(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->padding);

    return self->padding;
}

//
//  Reset buffer. Ensures capacity is enough.
//
static void
vscf_padding_cipher_reset_buffer(vsc_buffer_t *buffer, size_t capacity) {

    VSCF_ASSERT_PTR(buffer);

    if (vsc_buffer_is_valid(buffer) && vsc_buffer_capacity(buffer) >= capacity) {
        vsc_buffer_erase(buffer);
    } else if (capacity > 0) {
        vsc_buffer_release(buffer);
        vsc_buffer_alloc(buffer, capacity);
    } else {
        vsc_buffer_release(buffer);
    }
}

static vscf_status_t
vscf_padding_cipher_finish_encryption(vscf_padding_cipher_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->padding);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_padding_cipher_encrypted_out_len(self, 0));

    //
    //  Create padding.
    //
    vscf_padding_cipher_reset_buffer(self->padding_buffer, vscf_padding_len(self->padding));
    const vscf_status_t padding_status = vscf_padding_finish_data_processing(self->padding, self->padding_buffer);

    if (padding_status != vscf_status_SUCCESS) {
        return padding_status;
    }

    //
    //  Encrypt padding.
    //
    vscf_cipher_update(self->cipher, vsc_buffer_data(self->padding_buffer), out);
    vsc_buffer_erase(self->padding_buffer);

    //
    //  Finish encryption.
    //
    const vscf_status_t enc_status = vscf_cipher_finish(self->cipher, out);

    return enc_status;
}

static vscf_status_t
vscf_padding_cipher_finish_decryption(vscf_padding_cipher_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->padding);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_padding_cipher_decrypted_out_len(self, 0));

    vscf_padding_cipher_reset_buffer(self->padding_buffer, vscf_cipher_decrypted_out_len(self->cipher, 0));

    const vscf_status_t status = vscf_cipher_finish(self->cipher, self->padding_buffer);
    if (status != vscf_status_SUCCESS) {
        return status;
    }

    vscf_padding_process_padded_data(self->padding, vsc_buffer_data(self->padding_buffer), out);
    vsc_buffer_erase(self->padding_buffer);

    const vscf_status_t trim_status = vscf_padding_finish_padded_data_processing(self->padding, out);
    if (trim_status != vscf_status_SUCCESS) {
        return status;
    }

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
    VSCF_ASSERT_PTR(self->padding);

    vscf_impl_t *underlying_cipher_alg_info = vscf_alg_produce_alg_info(self->cipher);
    vscf_impl_t *underlying_padding_alg_info = vscf_alg_produce_alg_info(self->padding);

    vscf_padding_cipher_alg_info_t *alg_info =
            vscf_padding_cipher_alg_info_new_with_members(&underlying_padding_alg_info, &underlying_cipher_alg_info);

    return vscf_padding_cipher_alg_info_impl(alg_info);

    return NULL;
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

    const vscf_padding_cipher_alg_info_t *padding_cipher_alg_info = (const vscf_padding_cipher_alg_info_t *)alg_info;
    const vscf_impl_t *padding_alg_info = vscf_padding_cipher_alg_info_padding(padding_cipher_alg_info);
    const vscf_impl_t *cipher_alg_info = vscf_padding_cipher_alg_info_cipher(padding_cipher_alg_info);

    vscf_impl_t *padding = vscf_alg_factory_create_padding_from_info(padding_alg_info, NULL);
    if (NULL == padding) {
        return vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
    }

    vscf_impl_t *cipher = vscf_alg_factory_create_cipher_from_info(cipher_alg_info);
    if (NULL == cipher) {
        vscf_impl_destroy(&padding);
        return vscf_status_ERROR_UNSUPPORTED_ALGORITHM;
    }

    vscf_padding_cipher_release_padding(self);
    vscf_padding_cipher_take_padding(self, padding);

    vscf_padding_cipher_release_cipher(self);
    vscf_padding_cipher_take_cipher(self, cipher);

    return vscf_status_SUCCESS;
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
//  Encrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_padding_cipher_encrypt(vscf_padding_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->padding);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_padding_cipher_encrypted_len(self, data.len));

    //
    //  Encrypt data.
    //
    vscf_cipher_start_encryption(self->cipher);
    vscf_padding_start_data_processing(self->padding);
    vscf_cipher_update(self->cipher, vscf_padding_process_data(self->padding, data), out);

    //
    //  Create padding.
    //
    vscf_padding_cipher_reset_buffer(self->padding_buffer, vscf_padding_len(self->padding));

    const vscf_status_t padding_status = vscf_padding_finish_data_processing(self->padding, self->padding_buffer);
    if (padding_status != vscf_status_SUCCESS) {
        return padding_status;
    }

    //
    //  Encrypt padding.
    //
    vscf_cipher_update(self->cipher, vsc_buffer_data(self->padding_buffer), out);
    vsc_buffer_erase(self->padding_buffer);

    //
    //  Finish encryption.
    //
    const vscf_status_t enc_status = vscf_cipher_finish(self->cipher, out);

    return enc_status;
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_padding_cipher_encrypted_len(const vscf_padding_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->padding);

    const size_t padded_len = vscf_padding_padded_data_len(self->padding, data_len);
    const size_t len = vscf_encrypt_encrypted_len(self->cipher, padded_len);
    return len;
}

//
//  Precise length calculation of encrypted data.
//
VSCF_PUBLIC size_t
vscf_padding_cipher_precise_encrypted_len(const vscf_padding_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->padding);

    const size_t padded_len = vscf_padding_padded_data_len(self->padding, data_len);
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
    VSCF_ASSERT_PTR(self->padding);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_padding_cipher_decrypted_len(self, data.len));

    vscf_padding_start_padded_data_processing(self->padding);
    vscf_cipher_start_decryption(self->cipher);

    vscf_padding_cipher_reset_buffer(self->padding_buffer, vscf_cipher_decrypted_out_len(self->cipher, data.len));
    vscf_cipher_update(self->cipher, data, self->padding_buffer);
    vscf_padding_process_padded_data(self->padding, vsc_buffer_data(self->padding_buffer), out);

    vscf_padding_cipher_reset_buffer(self->padding_buffer, vscf_cipher_decrypted_out_len(self->cipher, 0));
    const vscf_status_t status = vscf_cipher_finish(self->cipher, self->padding_buffer);
    if (status != vscf_status_SUCCESS) {
        return status;
    }

    vscf_padding_process_padded_data(self->padding, vsc_buffer_data(self->padding_buffer), out);
    vsc_buffer_erase(self->padding_buffer);

    const vscf_status_t trim_status = vscf_padding_finish_padded_data_processing(self->padding, out);
    if (trim_status != vscf_status_SUCCESS) {
        return status;
    }

    return vscf_status_SUCCESS;
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_padding_cipher_decrypted_len(const vscf_padding_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    const size_t len =
            vscf_padding_cipher_decrypted_out_len(self, data_len) + vscf_padding_cipher_decrypted_out_len(self, 0);
    return len;
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
    VSCF_ASSERT_PTR(self->padding);

    vscf_padding_start_data_processing(self->padding);
    vscf_cipher_start_encryption(self->cipher);
}

//
//  Start sequential decryption.
//
VSCF_PUBLIC void
vscf_padding_cipher_start_decryption(vscf_padding_cipher_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->padding);

    vscf_padding_start_padded_data_processing(self->padding);
    vscf_cipher_start_decryption(self->cipher);
}

//
//  Process encryption or decryption of the given data chunk.
//
VSCF_PUBLIC void
vscf_padding_cipher_update(vscf_padding_cipher_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);
    VSCF_ASSERT_PTR(self->padding);
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_padding_cipher_out_len(self, data.len));
    VSCF_ASSERT(vscf_cipher_state(self->cipher) != vscf_cipher_state_INITIAL);

    if (vscf_cipher_state(self->cipher) == vscf_cipher_state_ENCRYPTION) {
        vscf_cipher_update(self->cipher, vscf_padding_process_data(self->padding, data), out);
    } else {
        vscf_padding_cipher_reset_buffer(self->padding_buffer, vscf_cipher_decrypted_out_len(self->cipher, data.len));
        vscf_cipher_update(self->cipher, data, self->padding_buffer);
        vscf_padding_process_padded_data(self->padding, vsc_buffer_data(self->padding_buffer), out);
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
vscf_padding_cipher_encrypted_out_len(const vscf_padding_cipher_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->cipher);

    if (data_len > 0) {
        const size_t len = vscf_cipher_encrypted_out_len(self->cipher, data_len);
        return len;
    }

    const size_t padding_len = vscf_padding_len(self->padding);
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
vscf_padding_cipher_decrypted_out_len(const vscf_padding_cipher_t *self, size_t data_len) {

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
