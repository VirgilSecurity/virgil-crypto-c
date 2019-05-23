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
//  This module contains 'aes256 gcm' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_aes256_gcm.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_alg_info.h"
#include "vscf_cipher_alg_info.h"
#include "vscf_aes256_gcm_defs.h"
#include "vscf_aes256_gcm_internal.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_aes256_gcm_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_aes256_gcm_init_ctx(vscf_aes256_gcm_t *self) {

    VSCF_ASSERT_PTR(self);

    mbedtls_cipher_init(&self->cipher_ctx);

    int status = mbedtls_cipher_setup(&self->cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM));

    VSCF_ASSERT_ALLOC(status != MBEDTLS_ERR_CIPHER_ALLOC_FAILED);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);

    vscf_zeroize(self->key, vscf_aes256_gcm_KEY_LEN);
    vscf_zeroize(self->nonce, vscf_aes256_gcm_NONCE_LEN);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_aes256_gcm_cleanup_ctx(vscf_aes256_gcm_t *self) {

    VSCF_ASSERT_PTR(self);

    mbedtls_cipher_free(&self->cipher_ctx);

    vscf_erase(self->key, vscf_aes256_gcm_KEY_LEN);
    vscf_erase(self->nonce, vscf_aes256_gcm_NONCE_LEN);
}

//
//  Provide algorithm identificator.
//
VSCF_PUBLIC vscf_alg_id_t
vscf_aes256_gcm_alg_id(const vscf_aes256_gcm_t *self) {

    VSCF_ASSERT_PTR(self);

    return vscf_alg_id_AES256_GCM;
}

//
//  Produce object with algorithm information and configuration parameters.
//
VSCF_PUBLIC vscf_impl_t *
vscf_aes256_gcm_produce_alg_info(const vscf_aes256_gcm_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_cipher_alg_info_t *cipher_alg_info = vscf_cipher_alg_info_new_with_members(
            vscf_alg_id_AES256_GCM, vsc_data(self->nonce, vscf_aes256_gcm_NONCE_LEN));

    return vscf_cipher_alg_info_impl(cipher_alg_info);
}

//
//  Restore algorithm configuration from the given object.
//
VSCF_PUBLIC vscf_status_t
vscf_aes256_gcm_restore_alg_info(vscf_aes256_gcm_t *self, const vscf_impl_t *alg_info) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(alg_info);
    VSCF_ASSERT(vscf_alg_info_alg_id(alg_info) == vscf_alg_id_AES256_GCM);

    const vscf_cipher_alg_info_t *cipher_alg_info = (const vscf_cipher_alg_info_t *)alg_info;
    vscf_aes256_gcm_set_nonce(self, vscf_cipher_alg_info_nonce(cipher_alg_info));

    return vscf_status_SUCCESS;
}

//
//  Encrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_aes256_gcm_encrypt(vscf_aes256_gcm_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_aes256_gcm_encrypted_len(self, data.len));

    vscf_aes256_gcm_start_encryption(self);
    vscf_aes256_gcm_update(self, data, out);
    vscf_status_t status = vscf_aes256_gcm_finish(self, out);

    return status;
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_aes256_gcm_encrypted_len(vscf_aes256_gcm_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);

    return data_len + vscf_aes256_gcm_BLOCK_LEN + vscf_aes256_gcm_AUTH_TAG_LEN;
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_aes256_gcm_decrypt(vscf_aes256_gcm_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_buffer_is_valid(out));

    VSCF_ASSERT(data.len >= vscf_aes256_gcm_AUTH_TAG_LEN);
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_aes256_gcm_decrypted_len(self, data.len));

    vscf_aes256_gcm_start_decryption(self);
    vscf_aes256_gcm_update(self, data, out);
    return vscf_aes256_gcm_finish(self, out);
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_aes256_gcm_decrypted_len(vscf_aes256_gcm_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(data_len >= vscf_aes256_gcm_AUTH_TAG_LEN);

    return data_len + vscf_aes256_gcm_BLOCK_LEN - vscf_aes256_gcm_AUTH_TAG_LEN;
}

//
//  Setup IV or nonce.
//
VSCF_PUBLIC void
vscf_aes256_gcm_set_nonce(vscf_aes256_gcm_t *self, vsc_data_t nonce) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(nonce));
    VSCF_ASSERT(vscf_aes256_gcm_NONCE_LEN == nonce.len);

    memcpy(self->nonce, nonce.bytes, vscf_aes256_gcm_NONCE_LEN);

    int status = mbedtls_cipher_set_iv(&self->cipher_ctx, nonce.bytes, nonce.len);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);
}

//
//  Set cipher encryption / decryption key.
//
VSCF_PUBLIC void
vscf_aes256_gcm_set_key(vscf_aes256_gcm_t *self, vsc_data_t key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(key));
    VSCF_ASSERT(vscf_aes256_gcm_KEY_LEN == key.len);

    memcpy(self->key, key.bytes, vscf_aes256_gcm_KEY_LEN);
}

//
//  Start sequential encryption.
//
VSCF_PUBLIC void
vscf_aes256_gcm_start_encryption(vscf_aes256_gcm_t *self) {

    VSCF_ASSERT_PTR(self);
    // VSCF_ASSERT(!vsc_data_is_zero(vsc_data(self->key, vscf_aes256_gcm_KEY_LEN)));

    self->do_decrypt = false;

    int status = mbedtls_cipher_setkey(&self->cipher_ctx, self->key, vscf_aes256_gcm_KEY_BITLEN, MBEDTLS_ENCRYPT);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);

    status = mbedtls_cipher_update_ad(&self->cipher_ctx, NULL, 0);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);

    status = mbedtls_cipher_reset(&self->cipher_ctx);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);
}

//
//  Start sequential decryption.
//
VSCF_PUBLIC void
vscf_aes256_gcm_start_decryption(vscf_aes256_gcm_t *self) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(!vsc_data_is_zero(vsc_data(self->key, vscf_aes256_gcm_KEY_LEN)));

    self->do_decrypt = true;

    int status = mbedtls_cipher_setkey(&self->cipher_ctx, self->key, vscf_aes256_gcm_KEY_BITLEN, MBEDTLS_DECRYPT);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);

    status = mbedtls_cipher_update_ad(&self->cipher_ctx, NULL, 0);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);

    status = mbedtls_cipher_reset(&self->cipher_ctx);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);
}

//
//  Process encryption or decryption of the given data chunk.
//
VSCF_PUBLIC void
vscf_aes256_gcm_update(vscf_aes256_gcm_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_buffer_is_valid(out));

    vsc_data_t filtered_data = data;

    //
    //  Filter auth tag from the input stream.
    //
    if (self->do_decrypt) {
        if (data.len >= vscf_aes256_gcm_AUTH_TAG_LEN) {
            filtered_data = vsc_data_slice_beg(data, 0, data.len - vscf_aes256_gcm_AUTH_TAG_LEN);
            vsc_data_t tag = vsc_data_slice_end(data, 0, vscf_aes256_gcm_AUTH_TAG_LEN);
            memcpy(self->auth_tag, tag.bytes, tag.len);

        } else {
            filtered_data = vsc_data_empty();
            byte *auth_tag_dst = self->auth_tag + vscf_aes256_gcm_AUTH_TAG_LEN - data.len;
            memmove(self->auth_tag, auth_tag_dst, data.len);
            memcpy(auth_tag_dst, data.bytes, data.len);
        }
    }

    //
    //  Process.
    //
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_aes256_gcm_out_len(self, filtered_data.len));

    size_t block_len = 0;

    int status = mbedtls_cipher_update(
            &self->cipher_ctx, filtered_data.bytes, filtered_data.len, vsc_buffer_unused_bytes(out), &block_len);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);

    vsc_buffer_inc_used(out, block_len);
}

//
//  Return buffer length required to hold an output of the methods
//  "update" or "finish" in an current mode.
//  Pass zero length to define buffer length of the method "finish".
//
VSCF_PUBLIC size_t
vscf_aes256_gcm_out_len(vscf_aes256_gcm_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);

    if (self->do_decrypt) {
        return vscf_aes256_gcm_decrypted_out_len(self, data_len);
    } else {
        return vscf_aes256_gcm_encrypted_out_len(self, data_len);
    }
}

//
//  Return buffer length required to hold an output of the methods
//  "update" or "finish" in an encryption mode.
//  Pass zero length to define buffer length of the method "finish".
//
VSCF_PUBLIC size_t
vscf_aes256_gcm_encrypted_out_len(vscf_aes256_gcm_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);

    if (data_len > 0) {
        return data_len + vscf_aes256_gcm_BLOCK_LEN;
    } else {
        return vscf_aes256_gcm_BLOCK_LEN + vscf_aes256_gcm_AUTH_TAG_LEN;
    }
}

//
//  Return buffer length required to hold an output of the methods
//  "update" or "finish" in an decryption mode.
//  Pass zero length to define buffer length of the method "finish".
//
VSCF_PUBLIC size_t
vscf_aes256_gcm_decrypted_out_len(vscf_aes256_gcm_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);

    return data_len + vscf_aes256_gcm_BLOCK_LEN;
}

//
//  Accomplish encryption or decryption process.
//
VSCF_PUBLIC vscf_status_t
vscf_aes256_gcm_finish(vscf_aes256_gcm_t *self, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_aes256_gcm_out_len(self, 0));

    size_t last_block_len = 0;
    int status = mbedtls_cipher_finish(&self->cipher_ctx, vsc_buffer_unused_bytes(out), &last_block_len);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);
    vsc_buffer_inc_used(out, last_block_len);

    if (self->do_decrypt) {
        int valid_tag_status =
                mbedtls_cipher_check_tag(&self->cipher_ctx, self->auth_tag, vscf_aes256_gcm_AUTH_TAG_LEN);
        if (0 != valid_tag_status) {
            return vscf_status_ERROR_AUTH_FAILED;
        }
    } else {
        int status =
                mbedtls_cipher_write_tag(&self->cipher_ctx, vsc_buffer_unused_bytes(out), vscf_aes256_gcm_AUTH_TAG_LEN);
        VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);
        vsc_buffer_inc_used(out, vscf_aes256_gcm_AUTH_TAG_LEN);
    }

    return vscf_status_SUCCESS;
}

//
//  Encrypt given data.
//  If 'tag' is not given, then it will written to the 'enc'.
//
VSCF_PUBLIC vscf_status_t
vscf_aes256_gcm_auth_encrypt(
        vscf_aes256_gcm_t *self, vsc_data_t data, vsc_data_t auth_data, vsc_buffer_t *out, vsc_buffer_t *tag) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_buffer_is_valid(out));

    if (NULL == tag) {
        VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_aes256_gcm_encrypted_len(self, data.len));
    } else {
        VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_aes256_gcm_auth_encrypted_len(self, data.len));
        VSCF_ASSERT(vsc_buffer_is_valid(tag));
        VSCF_ASSERT(vsc_buffer_unused_len(tag) >= vscf_aes256_gcm_AUTH_TAG_LEN);
    }

    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(
            mbedtls_cipher_setkey(&self->cipher_ctx, self->key, vscf_aes256_gcm_KEY_BITLEN, MBEDTLS_ENCRYPT));

    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_cipher_update_ad(&self->cipher_ctx, auth_data.bytes, auth_data.len));

    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_cipher_reset(&self->cipher_ctx));

    size_t first_block_len = 0;
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= data.len + vscf_aes256_gcm_BLOCK_LEN);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_cipher_update(
            &self->cipher_ctx, data.bytes, data.len, vsc_buffer_unused_bytes(out), &first_block_len));
    vsc_buffer_inc_used(out, first_block_len);

    size_t last_block_len = 0;
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_aes256_gcm_BLOCK_LEN);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(
            mbedtls_cipher_finish(&self->cipher_ctx, vsc_buffer_unused_bytes(out), &last_block_len));
    vsc_buffer_inc_used(out, last_block_len);

    if (NULL == tag) {
        VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_cipher_write_tag(
                &self->cipher_ctx, vsc_buffer_unused_bytes(out), vscf_aes256_gcm_AUTH_TAG_LEN));
        vsc_buffer_inc_used(out, vscf_aes256_gcm_AUTH_TAG_LEN);
    } else {
        VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_cipher_write_tag(
                &self->cipher_ctx, vsc_buffer_unused_bytes(tag), vscf_aes256_gcm_AUTH_TAG_LEN));
        vsc_buffer_inc_used(tag, vscf_aes256_gcm_AUTH_TAG_LEN);
    }

    return vscf_status_SUCCESS;
}

//
//  Calculate required buffer length to hold the authenticated encrypted data.
//
VSCF_PUBLIC size_t
vscf_aes256_gcm_auth_encrypted_len(vscf_aes256_gcm_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);

    return data_len + vscf_aes256_gcm_BLOCK_LEN + vscf_aes256_gcm_AUTH_TAG_LEN;
}

//
//  Decrypt given data.
//  If 'tag' is not given, then it will be taken from the 'enc'.
//
VSCF_PUBLIC vscf_status_t
vscf_aes256_gcm_auth_decrypt(
        vscf_aes256_gcm_t *self, vsc_data_t data, vsc_data_t auth_data, vsc_data_t tag, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_data_is_valid(auth_data));
    VSCF_ASSERT(vsc_data_is_valid(tag));
    VSCF_ASSERT(vsc_buffer_is_valid(out));

    if (vsc_data_is_empty(tag)) {
        VSCF_ASSERT(data.len >= vscf_aes256_gcm_AUTH_TAG_LEN);
        tag = vsc_data_slice_end(data, 0, vscf_aes256_gcm_AUTH_TAG_LEN);
        data = vsc_data_slice_beg(data, 0, (size_t)(data.len - vscf_aes256_gcm_AUTH_TAG_LEN));
    } else {
        VSCF_ASSERT(tag.len == vscf_aes256_gcm_AUTH_TAG_LEN);
    }

    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_aes256_gcm_auth_decrypted_len(self, data.len));

    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(
            mbedtls_cipher_setkey(&self->cipher_ctx, self->key, vscf_aes256_gcm_KEY_BITLEN, MBEDTLS_DECRYPT));

    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_cipher_update_ad(&self->cipher_ctx, auth_data.bytes, auth_data.len));
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_cipher_reset(&self->cipher_ctx));

    size_t first_block_len = 0;
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= data.len + vscf_aes256_gcm_BLOCK_LEN);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(mbedtls_cipher_update(
            &self->cipher_ctx, data.bytes, data.len, vsc_buffer_unused_bytes(out), &first_block_len));
    vsc_buffer_inc_used(out, first_block_len);

    size_t last_block_len = 0;
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_aes256_gcm_BLOCK_LEN);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(
            mbedtls_cipher_finish(&self->cipher_ctx, vsc_buffer_unused_bytes(out), &last_block_len));
    vsc_buffer_inc_used(out, last_block_len);

    if (0 != mbedtls_cipher_check_tag(&self->cipher_ctx, tag.bytes, tag.len)) {
        return vscf_status_ERROR_AUTH_FAILED;
    }

    return vscf_status_SUCCESS;
}

//
//  Calculate required buffer length to hold the authenticated decrypted data.
//
VSCF_PUBLIC size_t
vscf_aes256_gcm_auth_decrypted_len(vscf_aes256_gcm_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);

    return data_len + vscf_aes256_gcm_BLOCK_LEN;
}
