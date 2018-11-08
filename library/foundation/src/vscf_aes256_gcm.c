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
#include "vscf_aes256_gcm_impl.h"
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
vscf_aes256_gcm_init_ctx(vscf_aes256_gcm_impl_t *aes256_gcm_impl) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);

    mbedtls_cipher_init(&aes256_gcm_impl->cipher_ctx);

    int status = mbedtls_cipher_setup(
            &aes256_gcm_impl->cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM));

    VSCF_ASSERT_ALLOC(status != MBEDTLS_ERR_CIPHER_ALLOC_FAILED);
    VSCF_ASSERT_LIBRARY_MBEDTLS_SUCCESS(status);

    vscf_zeroize(aes256_gcm_impl->key, vscf_aes256_gcm_KEY_LEN);
    vscf_zeroize(aes256_gcm_impl->nonce, vscf_aes256_gcm_NONCE_LEN);
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_aes256_gcm_cleanup_ctx(vscf_aes256_gcm_impl_t *aes256_gcm_impl) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);

    mbedtls_cipher_free(&aes256_gcm_impl->cipher_ctx);

    vscf_erase(aes256_gcm_impl->key, vscf_aes256_gcm_KEY_LEN);
    vscf_erase(aes256_gcm_impl->nonce, vscf_aes256_gcm_NONCE_LEN);
}

//
//  Encrypt given data.
//
VSCF_PUBLIC vscf_error_t
vscf_aes256_gcm_encrypt(vscf_aes256_gcm_impl_t *aes256_gcm_impl, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT_OPT(vsc_buffer_left(out) >= vscf_aes256_gcm_encrypted_len(aes256_gcm_impl, data.len));


    VSCF_ASSERT_OPT(0 == mbedtls_cipher_setkey(&aes256_gcm_impl->cipher_ctx, aes256_gcm_impl->key,
                                 vscf_aes256_gcm_KEY_BITLEN, MBEDTLS_ENCRYPT));

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_update_ad(&aes256_gcm_impl->cipher_ctx, NULL, 0));

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_reset(&aes256_gcm_impl->cipher_ctx));

    size_t first_block_len = 0;
    VSCF_ASSERT(vsc_buffer_left(out) >= data.len + vscf_aes256_gcm_BLOCK_LEN);
    VSCF_ASSERT_OPT(0 == mbedtls_cipher_update(&aes256_gcm_impl->cipher_ctx, data.bytes, data.len, vsc_buffer_ptr(out),
                                 &first_block_len));
    vsc_buffer_reserve(out, first_block_len);

    size_t last_block_len = 0;
    VSCF_ASSERT(vsc_buffer_left(out) >= vscf_aes256_gcm_BLOCK_LEN);
    VSCF_ASSERT_OPT(0 == mbedtls_cipher_finish(&aes256_gcm_impl->cipher_ctx, vsc_buffer_ptr(out), &last_block_len));
    vsc_buffer_reserve(out, last_block_len);

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_write_tag(
                                 &aes256_gcm_impl->cipher_ctx, vsc_buffer_ptr(out), vscf_aes256_gcm_AUTH_TAG_LEN));
    vsc_buffer_reserve(out, vscf_aes256_gcm_AUTH_TAG_LEN);

    return vscf_SUCCESS;
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_aes256_gcm_encrypted_len(vscf_aes256_gcm_impl_t *aes256_gcm_impl, size_t data_len) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);

    return data_len + vscf_aes256_gcm_BLOCK_LEN + vscf_aes256_gcm_AUTH_TAG_LEN;
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_error_t
vscf_aes256_gcm_decrypt(vscf_aes256_gcm_impl_t *aes256_gcm_impl, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_buffer_is_valid(out));

    VSCF_ASSERT_OPT(data.len >= vscf_aes256_gcm_AUTH_TAG_LEN);
    VSCF_ASSERT_OPT(vsc_buffer_left(out) >= vscf_aes256_gcm_decrypted_len(aes256_gcm_impl, data.len));


    vsc_data_t enc = vsc_data_slice_beg(data, 0, data.len - vscf_aes256_gcm_AUTH_TAG_LEN);
    vsc_data_t tag = vsc_data_slice_end(data, 0, vscf_aes256_gcm_AUTH_TAG_LEN);

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_setkey(&aes256_gcm_impl->cipher_ctx, aes256_gcm_impl->key,
                                 vscf_aes256_gcm_KEY_BITLEN, MBEDTLS_DECRYPT));

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_update_ad(&aes256_gcm_impl->cipher_ctx, NULL, 0));

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_reset(&aes256_gcm_impl->cipher_ctx));

    size_t first_block_len = 0;
    VSCF_ASSERT(vsc_buffer_left(out) >= enc.len + vscf_aes256_gcm_BLOCK_LEN);
    VSCF_ASSERT_OPT(0 == mbedtls_cipher_update(&aes256_gcm_impl->cipher_ctx, enc.bytes, enc.len, vsc_buffer_ptr(out),
                                 &first_block_len));
    vsc_buffer_reserve(out, first_block_len);

    size_t last_block_len = 0;
    VSCF_ASSERT(vsc_buffer_left(out) >= vscf_aes256_gcm_BLOCK_LEN);
    VSCF_ASSERT_OPT(0 == mbedtls_cipher_finish(&aes256_gcm_impl->cipher_ctx, vsc_buffer_ptr(out), &last_block_len));
    vsc_buffer_reserve(out, last_block_len);

    if (0 != mbedtls_cipher_check_tag(&aes256_gcm_impl->cipher_ctx, tag.bytes, tag.len)) {
        return vscf_error_AUTH_FAILED;
    }

    return vscf_SUCCESS;
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_aes256_gcm_decrypted_len(vscf_aes256_gcm_impl_t *aes256_gcm_impl, size_t data_len) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);
    VSCF_ASSERT(data_len >= vscf_aes256_gcm_AUTH_TAG_LEN);

    return data_len + vscf_aes256_gcm_BLOCK_LEN - vscf_aes256_gcm_AUTH_TAG_LEN;
}

//
//  Setup IV or nonce.
//
VSCF_PUBLIC void
vscf_aes256_gcm_set_nonce(vscf_aes256_gcm_impl_t *aes256_gcm_impl, vsc_data_t nonce) {

    VSCF_ASSERT(vsc_data_is_valid(nonce));

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_set_iv(&aes256_gcm_impl->cipher_ctx, nonce.bytes, nonce.len));
}

//
//  Set cipher encryption / decryption key.
//
VSCF_PUBLIC void
vscf_aes256_gcm_set_key(vscf_aes256_gcm_impl_t *aes256_gcm_impl, vsc_data_t key) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);
    VSCF_ASSERT(vsc_data_is_valid(key));
    VSCF_ASSERT_OPT(vscf_aes256_gcm_KEY_LEN == key.len);

    memcpy(aes256_gcm_impl->key, key.bytes, key.len);
}

//
//  Encrypt given data.
//  If 'tag' is not give, then it will written to the 'enc'.
//
VSCF_PUBLIC vscf_error_t
vscf_aes256_gcm_auth_encrypt(vscf_aes256_gcm_impl_t *aes256_gcm_impl, vsc_data_t data, vsc_data_t auth_data,
        vsc_buffer_t *out, vsc_buffer_t *tag) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_is_valid(tag));

    VSCF_ASSERT(vsc_buffer_left(out) >= vscf_aes256_gcm_auth_encrypted_len(aes256_gcm_impl, data.len));
    VSCF_ASSERT(vsc_buffer_left(tag) >= vscf_aes256_gcm_AUTH_TAG_LEN);

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_setkey(&aes256_gcm_impl->cipher_ctx, aes256_gcm_impl->key,
                                 vscf_aes256_gcm_KEY_BITLEN, MBEDTLS_ENCRYPT));

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_update_ad(&aes256_gcm_impl->cipher_ctx, auth_data.bytes, auth_data.len));

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_reset(&aes256_gcm_impl->cipher_ctx));

    size_t first_block_len = 0;
    VSCF_ASSERT(vsc_buffer_left(out) >= data.len + vscf_aes256_gcm_BLOCK_LEN);
    VSCF_ASSERT_OPT(0 == mbedtls_cipher_update(&aes256_gcm_impl->cipher_ctx, data.bytes, data.len, vsc_buffer_ptr(out),
                                 &first_block_len));
    vsc_buffer_reserve(out, first_block_len);

    size_t last_block_len = 0;
    VSCF_ASSERT(vsc_buffer_left(out) >= vscf_aes256_gcm_BLOCK_LEN);
    VSCF_ASSERT_OPT(0 == mbedtls_cipher_finish(&aes256_gcm_impl->cipher_ctx, vsc_buffer_ptr(out), &last_block_len));
    vsc_buffer_reserve(out, last_block_len);


    VSCF_ASSERT_OPT(0 == mbedtls_cipher_write_tag(
                                 &aes256_gcm_impl->cipher_ctx, vsc_buffer_ptr(tag), vscf_aes256_gcm_AUTH_TAG_LEN));
    vsc_buffer_reserve(tag, vscf_aes256_gcm_AUTH_TAG_LEN);

    return vscf_SUCCESS;
}

//
//  Calculate required buffer length to hold the authenticated encrypted data.
//
VSCF_PUBLIC size_t
vscf_aes256_gcm_auth_encrypted_len(vscf_aes256_gcm_impl_t *aes256_gcm_impl, size_t data_len) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);

    return data_len + vscf_aes256_gcm_BLOCK_LEN;
}

//
//  Decrypt given data.
//  If 'tag' is not give, then it will be taken from the 'enc'.
//
VSCF_PUBLIC vscf_error_t
vscf_aes256_gcm_auth_decrypt(vscf_aes256_gcm_impl_t *aes256_gcm_impl, vsc_data_t data, vsc_data_t auth_data,
        vsc_data_t tag, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT(vsc_data_is_valid(tag));
    VSCF_ASSERT(vsc_buffer_is_valid(out));

    VSCF_ASSERT(tag.len == vscf_aes256_gcm_AUTH_TAG_LEN);
    VSCF_ASSERT(vsc_buffer_left(out) >= vscf_aes256_gcm_auth_decrypted_len(aes256_gcm_impl, data.len));


    VSCF_ASSERT_OPT(0 == mbedtls_cipher_setkey(&aes256_gcm_impl->cipher_ctx, aes256_gcm_impl->key,
                                 vscf_aes256_gcm_KEY_BITLEN, MBEDTLS_DECRYPT));

    if (vsc_data_is_valid(auth_data)) {
        VSCF_ASSERT_OPT(0 == mbedtls_cipher_update_ad(&aes256_gcm_impl->cipher_ctx, auth_data.bytes, auth_data.len));
    }

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_reset(&aes256_gcm_impl->cipher_ctx));

    size_t first_block_len = 0;
    VSCF_ASSERT(vsc_buffer_left(out) >= data.len + vscf_aes256_gcm_BLOCK_LEN);
    VSCF_ASSERT_OPT(0 == mbedtls_cipher_update(&aes256_gcm_impl->cipher_ctx, data.bytes, data.len, vsc_buffer_ptr(out),
                                 &first_block_len));
    vsc_buffer_reserve(out, first_block_len);

    size_t last_block_len = 0;
    VSCF_ASSERT(vsc_buffer_left(out) >= vscf_aes256_gcm_BLOCK_LEN);
    VSCF_ASSERT_OPT(0 == mbedtls_cipher_finish(&aes256_gcm_impl->cipher_ctx, vsc_buffer_ptr(out), &last_block_len));
    vsc_buffer_reserve(out, last_block_len);

    if (0 != mbedtls_cipher_check_tag(&aes256_gcm_impl->cipher_ctx, tag.bytes, tag.len)) {
        return vscf_error_AUTH_FAILED;
    }

    return vscf_SUCCESS;
}

//
//  Calculate required buffer length to hold the authenticated decrypted data.
//
VSCF_PUBLIC size_t
vscf_aes256_gcm_auth_decrypted_len(vscf_aes256_gcm_impl_t *aes256_gcm_impl, size_t data_len) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);

    return data_len + vscf_aes256_gcm_BLOCK_LEN;
}
