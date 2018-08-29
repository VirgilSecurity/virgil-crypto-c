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
//
VSCF_PRIVATE void
vscf_aes256_gcm_init_ctx(vscf_aes256_gcm_impl_t *aes256_gcm_impl) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);

    mbedtls_cipher_init(&aes256_gcm_impl->cipher_ctx);

    int result = mbedtls_cipher_setup(
            &aes256_gcm_impl->cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM));

    VSCF_ASSERT_ALLOC(result != MBEDTLS_ERR_CIPHER_ALLOC_FAILED);
    VSCF_ASSERT(result == 0 && "unhandled mbedtls error");

    vscf_zeroize(aes256_gcm_impl->key, vscf_aes256_gcm_KEY_LEN);
    vscf_zeroize(aes256_gcm_impl->nonce, vscf_aes256_gcm_NONCE_LEN);
}

//
//  Provides cleanup of the implementation specific context.
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
vscf_aes256_gcm_encrypt(vscf_aes256_gcm_impl_t *aes256_gcm_impl, const byte *data, size_t data_len, byte *enc,
        size_t enc_len, size_t *out_len) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);
    VSCF_ASSERT_PTR(data);
    VSCF_ASSERT_PTR(enc);
    VSCF_ASSERT_PTR(out_len);
    VSCF_ASSERT_OPT(enc_len >= vscf_aes256_gcm_required_enc_len(aes256_gcm_impl, data_len, 0));

    return vscf_aes256_gcm_auth_encrypt(aes256_gcm_impl, data, data_len, NULL, 0, enc, enc_len, out_len, NULL, 0);
}

//
//  Calculate required buffer length to hold the encrypted data.
//  If argument 'auth tag len' is 0, then returned length
//  adjusted to hold auth tag as well.
//
VSCF_PUBLIC size_t
vscf_aes256_gcm_required_enc_len(vscf_aes256_gcm_impl_t *aes256_gcm_impl, size_t data_len, size_t auth_tag_len) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);

    const size_t required_enc_len = data_len + (auth_tag_len > 0 ? 0 : vscf_aes256_gcm_AUTH_TAG_LEN);

    return required_enc_len;
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_error_t
vscf_aes256_gcm_decrypt(vscf_aes256_gcm_impl_t *aes256_gcm_impl, const byte *enc, size_t enc_len, byte *plain,
        size_t plain_len, size_t *out_len) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);
    VSCF_ASSERT_PTR(enc);
    VSCF_ASSERT_PTR(plain);
    VSCF_ASSERT_PTR(out_len);
    VSCF_ASSERT_OPT(enc_len >= vscf_aes256_gcm_AUTH_TAG_LEN);
    VSCF_ASSERT_OPT(plain_len >= enc_len - vscf_aes256_gcm_AUTH_TAG_LEN);

    return vscf_aes256_gcm_auth_decrypt(aes256_gcm_impl, enc, enc_len, NULL, 0, NULL, 0, plain, plain_len, out_len);
}

//
//  Calculate required buffer length to hold the decrypted data.
//  If argument 'auth tag len' is 0, then returned length
//  adjusted to cut of auth tag length.
//
VSCF_PUBLIC size_t
vscf_aes256_gcm_required_dec_len(vscf_aes256_gcm_impl_t *aes256_gcm_impl, size_t enc_len, size_t auth_tag_len) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);

    if (auth_tag_len > 0) {
        return enc_len;

    } else {
        VSCF_ASSERT_OPT(enc_len >= auth_tag_len);
        return enc_len - vscf_aes256_gcm_AUTH_TAG_LEN;
    }
}

//
//  Setup IV or nonce.
//
VSCF_PUBLIC void
vscf_aes256_gcm_set_nonce(vscf_aes256_gcm_impl_t *aes256_gcm_impl, const byte *nonce, size_t nonce_len) {

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_set_iv(&aes256_gcm_impl->cipher_ctx, nonce, nonce_len));
}

//
//  Set cipher encryption / decryption key.
//
VSCF_PUBLIC void
vscf_aes256_gcm_set_key(vscf_aes256_gcm_impl_t *aes256_gcm_impl, const byte *key, size_t key_len) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);
    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT_OPT(vscf_aes256_gcm_KEY_LEN == key_len);

    memcpy(aes256_gcm_impl->key, key, key_len);
}

//
//  Encrypt given data.
//  If 'tag' is not give, then it will written to the 'enc'.
//
VSCF_PUBLIC vscf_error_t
vscf_aes256_gcm_auth_encrypt(vscf_aes256_gcm_impl_t *aes256_gcm_impl, const byte *data, size_t data_len,
        const byte *auth_data, size_t auth_data_len, byte *enc, size_t enc_len, size_t *out_len, byte *tag,
        size_t tag_len) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);
    VSCF_ASSERT_PTR(data);
    VSCF_ASSERT_PTR(enc);
    VSCF_ASSERT_PTR(out_len);

    if (tag) {
        VSCF_ASSERT_OPT(tag_len >= vscf_aes256_gcm_AUTH_TAG_LEN);
        VSCF_ASSERT_OPT(enc_len >= data_len);

    } else {
        VSCF_ASSERT_OPT(0 == tag_len);
        VSCF_ASSERT_OPT(enc_len >= data_len + vscf_aes256_gcm_AUTH_TAG_LEN);
    }

    *out_len = 0;

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_setkey(&aes256_gcm_impl->cipher_ctx, aes256_gcm_impl->key,
                                 vscf_aes256_gcm_KEY_BITLEN, MBEDTLS_ENCRYPT));

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_update_ad(&aes256_gcm_impl->cipher_ctx, auth_data, auth_data_len));

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_reset(&aes256_gcm_impl->cipher_ctx));

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_update(&aes256_gcm_impl->cipher_ctx, data, data_len, enc, out_len));

    size_t last_block_len = 0;
    VSCF_ASSERT_OPT(0 == mbedtls_cipher_finish(&aes256_gcm_impl->cipher_ctx, enc + *out_len, &last_block_len));

    *out_len += last_block_len;

    if (tag) {
        VSCF_ASSERT_OPT(0 == mbedtls_cipher_write_tag(&aes256_gcm_impl->cipher_ctx, tag, vscf_aes256_gcm_AUTH_TAG_LEN));

    } else {
        VSCF_ASSERT_OPT(0 == mbedtls_cipher_write_tag(
                                     &aes256_gcm_impl->cipher_ctx, enc + *out_len, vscf_aes256_gcm_AUTH_TAG_LEN));
        *out_len += vscf_aes256_gcm_AUTH_TAG_LEN;
    }

    return vscf_SUCCESS;
}

//
//  Decrypt given data.
//  If 'tag' is not give, then it will be taken from the 'enc'.
//
VSCF_PUBLIC vscf_error_t
vscf_aes256_gcm_auth_decrypt(vscf_aes256_gcm_impl_t *aes256_gcm_impl, const byte *enc, size_t enc_len,
        const byte *auth_data, size_t auth_data_len, const byte *tag, size_t tag_len, byte *dec, size_t dec_len,
        size_t *out_len) {

    VSCF_ASSERT_PTR(aes256_gcm_impl);
    VSCF_ASSERT_PTR(enc);
    VSCF_ASSERT_PTR(dec);
    VSCF_ASSERT_PTR(out_len);
    VSCF_ASSERT_OPT((tag == NULL && tag_len == 0) || (tag != NULL && tag_len == vscf_aes256_gcm_AUTH_TAG_LEN));
    VSCF_ASSERT_OPT(dec_len >= vscf_aes256_gcm_required_dec_len(aes256_gcm_impl, enc_len, tag_len));

    if (NULL == tag) {
        VSCF_ASSERT_OPT(enc_len >= vscf_aes256_gcm_AUTH_TAG_LEN);
    }

    const byte *actual_tag = tag != NULL ? tag : enc + enc_len - vscf_aes256_gcm_AUTH_TAG_LEN;
    const size_t actual_enc_len = tag != NULL ? enc_len : enc_len - vscf_aes256_gcm_AUTH_TAG_LEN;

    size_t curr_out_len = 0;
    *out_len = 0;

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_setkey(&aes256_gcm_impl->cipher_ctx, aes256_gcm_impl->key,
                                 vscf_aes256_gcm_KEY_BITLEN, MBEDTLS_DECRYPT));

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_update_ad(&aes256_gcm_impl->cipher_ctx, auth_data, auth_data_len));

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_reset(&aes256_gcm_impl->cipher_ctx));

    VSCF_ASSERT_OPT(0 == mbedtls_cipher_update(&aes256_gcm_impl->cipher_ctx, enc, actual_enc_len, dec, &curr_out_len));

    size_t last_block_len = 0;
    VSCF_ASSERT_OPT(0 == mbedtls_cipher_finish(&aes256_gcm_impl->cipher_ctx, dec + *out_len, &last_block_len));

    curr_out_len += last_block_len;


    if (0 == mbedtls_cipher_check_tag(&aes256_gcm_impl->cipher_ctx, actual_tag, vscf_aes256_gcm_AUTH_TAG_LEN)) {
        *out_len = curr_out_len;
        return vscf_SUCCESS;
    }

    return vscf_error_AUTH_FAILED;
}
