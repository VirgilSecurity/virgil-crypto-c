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

#include "vsf_aes256_gcm.h"
#include "vsf_assert.h"
#include "vsf_memory.h"
#include "vsf_aes256_gcm_impl.h"
#include "vsf_aes256_gcm_internal.h"

#include <mbedtls/cipher.h>
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
VSF_PRIVATE vsf_error_t
vsf_aes256_gcm_init_ctx(vsf_aes256_gcm_impl_t* aes256_gcm_impl) {

    VSF_ASSERT_PTR(aes256_gcm_impl);

    mbedtls_cipher_init(&aes256_gcm_impl->cipher_ctx);

    int result = mbedtls_cipher_setup(
            &aes256_gcm_impl->cipher_ctx, mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM));

    switch (result) {
    case 0:
        break; // go ahead

    case MBEDTLS_ERR_CIPHER_ALLOC_FAILED:
        return vsf_error_NO_MEMORY;

    default:
        VSF_ASSERT(result && "mbedtls error");
        return vsf_error_BAD_ARGUMENTS;
    }

    vsf_zeroize(aes256_gcm_impl->key, vsf_aes256_gcm_KEY_LEN);
    vsf_zeroize(aes256_gcm_impl->nonce, vsf_aes256_gcm_NONCE_LEN);

    return vsf_SUCCESS;
}

//
//  Provides cleanup of the implementation specific context.
//
VSF_PRIVATE void
vsf_aes256_gcm_cleanup_ctx(vsf_aes256_gcm_impl_t* aes256_gcm_impl) {

    VSF_ASSERT_PTR(aes256_gcm_impl);

    mbedtls_cipher_free(&aes256_gcm_impl->cipher_ctx);

    vsf_erase(aes256_gcm_impl->key, vsf_aes256_gcm_KEY_LEN);
    vsf_erase(aes256_gcm_impl->nonce, vsf_aes256_gcm_NONCE_LEN);
}

//
//  Encrypt given data.
//
VSF_PUBLIC vsf_error_t
vsf_aes256_gcm_encrypt(vsf_aes256_gcm_impl_t* aes256_gcm_impl, const byte* data, size_t data_len, byte* enc,
        size_t enc_len, size_t* out_len) {

    VSF_ASSERT_PTR(aes256_gcm_impl);
    VSF_ASSERT_PTR(data);
    VSF_ASSERT_PTR(enc);
    VSF_ASSERT_PTR(out_len);
    VSF_ASSERT_OPT(enc_len >= vsf_aes256_gcm_required_enc_len(aes256_gcm_impl, data_len, 0));

    return vsf_aes256_gcm_auth_encrypt(aes256_gcm_impl, data, data_len, NULL, 0, enc, enc_len, out_len, NULL, 0);
}

//
//  Calculate required buffer length to hold the encrypted data.
//  If argument 'auth tag len' is 0, then returned length
//  adjusted to hold auth tag as well.
//
VSF_PUBLIC size_t
vsf_aes256_gcm_required_enc_len(vsf_aes256_gcm_impl_t* aes256_gcm_impl, size_t data_len, size_t auth_tag_len) {

    VSF_ASSERT_PTR(aes256_gcm_impl);

    const size_t required_enc_len = data_len + (auth_tag_len > 0 ? 0 : vsf_aes256_gcm_AUTH_TAG_LEN);

    return required_enc_len;
}

//
//  Decrypt given data.
//
VSF_PUBLIC vsf_error_t
vsf_aes256_gcm_decrypt(vsf_aes256_gcm_impl_t* aes256_gcm_impl, const byte* enc, size_t enc_len, byte* plain,
        size_t plain_len, size_t* out_len) {

    VSF_ASSERT_PTR(aes256_gcm_impl);
    VSF_ASSERT_PTR(enc);
    VSF_ASSERT_PTR(plain);
    VSF_ASSERT_PTR(out_len);
    VSF_ASSERT_OPT(enc_len >= vsf_aes256_gcm_AUTH_TAG_LEN);
    VSF_ASSERT_OPT(plain_len >= enc_len - vsf_aes256_gcm_AUTH_TAG_LEN);

    return vsf_aes256_gcm_auth_decrypt(aes256_gcm_impl, enc, enc_len, NULL, 0, NULL, 0, plain, plain_len, out_len);
}

//
//  Calculate required buffer length to hold the decrypted data.
//  If argument 'auth tag len' is 0, then returned length
//  adjusted to cut of auth tag length.
//
VSF_PUBLIC size_t
vsf_aes256_gcm_required_dec_len(vsf_aes256_gcm_impl_t* aes256_gcm_impl, size_t enc_len, size_t auth_tag_len) {

    VSF_ASSERT_PTR(aes256_gcm_impl);

    if (auth_tag_len > 0) {
        return enc_len;

    } else {
        VSF_ASSERT_OPT(enc_len >= auth_tag_len);
        return enc_len - vsf_aes256_gcm_AUTH_TAG_LEN;
    }
}

//
//  Setup IV or nonce.
//
VSF_PUBLIC void
vsf_aes256_gcm_set_nonce(vsf_aes256_gcm_impl_t* aes256_gcm_impl, const byte* nonce, size_t nonce_len) {

    VSF_ASSERT_OPT(0 == mbedtls_cipher_set_iv(&aes256_gcm_impl->cipher_ctx, nonce, nonce_len));
}

//
//  Set cipher encryption / decryption key.
//
VSF_PUBLIC void
vsf_aes256_gcm_set_key(vsf_aes256_gcm_impl_t* aes256_gcm_impl, const byte* key, size_t key_len) {

    VSF_ASSERT_PTR(aes256_gcm_impl);
    VSF_ASSERT_PTR(key);
    VSF_ASSERT_OPT(vsf_aes256_gcm_KEY_LEN == key_len);

    memcpy(aes256_gcm_impl->key, key, key_len);
}

//
//  Encrypt given data.
//  If 'tag' is not give, then it will written to the 'enc'.
//
VSF_PUBLIC vsf_error_t
vsf_aes256_gcm_auth_encrypt(vsf_aes256_gcm_impl_t* aes256_gcm_impl, const byte* data, size_t data_len,
        const byte* auth_data, size_t auth_data_len, byte* enc, size_t enc_len, size_t* out_len, byte* tag,
        size_t tag_len) {

    VSF_ASSERT_PTR(aes256_gcm_impl);
    VSF_ASSERT_PTR(data);
    VSF_ASSERT_PTR(enc);
    VSF_ASSERT_PTR(out_len);

    if (tag) {
        VSF_ASSERT_OPT(tag_len >= vsf_aes256_gcm_AUTH_TAG_LEN);
        VSF_ASSERT_OPT(enc_len >= data_len);

    } else {
        VSF_ASSERT_OPT(0 == tag_len);
        VSF_ASSERT_OPT(enc_len >= data_len + vsf_aes256_gcm_AUTH_TAG_LEN);
    }

    *out_len = 0;

    VSF_ASSERT_OPT(0 == mbedtls_cipher_setkey(&aes256_gcm_impl->cipher_ctx, aes256_gcm_impl->key,
                                vsf_aes256_gcm_KEY_BITLEN, MBEDTLS_ENCRYPT));

    VSF_ASSERT_OPT(0 == mbedtls_cipher_update_ad(&aes256_gcm_impl->cipher_ctx, auth_data, auth_data_len));

    VSF_ASSERT_OPT(0 == mbedtls_cipher_reset(&aes256_gcm_impl->cipher_ctx));

    VSF_ASSERT_OPT(0 == mbedtls_cipher_update(&aes256_gcm_impl->cipher_ctx, data, data_len, enc, out_len));

    size_t last_block_len = 0;
    VSF_ASSERT_OPT(0 == mbedtls_cipher_finish(&aes256_gcm_impl->cipher_ctx, enc + *out_len, &last_block_len));

    *out_len += last_block_len;

    if (tag) {
        VSF_ASSERT_OPT(0 == mbedtls_cipher_write_tag(&aes256_gcm_impl->cipher_ctx, tag, vsf_aes256_gcm_AUTH_TAG_LEN));

    } else {
        VSF_ASSERT_OPT(0 == mbedtls_cipher_write_tag(
                                    &aes256_gcm_impl->cipher_ctx, enc + *out_len, vsf_aes256_gcm_AUTH_TAG_LEN));
        *out_len += vsf_aes256_gcm_AUTH_TAG_LEN;
    }

    return vsf_SUCCESS;
}

//
//  Decrypt given data.
//  If 'tag' is not give, then it will be taken from the 'enc'.
//
VSF_PUBLIC vsf_error_t
vsf_aes256_gcm_auth_decrypt(vsf_aes256_gcm_impl_t* aes256_gcm_impl, const byte* enc, size_t enc_len,
        const byte* auth_data, size_t auth_data_len, const byte* tag, size_t tag_len, byte* dec, size_t dec_len,
        size_t* out_len) {

    VSF_ASSERT_PTR(aes256_gcm_impl);
    VSF_ASSERT_PTR(enc);
    VSF_ASSERT_PTR(dec);
    VSF_ASSERT_PTR(out_len);
    VSF_ASSERT_OPT((tag == NULL && tag_len == 0) || (tag != NULL && tag_len == vsf_aes256_gcm_AUTH_TAG_LEN));
    VSF_ASSERT_OPT(dec_len >= vsf_aes256_gcm_required_dec_len(aes256_gcm_impl, enc_len, tag_len));

    if (NULL == tag) {
        VSF_ASSERT_OPT(enc_len >= vsf_aes256_gcm_AUTH_TAG_LEN);
    }

    const byte* actual_tag = tag != NULL ? tag : enc + enc_len - vsf_aes256_gcm_AUTH_TAG_LEN;
    const size_t actual_enc_len = tag != NULL ? enc_len : enc_len - vsf_aes256_gcm_AUTH_TAG_LEN;

    size_t curr_out_len = 0;
    *out_len = 0;

    VSF_ASSERT_OPT(0 == mbedtls_cipher_setkey(&aes256_gcm_impl->cipher_ctx, aes256_gcm_impl->key,
                                vsf_aes256_gcm_KEY_BITLEN, MBEDTLS_DECRYPT));

    VSF_ASSERT_OPT(0 == mbedtls_cipher_update_ad(&aes256_gcm_impl->cipher_ctx, auth_data, auth_data_len));

    VSF_ASSERT_OPT(0 == mbedtls_cipher_reset(&aes256_gcm_impl->cipher_ctx));

    VSF_ASSERT_OPT(0 == mbedtls_cipher_update(&aes256_gcm_impl->cipher_ctx, enc, actual_enc_len, dec, &curr_out_len));

    size_t last_block_len = 0;
    VSF_ASSERT_OPT(0 == mbedtls_cipher_finish(&aes256_gcm_impl->cipher_ctx, dec + *out_len, &last_block_len));

    curr_out_len += last_block_len;


    if (0 == mbedtls_cipher_check_tag(&aes256_gcm_impl->cipher_ctx, actual_tag, vsf_aes256_gcm_AUTH_TAG_LEN)) {
        *out_len = curr_out_len;
        return vsf_SUCCESS;
    }

    return vsf_error_AUTH_FAILED;
}
