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
//  This module contains 'aes 256 gcm' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsf_aes_256_gcm.h"
#include "vsf_assert.h"
#include "vsf_memory.h"
#include "vsf_aes_256_gcm_impl.h"
#include "vsf_aes_256_gcm_internal.h"

#include <mbedtls/cipher.h>
//  @end


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//
VSF_PRIVATE void
vsf_aes_256_gcm_init_ctx (vsf_aes_256_gcm_impl_t* aes_256_gcm_impl) {

    VSF_ASSERT_PTR (aes_256_gcm_impl);

    mbedtls_cipher_init (&aes_256_gcm_impl->cipher_ctx);

    VSF_ASSERT_OPT (0 == mbedtls_cipher_setup (&aes_256_gcm_impl->cipher_ctx,
            mbedtls_cipher_info_from_type (MBEDTLS_CIPHER_AES_256_GCM)));

    vsf_zeroize (aes_256_gcm_impl->key, vsf_aes_256_gcm_KEY_LEN);
    vsf_zeroize (aes_256_gcm_impl->nonce, vsf_aes_256_gcm_NONCE_LEN);
}

//
//  Provides cleanup of the implementation specific context.
//
VSF_PRIVATE void
vsf_aes_256_gcm_cleanup_ctx (vsf_aes_256_gcm_impl_t* aes_256_gcm_impl) {

    VSF_ASSERT_PTR (aes_256_gcm_impl);

    mbedtls_cipher_free (&aes_256_gcm_impl->cipher_ctx);

    vsf_erase (aes_256_gcm_impl->key, vsf_aes_256_gcm_KEY_LEN);
    vsf_erase (aes_256_gcm_impl->nonce, vsf_aes_256_gcm_NONCE_LEN);
}

//
//  Encrypt given data.
//
VSF_PUBLIC int
vsf_aes_256_gcm_encrypt (vsf_aes_256_gcm_impl_t* aes_256_gcm_impl, const byte* data,
        size_t data_len, byte* enc, size_t enc_len, size_t* out_len) {

    VSF_ASSERT_PTR (aes_256_gcm_impl);
    VSF_ASSERT_PTR (data);
    VSF_ASSERT_PTR (enc);
    VSF_ASSERT_PTR (out_len);
    VSF_ASSERT_OPT (enc_len >= data_len + vsf_aes_256_gcm_BLOCK_LEN + vsf_aes_256_gcm_AUTH_TAG_LEN);

    *out_len = 0;

    VSF_ASSERT_OPT (0 ==
            mbedtls_cipher_setkey (
                    &aes_256_gcm_impl->cipher_ctx, aes_256_gcm_impl->key, vsf_aes_256_gcm_KEY_BITLEN, MBEDTLS_ENCRYPT));

    VSF_ASSERT_OPT (0 ==
            mbedtls_cipher_update_ad (&aes_256_gcm_impl->cipher_ctx, NULL, 0));


    VSF_ASSERT_OPT (0 ==
            mbedtls_cipher_reset (&aes_256_gcm_impl->cipher_ctx));

    VSF_ASSERT_OPT (0 ==
            mbedtls_cipher_update (&aes_256_gcm_impl->cipher_ctx, data, data_len, enc, out_len));

    size_t last_block_len = 0;
    VSF_ASSERT_OPT (0 ==
            mbedtls_cipher_finish (&aes_256_gcm_impl->cipher_ctx, enc + *out_len, &last_block_len));

    *out_len += last_block_len;

    VSF_ASSERT_OPT (0 ==
            mbedtls_cipher_write_tag (&aes_256_gcm_impl->cipher_ctx, enc + *out_len, vsf_aes_256_gcm_AUTH_TAG_LEN));

    *out_len += vsf_aes_256_gcm_AUTH_TAG_LEN;

    return 0;
}

//
//  Decrypt given data.
//
VSF_PUBLIC int
vsf_aes_256_gcm_decrypt (vsf_aes_256_gcm_impl_t* aes_256_gcm_impl, const byte* enc, size_t enc_len,
        byte* plain, size_t plain_len, size_t* out_len) {

    VSF_ASSERT_PTR (aes_256_gcm_impl);
    VSF_ASSERT_PTR (enc);
    VSF_ASSERT_PTR (plain);
    VSF_ASSERT_PTR (out_len);
    VSF_ASSERT_OPT (enc_len > vsf_aes_256_gcm_AUTH_TAG_LEN);
    VSF_ASSERT_OPT (plain_len >= enc_len + vsf_aes_256_gcm_BLOCK_LEN - vsf_aes_256_gcm_AUTH_TAG_LEN);

    size_t curr_out_len = 0;
    *out_len = 0;

    VSF_ASSERT_OPT (0 ==
            mbedtls_cipher_setkey (
                    &aes_256_gcm_impl->cipher_ctx, aes_256_gcm_impl->key, vsf_aes_256_gcm_KEY_BITLEN, MBEDTLS_DECRYPT));

    VSF_ASSERT_OPT (0 ==
            mbedtls_cipher_update_ad (&aes_256_gcm_impl->cipher_ctx, NULL, 0));

    VSF_ASSERT_OPT (0 ==
            mbedtls_cipher_reset (&aes_256_gcm_impl->cipher_ctx));

    VSF_ASSERT_OPT (0 ==
            mbedtls_cipher_update (&aes_256_gcm_impl->cipher_ctx, enc, enc_len - vsf_aes_256_gcm_AUTH_TAG_LEN,
                    plain, &curr_out_len));

    size_t last_block_len = 0;
    VSF_ASSERT_OPT (0 ==
            mbedtls_cipher_finish (&aes_256_gcm_impl->cipher_ctx, plain + *out_len, &last_block_len));

    curr_out_len += last_block_len;

    if (0 == mbedtls_cipher_check_tag (&aes_256_gcm_impl->cipher_ctx,
                enc + vsf_aes_256_gcm_AUTH_TAG_LEN, vsf_aes_256_gcm_AUTH_TAG_LEN)) {

        *out_len = curr_out_len;
        return 0;

    }

    return -1;
}

//
//  Setup IV or nonce.
//
VSF_PUBLIC void
vsf_aes_256_gcm_set_nonce (vsf_aes_256_gcm_impl_t* aes_256_gcm_impl, const byte* nonce,
        size_t nonce_len) {

    VSF_ASSERT_OPT (0 ==
            mbedtls_cipher_set_iv (&aes_256_gcm_impl->cipher_ctx, nonce, nonce_len));
}

//
//  Set cipher encryption / decryption key.
//
VSF_PUBLIC void
vsf_aes_256_gcm_set_key (vsf_aes_256_gcm_impl_t* aes_256_gcm_impl, const byte* key,
        size_t key_len) {

    VSF_ASSERT_PTR (aes_256_gcm_impl);
    VSF_ASSERT_PTR (key);
    VSF_ASSERT_OPT (vsf_aes_256_gcm_KEY_LEN == key_len);

    memcpy (aes_256_gcm_impl->key, key, key_len);
}

//
//  Encrypt given data.
//
VSF_PUBLIC int
vsf_aes_256_gcm_auth_encrypt (vsf_aes_256_gcm_impl_t* aes_256_gcm_impl, const byte* data,
        size_t data_len, const byte* auth_data, size_t auth_data_len, byte* enc, size_t enc_len,
        size_t* out_len, byte* tag, size_t tag_len) {

    //  TODO: This is STUB. Implement me.
    return 0;
}

//
//  Decrypt given data.
//
VSF_PUBLIC int
vsf_aes_256_gcm_auth_decrypt (vsf_aes_256_gcm_impl_t* aes_256_gcm_impl, const byte* enc,
        size_t enc_len, byte* data, size_t data_len, size_t* out_len, const byte* auth_data,
        size_t auth_data_len, const byte* tag, size_t tag_len) {

    //  TODO: This is STUB. Implement me.
    return 0;
}
