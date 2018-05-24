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


#include "unity.h"

#include "vsf_memory.h"
#include "vsf_cipher.h"
#include "vsf_aes_256_gcm.h"
#include "test_data_aes_256_gcm.h"

#include "test_utils.h"



// --------------------------------------------------------------------------
// Test implementation of the interface 'cipher info'.
// --------------------------------------------------------------------------

void test__NONCE_LEN__always__equals_12 (void) {
    TEST_ASSERT_EQUAL (12, vsf_aes_256_gcm_NONCE_LEN);
}

void test__KEY_LEN__always__equals_32 (void) {
    TEST_ASSERT_EQUAL (32, vsf_aes_256_gcm_KEY_LEN);
}

void test__KEY_BITLEN__always__equals_256 (void) {
    TEST_ASSERT_EQUAL (256, vsf_aes_256_gcm_KEY_BITLEN);
}

void test__BLOCK_LEN__always__equals_16 (void) {
    TEST_ASSERT_EQUAL (16, vsf_aes_256_gcm_BLOCK_LEN);
}

// --------------------------------------------------------------------------
// Test implementation of the interface 'cipher auth'.
// --------------------------------------------------------------------------

void test__AUTH_TAG_LEN__always__equals_16 (void) {
    TEST_ASSERT_EQUAL (16, vsf_aes_256_gcm_AUTH_TAG_LEN);
}

// --------------------------------------------------------------------------
// Test implementation of the interface 'cipher'.
// --------------------------------------------------------------------------

void test__cipher__vector_1__out_len_equals_16 (void) {

    vsf_aes_256_gcm_impl_t *aes_256_gcm_impl = vsf_aes_256_gcm_new ();

    size_t enc_len = test_aes_256_gcm_DATA_LEN + vsf_aes_256_gcm_BLOCK_LEN + vsf_aes_256_gcm_AUTH_TAG_LEN;
    byte *enc = vsf_alloc (enc_len);


    vsf_aes_256_gcm_set_key (aes_256_gcm_impl, test_aes_256_gcm_KEY, test_aes_256_gcm_KEY_LEN);
    vsf_aes_256_gcm_set_nonce (aes_256_gcm_impl, test_aes_256_gcm_NONCE, test_aes_256_gcm_NONCE_LEN);

    size_t actual_enc_len = 0;
    vsf_aes_256_gcm_encrypt (aes_256_gcm_impl, test_aes_256_gcm_DATA, test_aes_256_gcm_DATA_LEN,
            enc, enc_len, &actual_enc_len);

    vsf_aes_256_gcm_destroy (&aes_256_gcm_impl);

    TEST_ASSERT_EQUAL (test_aes_256_gcm_AUTH_TAG_LEN, actual_enc_len);
}

void test__cipher__vector_1__valid_encrypted_data (void) {

    vsf_aes_256_gcm_impl_t *aes_256_gcm_impl = vsf_aes_256_gcm_new ();

    size_t enc_len = test_aes_256_gcm_DATA_LEN + vsf_aes_256_gcm_BLOCK_LEN + vsf_aes_256_gcm_AUTH_TAG_LEN;
    byte *enc = vsf_alloc (enc_len);


    vsf_aes_256_gcm_set_key (aes_256_gcm_impl, test_aes_256_gcm_KEY, test_aes_256_gcm_KEY_LEN);
    vsf_aes_256_gcm_set_nonce (aes_256_gcm_impl, test_aes_256_gcm_NONCE, test_aes_256_gcm_NONCE_LEN);

    size_t actual_enc_len = 0;
    vsf_aes_256_gcm_encrypt (aes_256_gcm_impl, test_aes_256_gcm_DATA, test_aes_256_gcm_DATA_LEN,
            enc, enc_len, &actual_enc_len);

    vsf_aes_256_gcm_destroy (&aes_256_gcm_impl);

    TEST_ASSERT_EQUAL_HEX8_ARRAY (test_aes_256_gcm_AUTH_TAG, enc, test_aes_256_gcm_AUTH_TAG_LEN);
}

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------

int main (void) {
    UNITY_BEGIN ();


    RUN_TEST (test__NONCE_LEN__always__equals_12);
    RUN_TEST (test__KEY_LEN__always__equals_32);
    RUN_TEST (test__KEY_BITLEN__always__equals_256);
    RUN_TEST (test__BLOCK_LEN__always__equals_16);
    RUN_TEST (test__AUTH_TAG_LEN__always__equals_16);

    RUN_TEST (test__cipher__vector_1__out_len_equals_16);
    RUN_TEST (test__cipher__vector_1__valid_encrypted_data);

    return UNITY_END();
}
