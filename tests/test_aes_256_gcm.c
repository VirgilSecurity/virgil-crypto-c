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
// Test implementation of the interface 'cipher'.
// --------------------------------------------------------------------------

void test__encrypt__vector_1__encrypted_len_equals_16 (void) {

    vsf_aes_256_gcm_impl_t *aes_256_gcm_impl = vsf_aes_256_gcm_new ();

    size_t enc_len = vsf_aes_256_gcm_required_enc_len (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_1_DATA_LEN, 0);
    byte *enc = vsf_alloc (enc_len);


    vsf_aes_256_gcm_set_key (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_1_KEY, test_aes_256_gcm_VECTOR_1_KEY_LEN);
    vsf_aes_256_gcm_set_nonce (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_1_NONCE, test_aes_256_gcm_VECTOR_1_NONCE_LEN);

    size_t actual_enc_len = 0;
    vsf_aes_256_gcm_encrypt (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_1_DATA, test_aes_256_gcm_VECTOR_1_DATA_LEN,
            enc, enc_len, &actual_enc_len);

    vsf_aes_256_gcm_destroy (&aes_256_gcm_impl);

    TEST_ASSERT_EQUAL (16, actual_enc_len);

    vsf_dealloc (enc);
}

void test__encrypt__vector_1__valid_encrypted_data (void) {

    vsf_aes_256_gcm_impl_t *aes_256_gcm_impl = vsf_aes_256_gcm_new ();

    size_t enc_len = vsf_aes_256_gcm_required_enc_len (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_1_DATA_LEN, 0);
    byte *enc = vsf_alloc (enc_len);


    vsf_aes_256_gcm_set_key (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_1_KEY, test_aes_256_gcm_VECTOR_1_KEY_LEN);
    vsf_aes_256_gcm_set_nonce (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_1_NONCE, test_aes_256_gcm_VECTOR_1_NONCE_LEN);

    size_t actual_enc_len = 0;
    vsf_aes_256_gcm_encrypt (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_1_DATA, test_aes_256_gcm_VECTOR_1_DATA_LEN,
            enc, enc_len, &actual_enc_len);

    vsf_aes_256_gcm_destroy (&aes_256_gcm_impl);

    TEST_ASSERT_EQUAL_HEX8_ARRAY (
                test_aes_256_gcm_VECTOR_1_ENC_PLUS_AUTH_TAG, enc, test_aes_256_gcm_VECTOR_1_ENC_PLUS_AUTH_TAG_LEN);

    vsf_dealloc (enc);
}

void test__decrypt__vector_1__decrypted_len_equals_0 (void) {

    vsf_aes_256_gcm_impl_t *aes_256_gcm_impl = vsf_aes_256_gcm_new ();

    size_t dec_len = vsf_aes_256_gcm_required_dec_len (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_1_ENC_LEN, 0);
    byte *dec = vsf_alloc (dec_len);


    vsf_aes_256_gcm_set_key (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_1_KEY, test_aes_256_gcm_VECTOR_1_KEY_LEN);
    vsf_aes_256_gcm_set_nonce (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_1_NONCE, test_aes_256_gcm_VECTOR_1_NONCE_LEN);

    size_t actual_dec_len = 0;
    vsf_aes_256_gcm_decrypt (aes_256_gcm_impl,
            test_aes_256_gcm_VECTOR_1_ENC_PLUS_AUTH_TAG, test_aes_256_gcm_VECTOR_1_ENC_PLUS_AUTH_TAG_LEN,
            dec, dec_len, &actual_dec_len);

    vsf_aes_256_gcm_destroy (&aes_256_gcm_impl);

    TEST_ASSERT_EQUAL (0, actual_dec_len);

    vsf_dealloc (dec);
}

void test__decrypt__vector_1__valid_auth_tag (void) {

    vsf_aes_256_gcm_impl_t *aes_256_gcm_impl = vsf_aes_256_gcm_new ();

    size_t dec_len = vsf_aes_256_gcm_required_dec_len (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_1_ENC_LEN, 0);
    byte *dec = vsf_alloc (dec_len);


    vsf_aes_256_gcm_set_key (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_1_KEY, test_aes_256_gcm_VECTOR_1_KEY_LEN);
    vsf_aes_256_gcm_set_nonce (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_1_NONCE, test_aes_256_gcm_VECTOR_1_NONCE_LEN);

    size_t actual_dec_len = 0;
    int result = vsf_aes_256_gcm_decrypt (aes_256_gcm_impl,
            test_aes_256_gcm_VECTOR_1_ENC_PLUS_AUTH_TAG, test_aes_256_gcm_VECTOR_1_ENC_PLUS_AUTH_TAG_LEN,
            dec, dec_len, &actual_dec_len);

    vsf_aes_256_gcm_destroy (&aes_256_gcm_impl);

    TEST_ASSERT_EQUAL (0, result);

    vsf_dealloc (dec);
}

// --------------------------------------------------------------------------
// Test implementation of the interface 'cipher auth'.
// --------------------------------------------------------------------------
void test__AUTH_TAG_LEN__always__equals_16 (void) {
    TEST_ASSERT_EQUAL (16, vsf_aes_256_gcm_AUTH_TAG_LEN);
}

void test__auth_encrypt__vector_2__encrypted_len_equals_0 (void) {

    vsf_aes_256_gcm_impl_t *aes_256_gcm_impl = vsf_aes_256_gcm_new ();

    size_t enc_len = vsf_aes_256_gcm_required_enc_len (aes_256_gcm_impl,
                test_aes_256_gcm_VECTOR_2_DATA_LEN, test_aes_256_gcm_VECTOR_2_AUTH_TAG_LEN);

    byte *enc = vsf_alloc (enc_len);
    byte *tag = vsf_alloc (test_aes_256_gcm_VECTOR_2_AUTH_TAG_LEN);

    vsf_aes_256_gcm_set_key (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_2_KEY, test_aes_256_gcm_VECTOR_2_KEY_LEN);
    vsf_aes_256_gcm_set_nonce (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_2_NONCE, test_aes_256_gcm_VECTOR_2_NONCE_LEN);

    size_t actual_enc_len = 0;
    vsf_aes_256_gcm_auth_encrypt (aes_256_gcm_impl,
            test_aes_256_gcm_VECTOR_2_DATA, test_aes_256_gcm_VECTOR_2_DATA_LEN,
            test_aes_256_gcm_VECTOR_2_ADD, test_aes_256_gcm_VECTOR_2_ADD_LEN,
            enc, enc_len, &actual_enc_len,
            tag, test_aes_256_gcm_VECTOR_2_AUTH_TAG_LEN);

    vsf_aes_256_gcm_destroy (&aes_256_gcm_impl);

    TEST_ASSERT_EQUAL (0, actual_enc_len);

    vsf_dealloc (enc);
    vsf_dealloc (tag);
}

void test__auth_encrypt__vector_2__valid_auth_tag (void) {

    vsf_aes_256_gcm_impl_t *aes_256_gcm_impl = vsf_aes_256_gcm_new ();

    size_t enc_len = vsf_aes_256_gcm_required_enc_len (aes_256_gcm_impl,
            test_aes_256_gcm_VECTOR_2_DATA_LEN, test_aes_256_gcm_VECTOR_2_AUTH_TAG_LEN);

    byte *enc = vsf_alloc (enc_len);
    byte *tag = vsf_alloc (test_aes_256_gcm_VECTOR_2_AUTH_TAG_LEN);

    vsf_aes_256_gcm_set_key (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_2_KEY, test_aes_256_gcm_VECTOR_2_KEY_LEN);
    vsf_aes_256_gcm_set_nonce (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_2_NONCE, test_aes_256_gcm_VECTOR_2_NONCE_LEN);

    size_t actual_enc_len = 0;
    vsf_aes_256_gcm_auth_encrypt (aes_256_gcm_impl,
            test_aes_256_gcm_VECTOR_2_DATA, test_aes_256_gcm_VECTOR_2_DATA_LEN,
            test_aes_256_gcm_VECTOR_2_ADD, test_aes_256_gcm_VECTOR_2_ADD_LEN,
            enc, enc_len, &actual_enc_len,
            tag, test_aes_256_gcm_VECTOR_2_AUTH_TAG_LEN);

    vsf_aes_256_gcm_destroy (&aes_256_gcm_impl);

    TEST_ASSERT_EQUAL_HEX8_ARRAY (test_aes_256_gcm_VECTOR_2_AUTH_TAG, tag, test_aes_256_gcm_VECTOR_2_AUTH_TAG_LEN);

    vsf_dealloc (enc);
    vsf_dealloc (tag);
}

void test__auth_decrypt__vector_2__decrypted_len_equals_0 (void) {

    vsf_aes_256_gcm_impl_t *aes_256_gcm_impl = vsf_aes_256_gcm_new ();

    size_t dec_len = vsf_aes_256_gcm_required_dec_len (aes_256_gcm_impl,
                test_aes_256_gcm_VECTOR_2_DATA_LEN, test_aes_256_gcm_VECTOR_2_AUTH_TAG_LEN);

    byte *dec = vsf_alloc (dec_len);

    vsf_aes_256_gcm_set_key (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_2_KEY, test_aes_256_gcm_VECTOR_2_KEY_LEN);
    vsf_aes_256_gcm_set_nonce (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_2_NONCE, test_aes_256_gcm_VECTOR_2_NONCE_LEN);

    size_t actual_dec_len = 0;
    vsf_aes_256_gcm_auth_decrypt (aes_256_gcm_impl,
            test_aes_256_gcm_VECTOR_2_ENC, test_aes_256_gcm_VECTOR_2_ENC_LEN,
            test_aes_256_gcm_VECTOR_2_ADD, test_aes_256_gcm_VECTOR_2_ADD_LEN,
            test_aes_256_gcm_VECTOR_2_AUTH_TAG, test_aes_256_gcm_VECTOR_2_AUTH_TAG_LEN,
            dec, dec_len, &actual_dec_len);

    vsf_aes_256_gcm_destroy (&aes_256_gcm_impl);

    TEST_ASSERT_EQUAL (0, actual_dec_len);

    vsf_dealloc (dec);
}

void test__auth_decrypt__vector_2__valid_auth_tag (void) {

    vsf_aes_256_gcm_impl_t *aes_256_gcm_impl = vsf_aes_256_gcm_new ();

    size_t dec_len = vsf_aes_256_gcm_required_dec_len (aes_256_gcm_impl,
                test_aes_256_gcm_VECTOR_2_DATA_LEN, test_aes_256_gcm_VECTOR_2_AUTH_TAG_LEN);

    byte *dec = vsf_alloc (dec_len);

    vsf_aes_256_gcm_set_key (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_2_KEY, test_aes_256_gcm_VECTOR_2_KEY_LEN);
    vsf_aes_256_gcm_set_nonce (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_2_NONCE, test_aes_256_gcm_VECTOR_2_NONCE_LEN);

    size_t actual_dec_len = 0;
    int result = vsf_aes_256_gcm_auth_decrypt (aes_256_gcm_impl,
            test_aes_256_gcm_VECTOR_2_ENC, test_aes_256_gcm_VECTOR_2_ENC_LEN,
            test_aes_256_gcm_VECTOR_2_ADD, test_aes_256_gcm_VECTOR_2_ADD_LEN,
            test_aes_256_gcm_VECTOR_2_AUTH_TAG, test_aes_256_gcm_VECTOR_2_AUTH_TAG_LEN,
            dec, dec_len, &actual_dec_len);

    vsf_aes_256_gcm_destroy (&aes_256_gcm_impl);

    TEST_ASSERT_EQUAL (0, result);

    vsf_dealloc (dec);
}

void test__auth_encrypt__vector_3__encrypted_len_equals_128 (void) {

    vsf_aes_256_gcm_impl_t *aes_256_gcm_impl = vsf_aes_256_gcm_new ();

    size_t enc_len = vsf_aes_256_gcm_required_enc_len (aes_256_gcm_impl,
            test_aes_256_gcm_VECTOR_3_DATA_LEN, test_aes_256_gcm_VECTOR_3_AUTH_TAG_LEN);

    byte *enc = vsf_alloc (enc_len);
    byte *tag = vsf_alloc (test_aes_256_gcm_VECTOR_3_AUTH_TAG_LEN);

    vsf_aes_256_gcm_set_key (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_3_KEY, test_aes_256_gcm_VECTOR_3_KEY_LEN);
    vsf_aes_256_gcm_set_nonce (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_3_NONCE, test_aes_256_gcm_VECTOR_3_NONCE_LEN);

    size_t actual_enc_len = 0;
    vsf_aes_256_gcm_auth_encrypt (aes_256_gcm_impl,
            test_aes_256_gcm_VECTOR_3_DATA, test_aes_256_gcm_VECTOR_3_DATA_LEN,
            test_aes_256_gcm_VECTOR_3_ADD, test_aes_256_gcm_VECTOR_3_ADD_LEN,
            enc, enc_len, &actual_enc_len,
            tag, test_aes_256_gcm_VECTOR_3_AUTH_TAG_LEN);

    vsf_aes_256_gcm_destroy (&aes_256_gcm_impl);

    TEST_ASSERT_EQUAL (128, actual_enc_len);

    vsf_dealloc (enc);
    vsf_dealloc (tag);
}

void test__auth_encrypt__vector_3__valid_enc (void) {

    vsf_aes_256_gcm_impl_t *aes_256_gcm_impl = vsf_aes_256_gcm_new ();

    size_t enc_len = vsf_aes_256_gcm_required_enc_len (aes_256_gcm_impl,
            test_aes_256_gcm_VECTOR_3_DATA_LEN, test_aes_256_gcm_VECTOR_3_AUTH_TAG_LEN);

    byte *enc = vsf_alloc (enc_len);
    byte *tag = vsf_alloc (test_aes_256_gcm_VECTOR_3_AUTH_TAG_LEN);

    vsf_aes_256_gcm_set_key (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_3_KEY, test_aes_256_gcm_VECTOR_3_KEY_LEN);
    vsf_aes_256_gcm_set_nonce (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_3_NONCE, test_aes_256_gcm_VECTOR_3_NONCE_LEN);

    size_t actual_enc_len = 0;
    vsf_aes_256_gcm_auth_encrypt (aes_256_gcm_impl,
            test_aes_256_gcm_VECTOR_3_DATA, test_aes_256_gcm_VECTOR_3_DATA_LEN,
            test_aes_256_gcm_VECTOR_3_ADD, test_aes_256_gcm_VECTOR_3_ADD_LEN,
            enc, enc_len, &actual_enc_len,
            tag, test_aes_256_gcm_VECTOR_3_AUTH_TAG_LEN);

    vsf_aes_256_gcm_destroy (&aes_256_gcm_impl);

    TEST_ASSERT_EQUAL_HEX8_ARRAY (test_aes_256_gcm_VECTOR_3_ENC, enc, test_aes_256_gcm_VECTOR_3_ENC_LEN);

    vsf_dealloc (enc);
    vsf_dealloc (tag);
}

void test__auth_encrypt__vector_3__valid_auth_tag (void) {

    vsf_aes_256_gcm_impl_t *aes_256_gcm_impl = vsf_aes_256_gcm_new ();

    size_t enc_len = vsf_aes_256_gcm_required_enc_len (aes_256_gcm_impl,
            test_aes_256_gcm_VECTOR_3_DATA_LEN, test_aes_256_gcm_VECTOR_3_AUTH_TAG_LEN);

    byte *enc = vsf_alloc (enc_len);
    byte *tag = vsf_alloc (test_aes_256_gcm_VECTOR_3_AUTH_TAG_LEN);

    vsf_aes_256_gcm_set_key (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_3_KEY, test_aes_256_gcm_VECTOR_3_KEY_LEN);
    vsf_aes_256_gcm_set_nonce (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_3_NONCE, test_aes_256_gcm_VECTOR_3_NONCE_LEN);

    size_t actual_enc_len = 0;
    vsf_aes_256_gcm_auth_encrypt (aes_256_gcm_impl,
            test_aes_256_gcm_VECTOR_3_DATA, test_aes_256_gcm_VECTOR_3_DATA_LEN,
            test_aes_256_gcm_VECTOR_3_ADD, test_aes_256_gcm_VECTOR_3_ADD_LEN,
            enc, enc_len, &actual_enc_len,
            tag, test_aes_256_gcm_VECTOR_3_AUTH_TAG_LEN);

    vsf_aes_256_gcm_destroy (&aes_256_gcm_impl);

    TEST_ASSERT_EQUAL_HEX8_ARRAY (test_aes_256_gcm_VECTOR_3_AUTH_TAG, tag, test_aes_256_gcm_VECTOR_3_AUTH_TAG_LEN);

    vsf_dealloc (enc);
    vsf_dealloc (tag);
}


void test__auth_decrypt__vector_3__decrypted_len_equals_128 (void) {

    vsf_aes_256_gcm_impl_t *aes_256_gcm_impl = vsf_aes_256_gcm_new ();

    size_t dec_len = vsf_aes_256_gcm_required_dec_len (aes_256_gcm_impl,
                test_aes_256_gcm_VECTOR_3_DATA_LEN, test_aes_256_gcm_VECTOR_3_AUTH_TAG_LEN);

    byte *dec = vsf_alloc (dec_len);

    vsf_aes_256_gcm_set_key (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_3_KEY, test_aes_256_gcm_VECTOR_3_KEY_LEN);
    vsf_aes_256_gcm_set_nonce (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_3_NONCE, test_aes_256_gcm_VECTOR_3_NONCE_LEN);

    size_t actual_dec_len = 0;
    vsf_aes_256_gcm_auth_decrypt (aes_256_gcm_impl,
            test_aes_256_gcm_VECTOR_3_ENC, test_aes_256_gcm_VECTOR_3_ENC_LEN,
            test_aes_256_gcm_VECTOR_3_ADD, test_aes_256_gcm_VECTOR_3_ADD_LEN,
            test_aes_256_gcm_VECTOR_3_AUTH_TAG, test_aes_256_gcm_VECTOR_3_AUTH_TAG_LEN,
            dec, dec_len, &actual_dec_len);

    vsf_aes_256_gcm_destroy (&aes_256_gcm_impl);

    TEST_ASSERT_EQUAL (128, actual_dec_len);

    vsf_dealloc (dec);
}

void test__auth_decrypt__vector_3__valid_auth_tag (void) {

    vsf_aes_256_gcm_impl_t *aes_256_gcm_impl = vsf_aes_256_gcm_new ();

    size_t dec_len = vsf_aes_256_gcm_required_dec_len (aes_256_gcm_impl,
                test_aes_256_gcm_VECTOR_3_DATA_LEN, test_aes_256_gcm_VECTOR_3_AUTH_TAG_LEN);

    byte *dec = vsf_alloc (dec_len);

    vsf_aes_256_gcm_set_key (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_3_KEY, test_aes_256_gcm_VECTOR_3_KEY_LEN);
    vsf_aes_256_gcm_set_nonce (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_3_NONCE, test_aes_256_gcm_VECTOR_3_NONCE_LEN);

    size_t actual_dec_len = 0;
    int result = vsf_aes_256_gcm_auth_decrypt (aes_256_gcm_impl,
            test_aes_256_gcm_VECTOR_3_ENC, test_aes_256_gcm_VECTOR_3_ENC_LEN,
            test_aes_256_gcm_VECTOR_3_ADD, test_aes_256_gcm_VECTOR_3_ADD_LEN,
            test_aes_256_gcm_VECTOR_3_AUTH_TAG, test_aes_256_gcm_VECTOR_3_AUTH_TAG_LEN,
            dec, dec_len, &actual_dec_len);

    vsf_aes_256_gcm_destroy (&aes_256_gcm_impl);

    TEST_ASSERT_EQUAL (0, result);

    vsf_dealloc (dec);
}

void test__auth_decrypt__vector_3__valid_dec (void) {

    vsf_aes_256_gcm_impl_t *aes_256_gcm_impl = vsf_aes_256_gcm_new ();

    size_t dec_len = vsf_aes_256_gcm_required_dec_len (aes_256_gcm_impl,
                test_aes_256_gcm_VECTOR_3_DATA_LEN, test_aes_256_gcm_VECTOR_3_AUTH_TAG_LEN);

    byte *dec = vsf_alloc (dec_len);

    vsf_aes_256_gcm_set_key (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_3_KEY, test_aes_256_gcm_VECTOR_3_KEY_LEN);
    vsf_aes_256_gcm_set_nonce (aes_256_gcm_impl, test_aes_256_gcm_VECTOR_3_NONCE, test_aes_256_gcm_VECTOR_3_NONCE_LEN);

    size_t actual_dec_len = 0;
    int result = vsf_aes_256_gcm_auth_decrypt (aes_256_gcm_impl,
            test_aes_256_gcm_VECTOR_3_ENC, test_aes_256_gcm_VECTOR_3_ENC_LEN,
            test_aes_256_gcm_VECTOR_3_ADD, test_aes_256_gcm_VECTOR_3_ADD_LEN,
            test_aes_256_gcm_VECTOR_3_AUTH_TAG, test_aes_256_gcm_VECTOR_3_AUTH_TAG_LEN,
            dec, dec_len, &actual_dec_len);

    vsf_aes_256_gcm_destroy (&aes_256_gcm_impl);

    TEST_ASSERT_EQUAL_HEX8_ARRAY (test_aes_256_gcm_VECTOR_3_DATA, dec, test_aes_256_gcm_VECTOR_3_DATA_LEN);

    vsf_dealloc (dec);
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

    RUN_TEST (test__encrypt__vector_1__encrypted_len_equals_16);
    RUN_TEST (test__encrypt__vector_1__valid_encrypted_data);
    RUN_TEST (test__decrypt__vector_1__decrypted_len_equals_0);
    RUN_TEST (test__decrypt__vector_1__valid_auth_tag);

    RUN_TEST (test__auth_encrypt__vector_2__encrypted_len_equals_0);
    RUN_TEST (test__auth_encrypt__vector_2__valid_auth_tag);
    RUN_TEST (test__auth_decrypt__vector_2__decrypted_len_equals_0);
    RUN_TEST (test__auth_decrypt__vector_2__valid_auth_tag);

    RUN_TEST (test__auth_encrypt__vector_3__encrypted_len_equals_128);
    RUN_TEST (test__auth_encrypt__vector_3__valid_enc);
    RUN_TEST (test__auth_encrypt__vector_3__valid_auth_tag);
    RUN_TEST (test__auth_decrypt__vector_3__decrypted_len_equals_128);
    RUN_TEST (test__auth_decrypt__vector_3__valid_auth_tag);
    RUN_TEST (test__auth_decrypt__vector_3__valid_dec);

    return UNITY_END();
}
