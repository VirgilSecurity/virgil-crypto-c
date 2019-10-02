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


#define UNITY_BEGIN() UnityBegin(__FILENAME__)

#include "unity.h"
#include "test_utils.h"


#define TEST_DEPENDENCIES_AVAILABLE VSCF_CIPHER &&VSCF_AES256_GCM
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_memory.h"
#include "vscf_cipher.h"
#include "vscf_aes256_gcm.h"

#include "test_data_aes256_gcm.h"


// --------------------------------------------------------------------------
// Test implementation of the interface 'cipher info'.
// --------------------------------------------------------------------------
void
test__NONCE_LEN__always__equals_12(void) {
    TEST_ASSERT_EQUAL(12, vscf_aes256_gcm_NONCE_LEN);
}

void
test__KEY_LEN__always__equals_32(void) {
    TEST_ASSERT_EQUAL(32, vscf_aes256_gcm_KEY_LEN);
}

void
test__KEY_BITLEN__always__equals_256(void) {
    TEST_ASSERT_EQUAL(256, vscf_aes256_gcm_KEY_BITLEN);
}

void
test__BLOCK_LEN__always__equals_16(void) {
    TEST_ASSERT_EQUAL(16, vscf_aes256_gcm_BLOCK_LEN);
}

// --------------------------------------------------------------------------
// Test implementation of the interface 'cipher'.
// --------------------------------------------------------------------------
void
test__encrypt__vector_1__encrypted_len_equals_16(void) {

    vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();

    vsc_buffer_t *out =
            vsc_buffer_new_with_capacity(vscf_aes256_gcm_encrypted_len(aes256_gcm, test_aes256_gcm_VECTOR_1_DATA.len));


    vscf_aes256_gcm_set_key(aes256_gcm, test_aes256_gcm_VECTOR_1_KEY);
    vscf_aes256_gcm_set_nonce(aes256_gcm, test_aes256_gcm_VECTOR_1_NONCE);

    vscf_status_t result = vscf_aes256_gcm_encrypt(aes256_gcm, test_aes256_gcm_VECTOR_1_DATA, out);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, result);


    TEST_ASSERT_EQUAL(16, vsc_buffer_len(out));

    vscf_aes256_gcm_destroy(&aes256_gcm);
    vsc_buffer_destroy(&out);
}

void
test__encrypt__vector_1__valid_encrypted_data(void) {

    vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();

    vsc_buffer_t *out =
            vsc_buffer_new_with_capacity(vscf_aes256_gcm_encrypted_len(aes256_gcm, test_aes256_gcm_VECTOR_1_DATA.len));


    vscf_aes256_gcm_set_key(aes256_gcm, test_aes256_gcm_VECTOR_1_KEY);
    vscf_aes256_gcm_set_nonce(aes256_gcm, test_aes256_gcm_VECTOR_1_NONCE);

    vscf_status_t result = vscf_aes256_gcm_encrypt(aes256_gcm, test_aes256_gcm_VECTOR_1_DATA, out);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, result);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_aes256_gcm_VECTOR_1_ENC_PLUS_AUTH_TAG, out);

    vscf_aes256_gcm_destroy(&aes256_gcm);
    vsc_buffer_destroy(&out);
}

void
test__decrypt__encrypted_vector_1__decrypted_len_equals_0(void) {

    vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(
            vscf_aes256_gcm_decrypted_len(aes256_gcm, test_aes256_gcm_VECTOR_1_ENC_PLUS_AUTH_TAG.len));


    vscf_aes256_gcm_set_key(aes256_gcm, test_aes256_gcm_VECTOR_1_KEY);
    vscf_aes256_gcm_set_nonce(aes256_gcm, test_aes256_gcm_VECTOR_1_NONCE);

    vscf_status_t result = vscf_aes256_gcm_decrypt(aes256_gcm, test_aes256_gcm_VECTOR_1_ENC_PLUS_AUTH_TAG, out);


    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, result);
    TEST_ASSERT_EQUAL(0, vsc_buffer_len(out));

    vscf_aes256_gcm_destroy(&aes256_gcm);
    vsc_buffer_destroy(&out);
}

// --------------------------------------------------------------------------
// Test implementation of the interface 'cipher auth'.
// --------------------------------------------------------------------------
void
test__AUTH_TAG_LEN__always__equals_16(void) {
    TEST_ASSERT_EQUAL(16, vscf_aes256_gcm_AUTH_TAG_LEN);
}

void
test__auth_encrypt__vector_2__encrypted_len_equals_0(void) {

    vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();

    vsc_buffer_t *enc = vsc_buffer_new_with_capacity(
            vscf_aes256_gcm_auth_encrypted_len(aes256_gcm, test_aes256_gcm_VECTOR_2_DATA.len));

    vsc_buffer_t *tag = vsc_buffer_new_with_capacity(vscf_aes256_gcm_AUTH_TAG_LEN);

    vscf_aes256_gcm_set_key(aes256_gcm, test_aes256_gcm_VECTOR_2_KEY);
    vscf_aes256_gcm_set_nonce(aes256_gcm, test_aes256_gcm_VECTOR_2_NONCE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_aes256_gcm_auth_encrypt(aes256_gcm, test_aes256_gcm_VECTOR_2_DATA,
                                                   test_aes256_gcm_VECTOR_2_ADD, enc, tag));

    TEST_ASSERT_EQUAL(0, vsc_buffer_len(enc));

    vsc_buffer_destroy(&enc);
    vsc_buffer_destroy(&tag);
    vscf_aes256_gcm_destroy(&aes256_gcm);
}

void
test__auth_encrypt__vector_2__valid_auth_tag(void) {

    vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();

    vsc_buffer_t *enc = vsc_buffer_new_with_capacity(
            vscf_aes256_gcm_auth_encrypted_len(aes256_gcm, test_aes256_gcm_VECTOR_2_DATA.len));

    vsc_buffer_t *tag = vsc_buffer_new_with_capacity(vscf_aes256_gcm_AUTH_TAG_LEN);

    vscf_aes256_gcm_set_key(aes256_gcm, test_aes256_gcm_VECTOR_2_KEY);
    vscf_aes256_gcm_set_nonce(aes256_gcm, test_aes256_gcm_VECTOR_2_NONCE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_aes256_gcm_auth_encrypt(aes256_gcm, test_aes256_gcm_VECTOR_2_DATA,
                                                   test_aes256_gcm_VECTOR_2_ADD, enc, tag));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_aes256_gcm_VECTOR_2_AUTH_TAG, tag);

    vsc_buffer_destroy(&enc);
    vsc_buffer_destroy(&tag);
    vscf_aes256_gcm_destroy(&aes256_gcm);
}

void
test__auth_decrypt__encrypted_vector_2__decrypted_len_equals_0(void) {

    vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();

    vsc_buffer_t *dec = vsc_buffer_new_with_capacity(
            vscf_aes256_gcm_auth_decrypted_len(aes256_gcm, test_aes256_gcm_VECTOR_2_ENC.len));

    vscf_aes256_gcm_set_key(aes256_gcm, test_aes256_gcm_VECTOR_2_KEY);
    vscf_aes256_gcm_set_nonce(aes256_gcm, test_aes256_gcm_VECTOR_2_NONCE);

    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_aes256_gcm_auth_decrypt(aes256_gcm, test_aes256_gcm_VECTOR_2_ENC,
                                         test_aes256_gcm_VECTOR_2_ADD, test_aes256_gcm_VECTOR_2_AUTH_TAG, dec));


    TEST_ASSERT_EQUAL(0, vsc_buffer_len(dec));

    vsc_buffer_destroy(&dec);
    vscf_aes256_gcm_destroy(&aes256_gcm);
}

void
test__auth_decrypt__encrypted_vector_2__valid_auth_tag(void) {

    vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();

    vsc_buffer_t *dec = vsc_buffer_new_with_capacity(
            vscf_aes256_gcm_auth_decrypted_len(aes256_gcm, test_aes256_gcm_VECTOR_2_DATA.len));

    vscf_aes256_gcm_set_key(aes256_gcm, test_aes256_gcm_VECTOR_2_KEY);
    vscf_aes256_gcm_set_nonce(aes256_gcm, test_aes256_gcm_VECTOR_2_NONCE);

    vscf_status_t result = vscf_aes256_gcm_auth_decrypt(aes256_gcm, test_aes256_gcm_VECTOR_2_ENC,
            test_aes256_gcm_VECTOR_2_ADD, test_aes256_gcm_VECTOR_2_AUTH_TAG, dec);


    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, result);

    vsc_buffer_destroy(&dec);
    vscf_aes256_gcm_destroy(&aes256_gcm);
}

void
test__auth_encrypt__vector_3__encrypted_len_equals_128(void) {

    vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();

    vsc_buffer_t *enc = vsc_buffer_new_with_capacity(
            vscf_aes256_gcm_auth_encrypted_len(aes256_gcm, test_aes256_gcm_VECTOR_3_DATA.len));

    vsc_buffer_t *tag = vsc_buffer_new_with_capacity(vscf_aes256_gcm_AUTH_TAG_LEN);

    vscf_aes256_gcm_set_key(aes256_gcm, test_aes256_gcm_VECTOR_3_KEY);
    vscf_aes256_gcm_set_nonce(aes256_gcm, test_aes256_gcm_VECTOR_3_NONCE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_aes256_gcm_auth_encrypt(aes256_gcm, test_aes256_gcm_VECTOR_3_DATA,
                                                   test_aes256_gcm_VECTOR_3_ADD, enc, tag));


    TEST_ASSERT_EQUAL(128, vsc_buffer_len(enc));

    vsc_buffer_destroy(&enc);
    vsc_buffer_destroy(&tag);
    vscf_aes256_gcm_destroy(&aes256_gcm);
}

void
test__auth_encrypt__vector_3__equals_encrypted_vector_3(void) {

    vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();

    vsc_buffer_t *enc = vsc_buffer_new_with_capacity(
            vscf_aes256_gcm_auth_encrypted_len(aes256_gcm, test_aes256_gcm_VECTOR_3_DATA.len));

    vsc_buffer_t *tag = vsc_buffer_new_with_capacity(vscf_aes256_gcm_AUTH_TAG_LEN);

    vscf_aes256_gcm_set_key(aes256_gcm, test_aes256_gcm_VECTOR_3_KEY);
    vscf_aes256_gcm_set_nonce(aes256_gcm, test_aes256_gcm_VECTOR_3_NONCE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_aes256_gcm_auth_encrypt(aes256_gcm, test_aes256_gcm_VECTOR_3_DATA,
                                                   test_aes256_gcm_VECTOR_3_ADD, enc, tag));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_aes256_gcm_VECTOR_3_ENC, enc);

    vsc_buffer_destroy(&enc);
    vsc_buffer_destroy(&tag);
    vscf_aes256_gcm_destroy(&aes256_gcm);
}

void
test__auth_encrypt__vector_3__valid_auth_tag(void) {

    vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();

    vsc_buffer_t *enc = vsc_buffer_new_with_capacity(
            vscf_aes256_gcm_auth_encrypted_len(aes256_gcm, test_aes256_gcm_VECTOR_3_DATA.len));

    vsc_buffer_t *tag = vsc_buffer_new_with_capacity(vscf_aes256_gcm_AUTH_TAG_LEN);

    vscf_aes256_gcm_set_key(aes256_gcm, test_aes256_gcm_VECTOR_3_KEY);
    vscf_aes256_gcm_set_nonce(aes256_gcm, test_aes256_gcm_VECTOR_3_NONCE);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_aes256_gcm_auth_encrypt(aes256_gcm, test_aes256_gcm_VECTOR_3_DATA,
                                                   test_aes256_gcm_VECTOR_3_ADD, enc, tag));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_aes256_gcm_VECTOR_3_AUTH_TAG, tag);

    vsc_buffer_destroy(&enc);
    vsc_buffer_destroy(&tag);
    vscf_aes256_gcm_destroy(&aes256_gcm);
}


void
test__auth_decrypt__encrypted_vector_3__decrypted_len_equals_128(void) {

    vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();

    vsc_buffer_t *dec = vsc_buffer_new_with_capacity(
            vscf_aes256_gcm_auth_decrypted_len(aes256_gcm, test_aes256_gcm_VECTOR_3_DATA.len));

    vscf_aes256_gcm_set_key(aes256_gcm, test_aes256_gcm_VECTOR_3_KEY);
    vscf_aes256_gcm_set_nonce(aes256_gcm, test_aes256_gcm_VECTOR_3_NONCE);

    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_aes256_gcm_auth_decrypt(aes256_gcm, test_aes256_gcm_VECTOR_3_ENC,
                                         test_aes256_gcm_VECTOR_3_ADD, test_aes256_gcm_VECTOR_3_AUTH_TAG, dec));


    TEST_ASSERT_EQUAL(128, vsc_buffer_len(dec));

    vsc_buffer_destroy(&dec);
    vscf_aes256_gcm_destroy(&aes256_gcm);
}

void
test__auth_decrypt__encrypted_vector_3__valid_auth_tag(void) {

    vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();

    vsc_buffer_t *dec = vsc_buffer_new_with_capacity(
            vscf_aes256_gcm_auth_decrypted_len(aes256_gcm, test_aes256_gcm_VECTOR_3_DATA.len));

    vscf_aes256_gcm_set_key(aes256_gcm, test_aes256_gcm_VECTOR_3_KEY);
    vscf_aes256_gcm_set_nonce(aes256_gcm, test_aes256_gcm_VECTOR_3_NONCE);

    vscf_status_t result = vscf_aes256_gcm_auth_decrypt(aes256_gcm, test_aes256_gcm_VECTOR_3_ENC,
            test_aes256_gcm_VECTOR_3_ADD, test_aes256_gcm_VECTOR_3_AUTH_TAG, dec);


    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, result);

    vsc_buffer_destroy(&dec);
    vscf_aes256_gcm_destroy(&aes256_gcm);
}

void
test__auth_decrypt__encrypted_vector_3__equals_vector_3(void) {

    vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();

    vsc_buffer_t *dec = vsc_buffer_new_with_capacity(
            vscf_aes256_gcm_auth_decrypted_len(aes256_gcm, test_aes256_gcm_VECTOR_3_DATA.len));

    vscf_aes256_gcm_set_key(aes256_gcm, test_aes256_gcm_VECTOR_3_KEY);
    vscf_aes256_gcm_set_nonce(aes256_gcm, test_aes256_gcm_VECTOR_3_NONCE);

    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_aes256_gcm_auth_decrypt(aes256_gcm, test_aes256_gcm_VECTOR_3_ENC,
                                         test_aes256_gcm_VECTOR_3_ADD, test_aes256_gcm_VECTOR_3_AUTH_TAG, dec));


    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_aes256_gcm_VECTOR_3_DATA, dec);

    vsc_buffer_destroy(&dec);
    vscf_aes256_gcm_destroy(&aes256_gcm);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__NONCE_LEN__always__equals_12);
    RUN_TEST(test__KEY_LEN__always__equals_32);
    RUN_TEST(test__KEY_BITLEN__always__equals_256);
    RUN_TEST(test__BLOCK_LEN__always__equals_16);
    RUN_TEST(test__AUTH_TAG_LEN__always__equals_16);

    RUN_TEST(test__encrypt__vector_1__encrypted_len_equals_16);
    RUN_TEST(test__encrypt__vector_1__valid_encrypted_data);
    RUN_TEST(test__decrypt__encrypted_vector_1__decrypted_len_equals_0);

    RUN_TEST(test__auth_encrypt__vector_2__encrypted_len_equals_0);
    RUN_TEST(test__auth_encrypt__vector_2__valid_auth_tag);
    RUN_TEST(test__auth_decrypt__encrypted_vector_2__decrypted_len_equals_0);
    RUN_TEST(test__auth_decrypt__encrypted_vector_2__valid_auth_tag);

    RUN_TEST(test__auth_encrypt__vector_3__encrypted_len_equals_128);
    RUN_TEST(test__auth_encrypt__vector_3__equals_encrypted_vector_3);
    RUN_TEST(test__auth_encrypt__vector_3__valid_auth_tag);
    RUN_TEST(test__auth_decrypt__encrypted_vector_3__decrypted_len_equals_128);
    RUN_TEST(test__auth_decrypt__encrypted_vector_3__valid_auth_tag);
    RUN_TEST(test__auth_decrypt__encrypted_vector_3__equals_vector_3);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
