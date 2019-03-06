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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_CIPHER && VSCF_AES256_CBC)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_memory.h"
#include "vscf_cipher.h"
#include "vscf_aes256_cbc.h"

#include "test_data_aes256_cbc.h"


// --------------------------------------------------------------------------
//  Should have it to prevent linkage erros in MSVC.
// --------------------------------------------------------------------------
// clang-format off
void setUp(void) { }
void tearDown(void) { }
void suiteSetUp(void) { }
int suiteTearDown(int num_failures) { return num_failures; }
// clang-format on


// --------------------------------------------------------------------------
// Test implementation of the interface 'cipher info'.
// --------------------------------------------------------------------------
void
test__NONCE_LEN__always__equals_16(void) {
    TEST_ASSERT_EQUAL(16, vscf_aes256_cbc_NONCE_LEN);
}

void
test__KEY_LEN__always__equals_32(void) {
    TEST_ASSERT_EQUAL(32, vscf_aes256_cbc_KEY_LEN);
}

void
test__KEY_BITLEN__always__equals_256(void) {
    TEST_ASSERT_EQUAL(256, vscf_aes256_cbc_KEY_BITLEN);
}

void
test__BLOCK_LEN__always__equals_16(void) {
    TEST_ASSERT_EQUAL(16, vscf_aes256_cbc_BLOCK_LEN);
}

// --------------------------------------------------------------------------
// Test implementation of the interface 'cipher'.
// --------------------------------------------------------------------------
void
test__encrypt__data_of_length_16_and_pkcs7_padding__encrypted_len_equals_32(void) {

    vscf_aes256_cbc_t *aes256_cbc = vscf_aes256_cbc_new();

    vsc_buffer_t *out =
            vsc_buffer_new_with_capacity(vscf_aes256_cbc_encrypted_len(aes256_cbc, test_aes256_cbc_ONE_BLOCK_DATA.len));

    vscf_aes256_cbc_set_key(aes256_cbc, test_aes256_cbc_KEY);
    vscf_aes256_cbc_set_nonce(aes256_cbc, test_aes256_cbc_IV);

    vscf_status_t result = vscf_aes256_cbc_encrypt(aes256_cbc, test_aes256_cbc_ONE_BLOCK_DATA, out);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, result);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_aes256_cbc_ONE_BLOCK_ENCRYPTED_DATA, out);

    vsc_buffer_destroy(&out);
    vscf_aes256_cbc_destroy(&aes256_cbc);
}

void
test__encrypt__data_of_length_64_and_pkcs7_padding__encrypted_len_equals_80(void) {

    vscf_aes256_cbc_t *aes256_cbc = vscf_aes256_cbc_new();

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(
            vscf_aes256_cbc_encrypted_len(aes256_cbc, test_aes256_cbc_FOUR_BLOCK_DATA.len));

    vscf_aes256_cbc_set_key(aes256_cbc, test_aes256_cbc_KEY);
    vscf_aes256_cbc_set_nonce(aes256_cbc, test_aes256_cbc_IV);

    vscf_status_t result = vscf_aes256_cbc_encrypt(aes256_cbc, test_aes256_cbc_FOUR_BLOCK_DATA, out);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, result);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_aes256_cbc_FOUR_BLOCK_ENCRYPTED_DATA, out);

    vsc_buffer_destroy(&out);
    vscf_aes256_cbc_destroy(&aes256_cbc);
}

void
test__decrypt__encrypted_data_of_length_32_and_pkcs7_padding__decrypted_len_equals_16(void) {

    vscf_aes256_cbc_t *aes256_cbc = vscf_aes256_cbc_new();

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(
            vscf_aes256_cbc_decrypted_len(aes256_cbc, test_aes256_cbc_ONE_BLOCK_ENCRYPTED_DATA.len));

    vscf_aes256_cbc_set_key(aes256_cbc, test_aes256_cbc_KEY);
    vscf_aes256_cbc_set_nonce(aes256_cbc, test_aes256_cbc_IV);

    vscf_status_t result = vscf_aes256_cbc_decrypt(aes256_cbc, test_aes256_cbc_ONE_BLOCK_ENCRYPTED_DATA, out);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, result);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_aes256_cbc_ONE_BLOCK_DATA, out);

    vsc_buffer_destroy(&out);
    vscf_aes256_cbc_destroy(&aes256_cbc);
}

void
test__decrypt__encrypted_data_of_length_80_and_pkcs7_padding__decrypted_len_equals_32(void) {

    vscf_aes256_cbc_t *aes256_cbc = vscf_aes256_cbc_new();

    vsc_buffer_t *out = vsc_buffer_new_with_capacity(
            vscf_aes256_cbc_decrypted_len(aes256_cbc, test_aes256_cbc_FOUR_BLOCK_ENCRYPTED_DATA.len));

    vscf_aes256_cbc_set_key(aes256_cbc, test_aes256_cbc_KEY);
    vscf_aes256_cbc_set_nonce(aes256_cbc, test_aes256_cbc_IV);

    vscf_status_t result = vscf_aes256_cbc_decrypt(aes256_cbc, test_aes256_cbc_FOUR_BLOCK_ENCRYPTED_DATA, out);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, result);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_aes256_cbc_FOUR_BLOCK_DATA, out);

    vsc_buffer_destroy(&out);
    vscf_aes256_cbc_destroy(&aes256_cbc);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__NONCE_LEN__always__equals_16);
    RUN_TEST(test__KEY_LEN__always__equals_32);
    RUN_TEST(test__KEY_BITLEN__always__equals_256);
    RUN_TEST(test__BLOCK_LEN__always__equals_16);

    RUN_TEST(test__encrypt__data_of_length_16_and_pkcs7_padding__encrypted_len_equals_32);
    RUN_TEST(test__encrypt__data_of_length_64_and_pkcs7_padding__encrypted_len_equals_80);
    RUN_TEST(test__decrypt__encrypted_data_of_length_32_and_pkcs7_padding__decrypted_len_equals_16);
    RUN_TEST(test__decrypt__encrypted_data_of_length_80_and_pkcs7_padding__decrypted_len_equals_32);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
