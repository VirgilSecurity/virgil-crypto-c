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


#define UNITY_BEGIN() UnityBegin(__FILENAME__)

#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <virgil/crypto/foundation/vscf_fake_random.h>
#include <test_data_phe_cipher.h>
#include "unity.h"
#include "test_utils.h"


#define TEST_DEPENDENCIES_AVAILABLE VSCE_PHE_CIPHER
#if TEST_DEPENDENCIES_AVAILABLE

#include "vsce_phe_cipher.h"

// --------------------------------------------------------------------------
//  Should have it to prevent linkage errors in MSVC.
// --------------------------------------------------------------------------
// clang-format off
void setUp(void) { }
void tearDown(void) { }
void suiteSetUp(void) { }
int suiteTearDown(int num_failures) { return num_failures; }
// clang-format on


// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------
void
test__encrypt_decrypt__fixed_data__should_match(void) {
    vsce_phe_cipher_t *cipher = vsce_phe_cipher_new();

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_phe_cipher_rnd);

    vsce_phe_cipher_take_random(cipher, vscf_fake_random_impl(fake_random));

    TEST_ASSERT_EQUAL(
            test_phe_cipher_cipher_text_capacity, vsce_phe_cipher_encrypt_len(cipher, test_phe_cipher_plain_text.len));

    vsc_buffer_t *cipher_text = vsc_buffer_new_with_capacity(test_phe_cipher_cipher_text_capacity);

    TEST_ASSERT_EQUAL(vsce_SUCCESS,
            vsce_phe_cipher_encrypt(cipher, test_phe_cipher_plain_text, test_phe_cipher_account_key, cipher_text));

    TEST_ASSERT_EQUAL(test_phe_cipher_cipher_text.len, vsc_buffer_len(cipher_text));
    TEST_ASSERT_EQUAL_MEMORY(
            test_phe_cipher_cipher_text.bytes, vsc_buffer_bytes(cipher_text), test_phe_cipher_cipher_text.len);

    vsce_phe_cipher_destroy(&cipher);
    vsc_buffer_destroy(&cipher_text);
}

void
test__encrypt_decrypt__random_data__should_match(void) {
    vsce_phe_cipher_t *cipher1, *cipher2;

    cipher1 = vsce_phe_cipher_new();
    vsce_phe_cipher_setup_defaults(cipher1);

    cipher2 = vsce_phe_cipher_new();
    vsce_phe_cipher_setup_defaults(cipher2);

    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng);

    for (int i = 0; i < 100; i++) {
        vsc_buffer_t *account_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);

        TEST_ASSERT_EQUAL(vscf_SUCCESS, vscf_ctr_drbg_random(rng, vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH, account_key));

        byte len;

        vsc_buffer_t *len_buf = vsc_buffer_new();
        vsc_buffer_use(len_buf, &len, sizeof(len));

        TEST_ASSERT_EQUAL(vscf_SUCCESS, vscf_ctr_drbg_random(rng, sizeof(len), len_buf));

        if (len == 0) {
            len = 10;
        }

        vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(len);

        TEST_ASSERT_EQUAL(vscf_SUCCESS, vscf_ctr_drbg_random(rng, len, plain_text));

        vsc_buffer_t *cipher_text = vsc_buffer_new_with_capacity(vsce_phe_cipher_encrypt_len(cipher1, len));

        TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_cipher_encrypt(cipher1, vsc_buffer_data(plain_text),
                                                vsc_buffer_data(account_key), cipher_text));

        vsc_buffer_t *plain_text2 =
                vsc_buffer_new_with_capacity(vsce_phe_cipher_decrypt_len(cipher2, vsc_buffer_len(cipher_text)));

        TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_cipher_decrypt(cipher2, vsc_buffer_data(cipher_text),
                                                vsc_buffer_data(account_key), plain_text2));

        TEST_ASSERT_EQUAL(vsc_buffer_len(plain_text), vsc_buffer_len(plain_text2));

        TEST_ASSERT_EQUAL_MEMORY(
                vsc_buffer_bytes(plain_text), vsc_buffer_bytes(plain_text2), vsc_buffer_len(plain_text));

        vsc_buffer_destroy(&account_key);
        vsc_buffer_destroy(&len_buf);
        vsc_buffer_destroy(&plain_text);
        vsc_buffer_destroy(&cipher_text);
        vsc_buffer_destroy(&plain_text2);
    }

    vscf_ctr_drbg_destroy(&rng);

    vsce_phe_cipher_destroy(&cipher1);
    vsce_phe_cipher_destroy(&cipher2);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__encrypt_decrypt__fixed_data__should_match);
    RUN_TEST(test__encrypt_decrypt__random_data__should_match);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
