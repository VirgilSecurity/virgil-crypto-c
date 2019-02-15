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

// --------------------------------------------------------------------------
//  Should have it to prevent linkage errors in MSVC.
// --------------------------------------------------------------------------
// clang-format off
void setUp(void) { }
void tearDown(void) { }
void suiteSetUp(void) { }
int suiteTearDown(int num_failures) { return num_failures; }
// clang-format on

#define TEST_DEPENDENCIES_AVAILABLE VSCR_RATCHET
#if TEST_DEPENDENCIES_AVAILABLE

#include "virgil/crypto/ratchet/private/vscr_ratchet_cipher.h"
#include "virgil/crypto/foundation/vscf_ctr_drbg.h"
#include "virgil/crypto/ratchet/private/vscr_ratchet_common_hidden.h"
#include "test_data_ratchet_cipher.h"

void
test__encrypt__fixed_data__should_match(void) {
    vscr_ratchet_cipher_t *cipher = vscr_ratchet_cipher_new();

    size_t len = vscr_ratchet_cipher_encrypt_len(cipher, test_data_ratchet_cipher_plain_text.len);

    TEST_ASSERT_EQUAL(test_data_ratchet_cipher_cipher_text_len, len);

    vsc_buffer_t *cipher_text = vsc_buffer_new_with_capacity(len);

    TEST_ASSERT_EQUAL(vscr_SUCCESS,
            vscr_ratchet_cipher_encrypt(cipher, test_data_ratchet_cipher_key, test_data_ratchet_cipher_plain_text, cipher_text));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_ratchet_cipher_cipher_text, cipher_text);

    vscr_ratchet_cipher_destroy(&cipher);
    vsc_buffer_destroy(&cipher_text);
}

void
test__encrypt_decrypt__rnd_data__should_match(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng);

    for (size_t i = 0; i < 100; i++) {
        vsc_buffer_t *key = vsc_buffer_new_with_capacity(vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH);

        TEST_ASSERT_EQUAL(vscf_SUCCESS, vscf_ctr_drbg_random(rng, vscr_ratchet_common_hidden_RATCHET_KEY_LENGTH, key));

        uint16_t size;
        vsc_buffer_t *size_buf = vsc_buffer_new();
        vsc_buffer_use(size_buf, (byte *)&size, sizeof(size));

        TEST_ASSERT_EQUAL(vscf_SUCCESS, vscf_ctr_drbg_random(rng, sizeof(size), size_buf));

        // Do not exceed maximum value
        size /= UINT16_MAX / 64;
        if (size == 0)
            size = UINT16_MAX / 64;

        vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(size);
        TEST_ASSERT_EQUAL(vscf_SUCCESS, vscf_ctr_drbg_random(rng, size, plain_text));

        vscr_ratchet_cipher_t *cipher = vscr_ratchet_cipher_new();

        size_t len1 = vscr_ratchet_cipher_encrypt_len(cipher, vsc_buffer_len(plain_text));

        vsc_buffer_t *cipher_text = vsc_buffer_new_with_capacity(len1);

        TEST_ASSERT_EQUAL(vscr_SUCCESS,
                vscr_ratchet_cipher_encrypt(cipher, vsc_buffer_data(key), vsc_buffer_data(plain_text), cipher_text));

        size_t len2 = vscr_ratchet_cipher_decrypt_len(cipher, vsc_buffer_len(cipher_text));

        vsc_buffer_t *plain_text2 = vsc_buffer_new_with_capacity(len2);

        TEST_ASSERT_EQUAL(vscr_SUCCESS,
                vscr_ratchet_cipher_decrypt(cipher, vsc_buffer_data(key), vsc_buffer_data(cipher_text), plain_text2));

        TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(plain_text), plain_text2);

        vsc_buffer_destroy(&key);
        vscr_ratchet_cipher_destroy(&cipher);
        vsc_buffer_destroy(&plain_text);
        vsc_buffer_destroy(&plain_text2);
        vsc_buffer_destroy(&cipher_text);
        vsc_buffer_destroy(&size_buf);
    }

    vscf_ctr_drbg_destroy(&rng);
}

#endif

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__encrypt__fixed_data__should_match);
    RUN_TEST(test__encrypt_decrypt__rnd_data__should_match);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
