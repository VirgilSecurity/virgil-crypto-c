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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_PADDING_CIPHER && VSCF_AES256_GCM)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_memory.h"
#include "vscf_padding_cipher.h"
#include "vscf_aes256_gcm.h"
#include "vscf_fake_random.h"

#include "test_data_padding_cipher.h"

// --------------------------------------------------------------------------
//  Common helpers.
// --------------------------------------------------------------------------
static void
inner_test__encrypt__match_given(vscf_padding_cipher_t *cipher, vsc_data_t plaintext, vsc_data_t ciphertext) {
    //
    //  Encrypt.
    //
    const size_t out_len = vscf_padding_cipher_encrypted_len(cipher, plaintext.len);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(out_len);

    const vscf_status_t status = vscf_padding_cipher_encrypt(cipher, plaintext, out);

    //
    // Check.
    //
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(ciphertext, out);

    //
    //  Cleanup.
    //
    vsc_buffer_destroy(&out);
}

static void
inner_test__decrypt__match_given(vscf_padding_cipher_t *cipher, vsc_data_t ciphertext, vsc_data_t plaintext) {
    //
    //  Decrypt.
    //
    const size_t out_len = vscf_padding_cipher_decrypted_len(cipher, ciphertext.len);
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(out_len);

    const vscf_status_t status = vscf_padding_cipher_decrypt(cipher, ciphertext, out);

    //
    // Check.
    //
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(plaintext, out);

    //
    //  Cleanup.
    //
    vsc_buffer_destroy(&out);
}

// --------------------------------------------------------------------------
//  Suite 1: AES256-GCM, frame 160.
// --------------------------------------------------------------------------
static void
inner_test__encrypt__with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_given(
        vsc_data_t plaintext, vsc_data_t ciphertext) {

    //
    // Configure algs.
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);

    vscf_padding_cipher_t *cipher = vscf_padding_cipher_new();
    vscf_padding_cipher_take_cipher(cipher, vscf_aes256_gcm_impl(vscf_aes256_gcm_new()));
    vscf_padding_cipher_take_random(cipher, vscf_fake_random_impl(fake_random));

    vscf_padding_cipher_set_padding_frame(cipher, 160);
    vscf_padding_cipher_set_nonce(cipher, test_data_padding_cipher_SUITE1_AES256_NONCE);
    vscf_padding_cipher_set_key(cipher, test_data_padding_cipher_SUITE1_AES256_KEY);

    //
    // Check.
    //
    inner_test__encrypt__match_given(cipher, plaintext, ciphertext);

    //
    // Cleanup.
    //
    vscf_padding_cipher_destroy(&cipher);
}

static void
inner_test__decrypt__with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_given(
        vsc_data_t ciphertext, vsc_data_t plaintext) {

    //
    // Configure algs.
    //
    vscf_padding_cipher_t *cipher = vscf_padding_cipher_new();
    vscf_padding_cipher_take_cipher(cipher, vscf_aes256_gcm_impl(vscf_aes256_gcm_new()));

    vscf_padding_cipher_set_padding_frame(cipher, 160);
    vscf_padding_cipher_set_nonce(cipher, test_data_padding_cipher_SUITE1_AES256_NONCE);
    vscf_padding_cipher_set_key(cipher, test_data_padding_cipher_SUITE1_AES256_KEY);

    //
    // Check.
    //
    inner_test__decrypt__match_given(cipher, ciphertext, plaintext);

    //
    // Cleanup.
    //
    vscf_padding_cipher_destroy(&cipher);
}

void
test__encrypt__155_zero_bytes_with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_expected(void) {

    inner_test__encrypt__with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_given(
            test_data_padding_cipher_SUITE1_PLAINTEXT_155_ZERO_BYTES,
            test_data_padding_cipher_SUITE1_ENCRYPTED_155_ZERO_BYTES);
}

void
test__decrypt__155_zero_bytes_with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_expected(void) {

    inner_test__decrypt__with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_given(
            test_data_padding_cipher_SUITE1_ENCRYPTED_155_ZERO_BYTES,
            test_data_padding_cipher_SUITE1_PLAINTEXT_155_ZERO_BYTES);
}

void
test__encrypt__156_zero_bytes_with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_expected(void) {

    inner_test__encrypt__with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_given(
            test_data_padding_cipher_SUITE1_PLAINTEXT_156_ZERO_BYTES,
            test_data_padding_cipher_SUITE1_ENCRYPTED_156_ZERO_BYTES);
}

void
test__decrypt__156_zero_bytes_with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_expected(void) {

    inner_test__decrypt__with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_given(
            test_data_padding_cipher_SUITE1_ENCRYPTED_156_ZERO_BYTES,
            test_data_padding_cipher_SUITE1_PLAINTEXT_156_ZERO_BYTES);
}

void
test__encrypt__512_zero_bytes_with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_expected(void) {

    inner_test__encrypt__with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_given(
            test_data_padding_cipher_SUITE1_PLAINTEXT_512_ZERO_BYTES,
            test_data_padding_cipher_SUITE1_ENCRYPTED_512_ZERO_BYTES);
}

void
test__decrypt__512_zero_bytes_with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_expected(void) {

    inner_test__decrypt__with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_given(
            test_data_padding_cipher_SUITE1_ENCRYPTED_512_ZERO_BYTES,
            test_data_padding_cipher_SUITE1_PLAINTEXT_512_ZERO_BYTES);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__encrypt__155_zero_bytes_with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_expected);
    RUN_TEST(test__decrypt__155_zero_bytes_with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_expected);
    RUN_TEST(test__encrypt__156_zero_bytes_with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_expected);
    RUN_TEST(test__decrypt__156_zero_bytes_with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_expected);
    RUN_TEST(test__encrypt__512_zero_bytes_with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_expected);
    RUN_TEST(test__decrypt__512_zero_bytes_with_aes256_gcm_and_padding_frame_160_with_AB_pad__match_expected);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
