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

#define TEST_DEPENDENCIES_AVAILABLE (VSCF_POST_QUANTUM && ROUND5_LIBRARY)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_round5.h"
#include "vscf_fake_random.h"
#include "vscf_simple_alg_info.h"
#include "vscf_private_key.h"

#include "test_data_round5.h"

void
test__generate_key__success(void) {
    vscf_round5_t *round5 = vscf_round5_new();

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_round5_generate_key(round5, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_destroy(&private_key);
    vscf_round5_destroy(&round5);
}

void
test__encrypt__success(void) {
    //
    //  Configure alg.
    //
    vscf_round5_t *round5 = vscf_round5_new();

    //
    //  Import public key.
    //
    vscf_impl_t *alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ROUND5_ND_5PKE_5D));
    vscf_raw_public_key_t *raw_public_key =
            vscf_raw_public_key_new_with_data(test_data_round5_CCA_PKE_PUBLIC_KEY, &alg_info);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *public_key = vscf_round5_import_public_key(round5, raw_public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Encrypt.
    //
    TEST_ASSERT_TRUE(vscf_round5_can_encrypt(round5, public_key, test_data_round5_CCA_PKE_MESSAGE.len));

    const size_t enc_len = vscf_round5_encrypted_len(round5, public_key, test_data_round5_CCA_PKE_MESSAGE.len);
    TEST_ASSERT_GREATER_THAN(0, enc_len);

    vsc_buffer_t *enc = vsc_buffer_new_with_capacity(enc_len);
    const vscf_status_t status = vscf_round5_encrypt(round5, public_key, test_data_round5_CCA_PKE_MESSAGE, enc);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vsc_buffer_destroy(&enc);
    vscf_impl_destroy(&public_key);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_round5_destroy(&round5);
}

void
test__decrypt__success(void) {

    //
    //  Configure alg.
    //
    vscf_round5_t *round5 = vscf_round5_new();

    //
    //  Import private key.
    //
    vscf_impl_t *alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ROUND5_ND_5PKE_5D));
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_data_round5_CCA_PKE_PRIVATE_KEY, &alg_info);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_round5_import_private_key(round5, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Decrypt.
    //
    TEST_ASSERT_TRUE(vscf_round5_can_decrypt(round5, private_key, test_data_round5_CCA_PKE_ENC_MESSAGE.len));

    const size_t msg_len = vscf_round5_decrypted_len(round5, private_key, test_data_round5_CCA_PKE_ENC_MESSAGE.len);

    vsc_buffer_t *msg = vsc_buffer_new_with_capacity(msg_len);
    const vscf_status_t status = vscf_round5_decrypt(round5, private_key, test_data_round5_CCA_PKE_ENC_MESSAGE, msg);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vsc_buffer_destroy(&msg);
    vscf_impl_destroy(&private_key);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_round5_destroy(&round5);
}

void
test__export_public_key__from_generated_key__valid_alg_and_key_length(void) {
    //
    //  Configure alg.
    //
    vscf_round5_t *round5 = vscf_round5_new();

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Generate key.
    //
    vscf_impl_t *private_key = vscf_round5_generate_key(round5, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Export key.
    //
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    vscf_raw_public_key_t *raw_public_key = vscf_round5_export_public_key(round5, public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    // Check.
    //
    const vscf_alg_id_t alg_id = vscf_raw_public_key_alg_id(raw_public_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_ROUND5_ND_5PKE_5D, alg_id);
    TEST_ASSERT_EQUAL(978, vscf_raw_public_key_data(raw_public_key).len);

    //
    // Cleanup.
    //
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_round5_destroy(&round5);
}

void
test__export_private_key__from_generated_key__valid_alg_and_key_length(void) {
    //
    //  Configure alg.
    //
    vscf_round5_t *round5 = vscf_round5_new();

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Generate key.
    //
    vscf_impl_t *private_key = vscf_round5_generate_key(round5, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Export key.
    //
    vscf_raw_private_key_t *raw_private_key = vscf_round5_export_private_key(round5, private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    // Check.
    //
    const vscf_alg_id_t alg_id = vscf_raw_private_key_alg_id(raw_private_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_ROUND5_ND_5PKE_5D, alg_id);
    TEST_ASSERT_EQUAL(1042, vscf_raw_private_key_data(raw_private_key).len);

    //
    // Cleanup.
    //
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_impl_destroy(&private_key);
    vscf_round5_destroy(&round5);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__generate_key__success);
    RUN_TEST(test__encrypt__success);
    RUN_TEST(test__decrypt__success);
    RUN_TEST(test__export_public_key__from_generated_key__valid_alg_and_key_length);
    RUN_TEST(test__export_private_key__from_generated_key__valid_alg_and_key_length);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
