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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_CHAINED_KEY_ALG && VSCF_CURVE25519 && VSCF_FAKE_RANDOM)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_chained_key_alg.h"
#include "vscf_chained_public_key.h"
#include "vscf_chained_private_key.h"
#include "vscf_key.h"
#include "vscf_private_key.h"
#include "vscf_simple_alg_info.h"
#include "vscf_chained_key_alg_info.h"
#include "vscf_fake_random.h"
#include "vscf_curve25519.h"
#include "vscf_key_provider.h"

#include "test_data_curve25519.h"
#include "test_data_ed25519.h"
#include "test_data_round5.h"
#include "test_data_falcon.h"
#include "test_data_chained_key.h"

// --------------------------------------------------------------------------
//  Helpers.
// --------------------------------------------------------------------------
static vscf_impl_t *
inner_import_raw_public_key(
        vsc_data_t public_key_data, vscf_alg_id_t l1_cipher_alg_id, vscf_alg_id_t l2_cipher_alg_id) {

    vscf_impl_t *l1_cipher_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(l1_cipher_alg_id));
    vscf_impl_t *l2_cipher_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(l2_cipher_alg_id));
    vscf_impl_t *alg_info = vscf_chained_key_alg_info_impl(vscf_chained_key_alg_info_new_with_infos_disown(
            vscf_alg_id_CHAINED_KEY, &l1_cipher_alg_info, &l2_cipher_alg_info));

    vscf_raw_public_key_t *raw_public_key = vscf_raw_public_key_new_with_data(public_key_data, &alg_info);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_chained_key_alg_t *key_alg = vscf_chained_key_alg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chained_key_alg_setup_defaults(key_alg));

    vscf_impl_t *public_key = vscf_chained_key_alg_import_public_key(key_alg, raw_public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(public_key);

    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_chained_key_alg_destroy(&key_alg);

    return public_key;
}

static vscf_impl_t *
inner_import_raw_private_key(
        vsc_data_t private_key_data, vscf_alg_id_t l1_cipher_alg_id, vscf_alg_id_t l2_cipher_alg_id) {

    vscf_impl_t *l1_cipher_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(l1_cipher_alg_id));
    vscf_impl_t *l2_cipher_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(l2_cipher_alg_id));
    vscf_impl_t *alg_info = vscf_chained_key_alg_info_impl(vscf_chained_key_alg_info_new_with_infos_disown(
            vscf_alg_id_CHAINED_KEY, &l1_cipher_alg_info, &l2_cipher_alg_info));

    vscf_raw_private_key_t *raw_private_key = vscf_raw_private_key_new_with_data(private_key_data, &alg_info);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_chained_key_alg_t *key_alg = vscf_chained_key_alg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chained_key_alg_setup_defaults(key_alg));

    vscf_impl_t *private_key = vscf_chained_key_alg_import_private_key(key_alg, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_chained_key_alg_destroy(&key_alg);

    return private_key;
}

// --------------------------------------------------------------------------
//  Make key.
// --------------------------------------------------------------------------
static void
inner_test__make_key__expect_status(vsc_data_t l1_key_data, vsc_data_t l2_key_data, vscf_status_t expected_status) {

    //
    //  Create algs.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_take_random(key_provider, vscf_fake_random_impl(fake_random));
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_chained_key_alg_t *key_alg = vscf_chained_key_alg_new();

    //
    //  Import inner keys.
    //
    vscf_impl_t *l1_key = vscf_key_provider_import_private_key(key_provider, l1_key_data, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_t *l2_key = vscf_key_provider_import_private_key(key_provider, l2_key_data, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Create key.
    //
    vscf_impl_t *private_key = vscf_chained_key_alg_make_key(key_alg, l1_key, l2_key, &error);
    TEST_ASSERT_EQUAL(expected_status, vscf_error_status(&error));

    if (expected_status == vscf_status_SUCCESS) {
        TEST_ASSERT_NOT_NULL(private_key);
        TEST_ASSERT_EQUAL(vscf_alg_id_CHAINED_KEY, vscf_key_alg_id(private_key));

        vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
        TEST_ASSERT_NOT_NULL(public_key);
        TEST_ASSERT_EQUAL(vscf_alg_id_CHAINED_KEY, vscf_key_alg_id(public_key));

        vscf_impl_destroy(&public_key);
        vscf_impl_destroy(&private_key);
    } else {
        TEST_ASSERT_NULL(private_key);
    }

    //
    //  Cleanup.
    //
    vscf_impl_destroy(&l1_key);
    vscf_impl_destroy(&l2_key);
    vscf_chained_key_alg_destroy(&key_alg);
    vscf_key_provider_destroy(&key_provider);
}

void
test__make_key__curve25519_curve25519__is_valid_alg(void) {
    inner_test__make_key__expect_status(
            test_curve25519_PRIVATE_KEY_PKCS8_DER, test_curve25519_PRIVATE_KEY_PKCS8_DER, vscf_status_SUCCESS);
}

void
test__make_key_ed25519_ed25519__is_valid_alg(void) {
    inner_test__make_key__expect_status(
            test_ed25519_PRIVATE_KEY_PKCS8_DER, test_ed25519_PRIVATE_KEY_PKCS8_DER, vscf_status_SUCCESS);
}

void
test__make_key__curve25519_round5__is_valid_alg(void) {
#if VSCF_POST_QUANTUM
    inner_test__make_key__expect_status(test_curve25519_PRIVATE_KEY_PKCS8_DER,
            test_data_round5_ND_5PKE_5D_PRIVATE_KEY_PKCS8_DER, vscf_status_SUCCESS);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM is disabled");
#endif
}

void
test__make_key__curve25519_falcon__returns_error_unsupported_algorithm(void) {
#if VSCF_POST_QUANTUM
    inner_test__make_key__expect_status(test_curve25519_PRIVATE_KEY_PKCS8_DER,
            test_data_falcon_PRIVATE_KEY_512_PKCS8_DER, vscf_status_ERROR_UNSUPPORTED_ALGORITHM);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM is disabled");
#endif
}


// --------------------------------------------------------------------------
//  Import / Export
// --------------------------------------------------------------------------
static void
inner_test__import_public_key_then_export__should_match(
        vscf_alg_id_t l1_cipher_alg_id, vscf_alg_id_t l2_cipher_alg_id, vsc_data_t public_key_data) {
    //
    //  Create dependencies first.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Prepare algs.
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);

    vscf_chained_key_alg_t *key_alg = vscf_chained_key_alg_new();
    vscf_chained_key_alg_take_random(key_alg, vscf_fake_random_impl(fake_random));

    //
    //  Import key.
    //
    vscf_impl_t *public_key = inner_import_raw_public_key(public_key_data, l1_cipher_alg_id, l2_cipher_alg_id);

    //
    //  Export key.
    //
    vscf_raw_public_key_t *exported_raw_public_key =
            vscf_chained_key_alg_export_public_key(key_alg, public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(exported_raw_public_key);

    //
    //  Compare.
    //
    TEST_ASSERT_EQUAL_DATA(public_key_data, vscf_raw_public_key_data(exported_raw_public_key));

    //
    //  Cleanup.
    //
    vscf_impl_destroy(&public_key);
    vscf_raw_public_key_destroy(&exported_raw_public_key);
    vscf_chained_key_alg_destroy(&key_alg);
}

static void
inner_test__import_private_key_then_export__should_match(
        vscf_alg_id_t l1_cipher_alg_id, vscf_alg_id_t l2_cipher_alg_id, vsc_data_t private_key_data) {
    //
    //  Create dependencies first.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Prepare algs.
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);

    vscf_chained_key_alg_t *key_alg = vscf_chained_key_alg_new();
    vscf_chained_key_alg_take_random(key_alg, vscf_fake_random_impl(fake_random));

    //
    //  Import key.
    //
    vscf_impl_t *private_key = inner_import_raw_private_key(private_key_data, l1_cipher_alg_id, l2_cipher_alg_id);

    //
    //  Export key.
    //
    vscf_raw_private_key_t *exported_raw_private_key =
            vscf_chained_key_alg_export_private_key(key_alg, private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(exported_raw_private_key);

    //
    //  Compare.
    //
    TEST_ASSERT_EQUAL_DATA(private_key_data, vscf_raw_private_key_data(exported_raw_private_key));

    //
    //  Cleanup.
    //
    vscf_impl_destroy(&private_key);
    vscf_raw_private_key_destroy(&exported_raw_private_key);
    vscf_chained_key_alg_destroy(&key_alg);
}

static void
inner_test__import_private_key_then_export_public_key__should_match(vscf_alg_id_t l1_cipher_alg_id,
        vscf_alg_id_t l2_cipher_alg_id, vsc_data_t private_key_data, vsc_data_t public_key_data) {
    //
    //  Create dependencies first.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Prepare algs.
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);

    vscf_chained_key_alg_t *key_alg = vscf_chained_key_alg_new();
    vscf_chained_key_alg_take_random(key_alg, vscf_fake_random_impl(fake_random));

    //
    //  Import key.
    //
    vscf_impl_t *private_key = inner_import_raw_private_key(private_key_data, l1_cipher_alg_id, l2_cipher_alg_id);

    //
    //  Extract public.
    //
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    vscf_raw_public_key_t *raw_public_key = vscf_chained_key_alg_export_public_key(key_alg, public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(raw_public_key);

    //
    //  Compare.
    //
    TEST_ASSERT_EQUAL_DATA(public_key_data, vscf_raw_public_key_data(raw_public_key));

    //
    //  Cleanup.
    //
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_chained_key_alg_destroy(&key_alg);
}

void
test__import_public_key_then_export__curve25519_curve25519__should_match(void) {
    inner_test__import_public_key_then_export__should_match(
            vscf_alg_id_CURVE25519, vscf_alg_id_CURVE25519, test_data_chained_key_CURVE25519_CURVE25519_PUBLIC_KEY);
}

void
test__import_private_key_then_export__curve25519_curve25519__should_match(void) {
    inner_test__import_private_key_then_export__should_match(
            vscf_alg_id_CURVE25519, vscf_alg_id_CURVE25519, test_data_chained_key_CURVE25519_CURVE25519_PRIVATE_KEY);
}

void
test__import_private_key_then_export_public_key__curve25519_curve25519__should_match(void) {
    inner_test__import_private_key_then_export_public_key__should_match(vscf_alg_id_CURVE25519, vscf_alg_id_CURVE25519,
            test_data_chained_key_CURVE25519_CURVE25519_PRIVATE_KEY,
            test_data_chained_key_CURVE25519_CURVE25519_PUBLIC_KEY);
}

void
test__import_public_key_then_export__curve25519_round5__should_match(void) {
#if VSCF_POST_QUANTUM
    inner_test__import_public_key_then_export__should_match(vscf_alg_id_CURVE25519, vscf_alg_id_ROUND5_ND_5PKE_5D,
            test_data_chained_key_CURVE25519_ROUND5_ND_5PKE_5D_PUBLIC_KEY);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM is disabled");
#endif
}

void
test__import_private_key_then_export__curve25519_round5__should_match(void) {
#if VSCF_POST_QUANTUM
    inner_test__import_private_key_then_export__should_match(vscf_alg_id_CURVE25519, vscf_alg_id_ROUND5_ND_5PKE_5D,
            test_data_chained_key_CURVE25519_ROUND5_ND_5PKE_5D_PRIVATE_KEY);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM is disabled");
#endif
}

void
test__import_private_key_then_export_public_key__curve25519_round5__should_match(void) {
#if VSCF_POST_QUANTUM
    inner_test__import_private_key_then_export_public_key__should_match(vscf_alg_id_CURVE25519,
            vscf_alg_id_ROUND5_ND_5PKE_5D, test_data_chained_key_CURVE25519_ROUND5_ND_5PKE_5D_PRIVATE_KEY,
            test_data_chained_key_CURVE25519_ROUND5_ND_5PKE_5D_PUBLIC_KEY);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM is disabled");
#endif
}

// --------------------------------------------------------------------------
//  Encrypt / Decrypt
// --------------------------------------------------------------------------
void
inner_test__encrypt_decrypt__plain_text_match(const vscf_impl_t *public_key, const vscf_impl_t *private_key) {
    //
    //  Create dependencies first
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_chained_key_alg_t *key_alg = vscf_chained_key_alg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chained_key_alg_setup_defaults(key_alg));

    //
    //  Encrypt
    //
    const size_t enc_buf_len =
            vscf_chained_key_alg_encrypted_len(key_alg, public_key, test_data_chained_key_MESSAGE.len);
    vsc_buffer_t *enc = vsc_buffer_new_with_capacity(enc_buf_len);
    const vscf_status_t enc_status =
            vscf_chained_key_alg_encrypt(key_alg, public_key, test_data_chained_key_MESSAGE, enc);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, enc_status);

    //
    //  Decrypt
    //
    const size_t dec_buf_len = vscf_chained_key_alg_decrypted_len(key_alg, private_key, vsc_buffer_len(enc));
    vsc_buffer_t *dec = vsc_buffer_new_with_capacity(dec_buf_len);
    const vscf_status_t dec_status = vscf_chained_key_alg_decrypt(key_alg, private_key, vsc_buffer_data(enc), dec);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, dec_status);

    //
    //  Compare message
    //
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_chained_key_MESSAGE, dec);

    //
    //  Cleanup
    //
    vsc_buffer_destroy(&dec);
    vsc_buffer_destroy(&enc);
    vscf_chained_key_alg_destroy(&key_alg);
}

void
test__encrypt_decrypt__with_curve25519_and_curve25519_keys__plain_text_match(void) {

    vscf_impl_t *public_key = inner_import_raw_public_key(
            test_data_chained_key_CURVE25519_CURVE25519_PUBLIC_KEY, vscf_alg_id_CURVE25519, vscf_alg_id_CURVE25519);

    vscf_impl_t *private_key = inner_import_raw_private_key(
            test_data_chained_key_CURVE25519_CURVE25519_PRIVATE_KEY, vscf_alg_id_CURVE25519, vscf_alg_id_CURVE25519);

    inner_test__encrypt_decrypt__plain_text_match(public_key, private_key);

    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
}

void
test__encrypt_decrypt__with_curve25519_and_round5_keys__plain_text_match(void) {
#if VSCF_POST_QUANTUM
    vscf_impl_t *public_key = inner_import_raw_public_key(test_data_chained_key_CURVE25519_ROUND5_ND_5PKE_5D_PUBLIC_KEY,
            vscf_alg_id_CURVE25519, vscf_alg_id_ROUND5_ND_5PKE_5D);

    vscf_impl_t *private_key =
            inner_import_raw_private_key(test_data_chained_key_CURVE25519_ROUND5_ND_5PKE_5D_PRIVATE_KEY,
                    vscf_alg_id_CURVE25519, vscf_alg_id_ROUND5_ND_5PKE_5D);

    inner_test__encrypt_decrypt__plain_text_match(public_key, private_key);

    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM is disabled");
#endif
}

// --------------------------------------------------------------------------
//  Sign / Verify
// --------------------------------------------------------------------------
void
inner_test__sign_verify__success(const vscf_impl_t *public_key, const vscf_impl_t *private_key) {
    //
    //  Create dependencies first
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_chained_key_alg_t *key_alg = vscf_chained_key_alg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_chained_key_alg_setup_defaults(key_alg));

    //
    //  Sign
    //
    TEST_ASSERT_TRUE(vscf_chained_key_alg_can_sign(key_alg, private_key));
    const size_t signature_buf_len = vscf_chained_key_alg_signature_len(key_alg, private_key);
    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(signature_buf_len);
    const vscf_status_t sign_status = vscf_chained_key_alg_sign_hash(
            key_alg, private_key, vscf_alg_id_SHA512, test_data_chained_key_MESSAGE_TBS_SHA512_DIGEST, signature);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, sign_status);

    //
    //  Verify
    //
    TEST_ASSERT_TRUE(vscf_chained_key_alg_can_verify(key_alg, public_key));
    const bool verified = vscf_chained_key_alg_verify_hash(key_alg, public_key, vscf_alg_id_SHA512,
            test_data_chained_key_MESSAGE_TBS_SHA512_DIGEST, vsc_buffer_data(signature));
    TEST_ASSERT_TRUE(verified);

    //
    //
    //  Cleanup
    //
    vsc_buffer_destroy(&signature);
    vscf_chained_key_alg_destroy(&key_alg);
}

void
test__sign_verify__with_ed25519_and_ed25519_keys__success(void) {
    vscf_impl_t *public_key = inner_import_raw_public_key(
            test_data_chained_key_ED25519_ED25519_PUBLIC_KEY, vscf_alg_id_ED25519, vscf_alg_id_ED25519);

    vscf_impl_t *private_key = inner_import_raw_private_key(
            test_data_chained_key_ED25519_ED25519_PRIVATE_KEY, vscf_alg_id_ED25519, vscf_alg_id_ED25519);

    inner_test__sign_verify__success(public_key, private_key);

    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
}

void
test__sign_verify__with_ed25519_and_falcon_keys__success(void) {
#if VSCF_POST_QUANTUM
    vscf_impl_t *public_key = inner_import_raw_public_key(
            test_data_chained_key_ED25519_FALCON_512_PUBLIC_KEY, vscf_alg_id_ED25519, vscf_alg_id_FALCON);

    vscf_impl_t *private_key = inner_import_raw_private_key(
            test_data_chained_key_ED25519_FALCON_512_PRIVATE_KEY, vscf_alg_id_ED25519, vscf_alg_id_FALCON);

    inner_test__sign_verify__success(public_key, private_key);

    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM is disabled");
#endif
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__make_key__curve25519_curve25519__is_valid_alg);
    RUN_TEST(test__make_key_ed25519_ed25519__is_valid_alg);
    RUN_TEST(test__make_key__curve25519_round5__is_valid_alg);
    RUN_TEST(test__make_key__curve25519_falcon__returns_error_unsupported_algorithm);

    RUN_TEST(test__import_public_key_then_export__curve25519_curve25519__should_match);
    RUN_TEST(test__import_private_key_then_export__curve25519_curve25519__should_match);
    RUN_TEST(test__import_private_key_then_export_public_key__curve25519_curve25519__should_match);

    RUN_TEST(test__import_public_key_then_export__curve25519_round5__should_match);
    RUN_TEST(test__import_private_key_then_export__curve25519_round5__should_match);
    RUN_TEST(test__import_private_key_then_export_public_key__curve25519_round5__should_match);

    RUN_TEST(test__encrypt_decrypt__with_curve25519_and_curve25519_keys__plain_text_match);
    RUN_TEST(test__encrypt_decrypt__with_curve25519_and_round5_keys__plain_text_match);

    RUN_TEST(test__sign_verify__with_ed25519_and_ed25519_keys__success);
    RUN_TEST(test__sign_verify__with_ed25519_and_falcon_keys__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
