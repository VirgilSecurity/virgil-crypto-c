//  Copyright (C) 2015-2020 Virgil Security, Inc.
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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_COMPOUND_KEY_ALG && VSCF_KEY_PROVIDER && VSCF_FAKE_RANDOM)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_compound_key_alg.h"
#include "vscf_compound_public_key.h"
#include "vscf_compound_private_key.h"
#include "vscf_key.h"
#include "vscf_private_key.h"
#include "vscf_simple_alg_info.h"
#include "vscf_compound_key_alg_info.h"
#include "vscf_fake_random.h"
#include "vscf_key_provider.h"

#include "test_data_compound_key.h"

// --------------------------------------------------------------------------
//  Helpers.
// --------------------------------------------------------------------------
static vscf_impl_t *
inner_import_raw_public_key(vsc_data_t public_key_data, vscf_alg_id_t cipher_alg_id, vscf_alg_id_t signer_alg_id) {

    vscf_impl_t *cipher_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(cipher_alg_id));
    vscf_impl_t *signer_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(signer_alg_id));
    vscf_impl_t *alg_info = vscf_compound_key_alg_info_impl(vscf_compound_key_alg_info_new_with_infos_disown(
            vscf_alg_id_COMPOUND_KEY, &cipher_alg_info, &signer_alg_info));

    vscf_raw_public_key_t *raw_public_key = vscf_raw_public_key_new_with_data(public_key_data, &alg_info);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_compound_key_alg_t *key_alg = vscf_compound_key_alg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_compound_key_alg_setup_defaults(key_alg));

    vscf_impl_t *public_key = vscf_compound_key_alg_import_public_key(key_alg, raw_public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(public_key);

    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_compound_key_alg_destroy(&key_alg);

    return public_key;
}

static vscf_impl_t *
inner_import_raw_private_key(vsc_data_t private_key_data, vscf_alg_id_t cipher_alg_id, vscf_alg_id_t signer_alg_id) {

    vscf_impl_t *cipher_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(cipher_alg_id));
    vscf_impl_t *signer_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(signer_alg_id));
    vscf_impl_t *alg_info = vscf_compound_key_alg_info_impl(vscf_compound_key_alg_info_new_with_infos_disown(
            vscf_alg_id_COMPOUND_KEY, &cipher_alg_info, &signer_alg_info));

    vscf_raw_private_key_t *raw_private_key = vscf_raw_private_key_new_with_data(private_key_data, &alg_info);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_compound_key_alg_t *key_alg = vscf_compound_key_alg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_compound_key_alg_setup_defaults(key_alg));

    vscf_impl_t *private_key = vscf_compound_key_alg_import_private_key(key_alg, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_compound_key_alg_destroy(&key_alg);

    return private_key;
}

// --------------------------------------------------------------------------
//  Generate key.
// --------------------------------------------------------------------------
void
test__generate_key__curve25519_and_ed25519_with_fake_rng__success(void) {

    //
    //  Create dependencies first.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_take_random(key_provider, vscf_fake_random_impl(fake_random));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    //
    //  Generate key.
    //
    vscf_impl_t *private_key = vscf_key_provider_generate_compound_private_key(
            key_provider, vscf_alg_id_CURVE25519, vscf_alg_id_ED25519, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    //
    //  Check private keys.
    //
    TEST_ASSERT_EQUAL(vscf_impl_tag_COMPOUND_PRIVATE_KEY, vscf_impl_tag(private_key));
    vscf_compound_private_key_t *compound_private_key = (vscf_compound_private_key_t *)private_key;

    const vscf_impl_t *cipher_private_key = vscf_compound_private_key_cipher_key(compound_private_key);
    TEST_ASSERT_NOT_NULL(cipher_private_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_CURVE25519, vscf_key_alg_id(cipher_private_key));

    const vscf_impl_t *signer_private_key = vscf_compound_private_key_signer_key(compound_private_key);
    TEST_ASSERT_NOT_NULL(signer_private_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_ED25519, vscf_key_alg_id(signer_private_key));

    //
    //  Check public keys
    //
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_EQUAL(vscf_impl_tag_COMPOUND_PUBLIC_KEY, vscf_impl_tag(public_key));
    vscf_compound_public_key_t *compound_public_key = (vscf_compound_public_key_t *)public_key;

    const vscf_impl_t *cipher_public_key = vscf_compound_public_key_cipher_key(compound_public_key);
    TEST_ASSERT_NOT_NULL(cipher_public_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_CURVE25519, vscf_key_alg_id(cipher_public_key));

    const vscf_impl_t *signer_public_key = vscf_compound_public_key_signer_key(compound_public_key);
    TEST_ASSERT_NOT_NULL(signer_public_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_ED25519, vscf_key_alg_id(signer_public_key));

    //
    //  Cleanup
    //
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

// --------------------------------------------------------------------------
//  Import / Export
// --------------------------------------------------------------------------
static void
inner_test__import_public_key_then_export__should_match(
        vscf_alg_id_t cipher_alg_id, vscf_alg_id_t signer_alg_id, vsc_data_t public_key_data) {
    //
    //  Create dependencies first.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Prepare algs.
    //
    vscf_compound_key_alg_t *key_alg = vscf_compound_key_alg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_compound_key_alg_setup_defaults(key_alg));

    vscf_impl_t *cipher_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(cipher_alg_id));
    vscf_impl_t *signer_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(signer_alg_id));
    vscf_impl_t *alg_info = vscf_compound_key_alg_info_impl(vscf_compound_key_alg_info_new_with_infos_disown(
            vscf_alg_id_COMPOUND_KEY, &cipher_alg_info, &signer_alg_info));

    vscf_raw_public_key_t *raw_public_key = vscf_raw_public_key_new_with_data(public_key_data, &alg_info);

    //
    //  Import key.
    //
    vscf_impl_t *public_key = vscf_compound_key_alg_import_public_key(key_alg, raw_public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(public_key);

    //
    //  Export key.
    //
    vscf_raw_public_key_t *exported_raw_public_key =
            vscf_compound_key_alg_export_public_key(key_alg, public_key, &error);
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
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_compound_key_alg_destroy(&key_alg);
}

static void
inner_test__import_private_key_then_export__should_match(
        vscf_alg_id_t cipher_alg_id, vscf_alg_id_t signer_alg_id, vsc_data_t private_key_data) {
    //
    //  Create dependencies first.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Prepare algs.
    //
    vscf_compound_key_alg_t *key_alg = vscf_compound_key_alg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_compound_key_alg_setup_defaults(key_alg));

    vscf_impl_t *cipher_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(cipher_alg_id));
    vscf_impl_t *signer_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(signer_alg_id));
    vscf_impl_t *alg_info = vscf_compound_key_alg_info_impl(vscf_compound_key_alg_info_new_with_infos_disown(
            vscf_alg_id_COMPOUND_KEY, &cipher_alg_info, &signer_alg_info));

    vscf_raw_private_key_t *raw_private_key = vscf_raw_private_key_new_with_data(private_key_data, &alg_info);

    //
    //  Import key.
    //
    vscf_impl_t *private_key = vscf_compound_key_alg_import_private_key(key_alg, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    //
    //  Export key.
    //
    vscf_raw_private_key_t *exported_raw_private_key =
            vscf_compound_key_alg_export_private_key(key_alg, private_key, &error);
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
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_compound_key_alg_destroy(&key_alg);
}

static void
inner_test__import_private_key_then_export_public_key__should_match(vscf_alg_id_t cipher_alg_id,
        vscf_alg_id_t signer_alg_id, vsc_data_t private_key_data, vsc_data_t public_key_data) {
    //
    //  Create dependencies first.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Prepare algs.
    //
    vscf_compound_key_alg_t *key_alg = vscf_compound_key_alg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_compound_key_alg_setup_defaults(key_alg));

    vscf_impl_t *cipher_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(cipher_alg_id));
    vscf_impl_t *signer_alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(signer_alg_id));
    vscf_impl_t *alg_info = vscf_compound_key_alg_info_impl(vscf_compound_key_alg_info_new_with_infos_disown(
            vscf_alg_id_COMPOUND_KEY, &cipher_alg_info, &signer_alg_info));


    vscf_raw_private_key_t *raw_private_key = vscf_raw_private_key_new_with_data(private_key_data, &alg_info);

    //
    //  Import key.
    //
    vscf_impl_t *private_key = vscf_compound_key_alg_import_private_key(key_alg, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    //
    //  Extract public.
    //
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    vscf_raw_public_key_t *raw_public_key = vscf_compound_key_alg_export_public_key(key_alg, public_key, &error);
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
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_compound_key_alg_destroy(&key_alg);
}

void
test__import_public_key_then_export__curve25519_ed25519__should_match(void) {
    inner_test__import_public_key_then_export__should_match(
            vscf_alg_id_CURVE25519, vscf_alg_id_ED25519, test_data_compound_key_CURVE25519_ED25519_PUBLIC_KEY);
}

void
test__import_private_key_then_export__curve25519_ed25519__should_match(void) {
    inner_test__import_private_key_then_export__should_match(
            vscf_alg_id_CURVE25519, vscf_alg_id_ED25519, test_data_compound_key_CURVE25519_ED25519_PRIVATE_KEY);
}

void
test__import_private_key_then_export_public_key__curve25519_ed25519__should_match(void) {
    inner_test__import_private_key_then_export_public_key__should_match(vscf_alg_id_CURVE25519, vscf_alg_id_ED25519,
            test_data_compound_key_CURVE25519_ED25519_PRIVATE_KEY,
            test_data_compound_key_CURVE25519_ED25519_PUBLIC_KEY);
}

// --------------------------------------------------------------------------
//  Encrypt / Decrypt
// --------------------------------------------------------------------------
static void
inner_test__encrypt_decrypt__plain_text_match(const vscf_impl_t *public_key, const vscf_impl_t *private_key) {
    //
    //  Create dependencies first
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_compound_key_alg_t *key_alg = vscf_compound_key_alg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_compound_key_alg_setup_defaults(key_alg));

    //
    //  Encrypt
    //
    const size_t enc_buf_len =
            vscf_compound_key_alg_encrypted_len(key_alg, public_key, test_data_compound_key_MESSAGE.len);
    vsc_buffer_t *enc = vsc_buffer_new_with_capacity(enc_buf_len);
    const vscf_status_t enc_status =
            vscf_compound_key_alg_encrypt(key_alg, public_key, test_data_compound_key_MESSAGE, enc);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, enc_status);

    //
    //  Decrypt
    //
    const size_t dec_buf_len = vscf_compound_key_alg_decrypted_len(key_alg, private_key, vsc_buffer_len(enc));
    vsc_buffer_t *dec = vsc_buffer_new_with_capacity(dec_buf_len);
    const vscf_status_t dec_status = vscf_compound_key_alg_decrypt(key_alg, private_key, vsc_buffer_data(enc), dec);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, dec_status);

    //
    //  Compare message
    //
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_compound_key_MESSAGE, dec);

    //
    //  Cleanup
    //
    vsc_buffer_destroy(&dec);
    vsc_buffer_destroy(&enc);
    vscf_compound_key_alg_destroy(&key_alg);
}

void
test__encrypt_decrypt__with_curve25519_and_ed25519_keys__plain_text_match(void) {

    vscf_impl_t *public_key = inner_import_raw_public_key(
            test_data_compound_key_CURVE25519_ED25519_PUBLIC_KEY, vscf_alg_id_CURVE25519, vscf_alg_id_ED25519);

    vscf_impl_t *private_key = inner_import_raw_private_key(
            test_data_compound_key_CURVE25519_ED25519_PRIVATE_KEY, vscf_alg_id_CURVE25519, vscf_alg_id_ED25519);

    inner_test__encrypt_decrypt__plain_text_match(public_key, private_key);

    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
}

// --------------------------------------------------------------------------
//  Sign / Verify
// --------------------------------------------------------------------------
static void
inner_test__sign_verify__success(vscf_impl_t *public_key, vscf_impl_t *private_key) {
    //
    //  Create dependencies first
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_compound_key_alg_t *key_alg = vscf_compound_key_alg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_compound_key_alg_setup_defaults(key_alg));

    //
    //  Sign
    //
    TEST_ASSERT_TRUE(vscf_compound_key_alg_can_sign(key_alg, private_key));
    const size_t signature_buf_len = vscf_compound_key_alg_signature_len(key_alg, private_key);
    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(signature_buf_len);
    const vscf_status_t sign_status = vscf_compound_key_alg_sign_hash(
            key_alg, private_key, vscf_alg_id_SHA512, test_data_compound_key_MESSAGE_TBS_SHA512_DIGEST, signature);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, sign_status);

    //
    //  Verify
    //
    TEST_ASSERT_TRUE(vscf_compound_key_alg_can_verify(key_alg, public_key));
    const bool verified = vscf_compound_key_alg_verify_hash(key_alg, public_key, vscf_alg_id_SHA512,
            test_data_compound_key_MESSAGE_TBS_SHA512_DIGEST, vsc_buffer_data(signature));
    TEST_ASSERT_TRUE(verified);

    //
    //  Cleanup
    //
    vsc_buffer_destroy(&signature);
    vscf_compound_key_alg_destroy(&key_alg);
}

void
test__sign_verify__with_curve25519_and_ed25519_keys__success(void) {

    vscf_impl_t *public_key = inner_import_raw_public_key(
            test_data_compound_key_CURVE25519_ED25519_PUBLIC_KEY, vscf_alg_id_CURVE25519, vscf_alg_id_ED25519);

    vscf_impl_t *private_key = inner_import_raw_private_key(
            test_data_compound_key_CURVE25519_ED25519_PRIVATE_KEY, vscf_alg_id_CURVE25519, vscf_alg_id_ED25519);

    inner_test__sign_verify__success(public_key, private_key);

    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__generate_key__curve25519_and_ed25519_with_fake_rng__success);
    RUN_TEST(test__import_public_key_then_export__curve25519_ed25519__should_match);
    RUN_TEST(test__import_private_key_then_export__curve25519_ed25519__should_match);
    RUN_TEST(test__import_private_key_then_export_public_key__curve25519_ed25519__should_match);
    RUN_TEST(test__encrypt_decrypt__with_curve25519_and_ed25519_keys__plain_text_match);
    RUN_TEST(test__sign_verify__with_curve25519_and_ed25519_keys__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
