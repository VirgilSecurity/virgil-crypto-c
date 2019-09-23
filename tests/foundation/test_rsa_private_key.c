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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_RSA_PRIVATE_KEY && VSCF_FAKE_RANDOM && VSCF_KEY_MATERIAL_RNG)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_assert.h"

#include "vscf_fake_random.h"
#include "vscf_key_material_rng.h"
#include "vscf_private_key.h"
#include "vscf_public_key.h"
#include "vscf_raw_private_key.h"
#include "vscf_rsa.h"
#include "vscf_simple_alg_info.h"

#include "test_data_rsa.h"


// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------
void
test__rsa_private_key_key_len__imported_2048_PRIVATE_KEY_PKCS1__returns_256(void) {

    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_RSA));
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_rsa_2048_PRIVATE_KEY_PKCS1, &alg_info);

    vscf_rsa_t *rsa = vscf_rsa_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_rsa_setup_defaults(rsa));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *rsa_private_key = vscf_rsa_import_private_key(rsa, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(rsa_private_key);

    TEST_ASSERT_EQUAL(256, vscf_key_len(rsa_private_key));

    vscf_rsa_destroy(&rsa);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_impl_destroy(&rsa_private_key);
}

void
test__rsa_private_key_export_private_key__from_imported_2048_PRIVATE_KEY_PKCS1__expected_equal(void) {

    //  Create raw private key
    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_RSA));
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_rsa_2048_PRIVATE_KEY_PKCS1, &alg_info);

    //  Configure key algorithm
    vscf_rsa_t *rsa = vscf_rsa_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_rsa_setup_defaults(rsa));

    //  Import private key
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *rsa_private_key = vscf_rsa_import_private_key(rsa, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(rsa_private_key);

    //  Export private key
    vscf_raw_private_key_t *exported_raw_private_key = vscf_rsa_export_private_key(rsa, rsa_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(exported_raw_private_key);

    //   Check
    TEST_ASSERT_EQUAL_DATA(test_rsa_2048_PRIVATE_KEY_PKCS1, vscf_raw_private_key_data(exported_raw_private_key));

    //  Cleanup
    vscf_rsa_destroy(&rsa);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_impl_destroy(&rsa_private_key);
    vscf_raw_private_key_destroy(&exported_raw_private_key);
}

void
test__rsa_private_key_decrypt__with_imported_2048_PRIVATE_KEY_PKCS1_and_2048_ENCRYPTED_DATA_1_and_random_AB__returns_DATA_1(
        void) {

    //  Create raw private key
    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_RSA));
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_rsa_2048_PRIVATE_KEY_PKCS1, &alg_info);

    //  Configure key algorithm
    vscf_rsa_t *rsa = vscf_rsa_new();

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_rsa_take_random(rsa, vscf_fake_random_impl(fake_random));

    //  Import private key
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_rsa_import_private_key(rsa, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    //  Decrypt
    vsc_buffer_t *out =
            vsc_buffer_new_with_capacity(vscf_rsa_decrypted_len(rsa, private_key, test_rsa_2048_ENCRYPTED_DATA_1.len));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_rsa_decrypt(rsa, private_key, test_rsa_2048_ENCRYPTED_DATA_1, out));

    //  Check
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_rsa_DATA_1, out);

    //  Cleanup
    vscf_rsa_destroy(&rsa);
    vscf_impl_destroy(&private_key);
    vsc_buffer_destroy(&out);
    vscf_raw_private_key_destroy(&raw_private_key);
}


void
test__rsa_private_key_extract_public_key__from_imported_2048_PRIVATE_KEY_PKCS1__when_exported_equals_2048_PUBLIC_KEY_PKCS1(
        void) {

    //  Create raw private key
    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_RSA));
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_rsa_2048_PRIVATE_KEY_PKCS1, &alg_info);

    //  Configure key algorithm
    vscf_rsa_t *rsa = vscf_rsa_new();

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_rsa_take_random(rsa, vscf_fake_random_impl(fake_random));

    //  Import private key
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_rsa_import_private_key(rsa, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    //  Extract public key
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_NOT_NULL(public_key);

    //  Export public key
    vscf_raw_public_key_t *raw_public_key = vscf_rsa_export_public_key(rsa, public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(raw_public_key);

    //   Check
    TEST_ASSERT_EQUAL_DATA(test_rsa_2048_PUBLIC_KEY_PKCS1, vscf_raw_public_key_data(raw_public_key));

    //  Cleanup
    vscf_rsa_destroy(&rsa);
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_raw_public_key_destroy(&raw_public_key);
}

void
test__rsa_private_key_sign_hash__with_imported_2048_PRIVATE_KEY_PKCS1_and_random_AB_and_hash_sha512_and_DATA_1__equals_2048_DATA_1_SIGNATURE(
        void) {

    //  Create raw private key
    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_RSA));
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_rsa_2048_PRIVATE_KEY_PKCS1, &alg_info);

    //  Configure key algorithm
    vscf_rsa_t *rsa = vscf_rsa_new();

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_rsa_take_random(rsa, vscf_fake_random_impl(fake_random));

    //  Import private key
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_rsa_import_private_key(rsa, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    //  Sign
    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_rsa_signature_len(rsa, private_key));
    vscf_status_t sign_result =
            vscf_rsa_sign_hash(rsa, private_key, vscf_alg_id_SHA512, test_rsa_DATA_1_SHA512_DIGEST, signature);

    //  Check
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, sign_result);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_rsa_2048_DATA_1_SHA512_SIGNATURE, signature);

    //  Cleanup
    vscf_rsa_destroy(&rsa);
    vscf_impl_destroy(&private_key);
    vsc_buffer_destroy(&signature);
    vscf_raw_private_key_destroy(&raw_private_key);
}

void
test__rsa_private_key_generate_key__bitlen_2048_and_exponent_3__exported_equals_2048_GENERATED_PRIVATE_KEY_PKCS1(void) {

    //  Configure key algorithm
    vscf_rsa_t *rsa = vscf_rsa_new();

    vscf_key_material_rng_t *key_material_rng = vscf_key_material_rng_new();
    vscf_key_material_rng_reset_key_material(key_material_rng, test_rsa_DETERMINISTIC_KEY_MATERIAL);
    vscf_rsa_take_random(rsa, vscf_key_material_rng_impl(key_material_rng));

    //  Generate private key
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_rsa_generate_key(rsa, 2048, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    //  Export private key
    vscf_raw_private_key_t *raw_private_key = vscf_rsa_export_private_key(rsa, private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(raw_private_key);

    //   Check
    TEST_ASSERT_EQUAL_DATA(test_rsa_2048_GENERATED_PRIVATE_KEY_PKCS1, vscf_raw_private_key_data(raw_private_key));

    //  Cleanup
    vscf_rsa_destroy(&rsa);
    vscf_impl_destroy(&private_key);
    vscf_raw_private_key_destroy(&raw_private_key);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// clang-format off
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__rsa_private_key_key_len__imported_2048_PRIVATE_KEY_PKCS1__returns_256);
    RUN_TEST(test__rsa_private_key_export_private_key__from_imported_2048_PRIVATE_KEY_PKCS1__expected_equal);
    RUN_TEST(test__rsa_private_key_decrypt__with_imported_2048_PRIVATE_KEY_PKCS1_and_2048_ENCRYPTED_DATA_1_and_random_AB__returns_DATA_1);
    RUN_TEST(test__rsa_private_key_extract_public_key__from_imported_2048_PRIVATE_KEY_PKCS1__when_exported_equals_2048_PUBLIC_KEY_PKCS1);
    RUN_TEST(test__rsa_private_key_sign_hash__with_imported_2048_PRIVATE_KEY_PKCS1_and_random_AB_and_hash_sha512_and_DATA_1__equals_2048_DATA_1_SIGNATURE);
    RUN_TEST(test__rsa_private_key_generate_key__bitlen_2048_and_exponent_3__exported_equals_2048_GENERATED_PRIVATE_KEY_PKCS1);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
