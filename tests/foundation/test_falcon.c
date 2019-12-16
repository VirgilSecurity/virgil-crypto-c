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

#define TEST_DEPENDENCIES_AVAILABLE (VSCF_POST_QUANTUM && FALCON_LIBRARY)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_falcon.h"
#include "vscf_fake_random.h"
#include "vscf_private_key.h"
#include "vscf_simple_alg_info.h"

#include "test_data_falcon.h"

#include <falcon/falcon.h>

void
test__generate_key__512_degree_with_fake_rng__success(void) {

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_data_falcon_RNG_SEED);

    vscf_falcon_t *falcon = vscf_falcon_new();
    vscf_falcon_take_random(falcon, vscf_fake_random_impl(fake_random));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_falcon_generate_key(falcon, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_raw_private_key_t *raw_private_key = vscf_falcon_export_private_key(falcon, private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_EQUAL_DATA(test_data_falcon_PRIVATE_KEY_512, vscf_raw_private_key_data(raw_private_key));

    vscf_raw_public_key_t *raw_public_key =
            (vscf_raw_public_key_t *)vscf_raw_private_key_extract_public_key(raw_private_key);
    TEST_ASSERT_NOT_NULL(raw_public_key);
    TEST_ASSERT_EQUAL_DATA(test_data_falcon_PUBLIC_KEY_512, vscf_raw_public_key_data(raw_public_key));

    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_impl_destroy(&private_key);
    vscf_falcon_destroy(&falcon);
}

void
test__generate_key__512_degree_with_default_rng__success(void) {

    vscf_falcon_t *falcon = vscf_falcon_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_falcon_setup_defaults(falcon));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_falcon_generate_key(falcon, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_destroy(&private_key);
    vscf_falcon_destroy(&falcon);
}

void
test__sign_hash__sha512_digest_with_512_degree_key__produce_const_signature(void) {

    //
    //  Configure alg
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_data_falcon_RNG_SEED2);

    vscf_falcon_t *falcon = vscf_falcon_new();
    vscf_falcon_take_random(falcon, vscf_fake_random_impl(fake_random));

    //
    //  Import private key
    //
    vscf_impl_t *alg_info = vscf_falcon_produce_alg_info(falcon);
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_data_falcon_PRIVATE_KEY_512, &alg_info);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_falcon_import_private_key(falcon, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Sign
    //
    TEST_ASSERT_TRUE(vscf_falcon_can_sign(falcon, private_key));

    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_falcon_signature_len(falcon, private_key));
    const vscf_status_t status = vscf_falcon_sign_hash(
            falcon, private_key, vscf_alg_id_SHA512, test_data_falcon_DATA_SHA512_DIGEST, signature);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_falcon_CONST_SIGNATURE, signature);

    vsc_buffer_destroy(&signature);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_impl_destroy(&private_key);
    vscf_falcon_destroy(&falcon);
}

void
test__verify_hash__sha512_digest_and_const_signature_with_512_degree_key__success(void) {

    //
    //  Configure alg
    //
    vscf_falcon_t *falcon = vscf_falcon_new();

    //
    //  Import public key
    //
    vscf_impl_t *alg_info = vscf_falcon_produce_alg_info(falcon);
    vscf_raw_public_key_t *raw_public_key =
            vscf_raw_public_key_new_with_data(test_data_falcon_PUBLIC_KEY_512, &alg_info);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *public_key = vscf_falcon_import_public_key(falcon, raw_public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Verify
    //
    TEST_ASSERT_TRUE(vscf_falcon_can_verify(falcon, public_key));

    const bool verified = vscf_falcon_verify_hash(falcon, public_key, vscf_alg_id_SHA512,
            test_data_falcon_DATA_SHA512_DIGEST, test_data_falcon_CONST_SIGNATURE);
    TEST_ASSERT_TRUE(verified);

    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_impl_destroy(&public_key);
    vscf_falcon_destroy(&falcon);
}

void
test__export_public_key__from_generate_key__valid_alg_and_key_data(void) {

    //
    //  Prepare algs.
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_data_falcon_RNG_SEED);

    vscf_falcon_t *falcon = vscf_falcon_new();
    vscf_falcon_take_random(falcon, vscf_fake_random_impl(fake_random));

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Generate key.
    //
    vscf_impl_t *private_key = vscf_falcon_generate_key(falcon, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //  Export key.
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    vscf_raw_public_key_t *raw_public_key = vscf_falcon_export_public_key(falcon, public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Check.
    //
    const vscf_alg_id_t alg_id = vscf_raw_public_key_alg_id(raw_public_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_FALCON, alg_id);
    TEST_ASSERT_EQUAL_DATA(test_data_falcon_PUBLIC_KEY_512, vscf_raw_public_key_data(raw_public_key));

    //
    //  Cleanup.
    //
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_falcon_destroy(&falcon);
}

void
test__export_private_key__from_generate_key__valid_alg_and_key_data(void) {

    //
    //  Prepare algs.
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_data_falcon_RNG_SEED);

    vscf_falcon_t *falcon = vscf_falcon_new();
    vscf_falcon_take_random(falcon, vscf_fake_random_impl(fake_random));

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Generate key.
    //
    vscf_impl_t *private_key = vscf_falcon_generate_key(falcon, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //  Export key.
    vscf_raw_private_key_t *raw_private_key = vscf_falcon_export_private_key(falcon, private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Check.
    //
    const vscf_alg_id_t alg_id = vscf_raw_private_key_alg_id(raw_private_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_FALCON, alg_id);
    TEST_ASSERT_EQUAL_DATA(test_data_falcon_PRIVATE_KEY_512, vscf_raw_private_key_data(raw_private_key));

    //
    //  Cleanup.
    //
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_impl_destroy(&private_key);
    vscf_falcon_destroy(&falcon);
}

void
test__extract_public_key__from_imported_private_key__when_exported_are_equals(void) {
    //  Create raw private key
    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_FALCON));
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_data_falcon_PRIVATE_KEY_512, &alg_info);

    //  Configure key algorithm
    vscf_falcon_t *falcon = vscf_falcon_new();

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_falcon_take_random(falcon, vscf_fake_random_impl(fake_random));

    //  Import private key
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_falcon_import_private_key(falcon, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    //  Extract public key
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_NOT_NULL(public_key);

    //  Export public key
    vscf_raw_public_key_t *raw_public_key = vscf_falcon_export_public_key(falcon, public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(raw_public_key);

    //   Check
    TEST_ASSERT_EQUAL_DATA(test_data_falcon_PUBLIC_KEY_512, vscf_raw_public_key_data(raw_public_key));

    //  Cleanup
    vscf_falcon_destroy(&falcon);
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_raw_public_key_destroy(&raw_public_key);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__generate_key__512_degree_with_fake_rng__success);
    RUN_TEST(test__generate_key__512_degree_with_default_rng__success);
    RUN_TEST(test__sign_hash__sha512_digest_with_512_degree_key__produce_const_signature);
    RUN_TEST(test__verify_hash__sha512_digest_and_const_signature_with_512_degree_key__success);
    RUN_TEST(test__export_public_key__from_generate_key__valid_alg_and_key_data);
    RUN_TEST(test__export_private_key__from_generate_key__valid_alg_and_key_data);
    RUN_TEST(test__extract_public_key__from_imported_private_key__when_exported_are_equals);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
