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

#define TEST_DEPENDENCIES_AVAILABLE (VSCF_POST_QUANTUM && ROUND5_LIBRARY)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_round5.h"
#include "vscf_fake_random.h"
#include "vscf_simple_alg_info.h"
#include "vscf_private_key.h"

#include "test_data_round5.h"

void
test__generate_key__success(void) {
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_data_round5_RNG_SEED);

    vscf_round5_t *round5 = vscf_round5_new();
    vscf_round5_take_random(round5, vscf_fake_random_impl(fake_random));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_round5_generate_key(round5, vscf_alg_id_ROUND5_ND_5KEM_5D, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_destroy(&private_key);
    vscf_round5_destroy(&round5);
}

void
test__encapsulate__success(void) {
    //
    //  Configure alg.
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_data_round5_RNG_SEED);

    vscf_round5_t *round5 = vscf_round5_new();
    vscf_round5_take_random(round5, vscf_fake_random_impl(fake_random));

    //
    //  Import public key.
    //
    vscf_impl_t *alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ROUND5_ND_5KEM_5D));
    vscf_raw_public_key_t *raw_public_key =
            vscf_raw_public_key_new_with_data(test_data_round5_ND_5KEM_5D_PUBLIC_KEY, &alg_info);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *public_key = vscf_round5_import_public_key(round5, raw_public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Encapsulate.
    //
    const size_t encapsulated_key_len = vscf_round5_kem_encapsulated_key_len(round5, public_key);
    const size_t shared_key_len = vscf_round5_kem_shared_key_len(round5, public_key);
    TEST_ASSERT_GREATER_THAN(0, encapsulated_key_len);
    TEST_ASSERT_GREATER_THAN(0, shared_key_len);

    vsc_buffer_t *encapsulated_key = vsc_buffer_new_with_capacity(encapsulated_key_len);
    vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(shared_key_len);

    const vscf_status_t status = vscf_round5_kem_encapsulate(round5, public_key, shared_key, encapsulated_key);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_round5_ND_5KEM_5D_ENCAPSULATED_KEY, encapsulated_key);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_round5_ND_5KEM_5D_ENCAPSULATED_SHARED_KEY, shared_key);

    vsc_buffer_destroy(&encapsulated_key);
    vsc_buffer_destroy(&shared_key);
    vscf_impl_destroy(&public_key);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_round5_destroy(&round5);
}

void
test__decapsulate__success(void) {

    //
    //  Configure alg.
    //
    vscf_round5_t *round5 = vscf_round5_new();

    //
    //  Import private key.
    //
    vscf_impl_t *alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ROUND5_ND_5KEM_5D));
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_data_round5_ND_5KEM_5D_PRIVATE_KEY, &alg_info);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_round5_import_private_key(round5, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Decrypt.
    //
    const size_t shared_key_len = vscf_round5_kem_shared_key_len(round5, private_key);
    TEST_ASSERT_GREATER_THAN(0, shared_key_len);
    vsc_buffer_t *shared_key = vsc_buffer_new_with_capacity(shared_key_len);

    const vscf_status_t status =
            vscf_round5_kem_decapsulate(round5, test_data_round5_ND_5KEM_5D_ENCAPSULATED_KEY, private_key, shared_key);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_round5_ND_5KEM_5D_ENCAPSULATED_SHARED_KEY, shared_key);

    vsc_buffer_destroy(&shared_key);
    vscf_impl_destroy(&private_key);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_round5_destroy(&round5);
}

void
test__export_public_key__from_generated_key__valid_alg_and_key_length(void) {
    //
    //  Configure alg.
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_data_round5_RNG_SEED);

    vscf_round5_t *round5 = vscf_round5_new();
    vscf_round5_take_random(round5, vscf_fake_random_impl(fake_random));

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Generate key.
    //
    vscf_impl_t *private_key = vscf_round5_generate_key(round5, vscf_alg_id_ROUND5_ND_5KEM_5D, &error);
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
    TEST_ASSERT_EQUAL(vscf_alg_id_ROUND5_ND_5KEM_5D, alg_id);
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
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_data_round5_RNG_SEED);

    vscf_round5_t *round5 = vscf_round5_new();
    vscf_round5_take_random(round5, vscf_fake_random_impl(fake_random));

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Generate key.
    //
    vscf_impl_t *private_key = vscf_round5_generate_key(round5, vscf_alg_id_ROUND5_ND_5KEM_5D, &error);
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
    TEST_ASSERT_EQUAL(vscf_alg_id_ROUND5_ND_5KEM_5D, alg_id);
    TEST_ASSERT_EQUAL(1042, vscf_raw_private_key_data(raw_private_key).len);

    //
    // Cleanup.
    //
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_impl_destroy(&private_key);
    vscf_round5_destroy(&round5);
}

void
test__extract_public_key__from_imported_private_key__when_exported_are_equals(void) {

    //  Create raw private key
    vscf_impl_t *alg_info =
            vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ROUND5_ND_5KEM_5D));
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_data_round5_ND_5KEM_5D_PRIVATE_KEY, &alg_info);

    //  Configure key algorithm
    vscf_round5_t *round5 = vscf_round5_new();

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_round5_take_random(round5, vscf_fake_random_impl(fake_random));

    //  Import private key
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_round5_import_private_key(round5, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    //  Extract public key
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_NOT_NULL(public_key);

    //  Export public key
    vscf_raw_public_key_t *raw_public_key = vscf_round5_export_public_key(round5, public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(raw_public_key);

    //   Check
    TEST_ASSERT_EQUAL_DATA(test_data_round5_ND_5KEM_5D_PUBLIC_KEY, vscf_raw_public_key_data(raw_public_key));

    //  Cleanup
    vscf_round5_destroy(&round5);
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
    RUN_TEST(test__generate_key__success);
    RUN_TEST(test__encapsulate__success);
    RUN_TEST(test__decapsulate__success);
    RUN_TEST(test__export_public_key__from_generated_key__valid_alg_and_key_length);
    RUN_TEST(test__export_private_key__from_generated_key__valid_alg_and_key_length);
    RUN_TEST(test__extract_public_key__from_imported_private_key__when_exported_are_equals);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
