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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_CURVE25519 && VSCF_FAKE_RANDOM && VSCF_RANDOM)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_assert.h"

#include "vscf_public_key.h"
#include "vscf_curve25519.h"
#include "vscf_fake_random.h"
#include "vscf_simple_alg_info.h"
#include "vscf_private_key.h"

#include "test_data_curve25519.h"


// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------
void
test__key_len__imported_private_key__returns_32(void) {

    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_curve25519_PRIVATE_KEY, &alg_info);

    vscf_curve25519_t *curve25519 = vscf_curve25519_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_curve25519_setup_defaults(curve25519));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_curve25519_import_private_key(curve25519, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    TEST_ASSERT_EQUAL(32, vscf_key_len(private_key));

    vscf_curve25519_destroy(&curve25519);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_impl_destroy(&private_key);
}

void
test__export_private_key__from_imported_private_key__expected_equal(void) {
    //  Create raw private key
    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_curve25519_PRIVATE_KEY, &alg_info);

    //  Configure key algorithm
    vscf_curve25519_t *curve25519 = vscf_curve25519_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_curve25519_setup_defaults(curve25519));

    //  Import private key
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *curve25519_private_key = vscf_curve25519_import_private_key(curve25519, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(curve25519_private_key);

    //  Export private key
    vscf_raw_private_key_t *exported_raw_private_key =
            vscf_curve25519_export_private_key(curve25519, curve25519_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(exported_raw_private_key);

    //   Check
    TEST_ASSERT_EQUAL_DATA(test_curve25519_PRIVATE_KEY, vscf_raw_private_key_data(exported_raw_private_key));

    //  Cleanup
    vscf_curve25519_destroy(&curve25519);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_impl_destroy(&curve25519_private_key);
    vscf_raw_private_key_destroy(&exported_raw_private_key);
}

void
test__extract_public_key__from_imported_private_key__when_exported_equals_public_key(void) {

    //  Create raw private key
    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_curve25519_PRIVATE_KEY, &alg_info);

    //  Configure key algorithm
    vscf_curve25519_t *curve25519 = vscf_curve25519_new();

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_curve25519_take_random(curve25519, vscf_fake_random_impl(fake_random));

    //  Import private key
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_curve25519_import_private_key(curve25519, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    //  Extract public key
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_NOT_NULL(public_key);

    //  Export public key
    vscf_raw_public_key_t *raw_public_key = vscf_curve25519_export_public_key(curve25519, public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(raw_public_key);

    //   Check
    TEST_ASSERT_EQUAL_DATA(test_curve25519_PUBLIC_KEY, vscf_raw_public_key_data(raw_public_key));

    //  Cleanup
    vscf_curve25519_destroy(&curve25519);
    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_raw_public_key_destroy(&raw_public_key);
}

void
test__generate_key__exported_equals_private_key(void) {

    //  Configure key algorithm
    vscf_curve25519_t *curve25519 = vscf_curve25519_new();

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_curve25519_RANDOM);
    vscf_curve25519_take_random(curve25519, vscf_fake_random_impl(fake_random));

    //  Generate private key
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_curve25519_generate_key(curve25519, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    //  Export private key
    vscf_raw_private_key_t *raw_private_key = vscf_curve25519_export_private_key(curve25519, private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(raw_private_key);

    //   Check
    TEST_ASSERT_EQUAL_DATA(test_curve25519_PRIVATE_KEY, vscf_raw_private_key_data(raw_private_key));

    //  Cleanup
    vscf_curve25519_destroy(&curve25519);
    vscf_impl_destroy(&private_key);
    vscf_raw_private_key_destroy(&raw_private_key);
}

void
test__decrypt__message_with_imported_key__success(void) {

    //  Create raw private key
    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_CURVE25519));
    vscf_raw_private_key_t *raw_private_key =
            vscf_raw_private_key_new_with_data(test_curve25519_PRIVATE_KEY, &alg_info);

    //  Configure key algorithm
    vscf_curve25519_t *curve25519 = vscf_curve25519_new();

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_curve25519_take_random(curve25519, vscf_fake_random_impl(fake_random));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_curve25519_setup_defaults(curve25519));

    //  Import private key
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_curve25519_import_private_key(curve25519, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    //  Decrypt
    vsc_buffer_t *out = vsc_buffer_new_with_capacity(
            vscf_curve25519_decrypted_len(curve25519, private_key, test_curve25519_ENCRYPTED_MESSAGE.len));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_curve25519_decrypt(curve25519, private_key, test_curve25519_ENCRYPTED_MESSAGE, out));

    //  Check
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_curve25519_MESSAGE, out);

    //  Cleanup
    vscf_curve25519_destroy(&curve25519);
    vscf_impl_destroy(&private_key);
    vsc_buffer_destroy(&out);
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
    RUN_TEST(test__key_len__imported_private_key__returns_32);
    RUN_TEST(test__export_private_key__from_imported_private_key__expected_equal);
    RUN_TEST(test__extract_public_key__from_imported_private_key__when_exported_equals_public_key);
    RUN_TEST(test__generate_key__exported_equals_private_key);
    RUN_TEST(test__decrypt__message_with_imported_key__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
