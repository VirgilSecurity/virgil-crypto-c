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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_ED25519 && VSCF_FAKE_RANDOM && VSCF_RANDOM)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_assert.h"

#include "vscf_ed25519.h"
#include "vscf_random.h"
#include "vscf_fake_random.h"
#include "vscf_simple_alg_info.h"

#include "test_data_ed25519.h"


// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------
void
test__key_len__imported_public_key__returns_32(void) {

    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));
    vscf_raw_public_key_t *raw_public_key = vscf_raw_public_key_new_with_data(test_ed25519_PUBLIC_KEY, &alg_info);

    vscf_ed25519_t *ed25519 = vscf_ed25519_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ed25519_setup_defaults(ed25519));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *ed25519_public_key = vscf_ed25519_import_public_key(ed25519, raw_public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(ed25519_public_key);

    TEST_ASSERT_EQUAL(32, vscf_key_len(ed25519_public_key));

    vscf_ed25519_destroy(&ed25519);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_impl_destroy(&ed25519_public_key);
}

void
test__export_public_key__from_imported_public_key__are_equal(void) {

    //  Create raw public key
    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));
    vscf_raw_public_key_t *raw_public_key = vscf_raw_public_key_new_with_data(test_ed25519_PUBLIC_KEY, &alg_info);

    //  Configure key algorithm
    vscf_ed25519_t *ed25519 = vscf_ed25519_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ed25519_setup_defaults(ed25519));

    //  Import public key
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *ed25519_public_key = vscf_ed25519_import_public_key(ed25519, raw_public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(ed25519_public_key);

    //  Export public key
    vscf_raw_public_key_t *exported_raw_public_key =
            vscf_ed25519_export_public_key(ed25519, ed25519_public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(exported_raw_public_key);

    //   Check
    TEST_ASSERT_EQUAL_DATA(test_ed25519_PUBLIC_KEY, vscf_raw_public_key_data(exported_raw_public_key));

    //  Cleanup
    vscf_ed25519_destroy(&ed25519);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_impl_destroy(&ed25519_public_key);
    vscf_raw_public_key_destroy(&exported_raw_public_key);
}

void
test__verify__with_imported_public_key_and_data_signature__valid_signature(void) {

    //  Create raw public key
    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));
    vscf_raw_public_key_t *raw_public_key = vscf_raw_public_key_new_with_data(test_ed25519_PUBLIC_KEY, &alg_info);

    //  Configure key algorithm
    vscf_ed25519_t *ed25519 = vscf_ed25519_new();

    //  Import public key
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *public_key = vscf_ed25519_import_public_key(ed25519, raw_public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(public_key);

    //  Verify
    bool verify_result = vscf_ed25519_verify_hash(
            ed25519, public_key, vscf_alg_id_SHA256, test_ed25519_MESSAGE_SHA256_DIGEST, test_ed25519_SHA256_SIGNATURE);

    //  Check
    TEST_ASSERT_TRUE(verify_result);

    //  Cleanup
    vscf_ed25519_destroy(&ed25519);
    vscf_impl_destroy(&public_key);
    vscf_raw_public_key_destroy(&raw_public_key);
}

void
test__encrypt__message_with_imported_key__success(void) {

    //  Create raw public key
    vscf_impl_t *alg_info = vscf_simple_alg_info_impl(vscf_simple_alg_info_new_with_alg_id(vscf_alg_id_ED25519));
    vscf_raw_public_key_t *raw_public_key = vscf_raw_public_key_new_with_data(test_ed25519_PUBLIC_KEY, &alg_info);

    //  Configure key algorithm
    vscf_ed25519_t *ed25519 = vscf_ed25519_new();

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_ed25519_take_random(ed25519, vscf_fake_random_impl(fake_random));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ed25519_setup_defaults(ed25519));

    //  Import public key
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *public_key = vscf_ed25519_import_public_key(ed25519, raw_public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(public_key);

    //  Encrypt
    vsc_buffer_t *out =
            vsc_buffer_new_with_capacity(vscf_ed25519_encrypted_len(ed25519, public_key, test_ed25519_MESSAGE.len));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ed25519_encrypt(ed25519, public_key, test_ed25519_MESSAGE, out));

    //  Check
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_ed25519_ENCRYPTED_MESSAGE_WITH_AB_RANDOM, out);

    //  Cleanup
    vscf_ed25519_destroy(&ed25519);
    vscf_impl_destroy(&public_key);
    vsc_buffer_destroy(&out);
    vscf_raw_public_key_destroy(&raw_public_key);
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
    RUN_TEST(test__key_len__imported_public_key__returns_32);
    RUN_TEST(test__export_public_key__from_imported_public_key__are_equal);
    RUN_TEST(test__verify__with_imported_public_key_and_data_signature__valid_signature);
    RUN_TEST(test__encrypt__message_with_imported_key__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
