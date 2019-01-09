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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_ED25519_PRIVATE_KEY && VSCF_FAKE_RANDOM && VSCF_RANDOM && VSCF_ENDIANNESS)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_assert.h"

#include "vscf_public_key.h"
#include "vscf_ed25519_private_key.h"
#include "vscf_ed25519_public_key.h"
#include "vscf_fake_random.h"

#include "test_data_ed25519.h"


// --------------------------------------------------------------------------
//  Should have it to prevent linkage erros in MSVC.
// --------------------------------------------------------------------------
// clang-format off
void setUp(void) { }
void tearDown(void) { }
void suiteSetUp(void) { }
int suiteTearDown(int num_failures) { return num_failures; }
// clang-format on


// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------
void
test__ed25519_private_key_key_len__imported_PRIVATE_KEY__returns_32(void) {
    vscf_ed25519_private_key_t *private_key = vscf_ed25519_private_key_new();

    vscf_error_t result = vscf_ed25519_private_key_import_private_key(private_key, test_ed25519_PRIVATE_KEY);
    VSCF_ASSERT(result == vscf_SUCCESS);
    TEST_ASSERT_EQUAL(32, vscf_ed25519_private_key_key_len(private_key));
    vscf_ed25519_private_key_destroy(&private_key);
}

void
test__ed25519_private_key_export_private_key__from_imported_PRIVATE_KEY__expected_equal(void) {
    vscf_ed25519_private_key_t *private_key = vscf_ed25519_private_key_new();
    vscf_error_t result = vscf_ed25519_private_key_import_private_key(private_key, test_ed25519_PRIVATE_KEY);
    VSCF_ASSERT(result == vscf_SUCCESS);

    vsc_buffer_t *exported_key_buf =
            vsc_buffer_new_with_capacity(vscf_ed25519_private_key_exported_private_key_len(private_key));
    result = vscf_ed25519_private_key_export_private_key(private_key, exported_key_buf);

    TEST_ASSERT_EQUAL(vscf_SUCCESS, result);
    TEST_ASSERT_EQUAL(test_ed25519_PRIVATE_KEY.len, vsc_buffer_len(exported_key_buf));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(
            test_ed25519_PRIVATE_KEY.bytes, vsc_buffer_bytes(exported_key_buf), vsc_buffer_len(exported_key_buf));

    vsc_buffer_destroy(&exported_key_buf);
    vscf_ed25519_private_key_destroy(&private_key);
}

void
test__ed25519_private_key_extract_public_key__from_imported_PRIVATE_KEY__when_exported_equals_PUBLIC_KEY(void) {
    //  Setup dependencies
    vscf_ed25519_private_key_t *private_key = vscf_ed25519_private_key_new();

    //  Import private key
    // vscf_error_t result = vscf_ed25519_private_key_import_private_key(private_key, test_ed25519_PRIVATE_KEY);
    vscf_error_t result = vscf_ed25519_private_key_import_private_key(private_key, test_ed25519_PRIVATE_KEY_REVERSE);
    VSCF_ASSERT(result == vscf_SUCCESS);

    //  Extract public key
    vscf_impl_t *public_key = vscf_ed25519_private_key_extract_public_key(private_key);
    TEST_ASSERT_NOT_NULL(public_key);

    vsc_buffer_t *exported_key_buf = vsc_buffer_new_with_capacity(vscf_public_key_exported_public_key_len(public_key));

    vscf_error_t export_err = vscf_public_key_export_public_key(public_key, exported_key_buf);
    VSCF_ASSERT(export_err == vscf_SUCCESS);

    //  Check

    TEST_ASSERT_EQUAL(test_ed25519_PUBLIC_KEY.len, vsc_buffer_len(exported_key_buf));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(
            test_ed25519_PUBLIC_KEY.bytes, vsc_buffer_bytes(exported_key_buf), vsc_buffer_len(exported_key_buf));

    vscf_ed25519_private_key_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vsc_buffer_destroy(&exported_key_buf);
}

void
test__ed25519_private_key_sign__with_imported_PRIVATE_KEY_and_MESSAGE__equals_MESSAGE_SIGNATURE(void) {

    //  Setup dependencies
    vscf_ed25519_private_key_t *private_key = vscf_ed25519_private_key_new();

    //  Import private key
    vscf_error_t result = vscf_ed25519_private_key_import_private_key(private_key, test_ed25519_PRIVATE_KEY_REVERSE);
    VSCF_ASSERT(result == vscf_SUCCESS);

    //  Sign
    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_ed25519_private_key_signature_len(private_key));
    vscf_error_t sign_result = vscf_ed25519_private_key_sign(private_key, test_ed25519_MESSAGE, signature);

    //  Check
    TEST_ASSERT_EQUAL(vscf_SUCCESS, sign_result);
    TEST_ASSERT_EQUAL(test_ed25519_SIGNATURE.len, vsc_buffer_len(signature));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_ed25519_SIGNATURE.bytes, vsc_buffer_bytes(signature), vsc_buffer_len(signature));

    //  Cleanup
    vsc_buffer_destroy(&signature);
    vscf_ed25519_private_key_destroy(&private_key);
}

void
test__ed25519_private_key_export_private_key_with_imported_ed25519_PRIVATE_KEY__when_exported_equals_ed25519_PRIVATE_KEY(
        void) {
    //  Setup dependencies
    vscf_ed25519_private_key_t *private_key = vscf_ed25519_private_key_new();

    //  Import private key
    vscf_error_t result = vscf_ed25519_private_key_import_private_key(private_key, test_ed25519_PRIVATE_KEY);
    VSCF_ASSERT(result == vscf_SUCCESS);

    vsc_buffer_t *exported_key_buf =
            vsc_buffer_new_with_capacity(vscf_ed25519_private_key_exported_private_key_len(private_key));

    vscf_error_t export_err = vscf_ed25519_private_key_export_private_key(private_key, exported_key_buf);
    VSCF_ASSERT(export_err == vscf_SUCCESS);

    // Check
    TEST_ASSERT_EQUAL(test_ed25519_PRIVATE_KEY.len, vsc_buffer_len(exported_key_buf));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(
            test_ed25519_PRIVATE_KEY.bytes, vsc_buffer_bytes(exported_key_buf), vsc_buffer_len(exported_key_buf));
    vscf_ed25519_private_key_destroy(&private_key);
    vsc_buffer_destroy(&exported_key_buf);
}

void
test__ed25519_private_key_generate_key__exported_equals_GENERATED_PRIVATE_KEY(void) {
    //  Setup dependencies
    vscf_ed25519_private_key_t *private_key = vscf_ed25519_private_key_new();

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_ed25519_RANDOM);
    vscf_ed25519_private_key_take_random(private_key, vscf_fake_random_impl(fake_random));

    vscf_error_t gen_res = vscf_ed25519_private_key_generate_key(private_key);

    //  Check
    TEST_ASSERT_EQUAL(vscf_SUCCESS, gen_res);

    vsc_buffer_t *exported_key_buf =
            vsc_buffer_new_with_capacity(vscf_ed25519_private_key_exported_private_key_len(private_key));

    vscf_error_t export_res = vscf_ed25519_private_key_export_private_key(private_key, exported_key_buf);

    TEST_ASSERT_EQUAL(vscf_SUCCESS, export_res);
    TEST_ASSERT_EQUAL(test_ed25519_GENERATED_PRIVATE_KEY.len, vsc_buffer_len(exported_key_buf));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_ed25519_GENERATED_PRIVATE_KEY.bytes, vsc_buffer_bytes(exported_key_buf),
            vsc_buffer_len(exported_key_buf));

    //  Cleanup
    vsc_buffer_destroy(&exported_key_buf);
    vscf_ed25519_private_key_destroy(&private_key);
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
    RUN_TEST(test__ed25519_private_key_key_len__imported_PRIVATE_KEY__returns_32);
    RUN_TEST(test__ed25519_private_key_export_private_key__from_imported_PRIVATE_KEY__expected_equal);
    RUN_TEST(test__ed25519_private_key_extract_public_key__from_imported_PRIVATE_KEY__when_exported_equals_PUBLIC_KEY);
    RUN_TEST(test__ed25519_private_key_sign__with_imported_PRIVATE_KEY_and_MESSAGE__equals_MESSAGE_SIGNATURE);
    RUN_TEST(test__ed25519_private_key_export_private_key_with_imported_ed25519_PRIVATE_KEY__when_exported_equals_ed25519_PRIVATE_KEY);
    RUN_TEST(test__ed25519_private_key_generate_key__exported_equals_GENERATED_PRIVATE_KEY);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
