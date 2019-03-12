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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_X25519_PRIVATE_KEY && VSCF_FAKE_RANDOM && VSCF_RANDOM)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_assert.h"

#include "vscf_public_key.h"
#include "vscf_x25519_private_key.h"
#include "vscf_x25519_public_key.h"
#include "vscf_fake_random.h"

#include "test_data_x25519.h"


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
test__key_len__imported_private_key__returns_32(void) {
    vscf_x25519_private_key_t *private_key = vscf_x25519_private_key_new();

    vscf_status_t result = vscf_x25519_private_key_import_private_key(private_key, test_x25519_PRIVATE_KEY);
    VSCF_ASSERT(result == vscf_status_SUCCESS);
    TEST_ASSERT_EQUAL(32, vscf_x25519_private_key_key_len(private_key));
    vscf_x25519_private_key_destroy(&private_key);
}

void
test__export_private_key__from_imported_private_key__expected_equal(void) {
    vscf_x25519_private_key_t *private_key = vscf_x25519_private_key_new();
    vscf_status_t result = vscf_x25519_private_key_import_private_key(private_key, test_x25519_PRIVATE_KEY);
    VSCF_ASSERT(result == vscf_status_SUCCESS);

    vsc_buffer_t *exported_key_buf =
            vsc_buffer_new_with_capacity(vscf_x25519_private_key_exported_private_key_len(private_key));
    result = vscf_x25519_private_key_export_private_key(private_key, exported_key_buf);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, result);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_x25519_PRIVATE_KEY, exported_key_buf);

    vsc_buffer_destroy(&exported_key_buf);
    vscf_x25519_private_key_destroy(&private_key);
}

void
test__extract_public_key__from_imported_private_key__when_exported_equals_public_key(void) {
    //  Setup dependencies
    vscf_x25519_private_key_t *private_key = vscf_x25519_private_key_new();

    //  Import private key
    vscf_status_t result = vscf_x25519_private_key_import_private_key(private_key, test_x25519_PRIVATE_KEY);
    VSCF_ASSERT(result == vscf_status_SUCCESS);

    //  Extract public key
    vscf_impl_t *public_key = vscf_x25519_private_key_extract_public_key(private_key);
    TEST_ASSERT_NOT_NULL(public_key);

    vsc_buffer_t *exported_key_buf = vsc_buffer_new_with_capacity(vscf_public_key_exported_public_key_len(public_key));

    vscf_status_t export_err = vscf_public_key_export_public_key(public_key, exported_key_buf);
    VSCF_ASSERT(export_err == vscf_status_SUCCESS);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_x25519_PUBLIC_KEY, exported_key_buf);

    vscf_x25519_private_key_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vsc_buffer_destroy(&exported_key_buf);
}

void
test__export_private_key_with_imported_x25519_private_key__when_exported_equals_x25519_private_key(void) {
    vscf_x25519_private_key_t *private_key = vscf_x25519_private_key_new();

    vscf_status_t result = vscf_x25519_private_key_import_private_key(private_key, test_x25519_PRIVATE_KEY);
    VSCF_ASSERT(result == vscf_status_SUCCESS);

    vsc_buffer_t *exported_key_buf =
            vsc_buffer_new_with_capacity(vscf_x25519_private_key_exported_private_key_len(private_key));

    vscf_status_t export_err = vscf_x25519_private_key_export_private_key(private_key, exported_key_buf);
    VSCF_ASSERT(export_err == vscf_status_SUCCESS);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_x25519_PRIVATE_KEY, exported_key_buf);

    vscf_x25519_private_key_destroy(&private_key);
    vsc_buffer_destroy(&exported_key_buf);
}

void
test__generate_key__exported_equals_private_key(void) {
    //  Setup dependencies
    vscf_x25519_private_key_t *private_key = vscf_x25519_private_key_new();

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_x25519_RANDOM);
    vscf_x25519_private_key_take_random(private_key, vscf_fake_random_impl(fake_random));

    vscf_status_t gen_res = vscf_x25519_private_key_generate_key(private_key);

    //  Check
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, gen_res);

    vsc_buffer_t *exported_key_buf =
            vsc_buffer_new_with_capacity(vscf_x25519_private_key_exported_private_key_len(private_key));

    vscf_status_t export_res = vscf_x25519_private_key_export_private_key(private_key, exported_key_buf);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, export_res);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_x25519_PRIVATE_KEY, exported_key_buf);

    //  Cleanup
    vsc_buffer_destroy(&exported_key_buf);
    vscf_x25519_private_key_destroy(&private_key);
}

void
test__decrypt__message_with_imported_key__success(void) {

    vscf_x25519_private_key_t *private_key = vscf_x25519_private_key_new();
    vscf_x25519_private_key_setup_defaults(private_key);

    vscf_status_t result = vscf_x25519_private_key_import_private_key(private_key, test_x25519_PRIVATE_KEY);
    VSCF_ASSERT(result == vscf_status_SUCCESS);

    vsc_buffer_t *dec_msg = vsc_buffer_new_with_capacity(
            vscf_x25519_private_key_decrypted_len(private_key, test_x25519_ENCRYPTED_MESSAGE.len));
    vscf_status_t status = vscf_x25519_private_key_decrypt(private_key, test_x25519_ENCRYPTED_MESSAGE, dec_msg);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_x25519_MESSAGE, dec_msg);

    vsc_buffer_destroy(&dec_msg);
    vscf_x25519_private_key_destroy(&private_key);
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
    RUN_TEST(test__export_private_key_with_imported_x25519_private_key__when_exported_equals_x25519_private_key);
    RUN_TEST(test__generate_key__exported_equals_private_key);
    RUN_TEST(test__decrypt__message_with_imported_key__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
