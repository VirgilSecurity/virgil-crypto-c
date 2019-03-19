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
#include "test_data_phe_server_client.h"


#define TEST_DEPENDENCIES_AVAILABLE VSCE_PHE_CLIENT &&VSCF_FAKE_RANDOM
#if TEST_DEPENDENCIES_AVAILABLE

#include <virgil/crypto/phe/vsce_phe_client.h>
#include <virgil/crypto/foundation/vscf_fake_random.h>


// --------------------------------------------------------------------------
//  Should have it to prevent linkage errors in MSVC.
// --------------------------------------------------------------------------
// clang-format off
void setUp(void) { }
void tearDown(void) { }
void suiteSetUp(void) { }
int suiteTearDown(int num_failures) { return num_failures; }
// clang-format on


void
test__enroll_account__mocked_rnd__should_match(void) {
    vsce_phe_client_t *client = vsce_phe_client_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_phe_client_setup_defaults(client));

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_phe_client_set_keys(client, test_phe_client_private_key, test_phe_server_public_key));

    vsc_buffer_t *buffer1, *buffer2;
    buffer1 = vsc_buffer_new_with_capacity(vsce_phe_client_enrollment_record_len(client));
    buffer2 = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_phe_server_rnd);

    vsce_phe_client_release_random(client);
    vsce_phe_client_take_random(client, vscf_fake_random_impl(fake_random));

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_phe_client_enroll_account(client, test_phe_server_enrollment_response,
                                                   test_phe_client_password, buffer1, buffer2));

    TEST_ASSERT_EQUAL(test_phe_client_enrollment_record.len, vsc_buffer_len(buffer1));
    TEST_ASSERT_EQUAL_MEMORY(
            test_phe_client_enrollment_record.bytes, vsc_buffer_bytes(buffer1), vsc_buffer_len(buffer1));

    TEST_ASSERT_EQUAL(test_phe_client_record_key.len, vsc_buffer_len(buffer2));
    TEST_ASSERT_EQUAL_MEMORY(test_phe_client_record_key.bytes, vsc_buffer_bytes(buffer2), vsc_buffer_len(buffer2));

    vsc_buffer_destroy(&buffer1);
    vsc_buffer_destroy(&buffer2);
    vsce_phe_client_destroy(&client);
}

void
test__verify_password__mocked_rnd__should_match(void) {
    vsce_phe_client_t *client = vsce_phe_client_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_phe_client_setup_defaults(client));

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_phe_client_set_keys(client, test_phe_client_private_key, test_phe_server_public_key));

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(vsce_phe_client_enrollment_record_len(client));

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_phe_server_rnd);

    vsce_phe_client_release_random(client);
    vsce_phe_client_take_random(client, vscf_fake_random_impl(fake_random));

    TEST_ASSERT_EQUAL(
            vsce_status_SUCCESS, vsce_phe_client_create_verify_password_request(
                                         client, test_phe_client_password, test_phe_client_enrollment_record, buffer));

    TEST_ASSERT_EQUAL(test_phe_client_verify_password_req.len, vsc_buffer_len(buffer));
    TEST_ASSERT_EQUAL_MEMORY(
            test_phe_client_verify_password_req.bytes, vsc_buffer_bytes(buffer), vsc_buffer_len(buffer));

    vsc_buffer_destroy(&buffer);
    vsce_phe_client_destroy(&client);
}

void
test__verify_password__mocked_rnd_invalid_pwd__should_match(void) {
    vsce_phe_client_t *client = vsce_phe_client_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_phe_client_setup_defaults(client));

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_phe_client_set_keys(client, test_phe_client_private_key, test_phe_server_public_key));

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(vsce_phe_client_enrollment_record_len(client));

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_phe_server_rnd);

    vsce_phe_client_release_random(client);
    vsce_phe_client_take_random(client, vscf_fake_random_impl(fake_random));

    TEST_ASSERT_EQUAL(
            vsce_status_SUCCESS, vsce_phe_client_create_verify_password_request(client, test_phe_client_bad_password,
                                         test_phe_client_enrollment_record, buffer));

    TEST_ASSERT_EQUAL(test_phe_client_verify_bad_password_req.len, vsc_buffer_len(buffer));
    TEST_ASSERT_EQUAL_MEMORY(
            test_phe_client_verify_bad_password_req.bytes, vsc_buffer_bytes(buffer), vsc_buffer_len(buffer));

    vsc_buffer_destroy(&buffer);
    vsce_phe_client_destroy(&client);
}

void
test__check_response__mocked_rnd__should_match(void) {
    vsce_phe_client_t *client = vsce_phe_client_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_phe_client_setup_defaults(client));

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_phe_client_set_keys(client, test_phe_client_private_key, test_phe_server_public_key));

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_phe_client_check_response_and_decrypt(client, test_phe_client_password,
                    test_phe_client_enrollment_record, test_phe_server_verify_password_resp, buffer));

    TEST_ASSERT_EQUAL(test_phe_client_record_key.len, vsc_buffer_len(buffer));
    TEST_ASSERT_EQUAL_MEMORY(test_phe_client_record_key.bytes, vsc_buffer_bytes(buffer), vsc_buffer_len(buffer));

    vsc_buffer_destroy(&buffer);
    vsce_phe_client_destroy(&client);
}

void
test__check_response__mocked_rnd_invalid_pwd__should_match(void) {
    vsce_phe_client_t *client = vsce_phe_client_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_phe_client_setup_defaults(client));

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_phe_client_set_keys(client, test_phe_client_private_key, test_phe_server_public_key));

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_phe_client_check_response_and_decrypt(client, test_phe_client_bad_password,
                    test_phe_client_enrollment_record, test_phe_server_verify_bad_password_resp, buffer));

    TEST_ASSERT_EQUAL(0, vsc_buffer_len(buffer));

    vsc_buffer_destroy(&buffer);
    vsce_phe_client_destroy(&client);
}

void
test__rotate_key__test_vector__should_match(void) {
    vsce_phe_client_t *client = vsce_phe_client_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_phe_client_setup_defaults(client));

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_phe_client_set_keys(client, test_phe_client_private_key, test_phe_server_public_key));

    vsc_buffer_t *buffer1, *buffer2;
    buffer1 = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    buffer2 = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    TEST_ASSERT_EQUAL(
            vsce_status_SUCCESS, vsce_phe_client_rotate_keys(client, test_phe_server_token, buffer1, buffer2));

    TEST_ASSERT_EQUAL(test_phe_client_rotated_client_sk.len, vsc_buffer_len(buffer1));
    TEST_ASSERT_EQUAL_MEMORY(
            test_phe_client_rotated_client_sk.bytes, vsc_buffer_bytes(buffer1), vsc_buffer_len(buffer1));

    TEST_ASSERT_EQUAL(test_phe_server_rotated_server_pub.len, vsc_buffer_len(buffer2));
    TEST_ASSERT_EQUAL_MEMORY(
            test_phe_server_rotated_server_pub.bytes, vsc_buffer_bytes(buffer2), vsc_buffer_len(buffer2));

    vsc_buffer_destroy(&buffer1);
    vsc_buffer_destroy(&buffer2);
    vsce_phe_client_destroy(&client);
}

void
test__update_record__test_vector__should_match(void) {
    vsce_phe_client_t *client = vsce_phe_client_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_phe_client_setup_defaults(client));

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_phe_client_set_keys(client, test_phe_client_private_key, test_phe_server_public_key));

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(vsce_phe_client_enrollment_record_len(client));

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_phe_client_update_enrollment_record(client,
                                                   test_phe_client_enrollment_record, test_phe_server_token, buffer));

    TEST_ASSERT_EQUAL(test_phe_client_updated_record.len, vsc_buffer_len(buffer));
    TEST_ASSERT_EQUAL_MEMORY(test_phe_client_updated_record.bytes, vsc_buffer_bytes(buffer), vsc_buffer_len(buffer));

    vsc_buffer_destroy(&buffer);
    vsce_phe_client_destroy(&client);
}

#endif // TEST_DEPENDENCIES_AVAILABLE

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__enroll_account__mocked_rnd__should_match);
    RUN_TEST(test__verify_password__mocked_rnd__should_match);
    RUN_TEST(test__verify_password__mocked_rnd_invalid_pwd__should_match);
    RUN_TEST(test__check_response__mocked_rnd__should_match);
    RUN_TEST(test__check_response__mocked_rnd_invalid_pwd__should_match);
    RUN_TEST(test__rotate_key__test_vector__should_match);
    RUN_TEST(test__update_record__test_vector__should_match);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
