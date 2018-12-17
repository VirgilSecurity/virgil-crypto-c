//  Copyright (C) 2015-2018 Virgil Security Inc.
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

#include <virgil/crypto/phe/vsce_phe_server.h>
#include "unity.h"
#include "test_utils.h"
#include "test_data_phe_server_client.h"
#include <virgil/crypto/foundation/vscf_fake_random.h>

#define TEST_DEPENDENCIES_AVAILABLE VSCE_PHE_SERVER
#if TEST_DEPENDENCIES_AVAILABLE

void
test__get_enrollment__mocked_rnd__should_match(void) {
    vsce_phe_server_t *server = vsce_phe_server_new();

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(vsce_phe_server_enrollment_response_len(server));

    vscf_fake_random_impl_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_phe_server_rnd);

    vsce_phe_server_release_random(server);
    vsce_phe_server_take_random(server, vscf_fake_random_impl(fake_random));

    TEST_ASSERT_EQUAL(vsce_SUCCESS,
            vsce_phe_server_get_enrollment(server, test_phe_server_private_key, test_phe_server_public_key, buffer));

    TEST_ASSERT_EQUAL(test_phe_server_enrollment_response.len, vsc_buffer_len(buffer));
    TEST_ASSERT_EQUAL_MEMORY(
            test_phe_server_enrollment_response.bytes, vsc_buffer_bytes(buffer), vsc_buffer_len(buffer));

    vsc_buffer_destroy(&buffer);
    vsce_phe_server_destroy(&server);
}

void
test__verify_password__valid_password__should_match(void) {
    vsce_phe_server_t *server = vsce_phe_server_new();

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(vsce_phe_server_verify_password_response_len(server));

    vscf_fake_random_impl_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_phe_server_rnd);

    vsce_phe_server_release_random(server);
    vsce_phe_server_take_random(server, vscf_fake_random_impl(fake_random));

    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_verify_password(server, test_phe_server_private_key,
                                            test_phe_server_public_key, test_phe_client_verify_password_req, buffer));

    TEST_ASSERT_EQUAL(test_phe_server_verify_password_resp.len, vsc_buffer_len(buffer));
    TEST_ASSERT_EQUAL_MEMORY(
            test_phe_server_verify_password_resp.bytes, vsc_buffer_bytes(buffer), vsc_buffer_len(buffer));

    vsc_buffer_destroy(&buffer);
    vsce_phe_server_destroy(&server);
}

void
test__verify_password__invalid_password__should_match(void) {
    vsce_phe_server_t *server = vsce_phe_server_new();

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(vsce_phe_server_verify_password_response_len(server));

    vscf_fake_random_impl_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_phe_server_rnd);

    vsce_phe_server_release_random(server);
    vsce_phe_server_take_random(server, vscf_fake_random_impl(fake_random));

    TEST_ASSERT_EQUAL(
            vsce_SUCCESS, vsce_phe_server_verify_password(server, test_phe_server_private_key,
                                  test_phe_server_public_key, test_phe_client_verify_bad_password_req, buffer));

    TEST_ASSERT_EQUAL(test_phe_server_verify_bad_password_resp.len, vsc_buffer_len(buffer));
    TEST_ASSERT_EQUAL_MEMORY(
            test_phe_server_verify_bad_password_resp.bytes, vsc_buffer_bytes(buffer), vsc_buffer_len(buffer));

    vsc_buffer_destroy(&buffer);
    vsce_phe_server_destroy(&server);
}

void
test__rotate_keys__mocked_rnd__should_match(void) {
    vsce_phe_server_t *server = vsce_phe_server_new();

    vsc_buffer_t *buffer1, *buffer2, *buffer3;
    buffer1 = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    buffer2 = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    buffer3 = vsc_buffer_new_with_capacity(vsce_phe_server_update_token_len(server));

    vscf_fake_random_impl_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_phe_server_rnd);

    vsce_phe_server_release_random(server);
    vsce_phe_server_take_random(server, vscf_fake_random_impl(fake_random));

    TEST_ASSERT_EQUAL(
            vsce_SUCCESS, vsce_phe_server_rotate_keys(server, test_phe_server_private_key, buffer1, buffer2, buffer3));

    TEST_ASSERT_EQUAL(test_phe_server_rotated_server_sk.len, vsc_buffer_len(buffer1));
    TEST_ASSERT_EQUAL_MEMORY(
            test_phe_server_rotated_server_sk.bytes, vsc_buffer_bytes(buffer1), vsc_buffer_len(buffer1));

    TEST_ASSERT_EQUAL(test_phe_server_rotated_server_pub.len, vsc_buffer_len(buffer2));
    TEST_ASSERT_EQUAL_MEMORY(
            test_phe_server_rotated_server_pub.bytes, vsc_buffer_bytes(buffer2), vsc_buffer_len(buffer2));

    TEST_ASSERT_EQUAL(test_phe_server_token.len, vsc_buffer_len(buffer3));
    TEST_ASSERT_EQUAL_MEMORY(test_phe_server_token.bytes, vsc_buffer_bytes(buffer3), vsc_buffer_len(buffer3));

    vsc_buffer_destroy(&buffer1);
    vsc_buffer_destroy(&buffer2);
    vsc_buffer_destroy(&buffer3);
    vsce_phe_server_destroy(&server);
}

#endif // TEST_DEPENDENCIES_AVAILABLE

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__get_enrollment__mocked_rnd__should_match);
    RUN_TEST(test__verify_password__valid_password__should_match);
    RUN_TEST(test__verify_password__invalid_password__should_match);
    RUN_TEST(test__rotate_keys__mocked_rnd__should_match);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}