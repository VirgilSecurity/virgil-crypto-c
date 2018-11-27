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

#include <virgil/crypto/phe/vsce_phe_client.h>
#include <PHEModels.pb.h>
#include <virgil/crypto/phe/private/vsce_phe_client_defs.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <virgil/crypto/phe/vsce_phe_server.h>
#include "unity.h"
#include "test_utils.h"
#include "pb_encode.h"

#define TEST_DEPENDENCIES_AVAILABLE VSCE_PHE_CLIENT && VSCE_PHE_SERVER
#if TEST_DEPENDENCIES_AVAILABLE

void test__1() {
    byte client_private_key[vsce_phe_common_PHE_PRIVATE_KEY_LENGTH];

    vscf_ctr_drbg_impl_t *rng = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng);
    vsc_buffer_t *client_private_key_buf = vsc_buffer_new();
    vsc_buffer_use(client_private_key_buf, client_private_key, sizeof(client_private_key));
    vscf_ctr_drbg_random(rng, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH, client_private_key_buf);
    vsc_buffer_destroy(&client_private_key_buf);

    byte pwd[10];
    vsc_data_t pwd_data = vsc_data(pwd, sizeof(pwd));
    vsc_buffer_t *pwd1_buf = vsc_buffer_new();
    vsc_buffer_use(pwd1_buf, pwd, sizeof(pwd));
    vscf_ctr_drbg_random(rng, sizeof(pwd), pwd1_buf);
    vsc_buffer_destroy(&pwd1_buf);

    vscf_ctr_drbg_destroy(&rng);

    vsce_phe_client_t *client = vsce_phe_client_new_with_private_key(vsc_data(client_private_key, sizeof(client_private_key)));
    vsce_phe_server_t *server = vsce_phe_server_new();

    vsc_buffer_t *server_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t *server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_generate_server_key_pair(server, server_private_key, server_public_key));

    // FIXME
    vsc_buffer_t *enrollment_response = vsc_buffer_new_with_capacity(500);
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_get_enrollment(server,
            vsc_buffer_data(server_private_key), enrollment_response));

    vsc_buffer_t *enrollment_record = vsc_buffer_new_with_capacity(500);
    vsc_buffer_t *account_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH);
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_enroll_account(client, vsc_buffer_data(enrollment_response),
            pwd_data, enrollment_record, account_key));
    TEST_ASSERT_EQUAL(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH, vsc_buffer_len(account_key));

    vsc_buffer_t *verify_password_request = vsc_buffer_new_with_capacity(500);
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_create_verify_password_request(client, pwd_data,
            vsc_buffer_data(enrollment_record), verify_password_request));

    vsc_buffer_t *verify_password_response = vsc_buffer_new_with_capacity(500);
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_verify_password(server, vsc_buffer_data(server_private_key), vsc_buffer_data(server_public_key),
            vsc_buffer_data(verify_password_request), verify_password_response));

    vsc_buffer_t *account_key2 = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH);
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_check_response_and_decrypt(client, pwd_data,
            vsc_buffer_data(enrollment_record), vsc_buffer_data(verify_password_response), account_key2));

    TEST_ASSERT_EQUAL_MEMORY(vsc_buffer_bytes(account_key), vsc_buffer_bytes(account_key), vsc_buffer_len(account_key));
    TEST_ASSERT_EQUAL(vsc_buffer_len(account_key), vsc_buffer_len(account_key2));

    vsce_phe_client_destroy(&client);
    vsce_phe_server_destroy(&server);

    vsc_buffer_destroy(&server_private_key);
    vsc_buffer_destroy(&server_public_key);

    vsc_buffer_destroy(&enrollment_response);
    vsc_buffer_destroy(&enrollment_record);
    vsc_buffer_destroy(&account_key);
    vsc_buffer_destroy(&verify_password_request);
    vsc_buffer_destroy(&verify_password_response);
}

void test__2() {
    byte client_private_key[vsce_phe_common_PHE_PRIVATE_KEY_LENGTH];

    vscf_ctr_drbg_impl_t *rng = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng);
    vsc_buffer_t *client_private_key_buf = vsc_buffer_new();
    vsc_buffer_use(client_private_key_buf, client_private_key, sizeof(client_private_key));
    vscf_ctr_drbg_random(rng, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH, client_private_key_buf);
    vsc_buffer_destroy(&client_private_key_buf);

    byte pwd1[10], pwd2[10];
    vsc_data_t pwd1_data = vsc_data(pwd1, sizeof(pwd1));
    vsc_data_t pwd2_data = vsc_data(pwd2, sizeof(pwd2));
    vsc_buffer_t *pwd1_buf = vsc_buffer_new();
    vsc_buffer_t *pwd2_buf = vsc_buffer_new();
    vsc_buffer_use(pwd1_buf, pwd1, sizeof(pwd1));
    vsc_buffer_use(pwd2_buf, pwd2, sizeof(pwd2));
    vscf_ctr_drbg_random(rng, sizeof(pwd1), pwd1_buf);
    vscf_ctr_drbg_random(rng, sizeof(pwd2), pwd2_buf);
    vsc_buffer_destroy(&pwd1_buf);
    vsc_buffer_destroy(&pwd2_buf);

    vscf_ctr_drbg_destroy(&rng);

    vsce_phe_client_t *client = vsce_phe_client_new_with_private_key(vsc_data(client_private_key, sizeof(client_private_key)));
    vsce_phe_server_t *server = vsce_phe_server_new();

    vsc_buffer_t *server_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t *server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_generate_server_key_pair(server, server_private_key, server_public_key));

    // FIXME
    vsc_buffer_t *enrollment_response = vsc_buffer_new_with_capacity(500);
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_get_enrollment(server,
                                                                   vsc_buffer_data(server_private_key), enrollment_response));

    vsc_buffer_t *enrollment_record = vsc_buffer_new_with_capacity(500);
    vsc_buffer_t *account_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH);
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_enroll_account(client, vsc_buffer_data(enrollment_response),
                                                                   pwd1_data, enrollment_record, account_key));

    vsc_buffer_t *verify_password_request = vsc_buffer_new_with_capacity(500);
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_create_verify_password_request(client, pwd2_data,
                                                                                   vsc_buffer_data(enrollment_record), verify_password_request));

    vsc_buffer_t *verify_password_response = vsc_buffer_new_with_capacity(500);
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_verify_password(server, vsc_buffer_data(server_private_key), vsc_buffer_data(server_public_key),
                                                                    vsc_buffer_data(verify_password_request), verify_password_response));

    vsc_buffer_t *account_key2 = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH);
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_check_response_and_decrypt(client, pwd2_data,
                                                                               vsc_buffer_data(enrollment_record), vsc_buffer_data(verify_password_response), account_key2));

    TEST_ASSERT_EQUAL(0, vsc_buffer_len(account_key2));

    vsce_phe_client_destroy(&client);
    vsce_phe_server_destroy(&server);

    vsc_buffer_destroy(&server_private_key);
    vsc_buffer_destroy(&server_public_key);

    vsc_buffer_destroy(&enrollment_response);
    vsc_buffer_destroy(&enrollment_record);
    vsc_buffer_destroy(&account_key);
    vsc_buffer_destroy(&verify_password_request);
    vsc_buffer_destroy(&verify_password_response);
}


#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__1);
    RUN_TEST(test__2);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}

