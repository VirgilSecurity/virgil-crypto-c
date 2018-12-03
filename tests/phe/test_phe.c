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
#include <virgil/crypto/foundation/private/vscf_ctr_drbg_impl.h>
#include <virgil/crypto/phe/vsce_phe_server.h>
#include "unity.h"
#include "test_utils.h"
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

#define TEST_DEPENDENCIES_AVAILABLE VSCE_PHE_CLIENT &&VSCE_PHE_SERVER
#if TEST_DEPENDENCIES_AVAILABLE

static void
generate_pwd(vsc_buffer_t **pwd_ref) {
    vscf_ctr_drbg_impl_t rng;
    vscf_ctr_drbg_init(&rng);
    vscf_ctr_drbg_setup_defaults(&rng);

    *pwd_ref = vsc_buffer_new_with_capacity(10);

    vscf_error_t status = vscf_ctr_drbg_random(&rng, 10, *pwd_ref);
    TEST_ASSERT_EQUAL(vscf_SUCCESS, status);

    vscf_ctr_drbg_cleanup(&rng);
}

static void
init(vsce_phe_server_t **server_ref, vsce_phe_client_t **client_ref, vsc_buffer_t **server_private_key_ref,
        vsc_buffer_t **server_public_key_ref) {
    byte client_private_key[vsce_phe_common_PHE_PRIVATE_KEY_LENGTH];

    vscf_ctr_drbg_impl_t rng;
    vscf_ctr_drbg_init(&rng);
    vscf_ctr_drbg_setup_defaults(&rng);

    vsc_buffer_t buffer;
    vsc_buffer_init(&buffer);

    vsc_buffer_use(&buffer, client_private_key, sizeof(client_private_key));

    // Not secure way to generate private key, though it is OK for tests
    vscf_error_t status = vscf_ctr_drbg_random(&rng, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH, &buffer);
    TEST_ASSERT_EQUAL(vscf_SUCCESS, status);

    vsc_buffer_delete(&buffer);

    *server_ref = vsce_phe_server_new();

    *server_private_key_ref = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    *server_public_key_ref = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_SUCCESS,
            vsce_phe_server_generate_server_key_pair(*server_ref, *server_private_key_ref, *server_public_key_ref));

    *client_ref = vsce_phe_client_new_with_keys(
            vsc_data(client_private_key, sizeof(client_private_key)), vsc_buffer_data(*server_public_key_ref));

    vscf_ctr_drbg_cleanup(&rng);
}

static void
init_invalid_server_pub_key(vsce_phe_server_t **server_ref, vsce_phe_client_t **client_ref,
        vsc_buffer_t **server_private_key_ref, vsc_buffer_t **server_public_key_ref) {
    byte client_private_key[vsce_phe_common_PHE_PRIVATE_KEY_LENGTH];

    vscf_ctr_drbg_impl_t rng;
    vscf_ctr_drbg_init(&rng);
    vscf_ctr_drbg_setup_defaults(&rng);

    vsc_buffer_t buffer;
    vsc_buffer_init(&buffer);

    vsc_buffer_use(&buffer, client_private_key, sizeof(client_private_key));

    // Not secure way to generate private key, though it is OK for tests
    vscf_error_t status = vscf_ctr_drbg_random(&rng, vsce_phe_common_PHE_PRIVATE_KEY_LENGTH, &buffer);
    TEST_ASSERT_EQUAL(vscf_SUCCESS, status);

    vsc_buffer_delete(&buffer);

    *server_ref = vsce_phe_server_new();

    *server_private_key_ref = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    *server_public_key_ref = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_SUCCESS,
            vsce_phe_server_generate_server_key_pair(*server_ref, *server_private_key_ref, *server_public_key_ref));

    vsc_buffer_t *invalid_server_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t *invalid_server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_generate_server_key_pair(
                                            *server_ref, invalid_server_private_key, invalid_server_public_key));

    *client_ref = vsce_phe_client_new_with_keys(
            vsc_data(client_private_key, sizeof(client_private_key)), vsc_buffer_data(invalid_server_public_key));

    vscf_ctr_drbg_cleanup(&rng);

    vsc_buffer_destroy(&invalid_server_private_key);
    vsc_buffer_destroy(&invalid_server_public_key);
}

void
test__full_flow__random_correct_pwd__should_succeed() {
    vsce_phe_server_t *server;
    vsce_phe_client_t *client;
    vsc_buffer_t *server_private_key, *server_public_key;

    init(&server, &client, &server_private_key, &server_public_key);

    vsc_buffer_t *pwd;

    generate_pwd(&pwd);

    vsc_data_t pwd_data = vsc_data(vsc_buffer_bytes(pwd), vsc_buffer_len(pwd));

    vsc_buffer_t *enrollment_response = vsc_buffer_new_with_capacity(vsce_phe_server_enrollment_response_len(server));
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_get_enrollment(server, vsc_buffer_data(server_private_key),
                                            vsc_buffer_data(server_public_key), enrollment_response));

    vsc_buffer_t *enrollment_record = vsc_buffer_new_with_capacity(vsce_phe_client_enrollment_record_len(client));
    vsc_buffer_t *account_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH);
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_enroll_account(client, vsc_buffer_data(enrollment_response),
                                            pwd_data, enrollment_record, account_key));
    TEST_ASSERT_EQUAL(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH, vsc_buffer_len(account_key));

    vsc_buffer_t *verify_password_request =
            vsc_buffer_new_with_capacity(vsce_phe_client_verify_password_request_len(client));
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_create_verify_password_request(client, pwd_data,
                                            vsc_buffer_data(enrollment_record), verify_password_request));

    vsc_buffer_t *verify_password_response =
            vsc_buffer_new_with_capacity(vsce_phe_server_verify_password_response_len(server));
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_verify_password(server, vsc_buffer_data(server_private_key),
                                            vsc_buffer_data(server_public_key),
                                            vsc_buffer_data(verify_password_request), verify_password_response));

    vsc_buffer_t *account_key2 = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH);
    TEST_ASSERT_EQUAL(vsce_SUCCESS,
            vsce_phe_client_check_response_and_decrypt(client, pwd_data, vsc_buffer_data(enrollment_record),
                    vsc_buffer_data(verify_password_response), account_key2));

    TEST_ASSERT_EQUAL_MEMORY(
            vsc_buffer_bytes(account_key), vsc_buffer_bytes(account_key2), vsc_buffer_len(account_key));
    TEST_ASSERT_EQUAL(vsc_buffer_len(account_key), vsc_buffer_len(account_key2));

    vsce_phe_client_destroy(&client);
    vsce_phe_server_destroy(&server);

    vsc_buffer_destroy(&server_private_key);
    vsc_buffer_destroy(&server_public_key);
    vsc_buffer_destroy(&pwd);

    vsc_buffer_destroy(&enrollment_response);
    vsc_buffer_destroy(&enrollment_record);
    vsc_buffer_destroy(&account_key);
    vsc_buffer_destroy(&account_key2);
    vsc_buffer_destroy(&verify_password_request);
    vsc_buffer_destroy(&verify_password_response);
}

void
test__full_flow__random_incorrect_pwd__should_fail() {
    vsce_phe_server_t *server;
    vsce_phe_client_t *client;
    vsc_buffer_t *server_private_key, *server_public_key;

    init(&server, &client, &server_private_key, &server_public_key);

    vsc_buffer_t *pwd1, *pwd2;

    generate_pwd(&pwd1);
    generate_pwd(&pwd2);

    TEST_ASSERT(vsc_buffer_len(pwd1) != vsc_buffer_len(pwd2) ||
                memcmp(vsc_buffer_bytes(pwd1), vsc_buffer_bytes(pwd2), vsc_buffer_len(pwd1)) != 0);

    vsc_data_t pwd1_data = vsc_data(vsc_buffer_bytes(pwd1), vsc_buffer_len(pwd1));
    vsc_data_t pwd2_data = vsc_data(vsc_buffer_bytes(pwd2), vsc_buffer_len(pwd2));

    vsc_buffer_t *enrollment_response = vsc_buffer_new_with_capacity(vsce_phe_server_enrollment_response_len(server));
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_get_enrollment(server, vsc_buffer_data(server_private_key),
                                            vsc_buffer_data(server_public_key), enrollment_response));

    vsc_buffer_t *enrollment_record = vsc_buffer_new_with_capacity(vsce_phe_client_enrollment_record_len(client));
    vsc_buffer_t *account_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH);
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_enroll_account(client, vsc_buffer_data(enrollment_response),
                                            pwd1_data, enrollment_record, account_key));

    vsc_buffer_t *verify_password_request =
            vsc_buffer_new_with_capacity(vsce_phe_client_verify_password_request_len(client));
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_create_verify_password_request(client, pwd2_data,
                                            vsc_buffer_data(enrollment_record), verify_password_request));

    vsc_buffer_t *verify_password_response =
            vsc_buffer_new_with_capacity(vsce_phe_server_verify_password_response_len(server));
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_verify_password(server, vsc_buffer_data(server_private_key),
                                            vsc_buffer_data(server_public_key),
                                            vsc_buffer_data(verify_password_request), verify_password_response));

    vsc_buffer_t *account_key2 = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH);
    TEST_ASSERT_EQUAL(vsce_SUCCESS,
            vsce_phe_client_check_response_and_decrypt(client, pwd2_data, vsc_buffer_data(enrollment_record),
                    vsc_buffer_data(verify_password_response), account_key2));

    TEST_ASSERT_EQUAL(0, vsc_buffer_len(account_key2));

    vsce_phe_client_destroy(&client);
    vsce_phe_server_destroy(&server);

    vsc_buffer_destroy(&server_private_key);
    vsc_buffer_destroy(&server_public_key);

    vsc_buffer_destroy(&pwd1);
    vsc_buffer_destroy(&pwd2);

    vsc_buffer_destroy(&enrollment_response);
    vsc_buffer_destroy(&enrollment_record);
    vsc_buffer_destroy(&account_key);
    vsc_buffer_destroy(&account_key2);
    vsc_buffer_destroy(&verify_password_request);
    vsc_buffer_destroy(&verify_password_response);
}

void
test__rotation__random_rotation__server_public_keys_match() {
    vsce_phe_server_t *server;
    vsce_phe_client_t *client;
    vsc_buffer_t *server_private_key, *server_public_key;

    init(&server, &client, &server_private_key, &server_public_key);

    vsc_buffer_t *new_server_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t *new_server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_t *token = vsc_buffer_new_with_capacity(vsce_phe_server_update_token_len(server));

    vsce_phe_server_rotate_keys(
            server, vsc_buffer_data(server_private_key), new_server_private_key, new_server_public_key, token);

    vsc_buffer_t *new_client_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t *new_server_public_key2 = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_rotate_keys(client, vsc_buffer_data(token), new_client_private_key,
                                            new_server_public_key2));

    TEST_ASSERT_EQUAL(vsc_buffer_len(new_server_public_key), vsc_buffer_len(new_server_public_key2));
    TEST_ASSERT_EQUAL_MEMORY(vsc_buffer_bytes(new_server_public_key), vsc_buffer_bytes(new_server_public_key2),
            vsc_buffer_len(new_server_public_key));

    vsce_phe_client_destroy(&client);
    vsce_phe_server_destroy(&server);

    vsc_buffer_destroy(&server_private_key);
    vsc_buffer_destroy(&server_public_key);
    vsc_buffer_destroy(&new_server_private_key);
    vsc_buffer_destroy(&new_server_public_key);
    vsc_buffer_destroy(&new_server_public_key2);
    vsc_buffer_destroy(&new_client_private_key);
    vsc_buffer_destroy(&token);
}

void
test__rotation__random_rotation__enrollment_record_updated_successfully() {
    vsce_phe_server_t *server;
    vsce_phe_client_t *client;
    vsc_buffer_t *server_private_key, *server_public_key;

    init(&server, &client, &server_private_key, &server_public_key);

    vsc_buffer_t *pwd;

    generate_pwd(&pwd);

    vsc_data_t pwd_data = vsc_data(vsc_buffer_bytes(pwd), vsc_buffer_len(pwd));

    vsc_buffer_t *enrollment_response = vsc_buffer_new_with_capacity(vsce_phe_server_enrollment_response_len(server));
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_get_enrollment(server, vsc_buffer_data(server_private_key),
                                            vsc_buffer_data(server_public_key), enrollment_response));

    vsc_buffer_t *enrollment_record = vsc_buffer_new_with_capacity(vsce_phe_client_enrollment_record_len(client));
    vsc_buffer_t *account_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH);
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_enroll_account(client, vsc_buffer_data(enrollment_response),
                                            pwd_data, enrollment_record, account_key));
    TEST_ASSERT_EQUAL(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH, vsc_buffer_len(account_key));

    vsc_buffer_t *new_server_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t *new_server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_t *token = vsc_buffer_new_with_capacity(vsce_phe_server_update_token_len(server));

    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_rotate_keys(server, vsc_buffer_data(server_private_key),
                                            new_server_private_key, new_server_public_key, token));

    vsc_buffer_t *new_client_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t *new_server_public_key2 = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_rotate_keys(client, vsc_buffer_data(token), new_client_private_key,
                                            new_server_public_key2));

    vsce_phe_client_t *new_client = vsce_phe_client_new_with_keys(
            vsc_buffer_data(new_client_private_key), vsc_buffer_data(new_server_public_key));

    vsc_buffer_t *new_enrollment_record = vsc_buffer_new_with_capacity(vsce_phe_client_enrollment_record_len(client));

    TEST_ASSERT_EQUAL(
            vsce_SUCCESS, vsce_phe_client_update_enrollment_record(new_client, vsc_buffer_data(enrollment_record),
                                  vsc_buffer_data(token), new_enrollment_record));

    vsc_buffer_t *verify_password_request =
            vsc_buffer_new_with_capacity(vsce_phe_client_verify_password_request_len(client));
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_create_verify_password_request(new_client, pwd_data,
                                            vsc_buffer_data(new_enrollment_record), verify_password_request));

    vsc_buffer_t *verify_password_response =
            vsc_buffer_new_with_capacity(vsce_phe_server_verify_password_response_len(server));
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_verify_password(server, vsc_buffer_data(new_server_private_key),
                                            vsc_buffer_data(new_server_public_key),
                                            vsc_buffer_data(verify_password_request), verify_password_response));

    vsc_buffer_t *account_key2 = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH);
    TEST_ASSERT_EQUAL(vsce_SUCCESS,
            vsce_phe_client_check_response_and_decrypt(new_client, pwd_data, vsc_buffer_data(new_enrollment_record),
                    vsc_buffer_data(verify_password_response), account_key2));

    TEST_ASSERT_EQUAL_MEMORY(
            vsc_buffer_bytes(account_key), vsc_buffer_bytes(account_key2), vsc_buffer_len(account_key));
    TEST_ASSERT_EQUAL(vsc_buffer_len(account_key), vsc_buffer_len(account_key2));

    vsce_phe_client_destroy(&client);
    vsce_phe_client_destroy(&new_client);
    vsce_phe_server_destroy(&server);

    vsc_buffer_destroy(&server_private_key);
    vsc_buffer_destroy(&server_public_key);
    vsc_buffer_destroy(&new_server_private_key);
    vsc_buffer_destroy(&new_server_public_key);
    vsc_buffer_destroy(&new_server_public_key2);
    vsc_buffer_destroy(&new_client_private_key);

    vsc_buffer_destroy(&pwd);

    vsc_buffer_destroy(&enrollment_response);
    vsc_buffer_destroy(&enrollment_record);
    vsc_buffer_destroy(&account_key);
    vsc_buffer_destroy(&account_key2);
    vsc_buffer_destroy(&verify_password_request);
    vsc_buffer_destroy(&verify_password_response);
    vsc_buffer_destroy(&token);
    vsc_buffer_destroy(&new_enrollment_record);
}

void
test__full_flow__incorrect_server_public_key_correct_pwd__should_fail() {
    vsce_phe_server_t *server;
    vsce_phe_client_t *client;
    vsc_buffer_t *server_private_key, *server_public_key;

    vsce_phe_server_t *server2;
    vsce_phe_client_t *client2;
    vsc_buffer_t *server_private_key2, *server_public_key2;

    init(&server, &client, &server_private_key, &server_public_key);
    init(&server2, &client2, &server_private_key2, &server_public_key2);

    vsc_buffer_t *pwd;

    generate_pwd(&pwd);

    vsc_data_t pwd_data = vsc_data(vsc_buffer_bytes(pwd), vsc_buffer_len(pwd));

    vsc_buffer_t *enrollment_response = vsc_buffer_new_with_capacity(vsce_phe_server_enrollment_response_len(server));
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_get_enrollment(server, vsc_buffer_data(server_private_key),
                                            vsc_buffer_data(server_public_key), enrollment_response));

    vsc_buffer_t *enrollment_record = vsc_buffer_new_with_capacity(vsce_phe_client_enrollment_record_len(client));
    vsc_buffer_t *account_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH);
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_enroll_account(client, vsc_buffer_data(enrollment_response),
                                            pwd_data, enrollment_record, account_key));
    TEST_ASSERT_EQUAL(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH, vsc_buffer_len(account_key));

    vsc_buffer_t *verify_password_request =
            vsc_buffer_new_with_capacity(vsce_phe_client_verify_password_request_len(client));
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_create_verify_password_request(client, pwd_data,
                                            vsc_buffer_data(enrollment_record), verify_password_request));

    vsc_buffer_t *verify_password_response =
            vsc_buffer_new_with_capacity(vsce_phe_server_verify_password_response_len(server));
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_verify_password(server, vsc_buffer_data(server_private_key),
                                            vsc_buffer_data(server_public_key),
                                            vsc_buffer_data(verify_password_request), verify_password_response));

    vsc_buffer_t *account_key2 = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH);
    TEST_ASSERT_EQUAL(vsce_INVALID_SUCCESS_PROOF,
            vsce_phe_client_check_response_and_decrypt(client2, pwd_data, vsc_buffer_data(enrollment_record),
                    vsc_buffer_data(verify_password_response), account_key2));
    TEST_ASSERT_EQUAL(0, vsc_buffer_len(account_key2));

    vsce_phe_client_destroy(&client);
    vsce_phe_server_destroy(&server);
    vsce_phe_client_destroy(&client2);
    vsce_phe_server_destroy(&server2);

    vsc_buffer_destroy(&server_private_key);
    vsc_buffer_destroy(&server_public_key);
    vsc_buffer_destroy(&server_private_key2);
    vsc_buffer_destroy(&server_public_key2);
    vsc_buffer_destroy(&pwd);

    vsc_buffer_destroy(&enrollment_response);
    vsc_buffer_destroy(&enrollment_record);
    vsc_buffer_destroy(&account_key);
    vsc_buffer_destroy(&account_key2);
    vsc_buffer_destroy(&verify_password_request);
    vsc_buffer_destroy(&verify_password_response);
}

void
test__full_flow__incorrect_server_public_key_incorrect_pwd__should_fail() {
    vsce_phe_server_t *server;
    vsce_phe_client_t *client;
    vsc_buffer_t *server_private_key, *server_public_key;

    vsce_phe_server_t *server2;
    vsce_phe_client_t *client2;
    vsc_buffer_t *server_private_key2, *server_public_key2;

    init(&server, &client, &server_private_key, &server_public_key);
    init(&server2, &client2, &server_private_key2, &server_public_key2);

    vsc_buffer_t *pwd1, *pwd2;

    generate_pwd(&pwd1);
    generate_pwd(&pwd2);

    TEST_ASSERT(vsc_buffer_len(pwd1) != vsc_buffer_len(pwd2) ||
                memcmp(vsc_buffer_bytes(pwd1), vsc_buffer_bytes(pwd2), vsc_buffer_len(pwd1)) != 0);

    vsc_data_t pwd1_data = vsc_data(vsc_buffer_bytes(pwd1), vsc_buffer_len(pwd1));
    vsc_data_t pwd2_data = vsc_data(vsc_buffer_bytes(pwd2), vsc_buffer_len(pwd2));

    vsc_buffer_t *enrollment_response = vsc_buffer_new_with_capacity(vsce_phe_server_enrollment_response_len(server));
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_get_enrollment(server, vsc_buffer_data(server_private_key),
                                            vsc_buffer_data(server_public_key), enrollment_response));

    vsc_buffer_t *enrollment_record = vsc_buffer_new_with_capacity(vsce_phe_client_enrollment_record_len(client));
    vsc_buffer_t *account_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH);
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_enroll_account(client, vsc_buffer_data(enrollment_response),
                                            pwd1_data, enrollment_record, account_key));

    vsc_buffer_t *verify_password_request =
            vsc_buffer_new_with_capacity(vsce_phe_client_verify_password_request_len(client));
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_create_verify_password_request(client, pwd2_data,
                                            vsc_buffer_data(enrollment_record), verify_password_request));

    vsc_buffer_t *verify_password_response =
            vsc_buffer_new_with_capacity(vsce_phe_server_verify_password_response_len(server));
    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_server_verify_password(server, vsc_buffer_data(server_private_key),
                                            vsc_buffer_data(server_public_key),
                                            vsc_buffer_data(verify_password_request), verify_password_response));

    vsc_buffer_t *account_key2 = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_SECRET_MESSAGE_LENGTH);
    TEST_ASSERT_EQUAL(vsce_INVALID_FAIL_PROOF,
            vsce_phe_client_check_response_and_decrypt(client2, pwd2_data, vsc_buffer_data(enrollment_record),
                    vsc_buffer_data(verify_password_response), account_key2));

    TEST_ASSERT_EQUAL(0, vsc_buffer_len(account_key2));

    vsce_phe_client_destroy(&client);
    vsce_phe_server_destroy(&server);
    vsce_phe_client_destroy(&client2);
    vsce_phe_server_destroy(&server2);

    vsc_buffer_destroy(&server_private_key);
    vsc_buffer_destroy(&server_public_key);
    vsc_buffer_destroy(&server_private_key2);
    vsc_buffer_destroy(&server_public_key2);

    vsc_buffer_destroy(&pwd1);
    vsc_buffer_destroy(&pwd2);

    vsc_buffer_destroy(&enrollment_response);
    vsc_buffer_destroy(&enrollment_record);
    vsc_buffer_destroy(&account_key);
    vsc_buffer_destroy(&account_key2);
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
    RUN_TEST(test__full_flow__random_correct_pwd__should_succeed);
    RUN_TEST(test__full_flow__random_incorrect_pwd__should_fail);
    RUN_TEST(test__rotation__random_rotation__server_public_keys_match);
    RUN_TEST(test__rotation__random_rotation__enrollment_record_updated_successfully);
    RUN_TEST(test__full_flow__incorrect_server_public_key_correct_pwd__should_fail);
    RUN_TEST(test__full_flow__incorrect_server_public_key_incorrect_pwd__should_fail);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
