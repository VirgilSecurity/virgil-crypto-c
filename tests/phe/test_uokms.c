//  Copyright (C) 2015-2021 Virgil Security, Inc.
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


#define TEST_DEPENDENCIES_AVAILABLE VSCE_PHE_CLIENT &&VSCE_PHE_SERVER &&VSCF_CTR_DRBG
#if TEST_DEPENDENCIES_AVAILABLE

#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include <vsce_uokms_server.h>
#include <vsce_uokms_client.h>
#include <vsce_uokms_wrap_rotation.h>


// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------
static void
init(vsce_uokms_server_t **server_ref, vsce_uokms_client_t **client_ref, vsc_buffer_t **server_private_key_ref,
        vsc_buffer_t **server_public_key_ref) {
    byte client_private_key[vsce_phe_common_PHE_PRIVATE_KEY_LENGTH];

    vsc_buffer_t buffer;
    vsc_buffer_init(&buffer);

    vsc_buffer_use(&buffer, client_private_key, sizeof(client_private_key));

    *server_ref = vsce_uokms_server_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_server_setup_defaults(*server_ref));

    *server_private_key_ref = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    *server_public_key_ref = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_uokms_server_generate_server_key_pair(*server_ref, *server_private_key_ref, *server_public_key_ref));

    *client_ref = vsce_uokms_client_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_setup_defaults(*client_ref));

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_generate_client_private_key(*client_ref, &buffer));

    vsc_buffer_delete(&buffer);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_uokms_client_set_keys(*client_ref, vsc_data(client_private_key, sizeof(client_private_key)),
                    vsc_buffer_data(*server_public_key_ref)));
}

static void
init_oneparty(vsce_uokms_client_t **client_ref) {
    byte client_private_key[vsce_phe_common_PHE_PRIVATE_KEY_LENGTH];

    vsc_buffer_t buffer;
    vsc_buffer_init(&buffer);

    vsc_buffer_use(&buffer, client_private_key, sizeof(client_private_key));

    *client_ref = vsce_uokms_client_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_setup_defaults(*client_ref));

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_generate_client_private_key(*client_ref, &buffer));

    vsc_buffer_delete(&buffer);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_uokms_client_set_keys_oneparty(*client_ref, vsc_data(client_private_key, sizeof(client_private_key))));
}

void
test__encrypt_decrypt__full_flow__key_should_match(void) {
    vsce_uokms_server_t *server;
    vsce_uokms_client_t *client;
    vsc_buffer_t *server_private_key, *server_public_key;

    init(&server, &client, &server_private_key, &server_public_key);

    vsc_buffer_t *wrap = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_t *key = vsc_buffer_new_with_capacity(44);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_generate_encrypt_wrap(client, wrap, 44, key));

    vsc_buffer_t *deblind_factor = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t *decrypt_request = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_uokms_client_generate_decrypt_request(client, vsc_buffer_data(wrap), deblind_factor, decrypt_request));

    vsc_buffer_t *decrypt_response = vsc_buffer_new_with_capacity(vsce_uokms_server_decrypt_response_len(server));

    TEST_ASSERT_EQUAL(
            vsce_status_SUCCESS, vsce_uokms_server_process_decrypt_request(server, vsc_buffer_data(server_private_key),
                                         vsc_buffer_data(decrypt_request), decrypt_response));

    vsc_buffer_t *key2 = vsc_buffer_new_with_capacity(44);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_uokms_client_process_decrypt_response(client, vsc_buffer_data(wrap), vsc_buffer_data(decrypt_request),
                    vsc_buffer_data(decrypt_response), vsc_buffer_data(deblind_factor), 44, key2));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(key), key2);

    vsce_uokms_client_destroy(&client);
    vsce_uokms_server_destroy(&server);

    vsc_buffer_destroy(&server_private_key);
    vsc_buffer_destroy(&server_public_key);

    vsc_buffer_destroy(&wrap);
    vsc_buffer_destroy(&key);
    vsc_buffer_destroy(&deblind_factor);
    vsc_buffer_destroy(&decrypt_request);
    vsc_buffer_destroy(&decrypt_response);
    vsc_buffer_destroy(&key2);
}

void
test__encrypt_decrypt__full_oneparty_flow__key_should_match(void) {
    vsce_uokms_client_t *client;

    init_oneparty(&client);

    vsc_buffer_t *wrap = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_t *key = vsc_buffer_new_with_capacity(44);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_generate_encrypt_wrap(client, wrap, 44, key));

    vsc_buffer_t *key2 = vsc_buffer_new_with_capacity(44);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_decrypt_oneparty(client, vsc_buffer_data(wrap), 44, key2));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(key), key2);

    vsce_uokms_client_destroy(&client);
    vsc_buffer_destroy(&wrap);
    vsc_buffer_destroy(&key);
    vsc_buffer_destroy(&key2);
}

void
test__encrypt_decrypt__invalid_proof__should_not_succeed(void) {
    vsce_uokms_server_t *server;
    vsce_uokms_client_t *client;
    vsc_buffer_t *server_private_key, *server_public_key;
    vsc_buffer_t *server_private_key2 = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t *server_public_key2 = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    init(&server, &client, &server_private_key, &server_public_key);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_uokms_server_generate_server_key_pair(server, server_private_key2, server_public_key2));

    vsc_buffer_t *wrap = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_t *key = vsc_buffer_new_with_capacity(44);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_generate_encrypt_wrap(client, wrap, 44, key));

    vsc_buffer_t *deblind_factor = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t *decrypt_request = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_uokms_client_generate_decrypt_request(client, vsc_buffer_data(wrap), deblind_factor, decrypt_request));

    vsc_buffer_t *decrypt_response = vsc_buffer_new_with_capacity(vsce_uokms_server_decrypt_response_len(server));

    TEST_ASSERT_EQUAL(
            vsce_status_SUCCESS, vsce_uokms_server_process_decrypt_request(server, vsc_buffer_data(server_private_key2),
                                         vsc_buffer_data(decrypt_request), decrypt_response));

    vsc_buffer_t *key2 = vsc_buffer_new_with_capacity(44);

    TEST_ASSERT_EQUAL(vsce_status_ERROR_INVALID_SUCCESS_PROOF,
            vsce_uokms_client_process_decrypt_response(client, vsc_buffer_data(wrap), vsc_buffer_data(decrypt_request),
                    vsc_buffer_data(decrypt_response), vsc_buffer_data(deblind_factor), 44, key2));

    vsce_uokms_client_destroy(&client);
    vsce_uokms_server_destroy(&server);

    vsc_buffer_destroy(&server_private_key);
    vsc_buffer_destroy(&server_public_key);
    vsc_buffer_destroy(&server_private_key2);
    vsc_buffer_destroy(&server_public_key2);

    vsc_buffer_destroy(&wrap);
    vsc_buffer_destroy(&key);
    vsc_buffer_destroy(&deblind_factor);
    vsc_buffer_destroy(&decrypt_request);
    vsc_buffer_destroy(&decrypt_response);
    vsc_buffer_destroy(&key2);
}

void
test__rotate__full_flow__key_should_match(void) {
    vsce_uokms_server_t *server;
    vsce_uokms_client_t *client;
    vsc_buffer_t *server_private_key, *server_public_key;

    init(&server, &client, &server_private_key, &server_public_key);

    vsc_buffer_t *wrap = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_t *key = vsc_buffer_new_with_capacity(44);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_generate_encrypt_wrap(client, wrap, 44, key));

    vsc_buffer_t *new_server_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t *new_server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_t *update_token = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_server_rotate_keys(server, vsc_buffer_data(server_private_key),
                                                   new_server_private_key, new_server_public_key, update_token));

    vsc_buffer_t *new_server_public_key2 = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_t *new_client_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_rotate_keys(client, vsc_buffer_data(update_token),
                                                   new_client_private_key, new_server_public_key2));

    vsce_uokms_wrap_rotation_t *wrap_rotation = vsce_uokms_wrap_rotation_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_wrap_rotation_setup_defaults(wrap_rotation));
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_uokms_wrap_rotation_set_update_token(wrap_rotation, vsc_buffer_data(update_token)));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(new_server_public_key), new_server_public_key2);

    vsc_buffer_t *new_wrap = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    TEST_ASSERT_EQUAL(
            vsce_status_SUCCESS, vsce_uokms_wrap_rotation_update_wrap(wrap_rotation, vsc_buffer_data(wrap), new_wrap));

    vsce_uokms_client_t *client2 = vsce_uokms_client_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_setup_defaults(client2));
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_set_keys(client2, vsc_buffer_data(new_client_private_key),
                                                   vsc_buffer_data(new_server_public_key)));

    vsc_buffer_t *deblind_factor = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t *decrypt_request = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_generate_decrypt_request(client2,
                                                   vsc_buffer_data(new_wrap), deblind_factor, decrypt_request));

    vsc_buffer_t *decrypt_response = vsc_buffer_new_with_capacity(vsce_uokms_server_decrypt_response_len(server));

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_uokms_server_process_decrypt_request(server, vsc_buffer_data(new_server_private_key),
                    vsc_buffer_data(decrypt_request), decrypt_response));

    vsc_buffer_t *key2 = vsc_buffer_new_with_capacity(44);

    TEST_ASSERT_EQUAL(
            vsce_status_SUCCESS, vsce_uokms_client_process_decrypt_response(client2, vsc_buffer_data(new_wrap),
                                         vsc_buffer_data(decrypt_request), vsc_buffer_data(decrypt_response),
                                         vsc_buffer_data(deblind_factor), 44, key2));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(key), key2);

    vsce_uokms_client_destroy(&client);
    vsce_uokms_client_destroy(&client2);
    vsce_uokms_server_destroy(&server);
    vsce_uokms_wrap_rotation_destroy(&wrap_rotation);

    vsc_buffer_destroy(&new_server_private_key);
    vsc_buffer_destroy(&new_server_public_key);
    vsc_buffer_destroy(&update_token);
    vsc_buffer_destroy(&new_client_private_key);

    vsc_buffer_destroy(&new_server_public_key2);

    vsc_buffer_destroy(&server_private_key);
    vsc_buffer_destroy(&server_public_key);

    vsc_buffer_destroy(&new_wrap);
    vsc_buffer_destroy(&wrap);
    vsc_buffer_destroy(&key);
    vsc_buffer_destroy(&deblind_factor);
    vsc_buffer_destroy(&decrypt_request);
    vsc_buffer_destroy(&decrypt_response);
    vsc_buffer_destroy(&key2);
}

void
test__rotate__full_oneparty_flow__key_should_match(void) {
    vsce_uokms_client_t *client;

    init_oneparty(&client);

    vsc_buffer_t *wrap = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_t *key = vsc_buffer_new_with_capacity(44);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_generate_encrypt_wrap(client, wrap, 44, key));

    vsc_buffer_t *update_token = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_generate_update_token_oneparty(client, update_token));

    vsc_buffer_t *new_client_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_uokms_client_rotate_keys_oneparty(client, vsc_buffer_data(update_token), new_client_private_key));

    vsce_uokms_wrap_rotation_t *wrap_rotation = vsce_uokms_wrap_rotation_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_wrap_rotation_setup_defaults(wrap_rotation));
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_uokms_wrap_rotation_set_update_token(wrap_rotation, vsc_buffer_data(update_token)));

    vsc_buffer_t *new_wrap = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    TEST_ASSERT_EQUAL(
            vsce_status_SUCCESS, vsce_uokms_wrap_rotation_update_wrap(wrap_rotation, vsc_buffer_data(wrap), new_wrap));

    vsce_uokms_client_t *client2 = vsce_uokms_client_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_setup_defaults(client2));
    TEST_ASSERT_EQUAL(
            vsce_status_SUCCESS, vsce_uokms_client_set_keys_oneparty(client2, vsc_buffer_data(new_client_private_key)));

    vsc_buffer_t *key2 = vsc_buffer_new_with_capacity(44);

    TEST_ASSERT_EQUAL(
            vsce_status_SUCCESS, vsce_uokms_client_decrypt_oneparty(client2, vsc_buffer_data(new_wrap), 44, key2));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(key), key2);

    vsce_uokms_client_destroy(&client);
    vsce_uokms_client_destroy(&client2);
    vsce_uokms_wrap_rotation_destroy(&wrap_rotation);

    vsc_buffer_destroy(&update_token);
    vsc_buffer_destroy(&new_client_private_key);

    vsc_buffer_destroy(&new_wrap);
    vsc_buffer_destroy(&wrap);
    vsc_buffer_destroy(&key);
    vsc_buffer_destroy(&key2);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__encrypt_decrypt__full_flow__key_should_match);
    RUN_TEST(test__encrypt_decrypt__full_oneparty_flow__key_should_match);
    RUN_TEST(test__encrypt_decrypt__invalid_proof__should_not_succeed);
    RUN_TEST(test__rotate__full_flow__key_should_match);
    RUN_TEST(test__rotate__full_oneparty_flow__key_should_match);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
