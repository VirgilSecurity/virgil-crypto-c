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
#include "test_data_uokms_server_client.h"


#define TEST_DEPENDENCIES_AVAILABLE VSCE_UOKMS_CLIENT &&VSCF_FAKE_RANDOM
#if TEST_DEPENDENCIES_AVAILABLE

#include <virgil/crypto/phe/vsce_uokms_client.h>
#include <virgil/crypto/foundation/vscf_fake_random.h>

void
test__generate_private_key__mocked_rnd__should_match(void) {
    vsce_uokms_client_t *client = vsce_uokms_client_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_setup_defaults(client));

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_uokms_server_rnd);
    vsce_uokms_client_release_random(client);
    vsce_uokms_client_take_random(client, vscf_fake_random_impl(fake_random));

    vsc_buffer_t *priv = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_generate_client_private_key(client, priv));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_uokms_mocked_client_private_key, priv);

    vsc_buffer_destroy(&priv);
    vsce_uokms_client_destroy(&client);

    vscf_fake_random_destroy(&fake_random);
}

void
test__encrypt__mocked_rnd__should_match(void) {
    vsce_uokms_client_t *client = vsce_uokms_client_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_setup_defaults(client));

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_uokms_server_rnd);
    vsce_uokms_client_release_random(client);
    vsce_uokms_client_take_random(client, vscf_fake_random_impl(fake_random));

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_uokms_client_set_keys(client, test_uokms_client_private_key, test_uokms_server_public_key));

    vsc_buffer_t *wrap = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);
    vsc_buffer_t *key = vsc_buffer_new_with_capacity(test_uokms_key.len);

    TEST_ASSERT_EQUAL(
            vsce_status_SUCCESS, vsce_uokms_client_generate_encrypt_wrap(client, wrap, test_uokms_key.len, key));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_uokms_mocked_wrap, wrap);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_uokms_mocked_key, key);

    vsc_buffer_destroy(&wrap);
    vsc_buffer_destroy(&key);
    vsce_uokms_client_destroy(&client);

    vscf_fake_random_destroy(&fake_random);
}

void
test__decrypt_request__mocked_rnd__should_match(void) {
    vsce_uokms_client_t *client = vsce_uokms_client_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_setup_defaults(client));

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_uokms_server_rnd);
    vsce_uokms_client_release_random(client);
    vsce_uokms_client_take_random(client, vscf_fake_random_impl(fake_random));

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_uokms_client_set_keys(client, test_uokms_client_private_key, test_uokms_server_public_key));

    vsc_buffer_t *deblind_factor = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t *decrypt_request = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_uokms_client_generate_decrypt_request(client, test_uokms_wrap, deblind_factor, decrypt_request));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_uokms_mocked_deblind_factor, deblind_factor);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_uokms_mocked_decrypt_request, decrypt_request);

    vsc_buffer_destroy(&deblind_factor);
    vsc_buffer_destroy(&decrypt_request);
    vsce_uokms_client_destroy(&client);

    vscf_fake_random_destroy(&fake_random);
}

void
test__decrypt__mocked_rnd__should_match(void) {
    vsce_uokms_client_t *client = vsce_uokms_client_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_setup_defaults(client));

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_uokms_client_set_keys(client, test_uokms_client_private_key, test_uokms_server_public_key));

    vsc_buffer_t *key = vsc_buffer_new_with_capacity(test_uokms_key.len);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_uokms_client_process_decrypt_response(client, test_uokms_wrap, test_uokms_decrypt_request,
                    test_uokms_decrypt_response, test_uokms_deblind_factor, test_uokms_key.len, key));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_uokms_key, key);

    vsc_buffer_destroy(&key);
    vsce_uokms_client_destroy(&client);
}

void
test__rotate_keys__mocked_rnd__should_match(void) {
    vsce_uokms_client_t *client = vsce_uokms_client_new();
    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_setup_defaults(client));

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS,
            vsce_uokms_client_set_keys(client, test_uokms_client_private_key, test_uokms_server_public_key));

    vsc_buffer_t *new_client_private_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PRIVATE_KEY_LENGTH);
    vsc_buffer_t *new_server_public_key = vsc_buffer_new_with_capacity(vsce_phe_common_PHE_PUBLIC_KEY_LENGTH);

    TEST_ASSERT_EQUAL(vsce_status_SUCCESS, vsce_uokms_client_rotate_keys(client, test_uokms_update_token,
                                                   new_client_private_key, new_server_public_key));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_uokms_new_client_private_key, new_client_private_key);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_uokms_new_server_public_key, new_server_public_key);

    vsc_buffer_destroy(&new_client_private_key);
    vsc_buffer_destroy(&new_server_public_key);
    vsce_uokms_client_destroy(&client);
}

#endif // TEST_DEPENDENCIES_AVAILABLE

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__generate_private_key__mocked_rnd__should_match);
    RUN_TEST(test__encrypt__mocked_rnd__should_match);
    RUN_TEST(test__decrypt_request__mocked_rnd__should_match);
    RUN_TEST(test__decrypt__mocked_rnd__should_match);
    RUN_TEST(test__rotate_keys__mocked_rnd__should_match);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
