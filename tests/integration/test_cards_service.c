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


#define TEST_DEPENDENCIES_AVAILABLE (VSSC_VIRGIL_HTTP_CLIENT && VSSC_CARD_CLIENT && VSSC_CARD_MANAGER)
#if TEST_DEPENDENCIES_AVAILABLE


#include "test_env.h"

#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <virgil/crypto/foundation/vscf_key_provider.h>

#include <virgil/sdk/core/vssc_virgil_http_client.h>
#include <virgil/sdk/core/vssc_card_manager.h>
#include <virgil/sdk/core/vssc_card_client.h>


void
test__publish_card__with_new_jwt_and_new_keypair__returned_card_is_valid(void) {
    const test_env_t *env = test_env_get();

    //
    //  Init.
    //
    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vscf_ctr_drbg_t *ctr_drbg = vscf_ctr_drbg_new();
    foundation_error.status = vscf_ctr_drbg_setup_defaults(ctr_drbg);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, foundation_error.status);

    vscf_impl_t *random = vscf_ctr_drbg_impl(ctr_drbg);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, random);

    vssc_card_manager_t *card_manager = vssc_card_manager_new();
    vssc_card_manager_use_random(card_manager, random);
    core_sdk_error.status =
            vssc_card_manager_configure_with_service_public_key(card_manager, env->virgil_public_key_data);
    TEST_ASSERT_EQUAL(vssc_status_SUCCESS, core_sdk_error.status);

    vssc_card_client_t *card_client = vssc_card_client_new_with_base_url(env->url);

    //
    //  Generate Key Pair for a new Card.
    //
    vscf_impl_t *private_key =
            vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ED25519, &foundation_error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, foundation_error.status);

    //
    //  Generate a Raw Card.
    //
    vsc_str_t identity = vssc_jwt_identity(env->jwt);
    vsc_str_t previous_card_id = vsc_str_empty();
    vssc_raw_card_t *initial_raw_card =
            vssc_card_manager_generate_raw_card(card_manager, identity, private_key, previous_card_id, &core_sdk_error);


    //
    //  Publish a Raw Card.
    //
    vssc_http_request_t *publish_card_request =
            vssc_card_client_make_request_publish_card(card_client, initial_raw_card);

    vssc_virgil_http_response_t *publish_card_response =
            vssc_virgil_http_client_send(publish_card_request, env->jwt, &core_sdk_error);
    TEST_ASSERT_EQUAL(vssc_status_SUCCESS, core_sdk_error.status);

    if (vssc_virgil_http_response_has_service_error(publish_card_response)) {
        const size_t error_code = vssc_virgil_http_response_service_error_code(publish_card_response);
        vsc_str_t error_message = vssc_virgil_http_response_service_error_description(publish_card_response);

        printf("GOT SERVICE ERROR: %lu - %s\n", error_code, error_message.chars);
        TEST_FAIL();
    }

    vssc_raw_card_t *published_raw_card =
            vssc_card_client_process_response_publish_card(card_client, publish_card_response, &core_sdk_error);
    TEST_ASSERT_EQUAL(vssc_status_SUCCESS, core_sdk_error.status);

    vssc_card_t *card = vssc_card_manager_import_raw_card_with_initial_raw_card(
            card_manager, published_raw_card, initial_raw_card, &core_sdk_error);
    TEST_ASSERT_EQUAL(vssc_status_SUCCESS, core_sdk_error.status);
    TEST_ASSERT_NOT_NULL(card);
    TEST_ASSERT_EQUAL_STR(vsc_str_from_str("5.0"), vssc_card_version(card));
    TEST_ASSERT_EQUAL_STR(identity, vssc_card_identity(card));
    TEST_ASSERT_FALSE(vssc_card_has_previous_card(card));
    TEST_ASSERT_FALSE(vssc_card_has_previous_card(card));
    TEST_ASSERT_EQUAL_DATA(vssc_raw_card_content_snapshot(initial_raw_card), vssc_card_content_snapshot(card));

    //
    //  Cleanup.
    //
    vscf_ctr_drbg_destroy(&ctr_drbg);
    vscf_key_provider_destroy(&key_provider);
    vssc_card_manager_destroy(&card_manager);
    vssc_card_client_destroy(&card_client);
    vscf_impl_destroy(&private_key);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    const int env_load_status = test_env_load();
    if (env_load_status != 0) {
        return -1;
    }

    RUN_TEST(test__publish_card__with_new_jwt_and_new_keypair__returned_card_is_valid);

    test_env_release();
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
