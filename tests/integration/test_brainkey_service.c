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


#define TEST_DEPENDENCIES_AVAILABLE (VSSC_VIRGIL_HTTP_CLIENT && VSSB_BRAINKEY_CLIENT && VSCF_BRAINKEY_CLIENT)
#if TEST_DEPENDENCIES_AVAILABLE


#include "test_env.h"
#include "test_sdk_utils.h"

#include <virgil/crypto/common/vsc_str_buffer.h>
#include <virgil/crypto/foundation/vscf_binary.h>
#include <virgil/crypto/foundation/vscf_brainkey_client.h>
#include <virgil/crypto/foundation/vscf_error.h>
#include <virgil/crypto/foundation/vscf_error_message.h>

#include <virgil/sdk/core/vssc_unix_time.h>
#include <virgil/sdk/core/vssc_virgil_http_client.h>
#include <virgil/sdk/core/vssc_error_message.h>

#include <virgil/sdk/brainkey/vssb_brainkey_client.h>
#include <virgil/sdk/brainkey/vssb_error_message.h>


void
test__harden__with_blinded_password__expects_seed_len_32_after_deblind(void) {
    const test_env_t *env = test_env_get();

    //
    //  Init.
    //
    vssb_error_t brainkey_error;
    vssb_error_reset(&brainkey_error);

    vscf_error_t foundation_error;
    vscf_error_reset(&foundation_error);

    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vscf_brainkey_client_t *brainkey = vscf_brainkey_client_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_brainkey_client_setup_defaults(brainkey));

    vssb_brainkey_client_t *brainkey_client = vssb_brainkey_client_new_with_base_url(env->url);

    //
    //  Blind password.
    //
    vsc_str_t password = vsc_str_from_str("password");
    vsc_str_t password_id = vsc_str_from_str("password-id");

    vsc_buffer_t *deblind_factor = vsc_buffer_new_with_capacity(vscf_brainkey_client_MPI_LEN);
    vsc_buffer_t *blinded_point = vsc_buffer_new_with_capacity(vscf_brainkey_client_POINT_LEN);

    foundation_error.status =
            vscf_brainkey_client_blind(brainkey, vsc_str_as_data(password), deblind_factor, blinded_point);
    TEST_ASSERT_EQUAL_MESSAGE(vscf_status_SUCCESS, vscf_error_status(&foundation_error),
            vscf_error_message_from_error(&foundation_error).chars);

    //
    //  Request hardened point.
    //
    vssc_http_request_t *request =
            vssb_brainkey_client_make_request_harden_point(brainkey_client, vsc_buffer_data(blinded_point));

    vssc_http_request_set_auth_header_value_from_type_and_credentials(
            request, vssc_virgil_http_client_k_auth_type_virgil, vssc_jwt_as_string(env->jwt));

    vssc_http_response_t *response = vssc_virgil_http_client_send(request, &core_sdk_error);

    TEST_ASSERT_EQUAL_MESSAGE(vssc_status_SUCCESS, vssc_error_status(&core_sdk_error),
            vssc_error_message_from_error(&core_sdk_error).chars);

    TEST_ASSERT_VIRGIL_HTTP_RESPONSE(response);

    vssb_brainkey_hardened_point_t *hardened_point =
            vssb_brainkey_client_process_response_harden_point(response, &brainkey_error);

    TEST_ASSERT_EQUAL_MESSAGE(vssb_status_SUCCESS, vssb_error_status(&brainkey_error),
            vssb_error_message_from_error(&brainkey_error).chars);
    TEST_ASSERT_NOT_NULL(hardened_point);

    //
    //  De-blind the point and get a seed.
    //
    vsc_buffer_t *seed = vsc_buffer_new_with_capacity(vscf_brainkey_client_SEED_LEN);

    foundation_error.status = vscf_brainkey_client_deblind(brainkey, vsc_str_as_data(password),
            vssb_brainkey_hardened_point_value(hardened_point), vsc_buffer_data(deblind_factor),
            vsc_str_as_data(password_id), seed);
    TEST_ASSERT_EQUAL_MESSAGE(vscf_status_SUCCESS, vscf_error_status(&foundation_error),
            vscf_error_message_from_error(&foundation_error).chars);

    //
    //  Check.
    //
    TEST_ASSERT_EQUAL(vscf_brainkey_client_SEED_LEN, vsc_buffer_len(seed));

    //
    //  Cleanup.
    //
    vscf_brainkey_client_destroy(&brainkey);
    vssb_brainkey_client_destroy(&brainkey_client);
    vssc_http_request_destroy(&request);
    vssc_http_response_destroy(&response);
    vssb_brainkey_hardened_point_destroy(&hardened_point);
    vsc_buffer_destroy(&deblind_factor);
    vsc_buffer_destroy(&blinded_point);
    vsc_buffer_destroy(&seed);
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

    RUN_TEST(test__harden__with_blinded_password__expects_seed_len_32_after_deblind);

    test_env_release();
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
