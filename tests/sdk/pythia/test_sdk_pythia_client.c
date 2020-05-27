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


#define TEST_DEPENDENCIES_AVAILABLE VSSP_PYTHIA_CLIENT
#if TEST_DEPENDENCIES_AVAILABLE


#include "vssp_pythia_client.h"

#include "test_data_sdk_pythia_client.h"

void
test__request_generate_seed__http_request_equals_expected(void) {

    vssp_pythia_client_t *pythia_client = vssp_pythia_client_new();

    vssc_http_request_t *http_request =
            vssp_pythia_client_request_generate_seed(pythia_client, test_data_sdk_pythia_client_BLINDED_PASSWORD);

    vsc_str_t http_body = vssc_http_request_body(http_request);

    TEST_ASSERT_EQUAL_STR(test_data_sdk_pythia_client_GENERATE_SEED_REQUEST, http_body);

    vssp_pythia_client_destroy(&pythia_client);
    vssc_http_request_destroy(&http_request);
}

void
test__request_generate_seed_with_id__with_brain_key_id_1__http_request_equals_expected(void) {

    vssp_pythia_client_t *pythia_client = vssp_pythia_client_new();

    vssc_http_request_t *http_request = vssp_pythia_client_request_generate_seed_with_id(
            pythia_client, test_data_sdk_pythia_client_BLINDED_PASSWORD, test_data_sdk_pythia_client_BRAIN_KEY_ID_1);

    vsc_str_t http_body = vssc_http_request_body(http_request);

    TEST_ASSERT_EQUAL_STR(test_data_sdk_pythia_client_GENERATE_SEED_REQUEST_WITH_BRAIN_KEY_ID_1, http_body);

    vssp_pythia_client_destroy(&pythia_client);
    vssc_http_request_destroy(&http_request);
}


void
test__process_response_from_generate_seed__response_is_success__seed_equals_expected(void) {

    vssp_pythia_client_t *pythia_client = vssp_pythia_client_new();

    vssc_http_response_t *http_response =
            vssc_http_response_new_with_body(200, test_data_sdk_pythia_client_GENERATE_SEED_RESPONSE_BODY);


    vssc_error_t core_sdk_error;
    vssc_error_reset(&core_sdk_error);

    vssc_virgil_http_response_t *virgil_http_response =
            vssc_virgil_http_response_create_from_http_response(http_response, &core_sdk_error);

    TEST_ASSERT_EQUAL(vssc_status_SUCCESS, vssc_error_status(&core_sdk_error));
    TEST_ASSERT_NOT_NULL(virgil_http_response);

    vssp_error_t pythia_sdk_error;
    vssp_error_reset(&pythia_sdk_error);

    vssp_brain_key_seed_t *seed = vssp_pythia_client_process_response_from_generate_seed(
            pythia_client, virgil_http_response, &pythia_sdk_error);

    TEST_ASSERT_EQUAL(vssp_status_SUCCESS, vssp_error_status(&pythia_sdk_error));
    TEST_ASSERT_NOT_NULL(seed);

    vsc_data_t seed_data = vssp_brain_key_seed_get(seed);

    TEST_ASSERT_EQUAL_DATA(test_data_sdk_pythia_client_GENERATED_SEED, seed_data);

    vssp_pythia_client_destroy(&pythia_client);
    vssc_http_response_destroy(&http_response);
    vssc_virgil_http_response_destroy(&virgil_http_response);
    vssp_brain_key_seed_destroy(&seed);
}

#endif // TEST_DEPENDENCIES_AVAILABLE

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__request_generate_seed__http_request_equals_expected);
    RUN_TEST(test__request_generate_seed_with_id__with_brain_key_id_1__http_request_equals_expected);
    RUN_TEST(test__process_response_from_generate_seed__response_is_success__seed_equals_expected);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
