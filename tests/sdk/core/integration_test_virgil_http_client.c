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


#define TEST_DEPENDENCIES_AVAILABLE VSSC_VIRGIL_HTTP_CLIENT
#if TEST_DEPENDENCIES_AVAILABLE


#include "vssc_virgil_http_client.h"

#include "test_data_virgil_http_client.h"

void
test__send__with_stale_jwt__returns_response_with_service_error(void) {

    vssc_error_t error;
    vssc_error_reset(&error);

    vssc_jwt_t *jwt = vssc_jwt_parse(test_data_virgil_http_client_JWT, &error);
    TEST_ASSERT_EQUAL(vssc_status_SUCCESS, vssc_error_status(&error));
    TEST_ASSERT_NOT_NULL(jwt);

    vssc_http_request_t *request = vssc_http_request_new_with_body(vssc_http_request_method_post_str,
            test_data_virgil_http_client_HTTP_URL, test_data_virgil_http_client_HTTP_BODY);

    vssc_virgil_http_response_t *response = vssc_virgil_http_client_send(request, jwt, &error);
    TEST_ASSERT_EQUAL(vssc_status_SUCCESS, vssc_error_status(&error));
    TEST_ASSERT_NOT_NULL(jwt);

    TEST_ASSERT_EQUAL(
            test_data_virgil_http_client_RESPONSE_STATUS_CODE, vssc_virgil_http_response_status_code(response));

    TEST_ASSERT_TRUE(vssc_virgil_http_response_has_service_error(response));


    TEST_ASSERT_EQUAL(test_data_virgil_http_client_RESPONSE_SERVICE_ERROR_CODE,
            vssc_virgil_http_response_service_error_code(response));

    TEST_ASSERT_EQUAL_STR(test_data_virgil_http_client_RESPONSE_SERVICE_ERROR_DESRIPTION,
            vssc_virgil_http_response_service_error_description(response));

    vssc_virgil_http_response_destroy(&response);
    vssc_http_request_destroy(&request);
    vssc_jwt_destroy(&jwt);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__send__with_stale_jwt__returns_response_with_service_error);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
