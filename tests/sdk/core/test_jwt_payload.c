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


#define TEST_DEPENDENCIES_AVAILABLE VSCS_CORE_JWT_PAYLOAD
#if TEST_DEPENDENCIES_AVAILABLE


#include "vscs_core_jwt_payload.h"

#include "test_data_jwt.h"


void
test__parse__valid__success(void) {

    vscs_core_error_t error;
    vscs_core_error_reset(&error);

    vscs_core_jwt_payload_t *jwt_payload = vscs_core_jwt_payload_parse(test_data_jwt_PAYLOAD_VALID, &error);
    TEST_ASSERT_EQUAL(vscs_core_status_SUCCESS, vscs_core_error_status(&error));
    TEST_ASSERT_NOT_NULL(jwt_payload);

    TEST_ASSERT_EQUAL(test_data_jwt_ISSUED_AT, vscs_core_jwt_payload_issued_at(jwt_payload));
    TEST_ASSERT_EQUAL(test_data_jwt_EXPIRES_AT, vscs_core_jwt_payload_expires_at(jwt_payload));
    TEST_ASSERT_EQUAL_STR(test_data_jwt_APP_ID, vscs_core_jwt_payload_app_id(jwt_payload));
    TEST_ASSERT_EQUAL_STR(test_data_jwt_IDENTITY, vscs_core_jwt_payload_identity(jwt_payload));

    vscs_core_jwt_payload_destroy(&jwt_payload);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__parse__valid__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
