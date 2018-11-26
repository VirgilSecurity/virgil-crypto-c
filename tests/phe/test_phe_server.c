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
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <virgil/crypto/phe/private/vsce_phe_server_defs.h>
#include "unity.h"
#include "test_utils.h"

#define TEST_DEPENDENCIES_AVAILABLE VSCE_PHE_SERVER
#if TEST_DEPENDENCIES_AVAILABLE

void test__enroll_account__1() {
    vsce_phe_server_t *server = vsce_phe_server_new();
    server->secret_key = vsc_buffer_new_with_capacity(32);

    vscf_ctr_drbg_impl_t *rng = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng);
    vscf_ctr_drbg_random(rng, 32, server->secret_key);

    vscf_ctr_drbg_destroy(&rng);

    EnrollmentResponse response;
    vsc_buffer_t *enrollment_response = vsc_buffer_new_with_capacity(100);
    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_ptr(enrollment_response), vsc_buffer_capacity(enrollment_response));

    pb_encode(&ostream, EnrollmentResponse_fields, &response);

    char pwd[] = "PASSWORD";

    vsc_buffer_t *enrollment_record = vsc_buffer_new_with_capacity(100);
    vsc_buffer_t *account_key = vsc_buffer_new_with_capacity(32);

    TEST_ASSERT_EQUAL(vsce_SUCCESS, vsce_phe_client_enroll_account(client, vsc_buffer_data(enrollment_response),
                                                                   vsc_data((byte *)pwd, sizeof(pwd)), enrollment_record, account_key));

    TEST_ASSERT_EQUAL(32, vsc_buffer_len(account_key));

    vsc_buffer_destroy(&enrollment_record);
    vsc_buffer_destroy(&enrollment_response);
    vsc_buffer_destroy(&account_key);

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
    RUN_TEST(test__1);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
