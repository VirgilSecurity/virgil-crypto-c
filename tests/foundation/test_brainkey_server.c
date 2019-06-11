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

#define TEST_DEPENDENCIES_AVAILABLE VSCF_BRAINKEY_CLIENT
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_ctr_drbg.h"
#include "vscf_fake_random.h"
#include "vscf_brainkey_server.h"
#include "test_data_brainkey_server.h"

void
test__generate_identity_secret__fixed_data__should_match(void) {
    vscf_brainkey_server_t *server = vscf_brainkey_server_new();

    vscf_ctr_drbg_t *ctr_drbg = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(ctr_drbg));

    vscf_fake_random_t *rng = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(rng, test_data_brainkey_server_fake_rng);

    vscf_brainkey_server_take_random(server, vscf_fake_random_impl(rng));
    vscf_brainkey_server_take_operation_random(server, vscf_ctr_drbg_impl(ctr_drbg));

    vsc_buffer_t *identity_secret = vsc_buffer_new_with_capacity(vscf_brainkey_server_MPI_LEN);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_brainkey_server_generate_identity_secret(server, identity_secret));

    TEST_ASSERT_EQUAL_DATA(test_data_brainkey_server_fake_identity_secret, vsc_buffer_data(identity_secret));

    vsc_buffer_destroy(&identity_secret);

    vscf_brainkey_server_destroy(&server);
}

void
test__harden__fixed_data__should_match(void) {
    vscf_brainkey_server_t *server = vscf_brainkey_server_new();

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_brainkey_server_setup_defaults(server));

    vsc_buffer_t *hardened_point = vsc_buffer_new_with_capacity(vscf_brainkey_server_POINT_LEN);

    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_brainkey_server_harden(server, test_data_brainkey_server_identity_secret,
                                         test_data_brainkey_server_blinded_point, hardened_point));

    TEST_ASSERT_EQUAL_DATA(test_data_brainkey_server_hardened_point, vsc_buffer_data(hardened_point));

    vsc_buffer_destroy(&hardened_point);

    vscf_brainkey_server_destroy(&server);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__generate_identity_secret__fixed_data__should_match);
    RUN_TEST(test__harden__fixed_data__should_match);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
