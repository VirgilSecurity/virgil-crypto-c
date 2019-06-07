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

#include <virgil/crypto/foundation/vscf_brainkey_client.h>
#include <virgil/crypto/foundation/vscf_brainkey_server.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>

// --------------------------------------------------------------------------
// Test 'write' methods.
// --------------------------------------------------------------------------

void
test__full_flow__random_pwd__should_not_fail(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_brainkey_client_t *client = vscf_brainkey_client_new();
    vscf_brainkey_server_t *server = vscf_brainkey_server_new();

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_brainkey_client_setup_defaults(client));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_brainkey_server_setup_defaults(server));

    size_t pwd_len = 10;

    vsc_buffer_t *pwd = vsc_buffer_new_with_capacity(pwd_len);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_random(rng, pwd_len, pwd));

    vsc_buffer_t *deblind_factor = vsc_buffer_new_with_capacity(vscf_brainkey_client_MPI_LEN);
    vsc_buffer_t *blinded_point = vsc_buffer_new_with_capacity(vscf_brainkey_client_POINT_LEN);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_brainkey_client_blind(client, vsc_buffer_data(pwd), deblind_factor, blinded_point));

    vsc_buffer_t *identity_secret = vsc_buffer_new_with_capacity(vscf_brainkey_client_MPI_LEN);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_brainkey_server_generate_identity_secret(server, identity_secret));

    vsc_buffer_t *hardened_point = vsc_buffer_new_with_capacity(vscf_brainkey_client_POINT_LEN);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_brainkey_server_harden(server, vsc_buffer_data(identity_secret),
                                                   vsc_buffer_data(blinded_point), hardened_point));

    vsc_buffer_t *seed = vsc_buffer_new_with_capacity(vscf_brainkey_client_SEED_LEN);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_brainkey_client_deblind(client, vsc_buffer_data(hardened_point),
                                                   vsc_buffer_data(deblind_factor), vsc_data_empty(), seed));

    vsc_buffer_destroy(&seed);
    vsc_buffer_destroy(&hardened_point);
    vsc_buffer_destroy(&deblind_factor);
    vsc_buffer_destroy(&blinded_point);
    vsc_buffer_destroy(&identity_secret);

    vsc_buffer_destroy(&pwd);

    vscf_brainkey_server_destroy(&server);
    vscf_brainkey_client_destroy(&client);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__full_flow__random_pwd__should_not_fail);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
