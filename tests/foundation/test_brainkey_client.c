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

#define TEST_DEPENDENCIES_AVAILABLE VSCF_BRAINKEY_CLIENT
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_fake_random.h"
#include "vscf_ctr_drbg.h"
#include "vscf_brainkey_client.h"
#include "test_data_brainkey_client.h"

void
test__blind__fixed_valud__should_match(void) {
    vscf_ctr_drbg_t *ctr_drbg = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(ctr_drbg));

    vscf_brainkey_client_t *client = vscf_brainkey_client_new();

    vscf_fake_random_t *rng = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(rng, test_data_brainkey_client_fake_rng);

    vscf_brainkey_client_take_random(client, vscf_fake_random_impl(rng));
    vscf_brainkey_client_take_operation_random(client, vscf_ctr_drbg_impl(ctr_drbg));

    vsc_buffer_t *deblind_factor = vsc_buffer_new_with_capacity(vscf_brainkey_client_MPI_LEN);
    vsc_buffer_t *blinded_point = vsc_buffer_new_with_capacity(vscf_brainkey_client_POINT_LEN);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_brainkey_client_blind(client, test_data_brainkey_client_pwd, deblind_factor, blinded_point));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_brainkey_client_deblind_factor, deblind_factor);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_brainkey_client_blinded_point, blinded_point);

    vsc_buffer_destroy(&deblind_factor);
    vsc_buffer_destroy(&blinded_point);

    vscf_brainkey_client_destroy(&client);
}

void
test__deblind__fixed_valud__should_match(void) {
    vscf_ctr_drbg_t *ctr_drbg = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(ctr_drbg));

    vscf_brainkey_client_t *client = vscf_brainkey_client_new();

    vscf_fake_random_t *rng = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(rng, test_data_brainkey_client_fake_rng);

    vscf_brainkey_client_take_random(client, vscf_fake_random_impl(rng));
    vscf_brainkey_client_take_operation_random(client, vscf_ctr_drbg_impl(ctr_drbg));

    vsc_buffer_t *deblind_factor = vsc_buffer_new_with_capacity(vscf_brainkey_client_MPI_LEN);
    vsc_buffer_t *blinded_point = vsc_buffer_new_with_capacity(vscf_brainkey_client_POINT_LEN);

    vsc_buffer_t *seed = vsc_buffer_new_with_capacity(vscf_brainkey_client_SEED_LEN);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_brainkey_client_deblind(client, test_data_brainkey_client_pwd,
                    test_data_brainkey_client_hardened_point, test_data_brainkey_client_deblind_factor,
                    test_data_brainkey_client_key_name, seed));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_brainkey_client_seed, seed);
    vsc_buffer_destroy(&seed);
    vsc_buffer_destroy(&deblind_factor);
    vsc_buffer_destroy(&blinded_point);

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
    RUN_TEST(test__blind__fixed_valud__should_match);
    RUN_TEST(test__deblind__fixed_valud__should_match);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
