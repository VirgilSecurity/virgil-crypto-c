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


#define UNITY_BEGIN() UnityBegin(__FILENAME__)

#include "unity.h"
#include "test_utils.h"
#include "test_data_simple_swu.h"
#include "test_data_simple_swu.h"

#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>

#define TEST_DEPENDENCIES_AVAILABLE VSCE_SIMPLE_SWU &&VSCF_RANDOM &&VSCF_CTR_DRBG
#if TEST_DEPENDENCIES_AVAILABLE

#include "vsce_simple_swu.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>


// --------------------------------------------------------------------------
//  Should have it to prevent linkage erros in MSVC.
// --------------------------------------------------------------------------
// clang-format off
void setUp(void) { }
void tearDown(void) { }
void suiteSetUp(void) { }
int suiteTearDown(int num_failures) { return num_failures; }
// clang-format on


// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------
void
test__simple_swu__random_hashes__should_be_on_curve(void) {
    mbedtls_ecp_group group;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);

    int iterations = 1000;

    vscf_ctr_drbg_impl_t *rng = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng);

    size_t len = 32;
    vsc_buffer_t *t_buf = vsc_buffer_new_with_capacity(len);

    vsce_simple_swu_t *simple_swu = vsce_simple_swu_new();

    for (int i = 0; i < iterations; i++) {
        mbedtls_mpi t;

        while (true) {
            vscf_ctr_drbg_random(rng, len, t_buf);

            mbedtls_mpi_init(&t);
            mbedtls_mpi_read_binary(&t, vsc_buffer_bytes(t_buf), vsc_buffer_len(t_buf));
            vsc_buffer_erase(t_buf);

            if (mbedtls_mpi_cmp_mpi(&t, &group.P) < 0) {
                break;
            } else {
                mbedtls_mpi_free(&t);
            }
        }

        mbedtls_ecp_point p;
        mbedtls_ecp_point_init(&p);
        vsce_simple_swu_bignum_to_point(simple_swu, &t, &p);

        TEST_ASSERT(mbedtls_ecp_check_pubkey(&group, &p) == 0);

        mbedtls_ecp_point_free(&p);
        mbedtls_mpi_free(&t);
    }

    vsce_simple_swu_destroy(&simple_swu);

    vsc_buffer_destroy(&t_buf);
    mbedtls_ecp_group_free(&group);
    vscf_ctr_drbg_destroy(&rng);
}

void
test__simple_swu__const_hash1__should_match(void) {
    mbedtls_ecp_group group;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);

    mbedtls_mpi t;
    mbedtls_mpi_init(&t);
    mbedtls_mpi_read_string(&t, 16, (const char *)test_simple_swu_hash1.bytes);

    mbedtls_ecp_point p;
    mbedtls_ecp_point_init(&p);

    vsce_simple_swu_t *simple_swu = vsce_simple_swu_new();
    vsce_simple_swu_bignum_to_point(simple_swu, &t, &p);

    mbedtls_mpi x1_exp, y1_exp;
    mbedtls_mpi_init(&x1_exp);
    mbedtls_mpi_init(&y1_exp);

    mbedtls_mpi_read_string(&x1_exp, 10, (const char *)test_simple_swu_x1.bytes);
    mbedtls_mpi_read_string(&y1_exp, 10, (const char *)test_simple_swu_y1.bytes);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&group, &p) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&p.X, &x1_exp) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&p.Y, &y1_exp) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_int(&p.Z, 1) == 0);

    vsce_simple_swu_destroy(&simple_swu);
    mbedtls_ecp_point_free(&p);
    mbedtls_mpi_free(&x1_exp);
    mbedtls_mpi_free(&y1_exp);
    mbedtls_mpi_free(&t);
    mbedtls_ecp_group_free(&group);
}

void
test__simple_swu__const_hash2__should_match(void) {
    mbedtls_ecp_group group;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);

    mbedtls_mpi t;
    mbedtls_mpi_init(&t);
    mbedtls_mpi_read_string(&t, 16, (const char *)test_simple_swu_hash2.bytes);

    mbedtls_ecp_point p;
    mbedtls_ecp_point_init(&p);

    vsce_simple_swu_t *simple_swu = vsce_simple_swu_new();
    vsce_simple_swu_bignum_to_point(simple_swu, &t, &p);

    mbedtls_mpi x1_exp, y1_exp;
    mbedtls_mpi_init(&x1_exp);
    mbedtls_mpi_init(&y1_exp);

    mbedtls_mpi_read_string(&x1_exp, 10, (const char *)test_simple_swu_x2.bytes);
    mbedtls_mpi_read_string(&y1_exp, 10, (const char *)test_simple_swu_y2.bytes);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&group, &p) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&p.X, &x1_exp) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&p.Y, &y1_exp) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_int(&p.Z, 1) == 0);

    vsce_simple_swu_destroy(&simple_swu);
    mbedtls_ecp_point_free(&p);
    mbedtls_mpi_free(&x1_exp);
    mbedtls_mpi_free(&y1_exp);
    mbedtls_mpi_free(&t);
    mbedtls_ecp_group_free(&group);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__simple_swu__random_hashes__should_be_on_curve);
    RUN_TEST(test__simple_swu__const_hash1__should_match);
    RUN_TEST(test__simple_swu__const_hash2__should_match);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
