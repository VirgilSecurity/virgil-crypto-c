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
#include "test_data_phe_hash.h"

#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>


#define TEST_DEPENDENCIES_AVAILABLE VSCE_PHE_HASH &&VSCE_SIMPLE_SWU &&VSCF_RANDOM &&VSCF_CTR_DRBG
#if TEST_DEPENDENCIES_AVAILABLE

#include "vsce_simple_swu.h"
#include "vsce_phe_hash.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>

// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------
void
test__data2point__const_hash__should_match(void) {
    mbedtls_ecp_group group;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);

    mbedtls_ecp_point p;
    mbedtls_ecp_point_init(&p);

    vsce_phe_hash_t *phe_hash = vsce_phe_hash_new();
    vsce_phe_hash_data_to_point(phe_hash, test_phe_hash_data, &p);

    mbedtls_mpi x1_exp, y1_exp;
    mbedtls_mpi_init(&x1_exp);
    mbedtls_mpi_init(&y1_exp);

    mbedtls_mpi_read_string(&x1_exp, 10, test_phe_hash_x_DEC);
    mbedtls_mpi_read_string(&y1_exp, 10, test_phe_hash_y_DEC);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&group, &p) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&p.X, &x1_exp) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&p.Y, &y1_exp) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_int(&p.Z, 1) == 0);

    vsce_phe_hash_destroy(&phe_hash);
    mbedtls_ecp_point_free(&p);
    mbedtls_mpi_free(&x1_exp);
    mbedtls_mpi_free(&y1_exp);
    mbedtls_ecp_group_free(&group);
}

void
test__hs0__const_hash__should_match(void) {
    mbedtls_ecp_group group;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);

    vsce_phe_hash_t *phe_hash = vsce_phe_hash_new();

    mbedtls_ecp_point hs0;
    mbedtls_ecp_point_init(&hs0);

    mbedtls_mpi x, y;
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&y);

    mbedtls_mpi_read_string(&x, 10, test_phe_hash_hs0_x_DEC);
    mbedtls_mpi_read_string(&y, 10, test_phe_hash_hs0_y_DEC);

    vsce_phe_hash_hs0(phe_hash, test_phe_hash_ns1, &hs0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&group, &hs0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&hs0.X, &x) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&hs0.Y, &y) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_int(&hs0.Z, 1) == 0);

    mbedtls_ecp_point_free(&hs0);

    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&y);

    vsce_phe_hash_destroy(&phe_hash);

    mbedtls_ecp_group_free(&group);
}

void
test__hs1__const_hash__should_match(void) {
    mbedtls_ecp_group group;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);

    vsce_phe_hash_t *phe_hash = vsce_phe_hash_new();

    mbedtls_ecp_point hs1;
    mbedtls_ecp_point_init(&hs1);

    mbedtls_mpi x, y;
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&y);

    mbedtls_mpi_read_string(&x, 10, test_phe_hash_hs1_x_DEC);
    mbedtls_mpi_read_string(&y, 10, test_phe_hash_hs1_y_DEC);

    vsce_phe_hash_hs1(phe_hash, test_phe_hash_ns2, &hs1);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&group, &hs1) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&hs1.X, &x) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&hs1.Y, &y) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_int(&hs1.Z, 1) == 0);

    mbedtls_ecp_point_free(&hs1);

    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&y);

    vsce_phe_hash_destroy(&phe_hash);

    mbedtls_ecp_group_free(&group);
}

void
test__hc0__const_hash__should_match(void) {
    mbedtls_ecp_group group;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);

    vsce_phe_hash_t *phe_hash = vsce_phe_hash_new();

    mbedtls_ecp_point hc0;
    mbedtls_ecp_point_init(&hc0);

    mbedtls_mpi x, y;
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&y);

    mbedtls_mpi_read_string(&x, 10, test_phe_hash_hc0_x_DEC);
    mbedtls_mpi_read_string(&y, 10, test_phe_hash_hc0_y_DEC);

    vsce_phe_hash_hc0(phe_hash, test_phe_hash_nc1, test_phe_hash_hc0_pwd, &hc0);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&group, &hc0) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&hc0.X, &x) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&hc0.Y, &y) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_int(&hc0.Z, 1) == 0);

    mbedtls_ecp_point_free(&hc0);

    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&y);

    vsce_phe_hash_destroy(&phe_hash);

    mbedtls_ecp_group_free(&group);
}

void
test__hc1__const_hash__should_match(void) {
    mbedtls_ecp_group group;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);

    vsce_phe_hash_t *phe_hash = vsce_phe_hash_new();

    mbedtls_ecp_point hc1;
    mbedtls_ecp_point_init(&hc1);

    mbedtls_mpi x, y;
    mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&y);

    mbedtls_mpi_read_string(&x, 10, test_phe_hash_hc1_x_DEC);
    mbedtls_mpi_read_string(&y, 10, test_phe_hash_hc1_y_DEC);

    vsce_phe_hash_hc1(phe_hash, test_phe_hash_nc2, test_phe_hash_hc1_pwd, &hc1);

    TEST_ASSERT(mbedtls_ecp_check_pubkey(&group, &hc1) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&hc1.X, &x) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_mpi(&hc1.Y, &y) == 0);
    TEST_ASSERT(mbedtls_mpi_cmp_int(&hc1.Z, 1) == 0);

    mbedtls_ecp_point_free(&hc1);

    mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&y);

    vsce_phe_hash_destroy(&phe_hash);

    mbedtls_ecp_group_free(&group);
}

void
test__hash_z_s_success__const_hash__should_match(void) {
    mbedtls_ecp_group group;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);

    vsce_phe_hash_t *phe_hash = vsce_phe_hash_new();

    mbedtls_ecp_point c0, c1, term1, term2, term3;
    mbedtls_ecp_point_init(&c0);
    mbedtls_ecp_point_init(&c1);
    mbedtls_ecp_point_init(&term1);
    mbedtls_ecp_point_init(&term2);
    mbedtls_ecp_point_init(&term3);

    mbedtls_mpi_read_string(&c0.X, 10, test_phe_hash_z_s_c0_x_DEC);
    mbedtls_mpi_read_string(&c0.Y, 10, test_phe_hash_z_s_c0_y_DEC);
    mbedtls_mpi_lset(&c0.Z, 1);

    mbedtls_mpi_read_string(&c1.X, 10, test_phe_hash_z_s_c1_x_DEC);
    mbedtls_mpi_read_string(&c1.Y, 10, test_phe_hash_z_s_c1_y_DEC);
    mbedtls_mpi_lset(&c1.Z, 1);

    mbedtls_mpi_read_string(&term1.X, 10, test_phe_hash_z_s_term1_x_DEC);
    mbedtls_mpi_read_string(&term1.Y, 10, test_phe_hash_z_s_term1_y_DEC);
    mbedtls_mpi_lset(&term1.Z, 1);

    mbedtls_mpi_read_string(&term2.X, 10, test_phe_hash_z_s_term2_x_DEC);
    mbedtls_mpi_read_string(&term2.Y, 10, test_phe_hash_z_s_term2_y_DEC);
    mbedtls_mpi_lset(&term2.Z, 1);

    mbedtls_mpi_read_string(&term3.X, 10, test_phe_hash_z_s_term3_x_DEC);
    mbedtls_mpi_read_string(&term3.Y, 10, test_phe_hash_z_s_term3_y_DEC);
    mbedtls_mpi_lset(&term3.Z, 1);

    mbedtls_mpi z;
    mbedtls_mpi_init(&z);

    vsce_phe_hash_hash_z_success(phe_hash, test_phe_hash_z_s_pub, &c0, &c1, &term1, &term2, &term3, &z);

    mbedtls_mpi z_exp;
    mbedtls_mpi_init(&z_exp);
    mbedtls_mpi_read_string(&z_exp, 10, test_phe_hash_z_s_challenge_DEC);

    TEST_ASSERT_EQUAL(0, mbedtls_mpi_cmp_mpi(&z, &z_exp));

    vsce_phe_hash_destroy(&phe_hash);

    mbedtls_ecp_point_free(&c0);
    mbedtls_ecp_point_free(&c1);
    mbedtls_ecp_point_free(&term1);
    mbedtls_ecp_point_free(&term2);
    mbedtls_ecp_point_free(&term3);

    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&z_exp);
}

void
test__hash_z_s_failure__const_hash__should_match(void) {
    mbedtls_ecp_group group;
    mbedtls_ecp_group_init(&group);
    mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);

    vsce_phe_hash_t *phe_hash = vsce_phe_hash_new();

    mbedtls_ecp_point c0, c1, term1, term2, term3, term4;
    mbedtls_ecp_point_init(&c0);
    mbedtls_ecp_point_init(&c1);
    mbedtls_ecp_point_init(&term1);
    mbedtls_ecp_point_init(&term2);
    mbedtls_ecp_point_init(&term3);
    mbedtls_ecp_point_init(&term4);

    mbedtls_mpi_read_string(&c0.X, 10, test_phe_hash_z_f_c0_x_DEC);
    mbedtls_mpi_read_string(&c0.Y, 10, test_phe_hash_z_f_c0_y_DEC);
    mbedtls_mpi_lset(&c0.Z, 1);

    mbedtls_mpi_read_string(&c1.X, 10, test_phe_hash_z_f_c1_x_DEC);
    mbedtls_mpi_read_string(&c1.Y, 10, test_phe_hash_z_f_c1_y_DEC);
    mbedtls_mpi_lset(&c1.Z, 1);

    mbedtls_mpi_read_string(&term1.X, 10, test_phe_hash_z_f_term1_x_DEC);
    mbedtls_mpi_read_string(&term1.Y, 10, test_phe_hash_z_f_term1_y_DEC);
    mbedtls_mpi_lset(&term1.Z, 1);

    mbedtls_mpi_read_string(&term2.X, 10, test_phe_hash_z_f_term2_x_DEC);
    mbedtls_mpi_read_string(&term2.Y, 10, test_phe_hash_z_f_term2_y_DEC);
    mbedtls_mpi_lset(&term2.Z, 1);

    mbedtls_mpi_read_string(&term3.X, 10, test_phe_hash_z_f_term3_x_DEC);
    mbedtls_mpi_read_string(&term3.Y, 10, test_phe_hash_z_f_term3_y_DEC);
    mbedtls_mpi_lset(&term3.Z, 1);

    mbedtls_mpi_read_string(&term4.X, 10, test_phe_hash_z_f_term4_x_DEC);
    mbedtls_mpi_read_string(&term4.Y, 10, test_phe_hash_z_f_term4_y_DEC);
    mbedtls_mpi_lset(&term4.Z, 1);

    mbedtls_mpi z;
    mbedtls_mpi_init(&z);

    vsce_phe_hash_hash_z_failure(phe_hash, test_phe_hash_z_f_pub, &c0, &c1, &term1, &term2, &term3, &term4, &z);

    mbedtls_mpi z_exp;
    mbedtls_mpi_init(&z_exp);
    mbedtls_mpi_read_string(&z_exp, 10, test_phe_hash_z_f_challenge_DEC);

    TEST_ASSERT_EQUAL(0, mbedtls_mpi_cmp_mpi(&z, &z_exp));

    vsce_phe_hash_destroy(&phe_hash);

    mbedtls_ecp_point_free(&c0);
    mbedtls_ecp_point_free(&c1);
    mbedtls_ecp_point_free(&term1);
    mbedtls_ecp_point_free(&term2);
    mbedtls_ecp_point_free(&term3);
    mbedtls_ecp_point_free(&term4);

    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&z_exp);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__data2point__const_hash__should_match);
    RUN_TEST(test__hc0__const_hash__should_match);
    RUN_TEST(test__hc1__const_hash__should_match);
    RUN_TEST(test__hs0__const_hash__should_match);
    RUN_TEST(test__hs1__const_hash__should_match);
    RUN_TEST(test__hash_z_s_success__const_hash__should_match);
    RUN_TEST(test__hash_z_s_failure__const_hash__should_match);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
