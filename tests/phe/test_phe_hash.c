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


#include "unity.h"
#include "test_utils.h"
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <vsce_simple_swu.h>
#include <vsce_phe_hash.h>
#include "test_data_phe_hash.h"

#define TEST_DEPENDENCIES_AVAILABLE VSCE_PHE_HASH
#if TEST_DEPENDENCIES_AVAILABLE

void test__data2point__const_hash__should_match() {
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

    mbedtls_mpi_read_string(&x1_exp, 10, (const char *)test_phe_hash_x.bytes);
    mbedtls_mpi_read_string(&y1_exp, 10, (const char *)test_phe_hash_y.bytes);

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

// TODO: Implement
void test__hc0__const_hash__should_match() { }
void test__hc1__const_hash__should_match() { }
void test__hs0__const_hash__should_match() { }
void test__hs1__const_hash__should_match() { }
void test__hash_z_success__const_hash__should_match() { }
void test__hash_z_failure__const_hash__should_match() { }

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
    RUN_TEST(test__hash_z_success__const_hash__should_match);
    RUN_TEST(test__hash_z_failure__const_hash__should_match);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}