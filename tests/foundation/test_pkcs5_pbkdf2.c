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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_PKCS5_PBKDF2 && VSCF_HMAC && VSCF_SHA256)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_hmac.h"
#include "vscf_sha256.h"
#include "vscf_pkcs5_pbkdf2.h"

#include "test_data_pkcs5_pbkdf2.h"


// --------------------------------------------------------------------------
//  Should have it to prevent linkage erros in MSVC.
// --------------------------------------------------------------------------
// clang-format off
void setUp(void) { }
void tearDown(void) { }
void suiteSetUp(void) { }
int suiteTearDown(int num_failures) { return num_failures; }
// clang-format on

void
test__derive__hmac_sha256_vector_1__returns_valid_key(void) {
    vscf_sha256_t *hash = vscf_sha256_new();
    vscf_hmac_t *hmac = vscf_hmac_new();
    vscf_hmac_take_hash(hmac, vscf_sha256_impl(hash));

    vscf_pkcs5_pbkdf2_t *pbkdf2 = vscf_pkcs5_pbkdf2_new();
    vscf_pkcs5_pbkdf2_take_hmac(pbkdf2, vscf_hmac_impl(hmac));

    vsc_buffer_t *key = vsc_buffer_new_with_capacity(test_pkcs5_pbkdf2_VECTOR_1.len);

    vscf_pkcs5_pbkdf2_reset(pbkdf2, test_pkcs5_pbkdf2_VECTOR_1_SALT, test_pkcs5_pbkdf2_VECTOR_1_ITERATION_COUNT);
    vscf_pkcs5_pbkdf2_derive(pbkdf2, test_pkcs5_pbkdf2_VECTOR_1_KEY, test_pkcs5_pbkdf2_VECTOR_1.len, key);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_pkcs5_pbkdf2_VECTOR_1, key);

    vscf_pkcs5_pbkdf2_destroy(&pbkdf2);
    vsc_buffer_destroy(&key);
}

void
test__derive__hmac_sha256_vector_2__returns_valid_key(void) {
    vscf_sha256_t *hash = vscf_sha256_new();
    vscf_hmac_t *hmac = vscf_hmac_new();
    vscf_hmac_take_hash(hmac, vscf_sha256_impl(hash));

    vscf_pkcs5_pbkdf2_t *pbkdf2 = vscf_pkcs5_pbkdf2_new();
    vscf_pkcs5_pbkdf2_take_hmac(pbkdf2, vscf_hmac_impl(hmac));

    vsc_buffer_t *key = vsc_buffer_new_with_capacity(test_pkcs5_pbkdf2_VECTOR_2.len);

    vscf_pkcs5_pbkdf2_reset(pbkdf2, test_pkcs5_pbkdf2_VECTOR_2_SALT, test_pkcs5_pbkdf2_VECTOR_2_ITERATION_COUNT);
    vscf_pkcs5_pbkdf2_derive(pbkdf2, test_pkcs5_pbkdf2_VECTOR_2_KEY, test_pkcs5_pbkdf2_VECTOR_2.len, key);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_pkcs5_pbkdf2_VECTOR_2, key);

    vscf_pkcs5_pbkdf2_destroy(&pbkdf2);
    vsc_buffer_destroy(&key);
}

void
test__derive__hmac_sha256_vector_3__returns_valid_key(void) {
    vscf_sha256_t *hash = vscf_sha256_new();
    vscf_hmac_t *hmac = vscf_hmac_new();
    vscf_hmac_take_hash(hmac, vscf_sha256_impl(hash));

    vscf_pkcs5_pbkdf2_t *pbkdf2 = vscf_pkcs5_pbkdf2_new();
    vscf_pkcs5_pbkdf2_take_hmac(pbkdf2, vscf_hmac_impl(hmac));

    vsc_buffer_t *key = vsc_buffer_new_with_capacity(test_pkcs5_pbkdf2_VECTOR_3.len);

    vscf_pkcs5_pbkdf2_reset(pbkdf2, test_pkcs5_pbkdf2_VECTOR_3_SALT, test_pkcs5_pbkdf2_VECTOR_3_ITERATION_COUNT);
    vscf_pkcs5_pbkdf2_derive(pbkdf2, test_pkcs5_pbkdf2_VECTOR_3_KEY, test_pkcs5_pbkdf2_VECTOR_3.len, key);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_pkcs5_pbkdf2_VECTOR_3, key);

    vscf_pkcs5_pbkdf2_destroy(&pbkdf2);
    vsc_buffer_destroy(&key);
}

void
test__derive__hmac_sha256_vector_4__returns_valid_key(void) {
    TEST_IGNORE_MESSAGE("Heavy test.");
    return;

    vscf_sha256_t *hash = vscf_sha256_new();
    vscf_hmac_t *hmac = vscf_hmac_new();
    vscf_hmac_take_hash(hmac, vscf_sha256_impl(hash));

    vscf_pkcs5_pbkdf2_t *pbkdf2 = vscf_pkcs5_pbkdf2_new();
    vscf_pkcs5_pbkdf2_take_hmac(pbkdf2, vscf_hmac_impl(hmac));

    vsc_buffer_t *key = vsc_buffer_new_with_capacity(test_pkcs5_pbkdf2_VECTOR_4.len);

    vscf_pkcs5_pbkdf2_reset(pbkdf2, test_pkcs5_pbkdf2_VECTOR_4_SALT, test_pkcs5_pbkdf2_VECTOR_4_ITERATION_COUNT);
    vscf_pkcs5_pbkdf2_derive(pbkdf2, test_pkcs5_pbkdf2_VECTOR_4_KEY, test_pkcs5_pbkdf2_VECTOR_4.len, key);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_pkcs5_pbkdf2_VECTOR_4, key);

    vscf_pkcs5_pbkdf2_destroy(&pbkdf2);
    vsc_buffer_destroy(&key);
}

void
test__derive__hmac_sha256_vector_5__returns_valid_key(void) {
    vscf_sha256_t *hash = vscf_sha256_new();
    vscf_hmac_t *hmac = vscf_hmac_new();
    vscf_hmac_take_hash(hmac, vscf_sha256_impl(hash));

    vscf_pkcs5_pbkdf2_t *pbkdf2 = vscf_pkcs5_pbkdf2_new();
    vscf_pkcs5_pbkdf2_take_hmac(pbkdf2, vscf_hmac_impl(hmac));

    vsc_buffer_t *key = vsc_buffer_new_with_capacity(test_pkcs5_pbkdf2_VECTOR_5.len);

    vscf_pkcs5_pbkdf2_reset(pbkdf2, test_pkcs5_pbkdf2_VECTOR_5_SALT, test_pkcs5_pbkdf2_VECTOR_5_ITERATION_COUNT);
    vscf_pkcs5_pbkdf2_derive(pbkdf2, test_pkcs5_pbkdf2_VECTOR_5_KEY, test_pkcs5_pbkdf2_VECTOR_5.len, key);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_pkcs5_pbkdf2_VECTOR_5, key);

    vscf_pkcs5_pbkdf2_destroy(&pbkdf2);
    vsc_buffer_destroy(&key);
}

void
test__derive__hmac_sha256_vector_6__returns_valid_key(void) {
    vscf_sha256_t *hash = vscf_sha256_new();
    vscf_hmac_t *hmac = vscf_hmac_new();
    vscf_hmac_take_hash(hmac, vscf_sha256_impl(hash));

    vscf_pkcs5_pbkdf2_t *pbkdf2 = vscf_pkcs5_pbkdf2_new();
    vscf_pkcs5_pbkdf2_take_hmac(pbkdf2, vscf_hmac_impl(hmac));

    vsc_buffer_t *key = vsc_buffer_new_with_capacity(test_pkcs5_pbkdf2_VECTOR_6.len);

    vscf_pkcs5_pbkdf2_reset(pbkdf2, test_pkcs5_pbkdf2_VECTOR_6_SALT, test_pkcs5_pbkdf2_VECTOR_6_ITERATION_COUNT);
    vscf_pkcs5_pbkdf2_derive(pbkdf2, test_pkcs5_pbkdf2_VECTOR_6_KEY, test_pkcs5_pbkdf2_VECTOR_6.len, key);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_pkcs5_pbkdf2_VECTOR_6, key);

    vscf_pkcs5_pbkdf2_destroy(&pbkdf2);
    vsc_buffer_destroy(&key);
}

void
test__derive__hmac_sha256_vector_7__returns_valid_key(void) {
    vscf_sha256_t *hash = vscf_sha256_new();
    vscf_hmac_t *hmac = vscf_hmac_new();
    vscf_hmac_take_hash(hmac, vscf_sha256_impl(hash));

    vscf_pkcs5_pbkdf2_t *pbkdf2 = vscf_pkcs5_pbkdf2_new();
    vscf_pkcs5_pbkdf2_take_hmac(pbkdf2, vscf_hmac_impl(hmac));

    vsc_buffer_t *key = vsc_buffer_new_with_capacity(test_pkcs5_pbkdf2_VECTOR_7.len);

    vscf_pkcs5_pbkdf2_reset(pbkdf2, test_pkcs5_pbkdf2_VECTOR_7_SALT, test_pkcs5_pbkdf2_VECTOR_7_ITERATION_COUNT);
    vscf_pkcs5_pbkdf2_derive(pbkdf2, test_pkcs5_pbkdf2_VECTOR_7_KEY, test_pkcs5_pbkdf2_VECTOR_7.len, key);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_pkcs5_pbkdf2_VECTOR_7, key);

    vscf_pkcs5_pbkdf2_destroy(&pbkdf2);
    vsc_buffer_destroy(&key);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__derive__hmac_sha256_vector_1__returns_valid_key);
    RUN_TEST(test__derive__hmac_sha256_vector_2__returns_valid_key);
    RUN_TEST(test__derive__hmac_sha256_vector_3__returns_valid_key);
    RUN_TEST(test__derive__hmac_sha256_vector_4__returns_valid_key);
    RUN_TEST(test__derive__hmac_sha256_vector_5__returns_valid_key);
    RUN_TEST(test__derive__hmac_sha256_vector_6__returns_valid_key);
    RUN_TEST(test__derive__hmac_sha256_vector_7__returns_valid_key);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
