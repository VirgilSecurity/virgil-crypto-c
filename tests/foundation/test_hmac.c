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


#define TEST_DEPENDENCIES_AVAILABLE VSCF_HMAC &&VSCF_SHA256
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_hmac.h"
#include "vscf_assert.h"
#include "vscf_sha256.h"

#include "test_data_hmac.h"


// --------------------------------------------------------------------------
// Test implementation of the interface 'hmac'.
// --------------------------------------------------------------------------
void
test__hmac_mac__sha256_vector_1__success(void) {

    vscf_hmac_impl_t *hmac = vscf_hmac_new();
    vscf_hmac_take_hash(hmac, vscf_sha256_impl(vscf_sha256_new()));

    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha256_DIGEST_LEN);

    vscf_hmac_mac(hmac, test_hmac_SHA256_VECTOR_1_KEY, test_hmac_SHA256_VECTOR_1_DATA, digest);

    TEST_ASSERT_EQUAL(test_hmac_SHA256_VECTOR_1_DIGEST.len, vsc_buffer_len(digest));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(
            test_hmac_SHA256_VECTOR_1_DIGEST.bytes, vsc_buffer_bytes(digest), vsc_buffer_len(digest));

    vscf_hmac_destroy(&hmac);
    vsc_buffer_destroy(&digest);
}

void
test__hmac_mac__sha256_vector_2__success(void) {

    vscf_hmac_impl_t *hmac = vscf_hmac_new();
    vscf_hmac_take_hash(hmac, vscf_sha256_impl(vscf_sha256_new()));

    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha256_DIGEST_LEN);

    vscf_hmac_mac(hmac, test_hmac_SHA256_VECTOR_2_KEY, test_hmac_SHA256_VECTOR_2_DATA, digest);

    TEST_ASSERT_EQUAL(test_hmac_SHA256_VECTOR_2_DIGEST.len, vsc_buffer_len(digest));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(
            test_hmac_SHA256_VECTOR_2_DIGEST.bytes, vsc_buffer_bytes(digest), vsc_buffer_len(digest));

    vscf_hmac_destroy(&hmac);
    vsc_buffer_destroy(&digest);
}

void
test__hmac_mac__sha256_vector_3__success(void) {

    vscf_hmac_impl_t *hmac = vscf_hmac_new();
    vscf_hmac_take_hash(hmac, vscf_sha256_impl(vscf_sha256_new()));

    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha256_DIGEST_LEN);

    vscf_hmac_mac(hmac, test_hmac_SHA256_VECTOR_3_KEY, test_hmac_SHA256_VECTOR_3_DATA, digest);

    TEST_ASSERT_EQUAL(test_hmac_SHA256_VECTOR_3_DIGEST.len, vsc_buffer_len(digest));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(
            test_hmac_SHA256_VECTOR_3_DIGEST.bytes, vsc_buffer_bytes(digest), vsc_buffer_len(digest));

    vscf_hmac_destroy(&hmac);
    vsc_buffer_destroy(&digest);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE

    RUN_TEST(test__hmac_mac__sha256_vector_1__success);
    RUN_TEST(test__hmac_mac__sha256_vector_2__success);
    RUN_TEST(test__hmac_mac__sha256_vector_3__success);

#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
