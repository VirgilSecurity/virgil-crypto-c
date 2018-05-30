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

#include "vsf_hash_info.h"
#include "vsf_hash.h"
#include "vsf_hash_stream.h"
#include "vsf_sha224.h"
#include "vsf_assert.h"

#include "test_utils.h"
#include "test_data_sha224.h"


// --------------------------------------------------------------------------
// Test implementation helpers & lifecycle functions.
// --------------------------------------------------------------------------

void test__impl__valid_arg__returns_not_null (void) {
    vsf_sha224_impl_t *sha224_impl = vsf_sha224_new();
    vsf_impl_t *impl = vsf_sha224_impl(sha224_impl);

    TEST_ASSERT_NOT_NULL (impl);

    vsf_sha224_destroy(&sha224_impl);
}

void test__impl__null_arg__call_assert (void) {

    mock_assert ();

    vsf_impl_t *impl = vsf_sha224_impl(NULL);

    TEST_ASSERT_TRUE (g_mock_assert_result.handled);

    unmock_assert ();
}

// --------------------------------------------------------------------------
// Test implementation of the interface 'hash info'.
// --------------------------------------------------------------------------

void test__hash_info_api__always__returns_not_null (void) {
    const vsf_hash_info_api_t *hash_info_api = vsf_sha224_hash_info_api();

    TEST_ASSERT_NOT_NULL (hash_info_api);
}


void test__sha224_DIGEST_SIZE__always__equals_28 (void) {
    TEST_ASSERT_EQUAL(28, vsf_sha224_DIGEST_SIZE);
}

// --------------------------------------------------------------------------
// Test implementation of the interface 'hash'.
// --------------------------------------------------------------------------

void test__hash_api__always__returns_not_null (void) {
    const vsf_hash_api_t *hash_api = vsf_sha224_hash_api();

    TEST_ASSERT_NOT_NULL (hash_api);
}

void test__hash__vector_1__success (void) {

    byte digest[vsf_sha224_DIGEST_SIZE] = { 0x00 };

    vsf_sha224_hash(test_sha224_VECTOR_1_INPUT, test_sha224_VECTOR_1_INPUT_LEN, digest, vsf_sha224_DIGEST_SIZE);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_sha224_VECTOR_1_DIGEST, digest, test_sha224_VECTOR_1_DIGEST_LEN);
}

void test__hash__vector_2__success (void) {

    byte digest[vsf_sha224_DIGEST_SIZE] = { 0x00 };

    vsf_sha224_hash(test_sha224_VECTOR_2_INPUT, test_sha224_VECTOR_2_INPUT_LEN, digest, vsf_sha224_DIGEST_SIZE);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_sha224_VECTOR_2_DIGEST, digest, test_sha224_VECTOR_2_DIGEST_LEN);
}

void test__hash__vector_3__success (void) {

    byte digest[vsf_sha224_DIGEST_SIZE] = { 0x00 };

    vsf_sha224_hash (test_sha224_VECTOR_3_INPUT, test_sha224_VECTOR_3_INPUT_LEN, digest, vsf_sha224_DIGEST_SIZE);

    TEST_ASSERT_EQUAL_HEX8_ARRAY (test_sha224_VECTOR_3_DIGEST, digest, test_sha224_VECTOR_3_DIGEST_LEN);
}

// --------------------------------------------------------------------------
// Test implementation of the interface 'hash stream'.
// --------------------------------------------------------------------------

void test__hash_stream__vector_1__success (void) {

    byte digest[vsf_sha224_DIGEST_SIZE] = { 0x00 };

    vsf_sha224_impl_t *sha224_impl = vsf_sha224_new();

    vsf_sha224_start (sha224_impl);
    vsf_sha224_update (sha224_impl, test_sha224_VECTOR_1_INPUT, test_sha224_VECTOR_1_INPUT_LEN);
    vsf_sha224_finish (sha224_impl, digest, vsf_sha224_DIGEST_SIZE);

    vsf_sha224_destroy (&sha224_impl);

    TEST_ASSERT_EQUAL_HEX8_ARRAY (test_sha224_VECTOR_1_DIGEST, digest, test_sha224_VECTOR_1_DIGEST_LEN);
}

void test__hash_stream__vector_2__success (void) {

    byte digest[vsf_sha224_DIGEST_SIZE] = { 0x00 };

    vsf_sha224_impl_t *sha224_impl = vsf_sha224_new();

    vsf_sha224_start (sha224_impl);
    vsf_sha224_update (sha224_impl, test_sha224_VECTOR_2_INPUT, test_sha224_VECTOR_2_INPUT_LEN);
    vsf_sha224_finish (sha224_impl, digest, vsf_sha224_DIGEST_SIZE);

    vsf_sha224_destroy (&sha224_impl);

    TEST_ASSERT_EQUAL_HEX8_ARRAY (test_sha224_VECTOR_2_DIGEST, digest, test_sha224_VECTOR_2_DIGEST_LEN);
}

void test__hash_stream__vector_3__success (void) {

    byte digest[vsf_sha224_DIGEST_SIZE] = { 0x00 };

    vsf_sha224_impl_t *sha224_impl = vsf_sha224_new();

    vsf_sha224_start (sha224_impl);
    vsf_sha224_update (sha224_impl, test_sha224_VECTOR_3_INPUT, test_sha224_VECTOR_3_INPUT_LEN);
    vsf_sha224_finish (sha224_impl, digest, vsf_sha224_DIGEST_SIZE);

    vsf_sha224_destroy (&sha224_impl);

    TEST_ASSERT_EQUAL_HEX8_ARRAY (test_sha224_VECTOR_3_DIGEST, digest, test_sha224_VECTOR_3_DIGEST_LEN);
}

void test__hmac__vector_1__success(void) {

    byte digest[vsf_sha224_DIGEST_SIZE] = { 0x00 };

    vsf_sha224_hmac(test_sha224_HMAC_KEY_1_INPUT, test_sha224_HMAC_KEY_1_INPUT_LEN, test_sha224_HMAC_VECTOR_1_INPUT, test_sha224_HMAC_VECTOR_1_INPUT_LEN, digest, vsf_sha224_DIGEST_SIZE);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_sha224_HMAC_VECTOR_1_DIGEST, digest, test_sha224_HMAC_VECTOR_1_DIGEST_LEN);
}

void test__hmac__vector_2__success(void) {

    byte digest[vsf_sha224_DIGEST_SIZE] = { 0x00 };

    vsf_sha224_hmac(test_sha224_HMAC_KEY_2_INPUT, test_sha224_HMAC_KEY_2_INPUT_LEN, test_sha224_HMAC_VECTOR_2_INPUT, test_sha224_HMAC_VECTOR_2_INPUT_LEN, digest, vsf_sha224_DIGEST_SIZE);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_sha224_HMAC_VECTOR_2_DIGEST, digest, test_sha224_HMAC_VECTOR_2_DIGEST_LEN);
}

void test__hmac__vector_3__success(void) {

    byte digest[vsf_sha224_DIGEST_SIZE] = { 0x00 };

    vsf_sha224_hmac(test_sha224_HMAC_KEY_3_INPUT, test_sha224_HMAC_KEY_3_INPUT_LEN, test_sha224_HMAC_VECTOR_3_INPUT, test_sha224_HMAC_VECTOR_3_INPUT_LEN, digest, vsf_sha224_DIGEST_SIZE);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_sha224_HMAC_VECTOR_3_DIGEST, digest, test_sha224_HMAC_VECTOR_3_DIGEST_LEN);
}

void test__hmac_stream__vector_1_success(void) {

    byte digest[vsf_sha224_DIGEST_SIZE] = { 0x00 };

    vsf_sha224_impl_t *sha224_impl = vsf_sha224_new();

    vsf_sha224_hmac_reset(sha224_impl);
    vsf_sha224_hmac_start(sha224_impl, test_sha224_HMAC_KEY_1_INPUT, test_sha224_HMAC_KEY_1_INPUT_LEN);
    vsf_sha224_hmac_update(sha224_impl, test_sha224_HMAC_VECTOR_1_INPUT, test_sha224_HMAC_VECTOR_1_INPUT_LEN);
    vsf_sha224_hmac_finish(sha224_impl, digest, vsf_sha224_DIGEST_SIZE);
    
    vsf_sha224_destroy(&sha224_impl);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_sha224_HMAC_VECTOR_1_DIGEST, digest, test_sha224_HMAC_VECTOR_1_DIGEST_LEN);
}

void test__hmac_stream__vector_2_success(void) {

    byte digest[vsf_sha224_DIGEST_SIZE] = { 0x00 };

    vsf_sha224_impl_t *sha224_impl = vsf_sha224_new();

    vsf_sha224_hmac_reset(sha224_impl);
    vsf_sha224_hmac_start(sha224_impl, test_sha224_HMAC_KEY_2_INPUT, test_sha224_HMAC_KEY_2_INPUT_LEN);
    vsf_sha224_hmac_update(sha224_impl, test_sha224_HMAC_VECTOR_2_INPUT, test_sha224_HMAC_VECTOR_2_INPUT_LEN);
    vsf_sha224_hmac_finish(sha224_impl, digest, vsf_sha224_DIGEST_SIZE);
    
    vsf_sha224_destroy(&sha224_impl);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_sha224_HMAC_VECTOR_2_DIGEST, digest, test_sha224_HMAC_VECTOR_2_DIGEST_LEN);
}

void test__hmac_stream__vector_3_success(void) {

    byte digest[vsf_sha224_DIGEST_SIZE] = { 0x00 };

    vsf_sha224_impl_t *sha224_impl = vsf_sha224_new();

    vsf_sha224_hmac_reset(sha224_impl);
    vsf_sha224_hmac_start(sha224_impl, test_sha224_HMAC_KEY_3_INPUT, test_sha224_HMAC_KEY_3_INPUT_LEN);
    vsf_sha224_hmac_update(sha224_impl, test_sha224_HMAC_VECTOR_3_INPUT, test_sha224_HMAC_VECTOR_3_INPUT_LEN);
    vsf_sha224_hmac_finish(sha224_impl, digest, vsf_sha224_DIGEST_SIZE);
    
    vsf_sha224_destroy(&sha224_impl);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_sha224_HMAC_VECTOR_3_DIGEST, digest, test_sha224_HMAC_VECTOR_3_DIGEST_LEN);
}
// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------

int main (void) {
    UNITY_BEGIN ();

    RUN_TEST (test__impl__valid_arg__returns_not_null);
    RUN_TEST (test__impl__null_arg__call_assert);

    RUN_TEST (test__hash_info_api__always__returns_not_null);
    RUN_TEST (test__sha224_DIGEST_SIZE__always__equals_28);

    RUN_TEST (test__hash_api__always__returns_not_null);
    RUN_TEST (test__hash__vector_1__success);
    RUN_TEST (test__hash__vector_2__success);
    RUN_TEST (test__hash__vector_3__success);

    RUN_TEST (test__hash_stream__vector_1__success);
    RUN_TEST (test__hash_stream__vector_2__success);
    RUN_TEST (test__hash_stream__vector_3__success);
    
    RUN_TEST(test__hmac__vector_1__success);
    RUN_TEST(test__hmac__vector_2__success);
    RUN_TEST(test__hmac__vector_3__success);
    
    RUN_TEST(test__hmac_stream__vector_1_success);
    RUN_TEST(test__hmac_stream__vector_2_success);
    RUN_TEST(test__hmac_stream__vector_3_success);

    return UNITY_END();
}
