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


#define TEST_DEPENDENCIES_AVAILABLE VSCF_SHA256
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_sha256.h"
#include "vscf_assert.h"

#include "test_data_sha256.h"


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
// Test implementation helpers & lifecycle functions.
// --------------------------------------------------------------------------
void
test__impl__valid_arg__returns_not_null(void) {
    vscf_sha256_t *sha256 = vscf_sha256_new();
    vscf_impl_t *impl = vscf_sha256_impl(sha256);

    TEST_ASSERT_NOT_NULL(impl);

    vscf_sha256_destroy(&sha256);
}

void
test__impl__null_arg__call_assert(void) {

    vscf_assert_change_handler(mock_assert_handler);

    vscf_sha256_impl(NULL);

    TEST_ASSERT_TRUE(g_mock_assert_result.handled);

    vscf_assert_change_handler(vscf_assert_abort);
}


// --------------------------------------------------------------------------
// Test implementation of the interface 'hash info'.
// --------------------------------------------------------------------------
void
test__hash_info_api__always__returns_not_null(void) {
    const vscf_hash_info_api_t *hash_info_api = vscf_sha256_hash_info_api();

    TEST_ASSERT_NOT_NULL(hash_info_api);
}


void
test__sha256_DIGEST_LEN__always__equals_32(void) {
    TEST_ASSERT_EQUAL(32, vscf_sha256_DIGEST_LEN);
}


// --------------------------------------------------------------------------
// Test implementation of the interface 'hash'.
// --------------------------------------------------------------------------
void
test__hash_api__always__returns_not_null(void) {
    const vscf_hash_api_t *hash_api = vscf_sha256_hash_api();

    TEST_ASSERT_NOT_NULL(hash_api);
}

void
test__hash__vector_1__success(void) {

    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha256_DIGEST_LEN);

    vscf_sha256_hash(test_sha256_VECTOR_1_INPUT, digest);

    TEST_ASSERT_EQUAL(test_sha256_VECTOR_1_DIGEST.len, vsc_buffer_len(digest));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_sha256_VECTOR_1_DIGEST.bytes, vsc_buffer_bytes(digest), vsc_buffer_len(digest));

    vsc_buffer_destroy(&digest);
}

void
test__hash__vector_2__success(void) {

    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha256_DIGEST_LEN);

    vscf_sha256_hash(test_sha256_VECTOR_2_INPUT, digest);

    TEST_ASSERT_EQUAL(test_sha256_VECTOR_2_DIGEST.len, vsc_buffer_len(digest));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_sha256_VECTOR_2_DIGEST.bytes, vsc_buffer_bytes(digest), vsc_buffer_len(digest));

    vsc_buffer_destroy(&digest);
}

void
test__hash__vector_3__success(void) {

    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha256_DIGEST_LEN);

    vscf_sha256_hash(test_sha256_VECTOR_3_INPUT, digest);

    TEST_ASSERT_EQUAL(test_sha256_VECTOR_3_DIGEST.len, vsc_buffer_len(digest));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_sha256_VECTOR_3_DIGEST.bytes, vsc_buffer_bytes(digest), vsc_buffer_len(digest));

    vsc_buffer_destroy(&digest);
}

// --------------------------------------------------------------------------
// Test implementation of the interface 'hash stream'.
// --------------------------------------------------------------------------
void
test__hash_stream__vector_1__success(void) {

    vscf_sha256_t *sha256 = vscf_sha256_new();
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha256_DIGEST_LEN);

    vscf_sha256_start(sha256);
    vscf_sha256_update(sha256, test_sha256_VECTOR_1_INPUT);
    vscf_sha256_finish(sha256, digest);

    TEST_ASSERT_EQUAL(test_sha256_VECTOR_1_DIGEST.len, vsc_buffer_len(digest));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_sha256_VECTOR_1_DIGEST.bytes, vsc_buffer_bytes(digest), vsc_buffer_len(digest));

    vsc_buffer_destroy(&digest);
    vscf_sha256_destroy(&sha256);
}

void
test__hash_stream__vector_2__success(void) {

    vscf_sha256_t *sha256 = vscf_sha256_new();
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha256_DIGEST_LEN);

    vscf_sha256_start(sha256);
    vscf_sha256_update(sha256, test_sha256_VECTOR_2_INPUT);
    vscf_sha256_finish(sha256, digest);

    TEST_ASSERT_EQUAL(test_sha256_VECTOR_2_DIGEST.len, vsc_buffer_len(digest));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_sha256_VECTOR_2_DIGEST.bytes, vsc_buffer_bytes(digest), vsc_buffer_len(digest));

    vsc_buffer_destroy(&digest);
    vscf_sha256_destroy(&sha256);
}

void
test__hash_stream__vector_3__success(void) {

    vscf_sha256_t *sha256 = vscf_sha256_new();
    vsc_buffer_t *digest = vsc_buffer_new_with_capacity(vscf_sha256_DIGEST_LEN);

    vscf_sha256_start(sha256);
    vscf_sha256_update(sha256, test_sha256_VECTOR_3_INPUT);
    vscf_sha256_finish(sha256, digest);

    TEST_ASSERT_EQUAL(test_sha256_VECTOR_3_DIGEST.len, vsc_buffer_len(digest));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_sha256_VECTOR_3_DIGEST.bytes, vsc_buffer_bytes(digest), vsc_buffer_len(digest));

    vsc_buffer_destroy(&digest);
    vscf_sha256_destroy(&sha256);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__impl__valid_arg__returns_not_null);
    RUN_TEST(test__impl__null_arg__call_assert);

    RUN_TEST(test__hash_info_api__always__returns_not_null);
    RUN_TEST(test__sha256_DIGEST_LEN__always__equals_32);

    RUN_TEST(test__hash_api__always__returns_not_null);
    RUN_TEST(test__hash__vector_1__success);
    RUN_TEST(test__hash__vector_2__success);
    RUN_TEST(test__hash__vector_3__success);

    RUN_TEST(test__hash_stream__vector_1__success);
    RUN_TEST(test__hash_stream__vector_2__success);
    RUN_TEST(test__hash_stream__vector_3__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
