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


#define TEST_DEPENDENCIES_AVAILABLE VSCF_HMAC224
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_hmac224.h"
#include "vscf_assert.h"

#include "test_data_hmac224.h"


// --------------------------------------------------------------------------
// Test implementation helpers & lifecycle functions.
// --------------------------------------------------------------------------
void
test__impl__valid_arg__returns_not_null(void) {
    vscf_hmac224_impl_t *hmac224_impl = vscf_hmac224_new();
    vscf_impl_t *impl = vscf_hmac224_impl(hmac224_impl);

    TEST_ASSERT_NOT_NULL(impl);

    vscf_hmac224_destroy(&hmac224_impl);
}

void
test__impl__null_arg__call_assert(void) {

    vscf_assert_change_handler(mock_assert_handler);

    vscf_impl_t *impl = vscf_hmac224_impl(NULL);

    TEST_ASSERT_TRUE(g_mock_assert_result.handled);

    vscf_assert_change_handler(vscf_assert_abort);
}


// --------------------------------------------------------------------------
// Test implementation of the interface 'hmac info'.
// --------------------------------------------------------------------------
void
test__hmac_info_api__always__returns_not_null(void) {
    const vscf_hmac_info_api_t *hmac_info_api = vscf_hmac224_hmac_info_api();

    TEST_ASSERT_NOT_NULL(hmac_info_api);
}


void
test__hmac224_DIGEST_LEN__always__equals_28(void) {
    TEST_ASSERT_EQUAL(28, vscf_hmac224_DIGEST_LEN);
}


// --------------------------------------------------------------------------
// Test implementation of the interface 'hmac'.
// --------------------------------------------------------------------------
void
test__hmac__vector_1__success(void) {

    byte digest[vscf_hmac224_DIGEST_LEN] = {0x00};

    vscf_hmac224_hmac(test_hmac224_KEY_1_INPUT, test_hmac224_KEY_1_INPUT_LEN, test_hmac224_VECTOR_1_INPUT,
            test_hmac224_VECTOR_1_INPUT_LEN, digest, vscf_hmac224_DIGEST_LEN);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_hmac224_VECTOR_1_DIGEST, digest, test_hmac224_VECTOR_1_DIGEST_LEN);
}

void
test__hmac__vector_2__success(void) {

    byte digest[vscf_hmac224_DIGEST_LEN] = {0x00};

    vscf_hmac224_hmac(test_hmac224_KEY_2_INPUT, test_hmac224_KEY_2_INPUT_LEN, test_hmac224_VECTOR_2_INPUT,
            test_hmac224_VECTOR_2_INPUT_LEN, digest, vscf_hmac224_DIGEST_LEN);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_hmac224_VECTOR_2_DIGEST, digest, test_hmac224_VECTOR_2_DIGEST_LEN);
}

void
test__hmac__vector_3__success(void) {

    byte digest[vscf_hmac224_DIGEST_LEN] = {0x00};

    vscf_hmac224_hmac(test_hmac224_KEY_3_INPUT, test_hmac224_KEY_3_INPUT_LEN, test_hmac224_VECTOR_3_INPUT,
            test_hmac224_VECTOR_3_INPUT_LEN, digest, vscf_hmac224_DIGEST_LEN);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_hmac224_VECTOR_3_DIGEST, digest, test_hmac224_VECTOR_3_DIGEST_LEN);
}


// --------------------------------------------------------------------------
// Test implementation of the interface 'hmac stream'.
// --------------------------------------------------------------------------
void
test__hmac_stream__vector_1_success(void) {

    byte digest[vscf_hmac224_DIGEST_LEN] = {0x00};

    vscf_hmac224_impl_t *hmac224_impl = vscf_hmac224_new();

    vscf_hmac224_reset(hmac224_impl);
    vscf_hmac224_start(hmac224_impl, test_hmac224_KEY_1_INPUT, test_hmac224_KEY_1_INPUT_LEN);
    vscf_hmac224_update(hmac224_impl, test_hmac224_VECTOR_1_INPUT, test_hmac224_VECTOR_1_INPUT_LEN);
    vscf_hmac224_finish(hmac224_impl, digest, vscf_hmac224_DIGEST_LEN);

    vscf_hmac224_destroy(&hmac224_impl);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_hmac224_VECTOR_1_DIGEST, digest, test_hmac224_VECTOR_1_DIGEST_LEN);
}

void
test__hmac_stream__vector_2_success(void) {

    byte digest[vscf_hmac224_DIGEST_LEN] = {0x00};

    vscf_hmac224_impl_t *hmac224_impl = vscf_hmac224_new();

    vscf_hmac224_reset(hmac224_impl);
    vscf_hmac224_start(hmac224_impl, test_hmac224_KEY_2_INPUT, test_hmac224_KEY_2_INPUT_LEN);
    vscf_hmac224_update(hmac224_impl, test_hmac224_VECTOR_2_INPUT, test_hmac224_VECTOR_2_INPUT_LEN);
    vscf_hmac224_finish(hmac224_impl, digest, vscf_hmac224_DIGEST_LEN);

    vscf_hmac224_destroy(&hmac224_impl);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_hmac224_VECTOR_2_DIGEST, digest, test_hmac224_VECTOR_2_DIGEST_LEN);
}

void
test__hmac_stream__vector_3_success(void) {

    byte digest[vscf_hmac224_DIGEST_LEN] = {0x00};

    vscf_hmac224_impl_t *hmac224_impl = vscf_hmac224_new();

    vscf_hmac224_reset(hmac224_impl);
    vscf_hmac224_start(hmac224_impl, test_hmac224_KEY_3_INPUT, test_hmac224_KEY_3_INPUT_LEN);
    vscf_hmac224_update(hmac224_impl, test_hmac224_VECTOR_3_INPUT, test_hmac224_VECTOR_3_INPUT_LEN);
    vscf_hmac224_finish(hmac224_impl, digest, vscf_hmac224_DIGEST_LEN);

    vscf_hmac224_destroy(&hmac224_impl);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_hmac224_VECTOR_3_DIGEST, digest, test_hmac224_VECTOR_3_DIGEST_LEN);
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

    RUN_TEST(test__hmac_info_api__always__returns_not_null);
    RUN_TEST(test__hmac224_DIGEST_LEN__always__equals_28);

    RUN_TEST(test__hmac__vector_1__success);
    RUN_TEST(test__hmac__vector_2__success);
    RUN_TEST(test__hmac__vector_3__success);

    RUN_TEST(test__hmac_stream__vector_1_success);
    RUN_TEST(test__hmac_stream__vector_2_success);
    RUN_TEST(test__hmac_stream__vector_3_success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
