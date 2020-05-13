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


#define TEST_DEPENDENCIES_AVAILABLE VSCS_CORE_BASE64_URL
#if TEST_DEPENDENCIES_AVAILABLE

#include <virgil/sdk/core/vscs_core_base64_url.h>

#include "test_data_base64_url.h"


void
test__encode__bytes_that_when_base64_encoded_contains_symbol_plus__expected_replacement_with_dash(void) {

    const size_t base64url_len = vscs_core_base64_url_encoded_len(test_data_base64_url_DECODED_CONTAINS_PLUS.len);

    vsc_str_buffer_t *base64url = vsc_str_buffer_new_with_capacity(base64url_len);

    vscs_core_base64_url_encode(test_data_base64_url_DECODED_CONTAINS_PLUS, base64url);

    TEST_ASSERT_EQUAL_STR_AND_BUFFER(test_data_base64_url_ENCODED_REPLACED_PLUS, base64url);

    vsc_str_buffer_destroy(&base64url);
}

void
test__encode__bytes_that_when_base64_encoded_contains_symbol_slash__expected_replacement_with_underscore(void) {

    const size_t base64url_len = vscs_core_base64_url_encoded_len(test_data_base64_url_DECODED_CONTAINS_SLASH.len);

    vsc_str_buffer_t *base64url = vsc_str_buffer_new_with_capacity(base64url_len);

    vscs_core_base64_url_encode(test_data_base64_url_DECODED_CONTAINS_SLASH, base64url);

    TEST_ASSERT_EQUAL_STR_AND_BUFFER(test_data_base64_url_ENCODED_REPLACED_SLASH, base64url);

    vsc_str_buffer_destroy(&base64url);
}

void
test__encode__bytes_that_when_base64_encoded_contains_1_padding__expected_no_padding(void) {

    const size_t base64url_len = vscs_core_base64_url_encoded_len(test_data_base64_url_DECODED_CONTAINS_1_PADDING.len);

    vsc_str_buffer_t *base64url = vsc_str_buffer_new_with_capacity(base64url_len);

    vscs_core_base64_url_encode(test_data_base64_url_DECODED_CONTAINS_1_PADDING, base64url);

    TEST_ASSERT_EQUAL_STR_AND_BUFFER(test_data_base64_url_ENCODED_REMOVED_1_PADDING, base64url);

    vsc_str_buffer_destroy(&base64url);
}

void
test__encode__bytes_that_when_base64_encoded_contains_2_paddings__expected_no_paddings(void) {

    const size_t base64url_len = vscs_core_base64_url_encoded_len(test_data_base64_url_DECODED_CONTAINS_2_PADDINGS.len);

    vsc_str_buffer_t *base64url = vsc_str_buffer_new_with_capacity(base64url_len);

    vscs_core_base64_url_encode(test_data_base64_url_DECODED_CONTAINS_2_PADDINGS, base64url);

    TEST_ASSERT_EQUAL_STR_AND_BUFFER(test_data_base64_url_ENCODED_REMOVED_2_PADDINGS, base64url);

    vsc_str_buffer_destroy(&base64url);
}

void
test__decode__string_with_dash__equals_expected(void) {

    const size_t buffer_len = vscs_core_base64_url_decoded_len(test_data_base64_url_ENCODED_REPLACED_PLUS.len);

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(buffer_len);

    const vscs_core_status_t status = vscs_core_base64_url_decode(test_data_base64_url_ENCODED_REPLACED_PLUS, buffer);

    TEST_ASSERT_EQUAL(vscs_core_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_base64_url_DECODED_CONTAINS_PLUS, buffer);

    vsc_buffer_destroy(&buffer);
}

void
test__decode__string_with_underscore__equals_expected(void) {

    const size_t buffer_len = vscs_core_base64_url_decoded_len(test_data_base64_url_ENCODED_REPLACED_SLASH.len);

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(buffer_len);

    const vscs_core_status_t status = vscs_core_base64_url_decode(test_data_base64_url_ENCODED_REPLACED_SLASH, buffer);

    TEST_ASSERT_EQUAL(vscs_core_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_base64_url_DECODED_CONTAINS_SLASH, buffer);

    vsc_buffer_destroy(&buffer);
}

void
test__decode__string_with_trimmed_1_padding__equals_expected(void) {

    const size_t buffer_len = vscs_core_base64_url_decoded_len(test_data_base64_url_ENCODED_REMOVED_1_PADDING.len);

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(buffer_len);

    const vscs_core_status_t status =
            vscs_core_base64_url_decode(test_data_base64_url_ENCODED_REMOVED_1_PADDING, buffer);

    TEST_ASSERT_EQUAL(vscs_core_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_base64_url_DECODED_CONTAINS_1_PADDING, buffer);

    vsc_buffer_destroy(&buffer);
}

void
test__decode__string_with_trimmed_2_padding__equals_expected(void) {

    const size_t buffer_len = vscs_core_base64_url_decoded_len(test_data_base64_url_ENCODED_REMOVED_2_PADDINGS.len);

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(buffer_len);

    const vscs_core_status_t status =
            vscs_core_base64_url_decode(test_data_base64_url_ENCODED_REMOVED_2_PADDINGS, buffer);

    TEST_ASSERT_EQUAL(vscs_core_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_base64_url_DECODED_CONTAINS_2_PADDINGS, buffer);

    vsc_buffer_destroy(&buffer);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__encode__bytes_that_when_base64_encoded_contains_symbol_plus__expected_replacement_with_dash);
    RUN_TEST(test__encode__bytes_that_when_base64_encoded_contains_symbol_slash__expected_replacement_with_underscore);
    RUN_TEST(test__encode__bytes_that_when_base64_encoded_contains_1_padding__expected_no_padding);
    RUN_TEST(test__encode__bytes_that_when_base64_encoded_contains_2_paddings__expected_no_paddings);

    RUN_TEST(test__decode__string_with_dash__equals_expected);
    RUN_TEST(test__decode__string_with_underscore__equals_expected);
    RUN_TEST(test__decode__string_with_trimmed_1_padding__equals_expected);
    RUN_TEST(test__decode__string_with_trimmed_2_padding__equals_expected);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
