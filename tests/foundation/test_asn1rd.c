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


#define TEST_DEPENDENCIES_AVAILABLE VSCF_ASN1RD
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_asn1_tag.h"
#include "vscf_asn1rd.h"
#include "vscf_assert.h"

#include "test_data_asn1.h"


// --------------------------------------------------------------------------
// Test 'get' methods.
// --------------------------------------------------------------------------

void
test__asn1rd_get_tag__encoded_integer_2__returns_tag_integer(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_INT_2);

    int tag = vscf_asn1rd_get_tag(asn1rd);

    TEST_ASSERT_EQUAL(vscf_asn1_tag_INTEGER, tag);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_get_len__encoded_integer_2__returns_1(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_INT_2);

    size_t len = vscf_asn1rd_get_len(asn1rd);

    TEST_ASSERT_EQUAL(1, len);

    vscf_asn1rd_destroy(&asn1rd);
}

// --------------------------------------------------------------------------
// Test 'read' methods.
// --------------------------------------------------------------------------

void
test__asn1rd_read_int__encoded_integer_2__returns_2(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_INT_2);

    int value = vscf_asn1rd_read_int(asn1rd);

    TEST_ASSERT_EQUAL(2, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_int__encoded_integer_neg_2__returns_neg_2(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_INT_NEG_2);

    int value = vscf_asn1rd_read_int(asn1rd);

    TEST_ASSERT_EQUAL(-2, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_int8__encoded_int8_0__returns_0(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_INT8_0);

    int8_t value = vscf_asn1rd_read_int8(asn1rd);

    TEST_ASSERT_EQUAL_INT8(0, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_int8__encoded_int8_127__returns_127(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_INT8_127);

    int8_t value = vscf_asn1rd_read_int8(asn1rd);

    TEST_ASSERT_EQUAL_INT8(127, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_int8__encoded_int8_neg_128__returns_neg_128(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_INT8_NEG_128);

    int8_t value = vscf_asn1rd_read_int8(asn1rd);

    TEST_ASSERT_EQUAL_INT8(-128, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_int16__encoded_int16_32760__returns_32760(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_INT16_32760);

    int16_t value = vscf_asn1rd_read_int16(asn1rd);

    TEST_ASSERT_EQUAL_INT16(32760, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_int16__encoded_int16_neg_32760__returns_neg_32760(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_INT16_NEG_32760);

    int16_t value = vscf_asn1rd_read_int16(asn1rd);

    TEST_ASSERT_EQUAL_INT16(-32760, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_int32__encoded_int32_2147483000__returns_2147483000(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_INT32_2147483000);

    int32_t value = vscf_asn1rd_read_int32(asn1rd);

    TEST_ASSERT_EQUAL_INT32(2147483000, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_int32__encoded_int32_neg_2147483000__returns_neg_2147483000(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_INT32_NEG_2147483000);

    int32_t value = vscf_asn1rd_read_int32(asn1rd);

    TEST_ASSERT_EQUAL_INT32(-2147483000, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_uint8__encoded_uint8_255__returns_255(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_UINT8_255);

    uint8_t value = vscf_asn1rd_read_uint8(asn1rd);

    TEST_ASSERT_EQUAL_UINT8(255, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_uint8__encoded_uint8_0__returns_0(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_UINT8_0);

    uint8_t value = vscf_asn1rd_read_uint8(asn1rd);

    TEST_ASSERT_EQUAL_UINT8(0, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_uint16__encoded_uint16_65535__returns_65535(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_UINT16_65535);

    uint16_t value = vscf_asn1rd_read_uint16(asn1rd);

    TEST_ASSERT_EQUAL_UINT16(65535, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_uint32__encoded_uint32_4294967295__returns_4294967295(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_UINT32_4294967295);

    uint32_t value = vscf_asn1rd_read_uint32(asn1rd);

    TEST_ASSERT_EQUAL_UINT32(4294967295, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_uint__encoded_uint_4294967295__returns_4294967295(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_UINT_4294967295);

    unsigned int value = vscf_asn1rd_read_uint(asn1rd);

    TEST_ASSERT_EQUAL_UINT(4294967295, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_int64__encoded_int64_9223372036854775807__returns_9223372036854775807(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_INT64_9223372036854775807);

    int64_t value = vscf_asn1rd_read_int64(asn1rd);

    TEST_ASSERT_EQUAL_INT64(9223372036854775807, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_int64__encoded_int64_neg_9223372036854775808__returns_neg_9223372036854775808(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_INT64_NEG_9223372036854775808);

    int64_t value = vscf_asn1rd_read_int64(asn1rd);

    TEST_ASSERT_EQUAL_INT64(-9223372036854775808, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_uint64__encoded_uint64_18446744073709551615__returns_18446744073709551615(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_UINT64_18446744073709551615);

    uint64_t value = vscf_asn1rd_read_uint64(asn1rd);

    TEST_ASSERT_EQUAL_UINT64(18446744073709551615, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_bool__encoded_boolean_true__returns_true(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_BOOLEAN_TRUE);

    bool value = vscf_asn1rd_read_bool(asn1rd);

    TEST_ASSERT_EQUAL(true, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_bool__encoded_boolean_false__returns_false(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_BOOLEAN_FALSE);

    bool value = vscf_asn1rd_read_bool(asn1rd);

    TEST_ASSERT_EQUAL(false, value);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_tag__encoded_boolean_false__returns_1(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_BOOLEAN_FALSE);

    size_t tag_len = vscf_asn1rd_read_tag(asn1rd, vscf_asn1_tag_BOOLEAN);

    TEST_ASSERT_EQUAL(1, tag_len);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_octet_str__encoded_octet_string__returns_decoded_octet_string(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_OCTET_STRING);

    vsc_data_t decoded_string = vscf_asn1rd_read_octet_str(asn1rd);

    TEST_ASSERT_EQUAL(test_asn1_decoded_OCTET_STRING.len, decoded_string.len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_decoded_OCTET_STRING.bytes, decoded_string.bytes, decoded_string.len);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_utf8_str__encoded_utf8_string__returns_string_test(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_UTF8_STRING);

    vsc_data_t decoded_string = vscf_asn1rd_read_utf8_str(asn1rd);

    TEST_ASSERT_EQUAL(test_asn1_decoded_UTF8_STRING.len, decoded_string.len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_decoded_UTF8_STRING.bytes, decoded_string.bytes, decoded_string.len);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_read_oid__encoded_oid_sha256_returns_decoded_oid_sha256(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_OID_SHA256);

    vsc_data_t decoded_oid = vscf_asn1rd_read_oid(asn1rd);

    TEST_ASSERT_EQUAL(test_asn1_decoded_OID_SHA256.len, decoded_oid.len);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_decoded_OID_SHA256.bytes, decoded_oid.bytes, decoded_oid.len);

    vscf_asn1rd_destroy(&asn1rd);
}

// --------------------------------------------------------------------------
// Test 'error' method.
// --------------------------------------------------------------------------

void
test__asn1rd_error__after_read_null__returns_SUCCESS(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_NULL);

    vscf_asn1rd_read_null(asn1rd);

    vscf_error_t error = vscf_asn1rd_error(asn1rd);

    TEST_ASSERT_EQUAL(vscf_SUCCESS, error);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_error__after_read_int_twice__returns_OUT_OF_DATA(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_INT_2);

    (void)vscf_asn1rd_read_int(asn1rd);
    (void)vscf_asn1rd_read_int(asn1rd);

    vscf_error_t error = vscf_asn1rd_error(asn1rd);

    TEST_ASSERT_EQUAL(vscf_error_OUT_OF_DATA, error);

    vscf_asn1rd_destroy(&asn1rd);
}

void
test__asn1rd_error__after_read_int_from_encoded_boolean_true__returns_BAD_ASN1(void) {

    vscf_asn1rd_impl_t *asn1rd = vscf_asn1rd_new();
    VSCF_ASSERT_PTR(asn1rd);

    vscf_asn1rd_reset(asn1rd, test_asn1_encoded_BOOLEAN_TRUE);

    (void)vscf_asn1rd_read_int(asn1rd);

    vscf_error_t error = vscf_asn1rd_error(asn1rd);

    TEST_ASSERT_EQUAL(vscf_error_BAD_ASN1, error);

    vscf_asn1rd_destroy(&asn1rd);
}


#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__asn1rd_get_tag__encoded_integer_2__returns_tag_integer);
    RUN_TEST(test__asn1rd_get_len__encoded_integer_2__returns_1);

    RUN_TEST(test__asn1rd_read_int__encoded_integer_2__returns_2);
    RUN_TEST(test__asn1rd_read_int8__encoded_int8_0__returns_0);
    RUN_TEST(test__asn1rd_read_int8__encoded_int8_127__returns_127);
    RUN_TEST(test__asn1rd_read_int8__encoded_int8_neg_128__returns_neg_128);
    RUN_TEST(test__asn1rd_read_int16__encoded_int16_32760__returns_32760);
    RUN_TEST(test__asn1rd_read_int16__encoded_int16_neg_32760__returns_neg_32760);
    RUN_TEST(test__asn1rd_read_int32__encoded_int32_2147483000__returns_2147483000);
    RUN_TEST(test__asn1rd_read_int32__encoded_int32_neg_2147483000__returns_neg_2147483000);
    RUN_TEST(test__asn1rd_read_uint8__encoded_uint8_255__returns_255);
    RUN_TEST(test__asn1rd_read_uint8__encoded_uint8_0__returns_0);
    RUN_TEST(test__asn1rd_read_uint16__encoded_uint16_65535__returns_65535);
    RUN_TEST(test__asn1rd_read_uint32__encoded_uint32_4294967295__returns_4294967295);
    RUN_TEST(test__asn1rd_read_uint__encoded_uint_4294967295__returns_4294967295);
    RUN_TEST(test__asn1rd_read_int64__encoded_int64_9223372036854775807__returns_9223372036854775807);
    RUN_TEST(test__asn1rd_read_int64__encoded_int64_neg_9223372036854775808__returns_neg_9223372036854775808);
    RUN_TEST(test__asn1rd_read_uint64__encoded_uint64_18446744073709551615__returns_18446744073709551615);
    RUN_TEST(test__asn1rd_read_bool__encoded_boolean_true__returns_true);
    RUN_TEST(test__asn1rd_read_bool__encoded_boolean_false__returns_false);
    RUN_TEST(test__asn1rd_read_tag__encoded_boolean_false__returns_1);
    RUN_TEST(test__asn1rd_read_octet_str__encoded_octet_string__returns_decoded_octet_string);
    RUN_TEST(test__asn1rd_read_utf8_str__encoded_utf8_string__returns_string_test);
    RUN_TEST(test__asn1rd_read_oid__encoded_oid_sha256_returns_decoded_oid_sha256);

    RUN_TEST(test__asn1rd_error__after_read_null__returns_SUCCESS);
    RUN_TEST(test__asn1rd_error__after_read_int_twice__returns_OUT_OF_DATA);
    RUN_TEST(test__asn1rd_error__after_read_int_from_encoded_boolean_true__returns_BAD_ASN1);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
