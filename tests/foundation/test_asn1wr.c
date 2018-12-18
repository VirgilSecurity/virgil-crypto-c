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


#define TEST_DEPENDENCIES_AVAILABLE VSCF_ASN1RD
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_asn1_tag.h"
#include "vscf_asn1wr.h"
#include "vscf_assert.h"

#include "vsc_buffer.h"

#include "test_data_asn1.h"


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
// Test 'write' methods.
// --------------------------------------------------------------------------

void
test__asn1wr_finish__argument_integer_2_and_buffer_capacity_is_doubled__returns_encoded_integer_2(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(2 * test_asn1_encoded_INT_2.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_int(asn1wr, 2);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_2.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_2.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_INT_2.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_tag__argument_tag_int__returns_tag_int(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(1);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_tag(asn1wr, vscf_asn1_tag_INTEGER);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(1, len);
    TEST_ASSERT_EQUAL(1, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL(vscf_asn1_tag_INTEGER, *vsc_buffer_bytes(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_len__argument_len_100000__returns_hex_830186A0(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(4);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_len(asn1wr, 100000);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    byte encoded_len[] = {0x83, 0x01, 0x86, 0xA0};

    TEST_ASSERT_EQUAL(4, len);
    TEST_ASSERT_EQUAL(4, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(encoded_len, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_int__argument_int_2__returns_encoded_int_2(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_INT_2.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_int(asn1wr, 2);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_2.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_2.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_INT_2.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_int__argument_int_neg_2__returns_encoded_int_neg_2(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_INT_NEG_2.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_int(asn1wr, -2);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_NEG_2.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_NEG_2.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_INT_NEG_2.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_int8__argument_int_0__returns_encoded_int_0(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_INT_0.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_int8(asn1wr, 0);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_0.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_0.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_INT_0.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_int8__argument_int8_max__returns_encoded_int8_max(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_INT8_MAX.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_int8(asn1wr, INT8_MAX);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_INT8_MAX.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_INT8_MAX.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_INT8_MAX.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_int8__argument_int8_min__returns_encoded_int8_min(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_INT8_MIN.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_int8(asn1wr, INT8_MIN);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_INT8_MIN.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_INT8_MIN.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_INT8_MIN.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_int16__argument_int_32760__returns_encoded_int_32760(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_INT_32760.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_int16(asn1wr, 32760);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_32760.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_32760.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_INT_32760.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_int16__argument_int_neg_32760__returns_encoded_int_neg_32760(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_INT_NEG_32760.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_int16(asn1wr, (-32760));
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_NEG_32760.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_NEG_32760.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_INT_NEG_32760.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_int32__argument_int_2147483000__returns_encoded_int_2147483000(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_INT_2147483000.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_int32(asn1wr, 2147483000);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_2147483000.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_2147483000.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_INT_2147483000.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_int32__argument_int_neg_2147483000__returns_encoded_int_neg_2147483000(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_INT_NEG_2147483000.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_int32(asn1wr, -2147483000);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_NEG_2147483000.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_NEG_2147483000.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(
            test_asn1_encoded_INT_NEG_2147483000.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_uint8__argument_int_255__returns_encoded_int_255(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_INT_255.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_uint8(asn1wr, 255);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_255.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_255.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_INT_255.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_uint8__argument_int_0__returns_encoded_int_0(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_INT_0.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_uint8(asn1wr, 0);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_0.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_INT_0.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_INT_0.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_uint16__argument_uint16_max__returns_encoded_uint16_max(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_UINT16_MAX.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_uint16(asn1wr, UINT16_MAX);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_UINT16_MAX.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_UINT16_MAX.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_UINT16_MAX.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_uint32__argument_uint32_max__returns_encoded_uint32_max(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_UINT32_MAX.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_uint32(asn1wr, UINT32_MAX);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_UINT32_MAX.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_UINT32_MAX.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_UINT32_MAX.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_uint__argument_uint16_max__returns_encoded_uint16_max(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_UINT16_MAX.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_uint(asn1wr, UINT16_MAX);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_UINT16_MAX.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_UINT16_MAX.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_UINT16_MAX.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_int64__argument_int64_max__returns_encoded_int64_max(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_INT64_MAX.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_int64(asn1wr, INT64_MAX);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_INT64_MAX.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_INT64_MAX.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_INT64_MAX.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_int64__argument_int64_min__returns_encoded_int64_min(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_INT64_MIN.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_int64(asn1wr, INT64_MIN);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_INT64_MIN.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_INT64_MIN.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_INT64_MIN.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_uint64__argument_uint64_max__returns_encoded_uint64_max(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_UINT64_MAX.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_uint64(asn1wr, UINT64_MAX);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_UINT64_MAX.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_UINT64_MAX.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_UINT64_MAX.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_bool__argument_bool_false__returns_encoded_bool_false(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_BOOLEAN_FALSE.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_bool(asn1wr, false);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_BOOLEAN_FALSE.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_BOOLEAN_FALSE.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_BOOLEAN_FALSE.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_bool__argument_bool_true__returns_encoded_bool_true(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_BOOLEAN_TRUE.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_bool(asn1wr, true);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_BOOLEAN_TRUE.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_BOOLEAN_TRUE.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_BOOLEAN_TRUE.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_null__argument_null__returns_encoded_null(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_NULL.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_null(asn1wr);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_NULL.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_NULL.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_NULL.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_octet_str__argument_octet_string__returns_encoded_octet_string(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_OCTET_STRING.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_octet_str(asn1wr, test_asn1_decoded_OCTET_STRING);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_OCTET_STRING.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_OCTET_STRING.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_OCTET_STRING.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_utf8_str_argument_utf8_string__returns_encoded_utf8_string(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_UTF8_STRING.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_utf8_str(asn1wr, test_asn1_decoded_UTF8_STRING);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_UTF8_STRING.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_UTF8_STRING.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_UTF8_STRING.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_oid__argument_oid_sha256__returns_encoded_oid_sha256(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_OID_SHA256.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_oid(asn1wr, test_asn1_decoded_OID_SHA256);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_OID_SHA256.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_OID_SHA256.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_OID_SHA256.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_octet_str_as_bitstring__argument_bitstring__returns_encoded_bitstring(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_BIT_STRING.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_octet_str_as_bitstring(asn1wr, test_asn1_decoded_BIT_STRING);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_asn1_encoded_BIT_STRING, asn1);

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_sequence__argument_len_32__returns_encoded_sequence_with_len_32(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_SEQUENCE_WITH_LEN_32.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_sequence(asn1wr, 32);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_SEQUENCE_WITH_LEN_32.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_SEQUENCE_WITH_LEN_32.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(
            test_asn1_encoded_SEQUENCE_WITH_LEN_32.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}

void
test__asn1wr_write_set__argument_len_32__returns_encoded_set_with_len_32(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(test_asn1_encoded_SET_WITH_LEN_32.len);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    size_t len = vscf_asn1wr_write_set(asn1wr, 32);
    size_t writtenBytes = vscf_asn1wr_finish(asn1wr);
    vsc_buffer_reserve(asn1, writtenBytes);

    TEST_ASSERT_EQUAL(test_asn1_encoded_SET_WITH_LEN_32.len, len);
    TEST_ASSERT_EQUAL(test_asn1_encoded_SET_WITH_LEN_32.len, vsc_buffer_len(asn1));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(test_asn1_encoded_SET_WITH_LEN_32.bytes, vsc_buffer_bytes(asn1), vsc_buffer_len(asn1));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}


// --------------------------------------------------------------------------
// Test 'error' method.
// --------------------------------------------------------------------------

void
test__asn1wr_error__write_to_small_buffer__returns_error_small_buffer(void) {

    vscf_asn1wr_impl_t *asn1wr = vscf_asn1wr_new();
    VSCF_ASSERT_PTR(asn1wr);

    vsc_buffer_t *asn1 = vsc_buffer_new_with_capacity(1);

    vscf_asn1wr_reset(asn1wr, vsc_buffer_ptr(asn1), vsc_buffer_left(asn1));

    vscf_asn1wr_write_int(asn1wr, 2);

    TEST_ASSERT_EQUAL(vscf_error_SMALL_BUFFER, vscf_asn1wr_error(asn1wr));

    vsc_buffer_destroy(&asn1);
    vscf_asn1wr_destroy(&asn1wr);
}


#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__asn1wr_finish__argument_integer_2_and_buffer_capacity_is_doubled__returns_encoded_integer_2);

    RUN_TEST(test__asn1wr_write_tag__argument_tag_int__returns_tag_int);
    RUN_TEST(test__asn1wr_write_len__argument_len_100000__returns_hex_830186A0);

    RUN_TEST(test__asn1wr_write_int__argument_int_2__returns_encoded_int_2);
    RUN_TEST(test__asn1wr_write_int__argument_int_neg_2__returns_encoded_int_neg_2);
    RUN_TEST(test__asn1wr_write_int8__argument_int_0__returns_encoded_int_0);
    RUN_TEST(test__asn1wr_write_int8__argument_int8_max__returns_encoded_int8_max);
    RUN_TEST(test__asn1wr_write_int8__argument_int8_min__returns_encoded_int8_min);
    RUN_TEST(test__asn1wr_write_int16__argument_int_32760__returns_encoded_int_32760);
    RUN_TEST(test__asn1wr_write_int16__argument_int_neg_32760__returns_encoded_int_neg_32760);
    RUN_TEST(test__asn1wr_write_int32__argument_int_2147483000__returns_encoded_int_2147483000);
    RUN_TEST(test__asn1wr_write_int32__argument_int_neg_2147483000__returns_encoded_int_neg_2147483000);
    RUN_TEST(test__asn1wr_write_uint8__argument_int_255__returns_encoded_int_255);
    RUN_TEST(test__asn1wr_write_uint8__argument_int_0__returns_encoded_int_0);
    RUN_TEST(test__asn1wr_write_uint16__argument_uint16_max__returns_encoded_uint16_max);
    RUN_TEST(test__asn1wr_write_uint32__argument_uint32_max__returns_encoded_uint32_max);
    RUN_TEST(test__asn1wr_write_uint__argument_uint16_max__returns_encoded_uint16_max);
    RUN_TEST(test__asn1wr_write_int64__argument_int64_max__returns_encoded_int64_max);
    RUN_TEST(test__asn1wr_write_int64__argument_int64_min__returns_encoded_int64_min);
    RUN_TEST(test__asn1wr_write_uint64__argument_uint64_max__returns_encoded_uint64_max);
    RUN_TEST(test__asn1wr_write_bool__argument_bool_false__returns_encoded_bool_false);
    RUN_TEST(test__asn1wr_write_bool__argument_bool_true__returns_encoded_bool_true);
    RUN_TEST(test__asn1wr_write_null__argument_null__returns_encoded_null);

    RUN_TEST(test__asn1wr_write_octet_str__argument_octet_string__returns_encoded_octet_string);
    RUN_TEST(test__asn1wr_write_utf8_str_argument_utf8_string__returns_encoded_utf8_string);
    RUN_TEST(test__asn1wr_write_oid__argument_oid_sha256__returns_encoded_oid_sha256);
    RUN_TEST(test__asn1wr_write_octet_str_as_bitstring__argument_bitstring__returns_encoded_bitstring);

    RUN_TEST(test__asn1wr_write_sequence__argument_len_32__returns_encoded_sequence_with_len_32);
    RUN_TEST(test__asn1wr_write_set__argument_len_32__returns_encoded_set_with_len_32);

    RUN_TEST(test__asn1wr_error__write_to_small_buffer__returns_error_small_buffer);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
