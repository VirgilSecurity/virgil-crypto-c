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


#define TEST_DEPENDENCIES_AVAILABLE VSCF_BASE64
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_base64.h"

#include "test_data_base64.h"


// --------------------------------------------------------------------------
//  Should have it to prevent linkage erros in MSVC.
// --------------------------------------------------------------------------
void setUp(void) { }
void tearDown(void) { }
void suiteSetUp(void) { }
int suiteTearDown(int num_failures) { return num_failures; }


// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------
void
test__encoded_len__empty__returns_0(void) {

    size_t len = vscf_base64_encoded_len(test_base64_DECODED_EMPTY.len);
    TEST_ASSERT_EQUAL(0, len);
}


void
test__encode__empty__returns_empty(void) {

    vsc_buffer_t *encoded = vsc_buffer_new_with_capacity(vscf_base64_encoded_len(test_base64_DECODED_EMPTY.len));

    vscf_base64_encode(test_base64_DECODED_EMPTY, encoded);
    TEST_ASSERT_EQUAL(0, vsc_buffer_len(encoded));

    vsc_buffer_destroy(&encoded);
}

void
test__decode__encoded_empty__returns_empty(void) {
    vsc_buffer_t *decoded = vsc_buffer_new_with_capacity(vscf_base64_decoded_len(test_base64_ENCODED_EMPTY.len));

    vscf_error_t status = vscf_base64_decode(test_base64_ENCODED_EMPTY, decoded);
    TEST_ASSERT_EQUAL(vscf_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, vsc_buffer_len(decoded));

    vsc_buffer_destroy(&decoded);
}

void
test__encoded_len__f__returns_5(void) {

    size_t len = vscf_base64_encoded_len(test_base64_DECODED_LOWERCASE_F.len);
    TEST_ASSERT_EQUAL(5, len);
}

void
test__encode__f__returns_encoded_f(void) {

    vsc_buffer_t *encoded = vsc_buffer_new_with_capacity(vscf_base64_encoded_len(test_base64_DECODED_LOWERCASE_F.len));

    vscf_base64_encode(test_base64_DECODED_LOWERCASE_F, encoded);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_base64_ENCODED_LOWERCASE_F, encoded);

    vsc_buffer_destroy(&encoded);
}

void
test__decode__encoded_f__returns_f(void) {
    vsc_buffer_t *decoded = vsc_buffer_new_with_capacity(vscf_base64_decoded_len(test_base64_ENCODED_LOWERCASE_F.len));

    vscf_error_t status = vscf_base64_decode(test_base64_ENCODED_LOWERCASE_F, decoded);
    TEST_ASSERT_EQUAL(vscf_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_base64_DECODED_LOWERCASE_F, decoded);

    vsc_buffer_destroy(&decoded);
}

void
test__encoded_len__fo__returns_5(void) {

    size_t len = vscf_base64_encoded_len(test_base64_DECODED_LOWERCASE_FO.len);
    TEST_ASSERT_EQUAL(5, len);
}

void
test__encode__fo__returns_encoded_fo(void) {

    vsc_buffer_t *encoded = vsc_buffer_new_with_capacity(vscf_base64_encoded_len(test_base64_DECODED_LOWERCASE_FO.len));

    vscf_base64_encode(test_base64_DECODED_LOWERCASE_FO, encoded);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_base64_ENCODED_LOWERCASE_FO, encoded);

    vsc_buffer_destroy(&encoded);
}

void
test__decode__encoded_fo__returns_fo(void) {
    vsc_buffer_t *decoded = vsc_buffer_new_with_capacity(vscf_base64_decoded_len(test_base64_ENCODED_LOWERCASE_FO.len));

    vscf_error_t status = vscf_base64_decode(test_base64_ENCODED_LOWERCASE_FO, decoded);
    TEST_ASSERT_EQUAL(vscf_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_base64_DECODED_LOWERCASE_FO, decoded);

    vsc_buffer_destroy(&decoded);
}

void
test__encoded_len__foo__returns_5(void) {

    size_t len = vscf_base64_encoded_len(test_base64_DECODED_LOWERCASE_FOO.len);
    TEST_ASSERT_EQUAL(5, len);
}

void
test__encode__foo__returns_encoded_foo(void) {

    vsc_buffer_t *encoded =
            vsc_buffer_new_with_capacity(vscf_base64_encoded_len(test_base64_DECODED_LOWERCASE_FOO.len));

    vscf_base64_encode(test_base64_DECODED_LOWERCASE_FOO, encoded);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_base64_ENCODED_LOWERCASE_FOO, encoded);

    vsc_buffer_destroy(&encoded);
}

void
test__decode__encoded_foo__returns_foo(void) {
    vsc_buffer_t *decoded =
            vsc_buffer_new_with_capacity(vscf_base64_decoded_len(test_base64_ENCODED_LOWERCASE_FOO.len));

    vscf_error_t status = vscf_base64_decode(test_base64_ENCODED_LOWERCASE_FOO, decoded);
    TEST_ASSERT_EQUAL(vscf_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_base64_DECODED_LOWERCASE_FOO, decoded);

    vsc_buffer_destroy(&decoded);
}

void
test__encoded_len__foob__returns_9(void) {

    size_t len = vscf_base64_encoded_len(test_base64_DECODED_LOWERCASE_FOOB.len);
    TEST_ASSERT_EQUAL(9, len);
}

void
test__encode__foob__returns_encoded_foob(void) {

    vsc_buffer_t *encoded =
            vsc_buffer_new_with_capacity(vscf_base64_encoded_len(test_base64_DECODED_LOWERCASE_FOOB.len));

    vscf_base64_encode(test_base64_DECODED_LOWERCASE_FOOB, encoded);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_base64_ENCODED_LOWERCASE_FOOB, encoded);

    vsc_buffer_destroy(&encoded);
}

void
test__decode__encoded_foob__returns_foob(void) {
    vsc_buffer_t *decoded =
            vsc_buffer_new_with_capacity(vscf_base64_decoded_len(test_base64_ENCODED_LOWERCASE_FOOB.len));

    vscf_error_t status = vscf_base64_decode(test_base64_ENCODED_LOWERCASE_FOOB, decoded);
    TEST_ASSERT_EQUAL(vscf_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_base64_DECODED_LOWERCASE_FOOB, decoded);

    vsc_buffer_destroy(&decoded);
}

void
test__encoded_len__fooba__returns_9(void) {

    size_t len = vscf_base64_encoded_len(test_base64_DECODED_LOWERCASE_FOOBA.len);
    TEST_ASSERT_EQUAL(9, len);
}

void
test__encode__fooba__returns_encoded_fooba(void) {

    vsc_buffer_t *encoded =
            vsc_buffer_new_with_capacity(vscf_base64_encoded_len(test_base64_DECODED_LOWERCASE_FOOBA.len));

    vscf_base64_encode(test_base64_DECODED_LOWERCASE_FOOBA, encoded);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_base64_ENCODED_LOWERCASE_FOOBA, encoded);

    vsc_buffer_destroy(&encoded);
}

void
test__decode__encoded_fooba__returns_fooba(void) {
    vsc_buffer_t *decoded =
            vsc_buffer_new_with_capacity(vscf_base64_decoded_len(test_base64_ENCODED_LOWERCASE_FOOBA.len));

    vscf_error_t status = vscf_base64_decode(test_base64_ENCODED_LOWERCASE_FOOBA, decoded);
    TEST_ASSERT_EQUAL(vscf_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_base64_DECODED_LOWERCASE_FOOBA, decoded);

    vsc_buffer_destroy(&decoded);
}

void
test__encoded_len__foobar__returns_9(void) {

    size_t len = vscf_base64_encoded_len(test_base64_DECODED_LOWERCASE_FOOBAR.len);
    TEST_ASSERT_EQUAL(9, len);
}

void
test__encode__foobar__returns_encoded_foobar(void) {

    vsc_buffer_t *encoded =
            vsc_buffer_new_with_capacity(vscf_base64_encoded_len(test_base64_DECODED_LOWERCASE_FOOBAR.len));

    vscf_base64_encode(test_base64_DECODED_LOWERCASE_FOOBAR, encoded);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_base64_ENCODED_LOWERCASE_FOOBAR, encoded);

    vsc_buffer_destroy(&encoded);
}

void
test__decode__encoded_foobar__returns_foobar(void) {
    vsc_buffer_t *decoded =
            vsc_buffer_new_with_capacity(vscf_base64_decoded_len(test_base64_ENCODED_LOWERCASE_FOOBAR.len));

    vscf_error_t status = vscf_base64_decode(test_base64_ENCODED_LOWERCASE_FOOBAR, decoded);
    TEST_ASSERT_EQUAL(vscf_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_base64_DECODED_LOWERCASE_FOOBAR, decoded);

    vsc_buffer_destroy(&decoded);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__encoded_len__empty__returns_0);
    RUN_TEST(test__encode__empty__returns_empty);
    RUN_TEST(test__decode__encoded_empty__returns_empty);
    RUN_TEST(test__encoded_len__f__returns_5);
    RUN_TEST(test__encode__f__returns_encoded_f);
    RUN_TEST(test__decode__encoded_f__returns_f);
    RUN_TEST(test__encoded_len__fo__returns_5);
    RUN_TEST(test__encode__fo__returns_encoded_fo);
    RUN_TEST(test__decode__encoded_fo__returns_fo);
    RUN_TEST(test__encoded_len__foo__returns_5);
    RUN_TEST(test__encode__foo__returns_encoded_foo);
    RUN_TEST(test__decode__encoded_foo__returns_foo);
    RUN_TEST(test__encoded_len__foob__returns_9);
    RUN_TEST(test__encode__foob__returns_encoded_foob);
    RUN_TEST(test__decode__encoded_foob__returns_foob);
    RUN_TEST(test__encoded_len__fooba__returns_9);
    RUN_TEST(test__encode__fooba__returns_encoded_fooba);
    RUN_TEST(test__decode__encoded_fooba__returns_fooba);
    RUN_TEST(test__encoded_len__foobar__returns_9);
    RUN_TEST(test__encode__foobar__returns_encoded_foobar);
    RUN_TEST(test__decode__encoded_foobar__returns_foobar);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
