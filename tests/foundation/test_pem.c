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


#define TEST_DEPENDENCIES_AVAILABLE VSCF_PEM
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_pem.h"

#include "test_data_pem.h"


void
test__unwrap__broken_pem_no_header__returns_error_bad_pem(void) {

    vsc_buffer_t *data = vsc_buffer_new_with_capacity(vscf_pem_unwrapped_len(test_pem_NO_HEADER.len));

    vscf_error_t status = vscf_pem_unwrap(test_pem_NO_HEADER, data);
    TEST_ASSERT_EQUAL(vscf_error_BAD_PEM, status);

    vsc_buffer_destroy(&data);
}

void
test__unwrap__broken_pem_header_without_tariling_dashes__returns_error_bad_pem(void) {

    vsc_buffer_t *data =
            vsc_buffer_new_with_capacity(vscf_pem_unwrapped_len(test_pem_HEADER_WITHOUT_TRAILING_DASHES.len));

    vscf_error_t status = vscf_pem_unwrap(test_pem_HEADER_WITHOUT_TRAILING_DASHES, data);
    TEST_ASSERT_EQUAL(vscf_error_BAD_PEM, status);

    vsc_buffer_destroy(&data);
}


void
test__unwrap__broken_pem_no_footer__returns_error_bad_pem(void) {

    vsc_buffer_t *data = vsc_buffer_new_with_capacity(vscf_pem_unwrapped_len(test_pem_NO_FOOTER.len));

    vscf_error_t status = vscf_pem_unwrap(test_pem_NO_FOOTER, data);
    TEST_ASSERT_EQUAL(vscf_error_BAD_PEM, status);

    vsc_buffer_destroy(&data);
}


void
test__unwrap__broken_pem_footer_without_tariling_dashes__returns_error_bad_pem(void) {

    vsc_buffer_t *data =
            vsc_buffer_new_with_capacity(vscf_pem_unwrapped_len(test_pem_FOOTER_WITHOUT_TRAILING_DASHES.len));

    vscf_error_t status = vscf_pem_unwrap(test_pem_FOOTER_WITHOUT_TRAILING_DASHES, data);
    TEST_ASSERT_EQUAL(vscf_error_BAD_PEM, status);

    vsc_buffer_destroy(&data);
}


void
test__unwrap__valid_pem_oneline_body__returns_unwrapped_data(void) {

    vsc_buffer_t *data = vsc_buffer_new_with_capacity(vscf_pem_unwrapped_len(test_pem_wrapped_ONELINE.len));

    vscf_error_t status = vscf_pem_unwrap(test_pem_wrapped_ONELINE, data);
    TEST_ASSERT_EQUAL(vscf_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_pem_unwrapped_ONELINE, data);

    vsc_buffer_destroy(&data);
}


void
test__unwrap__valid_pem_multiline_body__returns_unwrapped_data(void) {

    vsc_buffer_t *data = vsc_buffer_new_with_capacity(vscf_pem_unwrapped_len(test_pem_wrapped_MULTILINE.len));

    vscf_error_t status = vscf_pem_unwrap(test_pem_wrapped_MULTILINE, data);
    TEST_ASSERT_EQUAL(vscf_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_pem_unwrapped_MULTILINE, data);

    vsc_buffer_destroy(&data);
}

void
test__wrap__data_that_fits_oneline__returns_oneline_body_pem(void) {

    vsc_buffer_t *pem =
            vsc_buffer_new_with_capacity(vscf_pem_wrapped_len(test_pem_TITLE, test_pem_unwrapped_ONELINE.len));

    vscf_pem_wrap(test_pem_TITLE, test_pem_unwrapped_ONELINE, pem);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_pem_wrapped_ONELINE, pem);

    vsc_buffer_destroy(&pem);
}

void
test__wrap__data_that_fits_multiline__returns_multiline_body_pem(void) {

    vsc_buffer_t *pem =
            vsc_buffer_new_with_capacity(vscf_pem_wrapped_len(test_pem_TITLE, test_pem_unwrapped_MULTILINE.len));

    vscf_pem_wrap(test_pem_TITLE, test_pem_unwrapped_MULTILINE, pem);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_pem_wrapped_MULTILINE, pem);

    vsc_buffer_destroy(&pem);
}

void
test__title__valid_pem_oneline_body__returns__public_key(void) {
    vsc_data_t title = vscf_pem_title(test_pem_wrapped_ONELINE);
    TEST_ASSERT_EQUAL_DATA(vsc_data_from_str(test_pem_TITLE, test_pem_TITLE_LEN), title);
}

void
test__title__broken_pem_no_header__returns__empty_data(void) {
    vsc_data_t title = vscf_pem_title(test_pem_NO_HEADER);
    TEST_ASSERT_EQUAL_DATA(vsc_data_empty(), title);
}


#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__unwrap__broken_pem_no_header__returns_error_bad_pem);
    RUN_TEST(test__unwrap__broken_pem_header_without_tariling_dashes__returns_error_bad_pem);
    RUN_TEST(test__unwrap__broken_pem_no_footer__returns_error_bad_pem);
    RUN_TEST(test__unwrap__broken_pem_footer_without_tariling_dashes__returns_error_bad_pem);
    RUN_TEST(test__unwrap__valid_pem_oneline_body__returns_unwrapped_data);
    RUN_TEST(test__unwrap__valid_pem_multiline_body__returns_unwrapped_data);
    RUN_TEST(test__wrap__data_that_fits_oneline__returns_oneline_body_pem);
    RUN_TEST(test__wrap__data_that_fits_multiline__returns_multiline_body_pem);
    RUN_TEST(test__wrap__data_that_fits_multiline__returns_multiline_body_pem);
    RUN_TEST(test__title__valid_pem_oneline_body__returns__public_key);
    RUN_TEST(test__title__broken_pem_no_header__returns__empty_data);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
