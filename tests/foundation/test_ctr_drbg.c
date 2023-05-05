//  Copyright (C) 2015-2022 Virgil Security, Inc.
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


#define TEST_DEPENDENCIES_AVAILABLE VSCF_CTR_DRBG
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_ctr_drbg.h"
#include "vscf_fake_random.h"

#include "test_data_ctr_drbg.h"


// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------
void
test__ctr_drbg_random__zero_entropy_and_len_128__returns__random_set_1(void) {
    vscf_fake_random_t *entropy = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(entropy, 0x00);

    vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_take_entropy_source(random, vscf_fake_random_impl(entropy)));

    size_t len = 128;
    vsc_buffer_t *data = vsc_buffer_new_with_capacity(len);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_random(random, len, data));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_ctr_drbg_RANDOM_SET_1, data);

    vsc_buffer_destroy(&data);
    vscf_ctr_drbg_destroy(&random);
}

void
test__ctr_drbg_random__zero_entropy_and_len_32_and_capacity_64__writes_32_bytes_only(void) {
    vscf_fake_random_t *entropy = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(entropy, 0x00);

    vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_take_entropy_source(random, vscf_fake_random_impl(entropy)));

    size_t len = 32;
    size_t capacity = 64;
    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(capacity);
    vsc_buffer_erase(buffer);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_random(random, len, buffer));

    vsc_data_t buffer_left = vsc_data_slice_beg(vsc_data(vsc_buffer_bytes(buffer), capacity), 32, 32);
    TEST_ASSERT_TRUE_MESSAGE(vsc_data_is_zero(buffer_left), "Writes more then requested");

    vsc_buffer_destroy(&buffer);
    vscf_ctr_drbg_destroy(&random);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
//  Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__ctr_drbg_random__zero_entropy_and_len_128__returns__random_set_1);
    RUN_TEST(test__ctr_drbg_random__zero_entropy_and_len_32_and_capacity_64__writes_32_bytes_only);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
