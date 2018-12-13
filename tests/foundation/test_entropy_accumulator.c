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


#define TEST_DEPENDENCIES_AVAILABLE VSCF_ENTROPY_ACCUMULATOR
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_entropy_accumulator.h"
#include "vscf_fake_random.h"

#include "test_data_entropy_accumulator.h"


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
test__entropy_accumulator__zero_entropy_and_len_64__returns__entropy_set_1(void) {
    vscf_fake_random_impl_t *entropy = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(entropy, 0x00);

    vscf_entropy_accumulator_impl_t *entropy_accumulator = vscf_entropy_accumulator_new();
    vscf_entropy_accumulator_add_source(entropy_accumulator, vscf_fake_random_impl(entropy), 32);

    size_t len = 64;
    vsc_buffer_t *data = vsc_buffer_new_with_capacity(len);

    vscf_error_t result = vscf_entropy_accumulator_gather(entropy_accumulator, len, data);

    TEST_ASSERT_EQUAL(vscf_SUCCESS, result);
    TEST_ASSERT_EQUAL(len, vsc_buffer_len(data));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_entropy_accumulator_ENTROPY_SET_1, data);

    vsc_buffer_destroy(&data);
    vscf_fake_random_destroy(&entropy);
    vscf_entropy_accumulator_destroy(&entropy_accumulator);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
//  Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__entropy_accumulator__zero_entropy_and_len_64__returns__entropy_set_1);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
