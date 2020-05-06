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

#include <pthread.h>


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_POST_QUANTUM && VSCF_ROUND5)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_fake_random.h"
#include "vscf_round5.h"

#include "test_data_round5.h"

// --------------------------------------------------------------------------
static void *
impl_new(void *ctx) {
    (void)ctx;

    for (size_t i = 0; i < 1000000; ++i) {
        vscf_round5_t *round5 = vscf_round5_new();
        vscf_round5_destroy(&round5);
    }

    return NULL;
}

void
test__new__1000000_times_3_threads__no_crash(void) {

    pthread_t t1;
    pthread_create(&t1, NULL, impl_new, NULL);

    pthread_t t2;
    pthread_create(&t2, NULL, impl_new, NULL);

    pthread_t t3;
    pthread_create(&t3, NULL, impl_new, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);
}

// --------------------------------------------------------------------------
static void *
impl_generate_key(void *ctx) {
    vscf_round5_t *round5 = (vscf_round5_t *)ctx;

    vscf_error_t error;
    vscf_error_reset(&error);

    for (size_t i = 0; i < 300; ++i) {
        vscf_impl_t *private_key = vscf_round5_generate_key(round5, vscf_alg_id_ROUND5_ND_1CCA_5D, &error);
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
        vscf_impl_destroy(&private_key);
    }

    return NULL;
}

void
test__generate_key__with__global_rng_300_times_3_threads__no_crash(void) {

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_data_round5_RNG_SEED);

    vscf_round5_t *round5 = vscf_round5_new();
    vscf_round5_take_random(round5, vscf_fake_random_impl(fake_random));

    pthread_t t1;
    pthread_create(&t1, NULL, impl_generate_key, (void *)round5);

    pthread_t t2;
    pthread_create(&t2, NULL, impl_generate_key, (void *)round5);

    pthread_t t3;
    pthread_create(&t3, NULL, impl_generate_key, (void *)round5);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);

    vscf_round5_destroy(&round5);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__new__1000000_times_3_threads__no_crash);
    RUN_TEST(test__generate_key__with__global_rng_300_times_3_threads__no_crash);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
