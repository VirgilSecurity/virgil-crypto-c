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
//      notice, this list of conditions and the following disclaimer in the
//      documentation and/or other materials provided with the distribution.
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

#define TEST_DEPENDENCIES_AVAILABLE (VSCF_POST_QUANTUM && MLKEM_LIBRARY)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_ctr_drbg.h"
#include "vscf_ml_kem.h"


static void *
impl_new(void *ctx) {
    (void)ctx;
    for (size_t i = 0; i < 1000000; ++i) {
        vscf_ml_kem_t *ml_kem = vscf_ml_kem_new();
        vscf_ml_kem_destroy(&ml_kem);
    }
    return NULL;
}

void
test__new__1000000_times_3_threads__no_crash(void) {
    pthread_t t1, t2, t3;
    pthread_create(&t1, NULL, impl_new, NULL);
    pthread_create(&t2, NULL, impl_new, NULL);
    pthread_create(&t3, NULL, impl_new, NULL);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);
}

static void *
impl_generate_key(void *ctx) {
    vscf_ml_kem_t *ml_kem = (vscf_ml_kem_t *)ctx;
    vscf_error_t error;
    vscf_error_reset(&error);

    for (size_t i = 0; i < 300; ++i) {
        vscf_impl_t *private_key = vscf_ml_kem_generate_key(ml_kem, &error);
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
        vscf_impl_destroy(&private_key);
    }
    return NULL;
}

void
test__generate_key__with_global_rng_300_times_3_threads__no_crash(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_ml_kem_t *ml_kem = vscf_ml_kem_new();
    vscf_ml_kem_use_random(ml_kem, vscf_ctr_drbg_impl(rng));

    pthread_t t1, t2, t3;
    pthread_create(&t1, NULL, impl_generate_key, ml_kem);
    pthread_create(&t2, NULL, impl_generate_key, ml_kem);
    pthread_create(&t3, NULL, impl_generate_key, ml_kem);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);

    vscf_ml_kem_destroy(&ml_kem);
    vscf_ctr_drbg_destroy(&rng);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


int
main(void) {
    UNITY_BEGIN();
#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__new__1000000_times_3_threads__no_crash);
    RUN_TEST(test__generate_key__with_global_rng_300_times_3_threads__no_crash);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif
    return UNITY_END();
}
