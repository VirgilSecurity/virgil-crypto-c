//  Copyright (C) 2015-2019 Virgil Security, Inc.
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

#define TEST_DEPENDENCIES_AVAILABLE (VSCF_POST_QUANTUM && FALCON_LIBRARY)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_falcon.h"
#include "vscf_fake_random.h"

#include "test_data_falcon.h"

#include <falcon/falcon.h>

void
test__generate_key__512_degree__success(void) {

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(fake_random, test_data_falcon_RNG_SEED);

    vscf_falcon_t *falcon = vscf_falcon_new();
    vscf_falcon_take_random(falcon, vscf_fake_random_impl(fake_random));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_falcon_generate_key(falcon, &error);
    TEST_ASSERT_FALSE(vscf_error_has_error(&error));

    vscf_raw_private_key_t *raw_private_key = vscf_falcon_export_private_key(falcon, private_key, &error);
    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_EQUAL_DATA(test_data_falcon_PRIVATE_KEY_512, vscf_raw_private_key_data(raw_private_key));

    vscf_raw_public_key_t *raw_public_key =
            (vscf_raw_public_key_t *)vscf_raw_private_key_extract_public_key(raw_private_key);
    TEST_ASSERT_NOT_NULL(raw_public_key);
    TEST_ASSERT_EQUAL_DATA(test_data_falcon_PUBLIC_KEY_512, vscf_raw_public_key_data(raw_public_key));

    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_impl_destroy(&private_key);
    vscf_falcon_destroy(&falcon);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__generate_key__512_degree__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
