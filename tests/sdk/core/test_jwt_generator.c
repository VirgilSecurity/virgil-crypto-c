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


#define TEST_DEPENDENCIES_AVAILABLE VSCS_CORE_JWT_GENERATOR
#if TEST_DEPENDENCIES_AVAILABLE

#include <virgil/crypto/foundation/vscf_private_key.h>
#include <virgil/crypto/foundation/vscf_key_provider.h>
#include <virgil/crypto/foundation/vscf_fake_random.h>

#include "vscs_core_jwt_generator.h"

#include "test_data_jwt.h"


void
test__generate__success(void) {

    vscs_core_error_t error;
    vscs_core_error_reset(&error);

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_take_random(key_provider, vscf_fake_random_impl(fake_random));

    vscf_impl_t *private_key = vscf_key_provider_import_private_key(key_provider, test_data_jwt_APP_KEY, NULL);
    TEST_ASSERT_NOT_NULL(private_key);

    vscs_core_jwt_generator_t *jwt_generator =
            vscs_core_jwt_generator_new_with_credentials(test_data_jwt_APP_ID, test_data_jwt_APP_KEY_ID, private_key);

    vscs_core_jwt_t *jwt = vscs_core_jwt_generator_generate_token(jwt_generator, test_data_jwt_IDENTITY, &error);
    TEST_ASSERT_EQUAL(vscs_core_status_SUCCESS, vscs_core_error_status(&error));
    TEST_ASSERT_NOT_NULL(jwt);

    print_str(vscs_core_jwt_as_string(jwt));

    vscf_key_provider_destroy(&key_provider);
    vscs_core_jwt_generator_destroy(&jwt_generator);
    vscs_core_jwt_destroy(&jwt);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__generate__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
