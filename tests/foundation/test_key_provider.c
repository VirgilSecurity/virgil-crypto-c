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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_KEY_PROVIDER && VSCF_KEY)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_alg.h"
#include "vscf_key.h"
#include "vscf_key_provider.h"


// --------------------------------------------------------------------------
//  Should have it to prevent linkage erros in MSVC.
// --------------------------------------------------------------------------
// clang-format off
void setUp(void) { }
void tearDown(void) { }
void suiteSetUp(void) { }
int suiteTearDown(int num_failures) { return num_failures; }
// clang-format on


void
test__generate_private_key__rsa_2048__success(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_error_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_SUCCESS, status);

    vscf_key_provider_set_rsa_params(key_provider, 2048, 65537);

    vscf_error_ctx_t error;
    vscf_error_ctx_reset(&error);

    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_RSA, &error);
    TEST_ASSERT_NOT_NULL(private_key);

    TEST_ASSERT_EQUAL(vscf_alg_id_RSA, vscf_alg_alg_id(private_key));
    TEST_ASSERT_EQUAL(2048, vscf_key_key_bitlen(private_key));

    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__generate_private_key__ed25519__success(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_error_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_SUCCESS, status);

    vscf_error_ctx_t error;
    vscf_error_ctx_reset(&error);

    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ED25519, &error);
    TEST_ASSERT_NOT_NULL(private_key);

    TEST_ASSERT_EQUAL(vscf_alg_id_ED25519, vscf_alg_alg_id(private_key));
    TEST_ASSERT_EQUAL(256, vscf_key_key_bitlen(private_key));

    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__generate_private_key__rsa_2048__success);
    RUN_TEST(test__generate_private_key__ed25519__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
