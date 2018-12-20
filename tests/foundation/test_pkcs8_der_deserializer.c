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


#define TEST_DEPENDENCIES_AVAILABLE VSCF_PKCS8_DER_DESERIALIZER &&VSCF_ASN1RD
#if TEST_DEPENDENCIES_AVAILABLE

#include "test_data_rsa.h"
#include "vscf_pkcs8_der_deserializer.h"


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
// PKCS#8 RSA keys.
// --------------------------------------------------------------------------
void
test__deserialize_public_key__rsa2048__no_errors(void) {
#if VSCF_RSA_PUBLIC_KEY
    vscf_pkcs8_der_deserializer_t *pkcs8 = vscf_pkcs8_der_deserializer_new();
    vscf_pkcs8_der_deserializer_setup_defaults(pkcs8);

    vscf_error_ctx_t error_ctx;
    vscf_raw_key_t *raw_public_key =
            vscf_pkcs8_der_deserializer_deserialize_public_key(pkcs8, test_rsa_2048_PUBLIC_KEY_PKCS8_DER, &error_ctx);

    TEST_ASSERT_EQUAL(vscf_SUCCESS, error_ctx.error);
    TEST_ASSERT_NOT_NULL(raw_public_key);

    vscf_raw_key_destroy(&raw_public_key);
    vscf_pkcs8_der_deserializer_destroy(&pkcs8);
#else
    TEST_IGNORE_MESSAGE("VSCF_RSA_PUBLIC_KEY is disabled");
#endif
}


void
test__deserialize_public_key__rsa2048__equals_to_rsa_2048_public_key_pkcs1_der(void) {
#if VSCF_RSA_PUBLIC_KEY
    vscf_pkcs8_der_deserializer_t *pkcs8 = vscf_pkcs8_der_deserializer_new();
    vscf_pkcs8_der_deserializer_setup_defaults(pkcs8);

    vscf_error_ctx_t error;
    vscf_raw_key_t *raw_public_key =
            vscf_pkcs8_der_deserializer_deserialize_public_key(pkcs8, test_rsa_2048_PUBLIC_KEY_PKCS8_DER, &error);

    TEST_ASSERT_EQUAL(vscf_raw_key_alg(raw_public_key), vscf_key_alg_RSA);

    TEST_ASSERT_EQUAL_DATA(test_rsa_2048_PUBLIC_KEY_PKCS1, vscf_raw_key_data(raw_public_key));

    vscf_raw_key_destroy(&raw_public_key);
    vscf_pkcs8_der_deserializer_destroy(&pkcs8);
#else
    TEST_IGNORE_MESSAGE("VSCF_RSA_PUBLIC_KEY is disabled");
#endif
}


void
test__deserialize_private_key__rsa2048__no_errors(void) {
#if VSCF_RSA_PRIVATE_KEY
    vscf_pkcs8_der_deserializer_t *pkcs8 = vscf_pkcs8_der_deserializer_new();
    vscf_pkcs8_der_deserializer_setup_defaults(pkcs8);

    vscf_error_ctx_t error_ctx;
    vscf_raw_key_t *raw_private_key =
            vscf_pkcs8_der_deserializer_deserialize_private_key(pkcs8, test_rsa_2048_PRIVATE_KEY_PKCS8_DER, &error_ctx);

    TEST_ASSERT_EQUAL(vscf_SUCCESS, error_ctx.error);
    TEST_ASSERT_NOT_NULL(raw_private_key);

    vscf_raw_key_destroy(&raw_private_key);
    vscf_pkcs8_der_deserializer_destroy(&pkcs8);
#else
    TEST_IGNORE_MESSAGE("VSCF_RSA_PRIVATE_KEY is disabled");
#endif
}


void
test__deserialize_private_key__rsa2048__equals_to_rsa_2048_private_key_pkcs1_der(void) {
#if VSCF_RSA_PRIVATE_KEY
    vscf_pkcs8_der_deserializer_t *pkcs8 = vscf_pkcs8_der_deserializer_new();
    vscf_pkcs8_der_deserializer_setup_defaults(pkcs8);

    vscf_error_ctx_t error;
    vscf_raw_key_t *raw_private_key =
            vscf_pkcs8_der_deserializer_deserialize_private_key(pkcs8, test_rsa_2048_PRIVATE_KEY_PKCS8_DER, &error);

    TEST_ASSERT_EQUAL(vscf_raw_key_alg(raw_private_key), vscf_key_alg_RSA);

    TEST_ASSERT_EQUAL_DATA(test_rsa_2048_PRIVATE_KEY_PKCS1, vscf_raw_key_data(raw_private_key));

    vscf_raw_key_destroy(&raw_private_key);
    vscf_pkcs8_der_deserializer_destroy(&pkcs8);
#else
    TEST_IGNORE_MESSAGE("VSCF_RSA_PRIVATE_KEY is disabled");
#endif
}


#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
//  Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__deserialize_public_key__rsa2048__no_errors);
    RUN_TEST(test__deserialize_public_key__rsa2048__equals_to_rsa_2048_public_key_pkcs1_der);
    RUN_TEST(test__deserialize_private_key__rsa2048__no_errors);
    RUN_TEST(test__deserialize_private_key__rsa2048__equals_to_rsa_2048_private_key_pkcs1_der);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
