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

#ifndef ROUND5_LIBRARY
#error lskdjhfkjsdhflkdsj
#endif

#define TEST_DEPENDENCIES_AVAILABLE ROUND5_LIBRARY
#if TEST_DEPENDENCIES_AVAILABLE

#include <r5_cpa_kem.h>

void
test__cpa_kem_keygen__returns_success(void) {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0x00};
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0x00};

    parameters *params = set_parameters_from_api();
    TEST_ASSERT_NOT_NULL(params);

    int status = r5_cpa_kem_keygen(pk, sk, params);
    TEST_ASSERT_EQUAL(0, status);
}

void
test__cpa_kem_encapsulate__returns_success(void) {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0x00};
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0x00};
    unsigned char shared_secret[CRYPTO_BYTES] = {0x00};
    unsigned char ciphertext[CRYPTO_CIPHERTEXTBYTES] = {0x00};

    parameters *params = set_parameters_from_api();
    TEST_ASSERT_NOT_NULL(params);

    int status = r5_cpa_kem_keygen(pk, sk, params);
    TEST_ASSERT_EQUAL(0, status);

    status = r5_cpa_kem_encapsulate(ciphertext, shared_secret, pk, params);
    TEST_ASSERT_EQUAL(0, status);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__cpa_kem_keygen__returns_success);
    RUN_TEST(test__cpa_kem_encapsulate__returns_success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
