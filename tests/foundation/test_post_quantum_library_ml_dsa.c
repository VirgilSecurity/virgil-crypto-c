//  Copyright (C) 2015-2026 Virgil Security, Inc.
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

#define TEST_DEPENDENCIES_AVAILABLE MLDSA_LIBRARY
#if TEST_DEPENDENCIES_AVAILABLE

#define MLD_CONFIG_API_PARAMETER_SET 65
#define MLD_CONFIG_API_NAMESPACE_PREFIX mldsa65
#define MLD_CONFIG_API_NO_SUPERCOP
#include <mldsa/mldsa_native.h>

#include <string.h>

static const uint8_t keygen_seed[MLDSA_SEEDBYTES] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F, 0x20};

static const uint8_t message[32] = {0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
        0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80};

/* Deterministic signing: zero randomness */
static const uint8_t rnd_zero[MLDSA_RNDBYTES] = {0};

void
test__keypair_internal__fixed_seed__success(void) {
    uint8_t pk[MLDSA65_PUBLICKEYBYTES];
    uint8_t sk[MLDSA65_SECRETKEYBYTES];

    const int status = mldsa65_keypair_internal(pk, sk, keygen_seed);
    TEST_ASSERT_EQUAL(0, status);

    TEST_ASSERT_EQUAL(MLDSA65_PUBLICKEYBYTES, sizeof(pk));
    TEST_ASSERT_EQUAL(MLDSA65_SECRETKEYBYTES, sizeof(sk));
}

void
test__sign_verify_internal__round_trip__success(void) {
    uint8_t pk[MLDSA65_PUBLICKEYBYTES];
    uint8_t sk[MLDSA65_SECRETKEYBYTES];
    uint8_t sig[MLDSA65_BYTES];
    size_t sig_len = sizeof(sig);

    int status = mldsa65_keypair_internal(pk, sk, keygen_seed);
    TEST_ASSERT_EQUAL(0, status);

    status = mldsa65_signature_internal(sig, &sig_len, message, sizeof(message), NULL, 0, rnd_zero, sk, 0);
    TEST_ASSERT_EQUAL(0, status);
    TEST_ASSERT_LESS_OR_EQUAL(MLDSA65_BYTES, sig_len);

    status = mldsa65_verify_internal(sig, sig_len, message, sizeof(message), NULL, 0, pk, 0);
    TEST_ASSERT_EQUAL(0, status);
}

void
test__verify__with_wrong_message__fails(void) {
    uint8_t pk[MLDSA65_PUBLICKEYBYTES];
    uint8_t sk[MLDSA65_SECRETKEYBYTES];
    uint8_t sig[MLDSA65_BYTES];
    size_t sig_len = sizeof(sig);
    uint8_t wrong_message[32];

    TEST_ASSERT_EQUAL(0, mldsa65_keypair_internal(pk, sk, keygen_seed));
    TEST_ASSERT_EQUAL(0, mldsa65_signature_internal(sig, &sig_len, message, sizeof(message), NULL, 0, rnd_zero, sk, 0));

    memcpy(wrong_message, message, sizeof(message));
    wrong_message[0] ^= 0xFF;

    const int status = mldsa65_verify_internal(sig, sig_len, wrong_message, sizeof(wrong_message), NULL, 0, pk, 0);
    TEST_ASSERT_NOT_EQUAL(0, status);
}

void
test__verify__deterministic_sign__produces_same_sig_twice(void) {
    uint8_t pk[MLDSA65_PUBLICKEYBYTES];
    uint8_t sk[MLDSA65_SECRETKEYBYTES];
    uint8_t sig1[MLDSA65_BYTES];
    uint8_t sig2[MLDSA65_BYTES];
    size_t sig_len1 = sizeof(sig1);
    size_t sig_len2 = sizeof(sig2);

    TEST_ASSERT_EQUAL(0, mldsa65_keypair_internal(pk, sk, keygen_seed));

    TEST_ASSERT_EQUAL(
            0, mldsa65_signature_internal(sig1, &sig_len1, message, sizeof(message), NULL, 0, rnd_zero, sk, 0));
    TEST_ASSERT_EQUAL(
            0, mldsa65_signature_internal(sig2, &sig_len2, message, sizeof(message), NULL, 0, rnd_zero, sk, 0));

    TEST_ASSERT_EQUAL(sig_len1, sig_len2);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(sig1, sig2, sig_len1);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__keypair_internal__fixed_seed__success);
    RUN_TEST(test__sign_verify_internal__round_trip__success);
    RUN_TEST(test__verify__with_wrong_message__fails);
    RUN_TEST(test__verify__deterministic_sign__produces_same_sig_twice);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
