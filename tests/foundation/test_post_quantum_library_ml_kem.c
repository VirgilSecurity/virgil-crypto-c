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

#define TEST_DEPENDENCIES_AVAILABLE MLKEM_LIBRARY
#if TEST_DEPENDENCIES_AVAILABLE

#define MLK_CONFIG_API_PARAMETER_SET 768
#define MLK_CONFIG_API_NAMESPACE_PREFIX mlkem768
#define MLK_CONFIG_API_NO_SUPERCOP
#include <mlkem/mlkem_native.h>

#include <string.h>

static const uint8_t keygen_seed[64] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31,
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40};

static const uint8_t enc_seed[32] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
        0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60};

void
test__keypair_derand__fixed_seed__success(void) {
    uint8_t pk[MLKEM768_PUBLICKEYBYTES];
    uint8_t sk[MLKEM768_SECRETKEYBYTES];

    const int status = mlkem768_keypair_derand(pk, sk, keygen_seed);
    TEST_ASSERT_EQUAL(0, status);

    TEST_ASSERT_EQUAL(MLKEM768_PUBLICKEYBYTES, sizeof(pk));
    TEST_ASSERT_EQUAL(MLKEM768_SECRETKEYBYTES, sizeof(sk));
}

void
test__enc_dec_derand__round_trip__shared_keys_match(void) {
    uint8_t pk[MLKEM768_PUBLICKEYBYTES];
    uint8_t sk[MLKEM768_SECRETKEYBYTES];
    uint8_t ct[MLKEM768_CIPHERTEXTBYTES];
    uint8_t ss_enc[MLKEM_BYTES];
    uint8_t ss_dec[MLKEM_BYTES];

    int status = mlkem768_keypair_derand(pk, sk, keygen_seed);
    TEST_ASSERT_EQUAL(0, status);

    status = mlkem768_enc_derand(ct, ss_enc, pk, enc_seed);
    TEST_ASSERT_EQUAL(0, status);

    status = mlkem768_dec(ss_dec, ct, sk);
    TEST_ASSERT_EQUAL(0, status);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(ss_enc, ss_dec, MLKEM_BYTES);
}

void
test__dec__with_wrong_ciphertext__produces_different_shared_key(void) {
    uint8_t pk[MLKEM768_PUBLICKEYBYTES];
    uint8_t sk[MLKEM768_SECRETKEYBYTES];
    uint8_t ct[MLKEM768_CIPHERTEXTBYTES];
    uint8_t ss_enc[MLKEM_BYTES];
    uint8_t ss_dec[MLKEM_BYTES];

    TEST_ASSERT_EQUAL(0, mlkem768_keypair_derand(pk, sk, keygen_seed));
    TEST_ASSERT_EQUAL(0, mlkem768_enc_derand(ct, ss_enc, pk, enc_seed));

    /* Corrupt the ciphertext */
    ct[0] ^= 0xFF;

    /* mlkem768_dec always succeeds (returns 0) with implicit rejection for bad ciphertext */
    TEST_ASSERT_EQUAL(0, mlkem768_dec(ss_dec, ct, sk));

    /* Decapsulation of a wrong ciphertext must produce a different shared key (implicit rejection) */
    TEST_ASSERT_NOT_EQUAL(0, memcmp(ss_enc, ss_dec, MLKEM_BYTES));
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__keypair_derand__fixed_seed__success);
    RUN_TEST(test__enc_dec_derand__round_trip__shared_keys_match);
    RUN_TEST(test__dec__with_wrong_ciphertext__produces_different_shared_key);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
