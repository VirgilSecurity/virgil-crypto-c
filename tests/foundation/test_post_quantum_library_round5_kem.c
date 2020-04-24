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

#define ROUND5_KEM_ENABLED 1

#define TEST_DEPENDENCIES_AVAILABLE ROUND5_LIBRARY &&ROUND5_KEM_ENABLED
#if TEST_DEPENDENCIES_AVAILABLE

#include "test_data_round5.h"

#include <round5/rng.h>
#include <round5/kem.h>

void
test__kem_keygen__with_nist_rng__equals_expected(void) {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0x00};
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0x00};

    randombytes_init((unsigned char *)test_data_round5_RNG_SEED.bytes, NULL, 1);

    int status = crypto_kem_keypair(pk, sk);
    TEST_ASSERT_EQUAL(0, status);

    TEST_ASSERT_EQUAL_DATA(test_data_round5_NIST_RNG_ND_5CCA_5D_PUBLIC_KEY, vsc_data(pk, sizeof(pk)));
    TEST_ASSERT_EQUAL_DATA(test_data_round5_NIST_RNG_ND_5CCA_5D_PRIVATE_KEY, vsc_data(sk, sizeof(sk)));
}

void
test__kem_encapsulate__with_nist_rng__cipher_text_and_shared_key_equals_to_expected(void) {
    unsigned char shared_secret[CRYPTO_BYTES] = {0x00};
    unsigned char ciphertext[CRYPTO_CIPHERTEXTBYTES] = {0x00};

    randombytes_init((unsigned char *)test_data_round5_RNG_SEED.bytes, NULL, 1);

    int status = crypto_kem_enc(ciphertext, shared_secret, test_data_round5_NIST_RNG_ND_5CCA_5D_PUBLIC_KEY.bytes);
    TEST_ASSERT_EQUAL(0, status);

    vsc_data_t ciphertext_data = vsc_data(ciphertext, sizeof(ciphertext));
    TEST_ASSERT_EQUAL_DATA(test_data_round5_NIST_RNG_ND_5CCA_5D_KEM_ENCAPSULATED_KEY, ciphertext_data);

    vsc_data_t shared_secret_data = vsc_data(shared_secret, sizeof(shared_secret));
    TEST_ASSERT_EQUAL_DATA(test_data_round5_NIST_RNG_ND_5CCA_5D_KEM_SHARED_KEY, shared_secret_data);
}

void
test__kem_decapsulate__with_nist_rng__shared_key_equals_to_expected(void) {
    unsigned char shared_secret[CRYPTO_BYTES] = {0x00};

    const byte *sk = test_data_round5_NIST_RNG_ND_5CCA_5D_PRIVATE_KEY.bytes;
    const byte *ct = test_data_round5_NIST_RNG_ND_5CCA_5D_KEM_ENCAPSULATED_KEY.bytes;

    int status = crypto_kem_dec(shared_secret, ct, sk);
    TEST_ASSERT_EQUAL(0, status);

    vsc_data_t shared_secret_data = vsc_data(shared_secret, sizeof(shared_secret));
    TEST_ASSERT_EQUAL_DATA(test_data_round5_NIST_RNG_ND_5CCA_5D_KEM_SHARED_KEY, shared_secret_data);
}

void
test__kem_encapsulate__then_decapsulate__shared_key_match(void) {
    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0x00};
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0x00};
    unsigned char shared_secret1[CRYPTO_BYTES] = {0x00};
    unsigned char shared_secret2[CRYPTO_BYTES] = {0x00};
    unsigned char ciphertext[CRYPTO_CIPHERTEXTBYTES] = {0x00};

    randombytes_init((unsigned char *)test_data_round5_RNG_SEED.bytes, NULL, 1);

    int status = crypto_kem_keypair(pk, sk);
    TEST_ASSERT_EQUAL(0, status);

    status = crypto_kem_enc(ciphertext, shared_secret1, pk);
    TEST_ASSERT_EQUAL(0, status);

    status = crypto_kem_dec(shared_secret2, ciphertext, sk);
    TEST_ASSERT_EQUAL(0, status);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(shared_secret1, shared_secret2, sizeof(shared_secret1));
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__kem_keygen__with_nist_rng__equals_expected);
    RUN_TEST(test__kem_encapsulate__with_nist_rng__cipher_text_and_shared_key_equals_to_expected);
    RUN_TEST(test__kem_decapsulate__with_nist_rng__shared_key_equals_to_expected);
    RUN_TEST(test__kem_encapsulate__then_decapsulate__shared_key_match);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
