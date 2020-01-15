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

#define TEST_DEPENDENCIES_AVAILABLE ROUND5_LIBRARY
#if TEST_DEPENDENCIES_AVAILABLE

#include "test_data_round5.h"

#include <round5/rng.h>
#include <round5/r5_cpa_kem.h>
#include <round5/r5_cca_pke.h>
#include <round5/r5_parameter_sets.h>

#define ROUND5_KEM_ENABLED 1
#define ROUND5_PKE_ENABLED (CRYPTO_CIPHERTEXTBYTES == 0)

void
test__cpa_kem_keygen__returns_success(void) {
#if ROUND5_KEM_ENABLED
    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0x00};
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0x00};

    randombytes_init((unsigned char *)test_data_round5_RNG_SEED.bytes, NULL, 1);

    int status = r5_cpa_kem_keygen(pk, sk);
    TEST_ASSERT_EQUAL(0, status);
#else
    TEST_IGNORE_MESSAGE("KEM is not available");
#endif
}

void
test__cpa_kem_encapsulate__then_decapsulate__shared_key_match(void) {
#if ROUND5_KEM_ENABLED
    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0x00};
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0x00};
    unsigned char shared_secret1[PARAMS_KAPPA_BYTES] = {0x00};
    unsigned char shared_secret2[PARAMS_KAPPA_BYTES] = {0x00};
    unsigned char ciphertext[PARAMS_CT_SIZE + PARAMS_KAPPA_BYTES] = {0x00};

    randombytes_init((unsigned char *)test_data_round5_RNG_SEED.bytes, NULL, 1);

    int status = r5_cpa_kem_keygen(pk, sk);
    TEST_ASSERT_EQUAL(0, status);

    status = r5_cpa_kem_encapsulate(ciphertext, shared_secret1, pk);
    TEST_ASSERT_EQUAL(0, status);

    status = r5_cpa_kem_decapsulate(shared_secret2, ciphertext, sk);
    TEST_ASSERT_EQUAL(0, status);

    TEST_ASSERT_EQUAL_UINT8_ARRAY(shared_secret1, shared_secret2, sizeof(shared_secret1));
#else
    TEST_IGNORE_MESSAGE("KEM is not available");
#endif
}

void
test__cca_pke_keygen__return_success(void) {
#if ROUND5_PKE_ENABLED
    randombytes_init((unsigned char *)test_data_round5_RNG_SEED.bytes, NULL, 1);

    const size_t sk_len = CRYPTO_SECRETKEYBYTES;
    const size_t pk_len = CRYPTO_PUBLICKEYBYTES;

    vsc_buffer_t *sk = vsc_buffer_new_with_capacity(sk_len);
    vsc_buffer_t *pk = vsc_buffer_new_with_capacity(pk_len);

    int status = r5_cca_pke_keygen(vsc_buffer_unused_bytes(pk), vsc_buffer_unused_bytes(sk));
    TEST_ASSERT_EQUAL(0, status);

    vsc_buffer_inc_used(pk, pk_len);
    vsc_buffer_inc_used(sk, sk_len);

    vsc_buffer_destroy(&pk);
    vsc_buffer_destroy(&sk);
#else
    TEST_IGNORE_MESSAGE("PKE is not available");
#endif
}

void
test__cca_pke_encrypt__return_success(void) {
#if ROUND5_PKE_ENABLED
    randombytes_init((unsigned char *)test_data_round5_RNG_SEED.bytes, NULL, 1);

    const size_t enc_overhead_len = CRYPTO_BYTES;
    const size_t enc_len_max = enc_overhead_len + test_data_round5_ND_5PKE_5D_MESSAGE.len;
    vsc_buffer_t *enc = vsc_buffer_new_with_capacity(enc_len_max);

    unsigned long long enc_len = 0;
    int status = r5_cca_pke_encrypt(vsc_buffer_unused_bytes(enc), &enc_len, test_data_round5_ND_5PKE_5D_MESSAGE.bytes,
            test_data_round5_ND_5PKE_5D_MESSAGE.len, test_data_round5_ND_5PKE_5D_PUBLIC_KEY.bytes);
    TEST_ASSERT_EQUAL(0, status);
    vsc_buffer_inc_used(enc, enc_len);

    vsc_buffer_destroy(&enc);
#else
    TEST_IGNORE_MESSAGE("PKE is not available");
#endif
}

void
test__cca_pke_decrypt__return_success(void) {
#if ROUND5_PKE_ENABLED
    randombytes_init((unsigned char *)test_data_round5_RNG_SEED.bytes, NULL, 1);

    const size_t enc_overhead_len = CRYPTO_BYTES;
    const size_t message_len_max = test_data_round5_ND_5PKE_5D_ENC_MESSAGE.len - enc_overhead_len;
    vsc_buffer_t *message = vsc_buffer_new_with_capacity(message_len_max);

    unsigned long long message_len = 0;
    int status = r5_cca_pke_decrypt(vsc_buffer_unused_bytes(message), &message_len,
            test_data_round5_ND_5PKE_5D_ENC_MESSAGE.bytes, test_data_round5_ND_5PKE_5D_ENC_MESSAGE.len,
            test_data_round5_ND_5PKE_5D_PRIVATE_KEY.bytes);
    TEST_ASSERT_EQUAL(0, status);
    vsc_buffer_inc_used(message, message_len);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_round5_ND_5PKE_5D_MESSAGE, message);

    vsc_buffer_destroy(&message);
#else
    TEST_IGNORE_MESSAGE("PKE is not available");
#endif
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
    RUN_TEST(test__cpa_kem_encapsulate__then_decapsulate__shared_key_match);

    RUN_TEST(test__cca_pke_keygen__return_success);
    RUN_TEST(test__cca_pke_encrypt__return_success);
    RUN_TEST(test__cca_pke_decrypt__return_success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
