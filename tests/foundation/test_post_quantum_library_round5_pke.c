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

#define TEST_DEPENDENCIES_AVAILABLE ROUND5_LIBRARY &&ROUND5_PKE_ENABLED
#if TEST_DEPENDENCIES_AVAILABLE

#include "test_data_round5.h"

#include <round5/rng.h>
#include <round5/pke.h>

void
test__pke_keygen__with_nist_rng__equals_expected(void) {
#ifdef ROUND5_CCA_PKE
    randombytes_init((unsigned char *)test_data_round5_RNG_SEED.bytes, NULL, 1);

    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0x00};
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0x00};

    randombytes_init((unsigned char *)test_data_round5_RNG_SEED.bytes, NULL, 1);

    int status = crypto_encrypt_keypair(pk, sk);
    TEST_ASSERT_EQUAL(0, status);

    TEST_ASSERT_EQUAL_DATA(test_data_round5_NIST_RNG_ND_5CCA_5D_PUBLIC_KEY, vsc_data(pk, sizeof(pk)));
    TEST_ASSERT_EQUAL_DATA(test_data_round5_NIST_RNG_ND_5CCA_5D_PRIVATE_KEY, vsc_data(sk, sizeof(sk)));
#else
    TEST_IGNORE_MESSAGE("Feature ROUND5 PKE algorithms are disabled");
#endif
}

void
test__pke_encrypt__with_nist_rng__equals_expected(void) {
#ifdef ROUND5_CCA_PKE
    randombytes_init((unsigned char *)test_data_round5_RNG_SEED.bytes, NULL, 1);

    const size_t enc_overhead_len = CRYPTO_BYTES;
    const size_t message_len = test_data_round5_MESSAGE.len;
    const size_t enc_len_max = enc_overhead_len + message_len;
    const byte *message = test_data_round5_MESSAGE.bytes;
    const byte *pk = test_data_round5_NIST_RNG_ND_5CCA_5D_PUBLIC_KEY.bytes;
    vsc_buffer_t *enc = vsc_buffer_new_with_capacity(enc_len_max);

    unsigned long long enc_len = 0;
    int status = crypto_encrypt(vsc_buffer_unused_bytes(enc), &enc_len, message, message_len, pk);
    TEST_ASSERT_EQUAL(0, status);
    vsc_buffer_inc_used(enc, enc_len);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_round5_NIST_RNG_ND_5CCA_5D_PKE_ENCRYPTED_MESSAGE, enc);

    vsc_buffer_destroy(&enc);
#else
    TEST_IGNORE_MESSAGE("Feature ROUND5 PKE algorithms are disabled");
#endif
}

void
test__pke_decrypt__with_nist_rng__equals_expected(void) {
#ifdef ROUND5_CCA_PKE
    const size_t enc_overhead_len = CRYPTO_BYTES;
    const size_t enc_len = test_data_round5_NIST_RNG_ND_5CCA_5D_PKE_ENCRYPTED_MESSAGE.len;
    const size_t message_len_max = enc_len - enc_overhead_len;
    const byte *enc = test_data_round5_NIST_RNG_ND_5CCA_5D_PKE_ENCRYPTED_MESSAGE.bytes;
    const byte *sk = test_data_round5_NIST_RNG_ND_5CCA_5D_PRIVATE_KEY.bytes;

    vsc_buffer_t *message = vsc_buffer_new_with_capacity(message_len_max);

    unsigned long long message_len = 0;
    int status = crypto_encrypt_open(vsc_buffer_unused_bytes(message), &message_len, enc, enc_len, sk);
    TEST_ASSERT_EQUAL(0, status);
    vsc_buffer_inc_used(message, message_len);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_round5_MESSAGE, message);

    vsc_buffer_destroy(&message);
#else
    TEST_IGNORE_MESSAGE("Feature ROUND5 PKE algorithms are disabled");
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
    RUN_TEST(test__pke_keygen__with_nist_rng__equals_expected);
    RUN_TEST(test__pke_encrypt__with_nist_rng__equals_expected);
    RUN_TEST(test__pke_decrypt__with_nist_rng__equals_expected);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
