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

#define TEST_DEPENDENCIES_AVAILABLE FALCON_LIBRARY
#if TEST_DEPENDENCIES_AVAILABLE

#include <test_data_falcon.h>

#include <falcon/falcon.h>

enum { LOGN_512 = 9, LOGN_1024 = 10 };

void
test__keygen__512_degree__success(void) {
    unsigned char privkey[FALCON_PRIVKEY_SIZE(LOGN_512)] = {0x00};
    unsigned char pubkey[FALCON_PUBKEY_SIZE(LOGN_512)] = {0x00};
    unsigned char tmp[FALCON_TMPSIZE_KEYGEN(LOGN_512)] = {0x00};

    falcon_shake256_context shake256;
    falcon_shake256_init(&shake256);
    falcon_shake256_inject(&shake256, test_data_falcon_RNG_SEED.bytes, test_data_falcon_RNG_SEED.len);
    falcon_shake256_flip(&shake256);

    const int status =
            falcon_keygen_make(&shake256, LOGN_512, privkey, sizeof(privkey), pubkey, sizeof(pubkey), tmp, sizeof(tmp));
    TEST_ASSERT_EQUAL(0, status);

    TEST_ASSERT_EQUAL_DATA(test_data_falcon_PRIVATE_KEY_512, vsc_data(privkey, sizeof(privkey)));
    TEST_ASSERT_EQUAL_DATA(test_data_falcon_PUBLIC_KEY_512, vsc_data(pubkey, sizeof(pubkey)));
}

void
test__sign_dyn__sha512_digest_with_512_degree_key__produce_const_signature(void) {
    falcon_shake256_context shake256;
    falcon_shake256_init(&shake256);
    falcon_shake256_inject(&shake256, test_data_falcon_RNG_SEED2.bytes, test_data_falcon_RNG_SEED2.len);
    falcon_shake256_flip(&shake256);

    unsigned char tmp[FALCON_TMPSIZE_SIGNDYN(LOGN_512)] = {0x00};
    unsigned char sig[FALCON_SIG_CT_SIZE(LOGN_512)];
    size_t sig_len = sizeof(sig);

    const int status = falcon_sign_dyn(&shake256, sig, &sig_len, test_data_falcon_PRIVATE_KEY_512.bytes,
            test_data_falcon_PRIVATE_KEY_512.len, test_data_falcon_DATA_SHA512_DIGEST.bytes,
            test_data_falcon_DATA_SHA512_DIGEST.len, 1, tmp, sizeof(tmp));
    TEST_ASSERT_EQUAL(0, status);
    TEST_ASSERT_EQUAL(sizeof(sig), sig_len);

    TEST_ASSERT_EQUAL_DATA(test_data_falcon_CONST_SIGNATURE, vsc_data(sig, sig_len));
}


void
test__verify__sha512_digest_and_const_signature_with_512_degree_key__success(void) {
    unsigned char tmp[FALCON_TMPSIZE_VERIFY(LOGN_512)] = {0x00};

    const int status = falcon_verify(test_data_falcon_CONST_SIGNATURE.bytes, test_data_falcon_CONST_SIGNATURE.len,
            test_data_falcon_PUBLIC_KEY_512.bytes, test_data_falcon_PUBLIC_KEY_512.len,
            test_data_falcon_DATA_SHA512_DIGEST.bytes, test_data_falcon_DATA_SHA512_DIGEST.len, tmp, sizeof(tmp));
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
    RUN_TEST(test__keygen__512_degree__success);
    RUN_TEST(test__sign_dyn__sha512_digest_with_512_degree_key__produce_const_signature);
    RUN_TEST(test__verify__sha512_digest_and_const_signature_with_512_degree_key__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
