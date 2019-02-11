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


#define TEST_DEPENDENCIES_AVAILABLE                                                                                    \
    (VSCF_PKCS5_PBES2 && VSCF_PKCS5_PBKDF2 && VSCF_HMAC && VSCF_SHA256 && VSCF_AES256_GCM)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_hmac.h"
#include "vscf_sha256.h"
#include "vscf_pkcs5_pbkdf2.h"
#include "vscf_pkcs5_pbes2.h"
#include "vscf_aes256_gcm.h"

#include "test_data_pkcs5_pbkdf2.h"
#include "test_data_pkcs5_pbes2.h"


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
test__encrypt__pbkdf2_with_hmac_sha256_and_aes256_gcm_with_valid_nonce__success(void) {
    vscf_sha256_t *hash = vscf_sha256_new();
    vscf_hmac_t *hmac = vscf_hmac_new();
    vscf_hmac_take_hash(hmac, vscf_sha256_impl(hash));

    vscf_pkcs5_pbkdf2_t *pbkdf2 = vscf_pkcs5_pbkdf2_new();
    vscf_pkcs5_pbkdf2_take_hmac(pbkdf2, vscf_hmac_impl(hmac));
    vscf_pkcs5_pbkdf2_reset(pbkdf2, test_pkcs5_pbes2_PBKDF2_SALT, test_pkcs5_pbes2_PBKDF2_ITERATION_COUNT);

    vscf_aes256_gcm_t *aes256 = vscf_aes256_gcm_new();
    vscf_aes256_gcm_set_nonce(aes256, test_pkcs5_pbes2_CIPHER_NONCE);

    vscf_pkcs5_pbes2_t *pbes2 = vscf_pkcs5_pbes2_new();
    vscf_pkcs5_pbes2_take_kdf(pbes2, vscf_pkcs5_pbkdf2_impl(pbkdf2));
    vscf_pkcs5_pbes2_take_cipher(pbes2, vscf_aes256_gcm_impl(aes256));
    vscf_pkcs5_pbes2_reset(pbes2, test_pkcs5_pbes2_PASSWORD);

    vsc_buffer_t *enc = vsc_buffer_new_with_capacity(vscf_pkcs5_pbes2_encrypted_len(pbes2, test_pkcs5_pbes2_DATA.len));
    vscf_pkcs5_pbes2_encrypt(pbes2, test_pkcs5_pbes2_DATA, enc);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_pkcs5_pbes2_ENCRYPTED_DATA, enc);

    vsc_buffer_destroy(&enc);
    vscf_pkcs5_pbes2_destroy(&pbes2);
}

void
test__decrypt__pbkdf2_with_hmac_sha256_and_aes256_gcm_with_valid_nonce__success(void) {
    vscf_sha256_t *hash = vscf_sha256_new();
    vscf_hmac_t *hmac = vscf_hmac_new();
    vscf_hmac_take_hash(hmac, vscf_sha256_impl(hash));

    vscf_pkcs5_pbkdf2_t *pbkdf2 = vscf_pkcs5_pbkdf2_new();
    vscf_pkcs5_pbkdf2_take_hmac(pbkdf2, vscf_hmac_impl(hmac));
    vscf_pkcs5_pbkdf2_reset(pbkdf2, test_pkcs5_pbes2_PBKDF2_SALT, test_pkcs5_pbes2_PBKDF2_ITERATION_COUNT);

    vscf_aes256_gcm_t *aes256 = vscf_aes256_gcm_new();
    vscf_aes256_gcm_set_nonce(aes256, test_pkcs5_pbes2_CIPHER_NONCE);

    vscf_pkcs5_pbes2_t *pbes2 = vscf_pkcs5_pbes2_new();
    vscf_pkcs5_pbes2_take_kdf(pbes2, vscf_pkcs5_pbkdf2_impl(pbkdf2));
    vscf_pkcs5_pbes2_take_cipher(pbes2, vscf_aes256_gcm_impl(aes256));
    vscf_pkcs5_pbes2_reset(pbes2, test_pkcs5_pbes2_PASSWORD);

    vsc_buffer_t *dec =
            vsc_buffer_new_with_capacity(vscf_pkcs5_pbes2_decrypted_len(pbes2, test_pkcs5_pbes2_ENCRYPTED_DATA.len));
    vscf_pkcs5_pbes2_decrypt(pbes2, test_pkcs5_pbes2_ENCRYPTED_DATA, dec);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_pkcs5_pbes2_DATA, dec);

    vsc_buffer_destroy(&dec);
    vscf_pkcs5_pbes2_destroy(&pbes2);
}


#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__encrypt__pbkdf2_with_hmac_sha256_and_aes256_gcm_with_valid_nonce__success);
    RUN_TEST(test__decrypt__pbkdf2_with_hmac_sha256_and_aes256_gcm_with_valid_nonce__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
