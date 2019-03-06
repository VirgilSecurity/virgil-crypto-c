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
    (VSCF_ECIES && VSCF_AES256_CBC && VSCF_ED25519_PUBLIC_KEY && VSCF_HMAC && VSCF_KDF2 && VSCF_SHA384 &&              \
            VSCF_PKCS8_DESERIALIZER && VSCF_ALG_FACTORY && VSCF_FAKE_RANDOM)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_aes256_cbc.h"
#include "vscf_ecies.h"
#include "vscf_hmac.h"
#include "vscf_kdf2.h"
#include "vscf_sha384.h"
#include "vscf_pkcs8_deserializer.h"
#include "vscf_alg_factory.h"
#include "vscf_fake_random.h"

#include "test_data_ecies.h"


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
test__encrypt__virgil_message__success(void) {

    vscf_pkcs8_deserializer_t *pkcs8 = vscf_pkcs8_deserializer_new();
    vscf_pkcs8_deserializer_setup_defaults(pkcs8);

    vscf_ecies_t *ecies = vscf_ecies_new();
    vscf_ecies_setup_defaults(ecies);

    vscf_raw_key_t *raw_public_key =
            vscf_pkcs8_deserializer_deserialize_public_key(pkcs8, test_data_ecies_ED25519_RECEIVER_PUBLIC_KEY, NULL);

    vscf_impl_t *public_key = vscf_alg_factory_create_public_key_from_raw_key(raw_public_key);

    vscf_ecies_take_encryption_key(ecies, public_key);

    vsc_buffer_t *enc_msg = vsc_buffer_new_with_capacity(vscf_ecies_encrypted_len(ecies, test_data_ecies_MESSAGE.len));
    vscf_status_t status = vscf_ecies_encrypt(ecies, test_data_ecies_MESSAGE, enc_msg);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vsc_buffer_destroy(&enc_msg);
    vscf_raw_key_destroy(&raw_public_key);
    vscf_ecies_destroy(&ecies);
    vscf_pkcs8_deserializer_destroy(&pkcs8);
}

void
test__encrypt__messege_with_ed25519_and_sha384_and_aes256_cbc_and_kdf2_and_hmac__return_encrypted_message(void) {

    vscf_impl_t *hash = vscf_sha384_impl(vscf_sha384_new());

    vscf_kdf2_t *kdf2 = vscf_kdf2_new();
    vscf_kdf2_use_hash(kdf2, hash);
    vscf_impl_t *kdf = vscf_kdf2_impl(kdf2);

    vscf_hmac_t *hmac = vscf_hmac_new();
    vscf_hmac_take_hash(hmac, hash);
    vscf_impl_t *mac = vscf_hmac_impl(hmac);

    vscf_aes256_cbc_t *aes256 = vscf_aes256_cbc_new();
    vscf_aes256_cbc_set_nonce(aes256, test_data_ecies_ED25519_AES256_CBC_IV);
    vscf_impl_t *cipher = vscf_aes256_cbc_impl(aes256);

    vscf_fake_random_t *cipher_nonce_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(cipher_nonce_random, test_data_ecies_ED25519_AES256_CBC_IV);

    vscf_ecies_t *ecies = vscf_ecies_new();
    vscf_ecies_take_random(ecies, vscf_fake_random_impl(cipher_nonce_random));
    vscf_ecies_take_kdf(ecies, kdf);
    vscf_ecies_take_mac(ecies, mac);
    vscf_ecies_take_cipher(ecies, cipher);

    vscf_pkcs8_deserializer_t *pkcs8 = vscf_pkcs8_deserializer_new();
    vscf_pkcs8_deserializer_setup_defaults(pkcs8);

    vscf_raw_key_t *raw_public_key =
            vscf_pkcs8_deserializer_deserialize_public_key(pkcs8, test_data_ecies_ED25519_RECEIVER_PUBLIC_KEY, NULL);

    vscf_impl_t *public_key = vscf_alg_factory_create_public_key_from_raw_key(raw_public_key);

    vscf_raw_key_t *raw_ephemeral_key =
            vscf_pkcs8_deserializer_deserialize_private_key(pkcs8, test_data_ecies_ED25519_EPHEMERAL_PRIVATE_KEY, NULL);

    vscf_impl_t *ephemeral_key = vscf_alg_factory_create_private_key_from_raw_key(raw_ephemeral_key);

    vscf_ecies_take_encryption_key(ecies, public_key);
    vscf_ecies_take_ephemeral_key(ecies, ephemeral_key);

    vsc_buffer_t *enc_msg = vsc_buffer_new_with_capacity(vscf_ecies_encrypted_len(ecies, test_data_ecies_MESSAGE.len));
    vscf_status_t status = vscf_ecies_encrypt(ecies, test_data_ecies_MESSAGE, enc_msg);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_ecies_ED25519_ENCRYPTED_MESSAGE, enc_msg);

    vsc_buffer_destroy(&enc_msg);
    vscf_raw_key_destroy(&raw_ephemeral_key);
    vscf_raw_key_destroy(&raw_public_key);
    vscf_pkcs8_deserializer_destroy(&pkcs8);
    vscf_ecies_destroy(&ecies);
}

void
test__decrypt__ed25519_encrypted_message__match_virgil_message(void) {

    vscf_pkcs8_deserializer_t *pkcs8 = vscf_pkcs8_deserializer_new();
    vscf_pkcs8_deserializer_setup_defaults(pkcs8);

    vscf_ecies_t *ecies = vscf_ecies_new();
    vscf_ecies_setup_defaults(ecies);

    vscf_raw_key_t *raw_private_key =
            vscf_pkcs8_deserializer_deserialize_private_key(pkcs8, test_data_ecies_ED25519_RECEIVER_PRIVATE_KEY, NULL);

    vscf_impl_t *private_key = vscf_alg_factory_create_private_key_from_raw_key(raw_private_key);

    vscf_ecies_take_decryption_key(ecies, private_key);

    vsc_buffer_t *dec_msg = vsc_buffer_new_with_capacity(
            vscf_ecies_decrypted_len(ecies, test_data_ecies_ED25519_ENCRYPTED_MESSAGE.len));
    vscf_status_t status = vscf_ecies_decrypt(ecies, test_data_ecies_ED25519_ENCRYPTED_MESSAGE, dec_msg);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_ecies_MESSAGE, dec_msg);

    vsc_buffer_destroy(&dec_msg);
    vscf_raw_key_destroy(&raw_private_key);
    vscf_ecies_destroy(&ecies);
    vscf_pkcs8_deserializer_destroy(&pkcs8);
}


#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

    RUN_TEST(test__encrypt__virgil_message__success);
    RUN_TEST(test__encrypt__messege_with_ed25519_and_sha384_and_aes256_cbc_and_kdf2_and_hmac__return_encrypted_message);
    RUN_TEST(test__decrypt__ed25519_encrypted_message__match_virgil_message);

#if TEST_DEPENDENCIES_AVAILABLE
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
