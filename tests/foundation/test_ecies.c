//  Copyright (C) 2015-2022 Virgil Security, Inc.
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
    (VSCF_ECIES && VSCF_AES256_CBC && VSCF_KEY_ALG && VSCF_HMAC && VSCF_KDF2 && VSCF_SHA384 &&                         \
            VSCF_KEY_ASN1_DESERIALIZER && VSCF_ALG_FACTORY && VSCF_FAKE_RANDOM)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_aes256_cbc.h"
#include "vscf_ecies.h"
#include "vscf_hmac.h"
#include "vscf_kdf2.h"
#include "vscf_sha384.h"
#include "vscf_key_asn1_deserializer.h"
#include "vscf_fake_random.h"
#include "vscf_key_alg.h"
#include "vscf_key_alg_factory.h"

#include "test_data_ecies.h"


void
test__encrypt__virgil_message__success(void) {

    //  Common
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);
    vscf_impl_t *random = vscf_fake_random_impl(fake_random);
    fake_random = NULL;

    //  Get keys
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_asn1_deserializer_t *key_asn1_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_asn1_deserializer);

    vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_alg_id(vscf_alg_id_ED25519, random, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_raw_public_key_t *raw_public_key = vscf_key_asn1_deserializer_deserialize_public_key(
            key_asn1_deserializer, test_data_ecies_ED25519_RECEIVER_PUBLIC_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_t *public_key = vscf_key_alg_import_public_key(key_alg, raw_public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    // Configure ECIES
    vscf_ecies_t *ecies = vscf_ecies_new();
    vscf_ecies_set_key_alg(ecies, key_alg);
    vscf_ecies_use_random(ecies, random);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ecies_setup_defaults(ecies));

    //  Encrypt
    vsc_buffer_t *enc_msg =
            vsc_buffer_new_with_capacity(vscf_ecies_encrypted_len(ecies, public_key, test_data_ecies_MESSAGE.len));
    vscf_status_t status = vscf_ecies_encrypt(ecies, public_key, test_data_ecies_MESSAGE, enc_msg);

    //  Check
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    //  Cleanup
    vsc_buffer_destroy(&enc_msg);
    vscf_impl_destroy(&public_key);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_ecies_destroy(&ecies);
    vscf_impl_destroy(&key_alg);
    vscf_impl_destroy(&random);
    vscf_key_asn1_deserializer_destroy(&key_asn1_deserializer);
}

void
test__encrypt__messege_with_ed25519_and_sha384_and_aes256_cbc_and_kdf2_and_hmac__return_encrypted_message(void) {

    //  Get keys
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_asn1_deserializer_t *key_asn1_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_asn1_deserializer);

    vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_alg_id(vscf_alg_id_ED25519, NULL, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_raw_public_key_t *raw_public_key = vscf_key_asn1_deserializer_deserialize_public_key(
            key_asn1_deserializer, test_data_ecies_ED25519_RECEIVER_PUBLIC_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_raw_private_key_t *raw_ephemeral_key = vscf_key_asn1_deserializer_deserialize_private_key(
            key_asn1_deserializer, test_data_ecies_ED25519_EPHEMERAL_PRIVATE_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_t *public_key = vscf_key_alg_import_public_key(key_alg, raw_public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_t *ephemeral_key = vscf_key_alg_import_private_key(key_alg, raw_ephemeral_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //  Configure ECIES
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
    vscf_ecies_set_key_alg(ecies, key_alg);
    vscf_ecies_take_random(ecies, vscf_fake_random_impl(cipher_nonce_random));
    vscf_ecies_take_kdf(ecies, kdf);
    vscf_ecies_take_mac(ecies, mac);
    vscf_ecies_take_cipher(ecies, cipher);
    vscf_ecies_take_ephemeral_key(ecies, ephemeral_key);

    //  Encrypt
    vsc_buffer_t *enc_msg =
            vsc_buffer_new_with_capacity(vscf_ecies_encrypted_len(ecies, public_key, test_data_ecies_MESSAGE.len));
    vscf_status_t status = vscf_ecies_encrypt(ecies, public_key, test_data_ecies_MESSAGE, enc_msg);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_ecies_ED25519_ENCRYPTED_MESSAGE_V2_COMPAT, enc_msg);

    //  Cleanup
    vsc_buffer_destroy(&enc_msg);
    vscf_raw_private_key_destroy(&raw_ephemeral_key);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_impl_destroy(&public_key);
    vscf_ecies_destroy(&ecies);
    vscf_impl_destroy(&key_alg);
    vscf_key_asn1_deserializer_destroy(&key_asn1_deserializer);
}

void
test__decrypt__ed25519_encrypted_message__match_virgil_message(void) {

    //  Get keys
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_asn1_deserializer_t *key_asn1_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_asn1_deserializer);

    vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_alg_id(vscf_alg_id_ED25519, NULL, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_raw_private_key_t *raw_private_key = vscf_key_asn1_deserializer_deserialize_private_key(
            key_asn1_deserializer, test_data_ecies_ED25519_RECEIVER_PRIVATE_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_t *private_key = vscf_key_alg_import_private_key(key_alg, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    // Configure ECIES
    vscf_ecies_t *ecies = vscf_ecies_new();
    vscf_ecies_set_key_alg(ecies, key_alg);

    //  Decrypt
    vsc_buffer_t *dec_msg = vsc_buffer_new_with_capacity(
            vscf_ecies_decrypted_len(ecies, private_key, test_data_ecies_ED25519_ENCRYPTED_MESSAGE.len));
    vscf_status_t status = vscf_ecies_decrypt(ecies, private_key, test_data_ecies_ED25519_ENCRYPTED_MESSAGE, dec_msg);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_ecies_MESSAGE, dec_msg);

    vsc_buffer_destroy(&dec_msg);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_impl_destroy(&private_key);
    vscf_ecies_destroy(&ecies);
    vscf_impl_destroy(&key_alg);
    vscf_key_asn1_deserializer_destroy(&key_asn1_deserializer);
}

void
test__decrypt__secp256r1_encrypted_message__match(void) {
#if VSCF_ECC
    //  Configure algs
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);

    //  Get keys
    vscf_key_asn1_deserializer_t *key_asn1_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_asn1_deserializer);

    vscf_impl_t *key_alg =
            vscf_key_alg_factory_create_from_alg_id(vscf_alg_id_SECP256R1, vscf_fake_random_impl(fake_random), &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_raw_private_key_t *raw_private_key = vscf_key_asn1_deserializer_deserialize_private_key(
            key_asn1_deserializer, test_data_ecies_SECP256R1_RECEIVER_PRIVATE_KEY, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_impl_t *private_key = vscf_key_alg_import_private_key(key_alg, raw_private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    // Configure ECIES
    vscf_ecies_t *ecies = vscf_ecies_new();
    vscf_ecies_set_key_alg(ecies, key_alg);
    vscf_ecies_take_random(ecies, vscf_fake_random_impl(fake_random));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ecies_setup_defaults(ecies));

    //  Decrypt
    vsc_buffer_t *dec_msg = vsc_buffer_new_with_capacity(
            vscf_ecies_decrypted_len(ecies, private_key, test_data_ecies_SECP256R1_ENCRYPTED_MESSAGE.len));
    vscf_status_t status = vscf_ecies_decrypt(ecies, private_key, test_data_ecies_SECP256R1_ENCRYPTED_MESSAGE, dec_msg);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_ecies_SECP256R1_MESSAGE, dec_msg);

    vsc_buffer_destroy(&dec_msg);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_impl_destroy(&private_key);
    vscf_ecies_destroy(&ecies);
    vscf_impl_destroy(&key_alg);
    vscf_key_asn1_deserializer_destroy(&key_asn1_deserializer);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_ECC is disabled");
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
    RUN_TEST(test__encrypt__virgil_message__success);
    RUN_TEST(test__encrypt__messege_with_ed25519_and_sha384_and_aes256_cbc_and_kdf2_and_hmac__return_encrypted_message);
    RUN_TEST(test__decrypt__ed25519_encrypted_message__match_virgil_message);
    RUN_TEST(test__decrypt__secp256r1_encrypted_message__match);

#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
