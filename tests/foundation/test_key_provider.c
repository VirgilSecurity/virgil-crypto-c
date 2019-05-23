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
    (VSCF_KEY_PROVIDER && VSCF_KEY && VSCF_PRIVATE_KEY && VSCF_ENCRYPT && VSCF_DECRYPT && VSCF_SIGN_HASH &&            \
            VSCF_VERIFY_HASH && VSCF_KEY_MATERIAL_RNG)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_alg.h"
#include "vscf_key.h"
#include "vscf_key_provider.h"
#include "vscf_private_key.h"
#include "vscf_encrypt.h"
#include "vscf_decrypt.h"
#include "vscf_sign_hash.h"
#include "vscf_verify_hash.h"
#include "vscf_key_material_rng.h"

#include "test_data_deterministic_key.h"
#include "test_data_key_provider.h"
#include "test_data_ed25519.h"
#include "test_data_rsa.h"
#include "test_data_secp256r1.h"

// --------------------------------------------------------------------------
//  Ed25519
// --------------------------------------------------------------------------
void
test__generate_private_key__ed25519__success(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ED25519, &error);
    TEST_ASSERT_NOT_NULL(private_key);

    TEST_ASSERT_EQUAL(vscf_alg_id_ED25519, vscf_alg_alg_id(private_key));
    TEST_ASSERT_EQUAL(256, vscf_key_key_bitlen(private_key));

    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__generate_private_key__ed25519_and_then_do_encrypt_decrypt__success(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ED25519, &error);
    TEST_ASSERT_NOT_NULL(private_key);

    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_NOT_NULL(public_key);

    vsc_data_t plain_data = vsc_data_from_str("test data", 9);

    vsc_buffer_t *enc_data = vsc_buffer_new_with_capacity(vscf_encrypt_encrypted_len(public_key, plain_data.len));
    vscf_status_t enc_status = vscf_encrypt(public_key, plain_data, enc_data);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, enc_status);

    vsc_buffer_t *dec_data =
            vsc_buffer_new_with_capacity(vscf_decrypt_decrypted_len(private_key, vsc_buffer_len(enc_data)));
    vscf_status_t dec_status = vscf_decrypt(private_key, vsc_buffer_data(enc_data), dec_data);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, dec_status);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(plain_data, dec_data);

    vsc_buffer_destroy(&dec_data);
    vsc_buffer_destroy(&enc_data);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__generate_private_key__ed25519_and_then_do_sign_hash_and_verify_hash__success(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ED25519, &error);
    TEST_ASSERT_NOT_NULL(private_key);

    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_NOT_NULL(public_key);

    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_sign_hash_signature_len(private_key));
    vscf_status_t sign_status =
            vscf_sign_hash(private_key, test_key_provider_MESSAGE_SHA512_DIGEST, vscf_alg_id_SHA512, signature);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, sign_status);

    bool verified = vscf_verify_hash(
            public_key, test_key_provider_MESSAGE_SHA512_DIGEST, vscf_alg_id_SHA512, vsc_buffer_data(signature));
    TEST_ASSERT_TRUE(verified);

    vsc_buffer_destroy(&signature);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__generate_private_key__ed25519_with_key_material_rng__success(void) {

    vscf_key_material_rng_t *key_material_rng = vscf_key_material_rng_new();
    vscf_key_material_rng_reset_key_material(key_material_rng, test_data_deterministic_key_KEY_MATERIAL);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_take_random(key_provider, vscf_key_material_rng_impl(key_material_rng));
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ED25519, &error);
    TEST_ASSERT_NOT_NULL(private_key);

    vsc_buffer_t *exported_private_key =
            vsc_buffer_new_with_capacity(vscf_private_key_exported_private_key_len(private_key));
    status = vscf_private_key_export_private_key(private_key, exported_private_key);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_deterministic_key_ED25519_PRIVATE_KEY, exported_private_key);

    vsc_buffer_destroy(&exported_private_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

// --------------------------------------------------------------------------
//  RSA
// --------------------------------------------------------------------------
void
test__generate_private_key__rsa_2048__success(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_key_provider_set_rsa_params(key_provider, 2048);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_RSA, &error);
    TEST_ASSERT_NOT_NULL(private_key);

    TEST_ASSERT_EQUAL(vscf_alg_id_RSA, vscf_alg_alg_id(private_key));
    TEST_ASSERT_EQUAL(2048, vscf_key_key_bitlen(private_key));

    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__generate_private_key__rsa2048_and_then_do_encrypt_decrypt__success(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    vscf_key_provider_set_rsa_params(key_provider, 2048);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_RSA, &error);
    TEST_ASSERT_NOT_NULL(private_key);

    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_NOT_NULL(public_key);

    vsc_data_t plain_data = vsc_data_from_str("test data", 9);

    vsc_buffer_t *enc_data = vsc_buffer_new_with_capacity(vscf_encrypt_encrypted_len(public_key, plain_data.len));
    vscf_status_t enc_status = vscf_encrypt(public_key, plain_data, enc_data);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, enc_status);

    vsc_buffer_t *dec_data =
            vsc_buffer_new_with_capacity(vscf_decrypt_decrypted_len(private_key, vsc_buffer_len(enc_data)));
    vscf_status_t dec_status = vscf_decrypt(private_key, vsc_buffer_data(enc_data), dec_data);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, dec_status);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(plain_data, dec_data);

    vsc_buffer_destroy(&dec_data);
    vsc_buffer_destroy(&enc_data);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__generate_private_key__rsa2048_and_then_do_sign_hash_and_verify_hash__success(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    vscf_key_provider_set_rsa_params(key_provider, 2048);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_RSA, &error);
    TEST_ASSERT_NOT_NULL(private_key);

    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_NOT_NULL(public_key);

    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_sign_hash_signature_len(private_key));
    vscf_status_t sign_status =
            vscf_sign_hash(private_key, test_key_provider_MESSAGE_SHA512_DIGEST, vscf_alg_id_SHA512, signature);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, sign_status);

    bool verified = vscf_verify_hash(
            public_key, test_key_provider_MESSAGE_SHA512_DIGEST, vscf_alg_id_SHA512, vsc_buffer_data(signature));
    TEST_ASSERT_TRUE(verified);

    vsc_buffer_destroy(&signature);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__generate_private_key__rsa4096_with_key_material_rng__success(void) {
    vscf_key_material_rng_t *key_material_rng = vscf_key_material_rng_new();
    vscf_key_material_rng_reset_key_material(key_material_rng, test_data_deterministic_key_KEY_MATERIAL);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_take_random(key_provider, vscf_key_material_rng_impl(key_material_rng));
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_set_rsa_params(key_provider, 4096);
    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_RSA, &error);
    TEST_ASSERT_NOT_NULL(private_key);

    vsc_buffer_t *exported_private_key =
            vsc_buffer_new_with_capacity(vscf_private_key_exported_private_key_len(private_key));
    status = vscf_private_key_export_private_key(private_key, exported_private_key);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_deterministic_key_RSA4096_PRIVATE_KEY, exported_private_key);

    vsc_buffer_destroy(&exported_private_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__import_public_key__ed25519_and_then_export__are_equals(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *public_key =
            vscf_key_provider_import_public_key(key_provider, test_ed25519_PUBLIC_KEY_PKCS8_DER, NULL);
    TEST_ASSERT_NOT_NULL(public_key);

    vsc_buffer_t *exported_public_key =
            vsc_buffer_new_with_capacity(vscf_key_provider_exported_public_key_len(key_provider, public_key));
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_key_provider_export_public_key(key_provider, public_key, exported_public_key));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_ed25519_PUBLIC_KEY_PKCS8_DER, exported_public_key);

    vsc_buffer_destroy(&exported_public_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__import_private_key__ed25519_and_then_export__are_equals(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *private_key =
            vscf_key_provider_import_private_key(key_provider, test_ed25519_PRIVATE_KEY_PKCS8_DER, NULL);
    TEST_ASSERT_NOT_NULL(private_key);

    vsc_buffer_t *exported_private_key =
            vsc_buffer_new_with_capacity(vscf_key_provider_exported_private_key_len(key_provider, private_key));
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_key_provider_export_private_key(key_provider, private_key, exported_private_key));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_ed25519_PRIVATE_KEY_PKCS8_DER, exported_private_key);

    vsc_buffer_destroy(&exported_private_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__import_public_key__rsa2048_and_then_export__are_equals(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *public_key =
            vscf_key_provider_import_public_key(key_provider, test_rsa_2048_PUBLIC_KEY_PKCS8_DER, NULL);
    TEST_ASSERT_NOT_NULL(public_key);

    vsc_buffer_t *exported_public_key =
            vsc_buffer_new_with_capacity(vscf_key_provider_exported_public_key_len(key_provider, public_key));
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_key_provider_export_public_key(key_provider, public_key, exported_public_key));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_rsa_2048_PUBLIC_KEY_PKCS8_DER, exported_public_key);

    vsc_buffer_destroy(&exported_public_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__import_private_key__rsa2048_and_then_export__are_equals(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *private_key =
            vscf_key_provider_import_private_key(key_provider, test_rsa_2048_PRIVATE_KEY_PKCS8_DER, NULL);
    TEST_ASSERT_NOT_NULL(private_key);

    vsc_buffer_t *exported_private_key =
            vsc_buffer_new_with_capacity(vscf_key_provider_exported_private_key_len(key_provider, private_key));
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_key_provider_export_private_key(key_provider, private_key, exported_private_key));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_rsa_2048_PRIVATE_KEY_PKCS8_DER, exported_private_key);

    vsc_buffer_destroy(&exported_private_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__import_public_key__secp256r1_and_then_export__are_equals(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *public_key =
            vscf_key_provider_import_public_key(key_provider, test_secp256r1_PUBLIC_KEY_SEC1_DER, NULL);
    TEST_ASSERT_NOT_NULL(public_key);

    vsc_buffer_t *exported_public_key =
            vsc_buffer_new_with_capacity(vscf_key_provider_exported_public_key_len(key_provider, public_key));
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_key_provider_export_public_key(key_provider, public_key, exported_public_key));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_secp256r1_PUBLIC_KEY_SEC1_DER, exported_public_key);

    vsc_buffer_destroy(&exported_public_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__import_private_key__secp256r1_and_then_export__are_equals(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *private_key =
            vscf_key_provider_import_private_key(key_provider, test_secp256r1_PRIVATE_KEY_SEC1_DER, NULL);
    TEST_ASSERT_NOT_NULL(private_key);

    vsc_buffer_t *exported_private_key =
            vsc_buffer_new_with_capacity(vscf_key_provider_exported_private_key_len(key_provider, private_key));
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_key_provider_export_private_key(key_provider, private_key, exported_private_key));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_secp256r1_PRIVATE_KEY_SEC1_DER, exported_private_key);

    vsc_buffer_destroy(&exported_private_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

// --------------------------------------------------------------------------
//  SECP256R1
// --------------------------------------------------------------------------
void
test__generate_private_key__secp256r1__success(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_SECP256R1, &error);
    TEST_ASSERT_NOT_NULL(private_key);

    TEST_ASSERT_EQUAL(vscf_alg_id_SECP256R1, vscf_alg_alg_id(private_key));
    TEST_ASSERT_EQUAL(256, vscf_key_key_bitlen(private_key));

    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__generate_private_key__secp256r1_and_then_do_encrypt_decrypt__success(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_SECP256R1, &error);
    TEST_ASSERT_NOT_NULL(private_key);

    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_NOT_NULL(public_key);

    vsc_data_t plain_data = vsc_data_from_str("test data", 9);

    vsc_buffer_t *enc_data = vsc_buffer_new_with_capacity(vscf_encrypt_encrypted_len(public_key, plain_data.len));
    vscf_status_t enc_status = vscf_encrypt(public_key, plain_data, enc_data);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, enc_status);

    vsc_buffer_t *dec_data =
            vsc_buffer_new_with_capacity(vscf_decrypt_decrypted_len(private_key, vsc_buffer_len(enc_data)));
    vscf_status_t dec_status = vscf_decrypt(private_key, vsc_buffer_data(enc_data), dec_data);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, dec_status);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(plain_data, dec_data);

    vsc_buffer_destroy(&dec_data);
    vsc_buffer_destroy(&enc_data);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__generate_private_key__secp256r1_and_then_do_sign_hash_and_verify_hash__success(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_SECP256R1, &error);
    TEST_ASSERT_NOT_NULL(private_key);

    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_NOT_NULL(public_key);

    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_sign_hash_signature_len(private_key));
    vscf_status_t sign_status =
            vscf_sign_hash(private_key, test_key_provider_MESSAGE_SHA512_DIGEST, vscf_alg_id_SHA512, signature);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, sign_status);

    bool verified = vscf_verify_hash(
            public_key, test_key_provider_MESSAGE_SHA512_DIGEST, vscf_alg_id_SHA512, vsc_buffer_data(signature));
    TEST_ASSERT_TRUE(verified);

    vsc_buffer_destroy(&signature);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__import_invalid_public_key__fail(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    const char str_message[] = "Lorem Ipsum is simply dummy text of the printing and typesetting industry.";

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *public_key = vscf_key_provider_import_public_key(
            key_provider, vsc_data_from_str(str_message, strlen(str_message)), &error);

    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_DER_PUBLIC_KEY, vscf_error_status(&error));
}

void
test__import_invalid_private_key__fail(void) {

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    const char str_message[] = "Lorem Ipsum is simply dummy text of the printing and typesetting industry.";

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_key_provider_import_private_key(
            key_provider, vsc_data_from_str(str_message, strlen(str_message)), &error);

    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_DER_PRIVATE_KEY, vscf_error_status(&error));
}


#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__generate_private_key__ed25519__success);
    RUN_TEST(test__generate_private_key__ed25519_and_then_do_encrypt_decrypt__success);
    RUN_TEST(test__generate_private_key__ed25519_and_then_do_sign_hash_and_verify_hash__success);
    RUN_TEST(test__generate_private_key__ed25519_with_key_material_rng__success);

    RUN_TEST(test__generate_private_key__rsa_2048__success);
    RUN_TEST(test__generate_private_key__rsa2048_and_then_do_encrypt_decrypt__success);
    RUN_TEST(test__generate_private_key__rsa2048_and_then_do_sign_hash_and_verify_hash__success);
    RUN_TEST(test__generate_private_key__rsa4096_with_key_material_rng__success);

    RUN_TEST(test__import_public_key__ed25519_and_then_export__are_equals);
    RUN_TEST(test__import_private_key__ed25519_and_then_export__are_equals);
    RUN_TEST(test__import_public_key__rsa2048_and_then_export__are_equals);
    RUN_TEST(test__import_private_key__rsa2048_and_then_export__are_equals);
    RUN_TEST(test__import_public_key__secp256r1_and_then_export__are_equals);
    RUN_TEST(test__import_private_key__secp256r1_and_then_export__are_equals);

    RUN_TEST(test__generate_private_key__secp256r1__success);
    RUN_TEST(test__generate_private_key__secp256r1_and_then_do_encrypt_decrypt__success);
    RUN_TEST(test__generate_private_key__secp256r1_and_then_do_sign_hash_and_verify_hash__success);
    RUN_TEST(test__import_invalid_public_key__fail);
    RUN_TEST(test__import_invalid_private_key__fail);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
