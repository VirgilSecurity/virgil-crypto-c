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


#define TEST_DEPENDENCIES_AVAILABLE VSCF_ALG_INFO_DER_DESERIALIZER
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_alg_info.h"
#include "vscf_alg_info_der_deserializer.h"
#include "vscf_hash_based_alg_info.h"
#include "vscf_simple_alg_info.h"
#include "vscf_cipher_alg_info.h"
#include "vscf_compound_key_alg_info.h"
#include "vscf_hybrid_key_alg_info.h"

#include "test_data_alg_info_der.h"


void
test__deserialize__sha256__returns_valid_simple_info(void) {
    vscf_alg_info_der_deserializer_t *deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_setup_defaults(deserializer);

    vscf_impl_t *sha256_info = vscf_alg_info_der_deserializer_deserialize(deserializer, test_alg_info_SHA256_DER, NULL);

    TEST_ASSERT_NOT_NULL(sha256_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_SHA256, vscf_alg_info_alg_id(sha256_info));

    vscf_impl_destroy(&sha256_info);
    vscf_alg_info_der_deserializer_destroy(&deserializer);
}

void
test__deserialize__sha256_v2_compat__returns_valid_simple_info(void) {
    vscf_alg_info_der_deserializer_t *deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_setup_defaults(deserializer);

    vscf_impl_t *sha256_info = vscf_alg_info_der_deserializer_deserialize(deserializer, test_alg_info_SHA256_DER, NULL);

    TEST_ASSERT_NOT_NULL(sha256_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_SHA256, vscf_alg_info_alg_id(sha256_info));

    vscf_impl_destroy(&sha256_info);
    vscf_alg_info_der_deserializer_destroy(&deserializer);
}

void
test__deserialize__kdf1_sha256__returns_valid_hash_based_alg_info(void) {
    vscf_alg_info_der_deserializer_t *deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_setup_defaults(deserializer);

    vscf_hash_based_alg_info_t *kdf_info = (vscf_hash_based_alg_info_t *)vscf_alg_info_der_deserializer_deserialize(
            deserializer, test_alg_info_KDF1_SHA256_DER, NULL);


    TEST_ASSERT_NOT_NULL(kdf_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_KDF1, vscf_hash_based_alg_info_alg_id(kdf_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_SHA256, vscf_alg_info_alg_id(vscf_hash_based_alg_info_hash_alg_info(kdf_info)));

    vscf_hash_based_alg_info_destroy(&kdf_info);
    vscf_alg_info_der_deserializer_destroy(&deserializer);
}

void
test__deserialize__kdf1_sha256_v2_compat__returns_valid_hash_based_alg_info(void) {
    vscf_alg_info_der_deserializer_t *deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_setup_defaults(deserializer);

    vscf_hash_based_alg_info_t *kdf_info = (vscf_hash_based_alg_info_t *)vscf_alg_info_der_deserializer_deserialize(
            deserializer, test_alg_info_KDF1_SHA256_DER, NULL);


    TEST_ASSERT_NOT_NULL(kdf_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_KDF1, vscf_hash_based_alg_info_alg_id(kdf_info));
    TEST_ASSERT_EQUAL(vscf_alg_id_SHA256, vscf_alg_info_alg_id(vscf_hash_based_alg_info_hash_alg_info(kdf_info)));

    vscf_hash_based_alg_info_destroy(&kdf_info);
    vscf_alg_info_der_deserializer_destroy(&deserializer);
}

void
test__deserialize__aes256_gcm__returns_valid_cipher_alg_info(void) {
    vscf_alg_info_der_deserializer_t *deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_setup_defaults(deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_cipher_alg_info_t *cipher_info = (vscf_cipher_alg_info_t *)vscf_alg_info_der_deserializer_deserialize(
            deserializer, test_alg_info_AES256_GCM_DER, &error);


    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(cipher_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_AES256_GCM, vscf_cipher_alg_info_alg_id(cipher_info));
    TEST_ASSERT_EQUAL_DATA(test_alg_info_AES256_GCM_NONCE, vscf_cipher_alg_info_nonce(cipher_info));

    vscf_cipher_alg_info_destroy(&cipher_info);
    vscf_alg_info_der_deserializer_destroy(&deserializer);
}

void
test__deserialize__aes256_gcm_v2_compat__returns_valid_cipher_alg_info(void) {
    vscf_alg_info_der_deserializer_t *deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_setup_defaults(deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_cipher_alg_info_t *cipher_info = (vscf_cipher_alg_info_t *)vscf_alg_info_der_deserializer_deserialize(
            deserializer, test_alg_info_AES256_GCM_DER, &error);


    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(cipher_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_AES256_GCM, vscf_cipher_alg_info_alg_id(cipher_info));
    TEST_ASSERT_EQUAL_DATA(test_alg_info_AES256_GCM_NONCE, vscf_cipher_alg_info_nonce(cipher_info));

    vscf_cipher_alg_info_destroy(&cipher_info);
    vscf_alg_info_der_deserializer_destroy(&deserializer);
}

void
test__deserialize__valid_compound_key_alg_info___success(void) {
    vscf_alg_info_der_deserializer_t *deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_setup_defaults(deserializer);

    vscf_impl_t *alg_info = vscf_alg_info_der_deserializer_deserialize(
            deserializer, test_alg_info_COMPOUND_KEY_CURVE25519_ED25519, NULL);

    TEST_ASSERT_NOT_NULL(alg_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_COMPOUND_KEY, vscf_alg_info_alg_id(alg_info));

    vscf_compound_key_alg_info_t *compound_alg_info = (vscf_compound_key_alg_info_t *)alg_info;

    const vscf_impl_t *cipher_alg_info = vscf_compound_key_alg_info_cipher_alg_info(compound_alg_info);
    TEST_ASSERT_NOT_NULL(cipher_alg_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_CURVE25519, vscf_alg_info_alg_id(cipher_alg_info));

    const vscf_impl_t *signer_alg_info = vscf_compound_key_alg_info_signer_alg_info(compound_alg_info);
    TEST_ASSERT_NOT_NULL(signer_alg_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_ED25519, vscf_alg_info_alg_id(signer_alg_info));

    vscf_impl_destroy(&alg_info);
    vscf_alg_info_der_deserializer_destroy(&deserializer);
}

void
test__deserialize__valid_hybrid_key_alg_info___success(void) {
    vscf_alg_info_der_deserializer_t *deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_setup_defaults(deserializer);

    vscf_impl_t *alg_info =
            vscf_alg_info_der_deserializer_deserialize(deserializer, test_alg_info_HYBRID_KEY_CURVE25519_ED25519, NULL);

    TEST_ASSERT_NOT_NULL(alg_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_HYBRID_KEY, vscf_alg_info_alg_id(alg_info));

    vscf_hybrid_key_alg_info_t *hybrid_alg_info = (vscf_hybrid_key_alg_info_t *)alg_info;

    const vscf_impl_t *first_alg_info = vscf_hybrid_key_alg_info_first_key_alg_info(hybrid_alg_info);
    TEST_ASSERT_NOT_NULL(first_alg_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_CURVE25519, vscf_alg_info_alg_id(first_alg_info));

    const vscf_impl_t *second_alg_info = vscf_hybrid_key_alg_info_second_key_alg_info(hybrid_alg_info);
    TEST_ASSERT_NOT_NULL(second_alg_info);
    TEST_ASSERT_EQUAL(vscf_alg_id_ED25519, vscf_alg_info_alg_id(second_alg_info));

    vscf_impl_destroy(&alg_info);
    vscf_alg_info_der_deserializer_destroy(&deserializer);
}

void
test__deserialize__compound_key_alg_info_with_unsupported_cipher_alg_info___error_unsupported_algorithm(void) {
    vscf_alg_info_der_deserializer_t *deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_setup_defaults(deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *alg_info = vscf_alg_info_der_deserializer_deserialize(
            deserializer, test_alg_info_COMPOUND_KEY_UNSUPPORTED_ED25519, &error);

    TEST_ASSERT_NULL(alg_info);
    TEST_ASSERT_EQUAL(vscf_status_ERROR_UNSUPPORTED_ALGORITHM, vscf_error_status(&error));

    vscf_impl_destroy(&alg_info);
    vscf_alg_info_der_deserializer_destroy(&deserializer);
}

void
test__deserialize__compound_key_alg_info_with_unsupported_signer_alg_info___error_unsupported_algorithm(void) {
    vscf_alg_info_der_deserializer_t *deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_setup_defaults(deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *alg_info = vscf_alg_info_der_deserializer_deserialize(
            deserializer, test_alg_info_COMPOUND_KEY_CURVE25519_UNSUPPORTED, &error);

    TEST_ASSERT_NULL(alg_info);
    TEST_ASSERT_EQUAL(vscf_status_ERROR_UNSUPPORTED_ALGORITHM, vscf_error_status(&error));

    vscf_impl_destroy(&alg_info);
    vscf_alg_info_der_deserializer_destroy(&deserializer);
}

void
test__deserialize__hybrid_key_alg_info_with_unsupported_first_alg_info___error_unsupported_algorithm(void) {
    vscf_alg_info_der_deserializer_t *deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_setup_defaults(deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *alg_info = vscf_alg_info_der_deserializer_deserialize(
            deserializer, test_alg_info_HYBRID_KEY_UNSUPPORTED_ED25519, &error);

    TEST_ASSERT_NULL(alg_info);
    TEST_ASSERT_EQUAL(vscf_status_ERROR_UNSUPPORTED_ALGORITHM, vscf_error_status(&error));

    vscf_impl_destroy(&alg_info);
    vscf_alg_info_der_deserializer_destroy(&deserializer);
}

void
test__deserialize__hybrid_key_alg_info_with_unsupported_second_alg_info___error_unsupported_algorithm(void) {
    vscf_alg_info_der_deserializer_t *deserializer = vscf_alg_info_der_deserializer_new();
    vscf_alg_info_der_deserializer_setup_defaults(deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *alg_info = vscf_alg_info_der_deserializer_deserialize(
            deserializer, test_alg_info_HYBRID_KEY_CURVE25519_UNSUPPORTED, &error);

    TEST_ASSERT_NULL(alg_info);
    TEST_ASSERT_EQUAL(vscf_status_ERROR_UNSUPPORTED_ALGORITHM, vscf_error_status(&error));

    vscf_impl_destroy(&alg_info);
    vscf_alg_info_der_deserializer_destroy(&deserializer);
}


#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__deserialize__sha256__returns_valid_simple_info);
    RUN_TEST(test__deserialize__sha256_v2_compat__returns_valid_simple_info);
    RUN_TEST(test__deserialize__kdf1_sha256__returns_valid_hash_based_alg_info);
    RUN_TEST(test__deserialize__kdf1_sha256_v2_compat__returns_valid_hash_based_alg_info);
    RUN_TEST(test__deserialize__aes256_gcm__returns_valid_cipher_alg_info);
    RUN_TEST(test__deserialize__aes256_gcm_v2_compat__returns_valid_cipher_alg_info);
    RUN_TEST(test__deserialize__valid_compound_key_alg_info___success);
    RUN_TEST(test__deserialize__valid_hybrid_key_alg_info___success);
    RUN_TEST(test__deserialize__compound_key_alg_info_with_unsupported_cipher_alg_info___error_unsupported_algorithm);
    RUN_TEST(test__deserialize__compound_key_alg_info_with_unsupported_signer_alg_info___error_unsupported_algorithm);
    RUN_TEST(test__deserialize__hybrid_key_alg_info_with_unsupported_first_alg_info___error_unsupported_algorithm);
    RUN_TEST(test__deserialize__hybrid_key_alg_info_with_unsupported_second_alg_info___error_unsupported_algorithm);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
