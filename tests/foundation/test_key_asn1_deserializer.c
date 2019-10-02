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


#define TEST_DEPENDENCIES_AVAILABLE VSCF_KEY_ASN1_DESERIALIZER
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_key_asn1_deserializer.h"

#include "test_data_rsa.h"
#include "test_data_ed25519.h"
#include "test_data_curve25519.h"
#include "test_data_secp256r1.h"


// --------------------------------------------------------------------------
// PKCS#8 RSA keys.
// --------------------------------------------------------------------------
void
test__deserialize_public_key__rsa2048_der__equals_to_rsa_2048_public_key_pkcs1_der(void) {
    vscf_key_asn1_deserializer_t *key_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_raw_public_key_t *raw_public_key = vscf_key_asn1_deserializer_deserialize_public_key(
            key_deserializer, test_rsa_2048_PUBLIC_KEY_PKCS8_DER, &error);

    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(raw_public_key);
    TEST_ASSERT_EQUAL(vscf_raw_public_key_alg_id(raw_public_key), vscf_alg_id_RSA);
    TEST_ASSERT_EQUAL_DATA(test_rsa_2048_PUBLIC_KEY_PKCS1, vscf_raw_public_key_data(raw_public_key));

    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_key_asn1_deserializer_destroy(&key_deserializer);
}

void
test__deserialize_public_key__rsa2048_pem__equals_to_rsa_2048_public_key_pkcs1_der(void) {
    vscf_key_asn1_deserializer_t *key_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_raw_public_key_t *raw_public_key = vscf_key_asn1_deserializer_deserialize_public_key(
            key_deserializer, test_rsa_2048_PUBLIC_KEY_PKCS8_PEM, &error);

    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(raw_public_key);
    TEST_ASSERT_EQUAL(vscf_raw_public_key_alg_id(raw_public_key), vscf_alg_id_RSA);
    TEST_ASSERT_EQUAL_DATA(test_rsa_2048_PUBLIC_KEY_PKCS1, vscf_raw_public_key_data(raw_public_key));

    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_key_asn1_deserializer_destroy(&key_deserializer);
}

void
test__deserialize_private_key__rsa2048_der__equals_to_rsa_2048_private_key_pkcs1_der(void) {
    vscf_key_asn1_deserializer_t *key_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_raw_private_key_t *raw_private_key = vscf_key_asn1_deserializer_deserialize_private_key(
            key_deserializer, test_rsa_2048_PRIVATE_KEY_PKCS8_DER, &error);

    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(raw_private_key);
    TEST_ASSERT_EQUAL(vscf_raw_private_key_alg_id(raw_private_key), vscf_alg_id_RSA);
    TEST_ASSERT_EQUAL_DATA(test_rsa_2048_PRIVATE_KEY_PKCS1, vscf_raw_private_key_data(raw_private_key));

    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_key_asn1_deserializer_destroy(&key_deserializer);
}

void
test__deserialize_private_key__rsa2048_pem__equals_to_rsa_2048_private_key_pkcs1_der(void) {
    vscf_key_asn1_deserializer_t *key_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_raw_private_key_t *raw_private_key = vscf_key_asn1_deserializer_deserialize_private_key(
            key_deserializer, test_rsa_2048_PRIVATE_KEY_PKCS8_PEM, &error);

    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(raw_private_key);
    TEST_ASSERT_EQUAL(vscf_raw_private_key_alg_id(raw_private_key), vscf_alg_id_RSA);
    TEST_ASSERT_EQUAL_DATA(test_rsa_2048_PRIVATE_KEY_PKCS1, vscf_raw_private_key_data(raw_private_key));

    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_key_asn1_deserializer_destroy(&key_deserializer);
}

// --------------------------------------------------------------------------
// PKCS#8 ed25519 keys.
// --------------------------------------------------------------------------
void
test__deserialize_public_key__ed25519_der__equals_to_ed25519_public_key(void) {
    vscf_key_asn1_deserializer_t *key_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_raw_public_key_t *raw_public_key = vscf_key_asn1_deserializer_deserialize_public_key(
            key_deserializer, test_ed25519_PUBLIC_KEY_PKCS8_DER, &error);

    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(raw_public_key);
    TEST_ASSERT_EQUAL(vscf_raw_public_key_alg_id(raw_public_key), vscf_alg_id_ED25519);
    TEST_ASSERT_EQUAL_DATA(test_ed25519_PUBLIC_KEY, vscf_raw_public_key_data(raw_public_key));

    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_key_asn1_deserializer_destroy(&key_deserializer);
}

void
test__deserialize_public_key__ed25519_pem__equals_to_ed25519_public_key(void) {
    vscf_key_asn1_deserializer_t *key_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_raw_public_key_t *raw_public_key = vscf_key_asn1_deserializer_deserialize_public_key(
            key_deserializer, test_ed25519_PUBLIC_KEY_PKCS8_PEM, &error);

    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(raw_public_key);
    TEST_ASSERT_EQUAL(vscf_raw_public_key_alg_id(raw_public_key), vscf_alg_id_ED25519);
    TEST_ASSERT_EQUAL_DATA(test_ed25519_PUBLIC_KEY, vscf_raw_public_key_data(raw_public_key));

    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_key_asn1_deserializer_destroy(&key_deserializer);
}

void
test__deserialize_private_key__ed25519_der__equals_to_ed25519_private_key(void) {
    vscf_key_asn1_deserializer_t *key_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_raw_private_key_t *raw_private_key = vscf_key_asn1_deserializer_deserialize_private_key(
            key_deserializer, test_ed25519_PRIVATE_KEY_PKCS8_PEM, &error);

    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(raw_private_key);
    TEST_ASSERT_EQUAL(vscf_raw_private_key_alg_id(raw_private_key), vscf_alg_id_ED25519);
    TEST_ASSERT_EQUAL_DATA(test_ed25519_PRIVATE_KEY, vscf_raw_private_key_data(raw_private_key));

    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_key_asn1_deserializer_destroy(&key_deserializer);
}

void
test__deserialize_private_key__ed25519_pem__equals_to_ed25519_private_key(void) {
    vscf_key_asn1_deserializer_t *key_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_raw_private_key_t *raw_private_key = vscf_key_asn1_deserializer_deserialize_private_key(
            key_deserializer, test_ed25519_PRIVATE_KEY_PKCS8_PEM, &error);

    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(raw_private_key);
    TEST_ASSERT_EQUAL(vscf_raw_private_key_alg_id(raw_private_key), vscf_alg_id_ED25519);
    TEST_ASSERT_EQUAL_DATA(test_ed25519_PRIVATE_KEY, vscf_raw_private_key_data(raw_private_key));

    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_key_asn1_deserializer_destroy(&key_deserializer);
}

// --------------------------------------------------------------------------
// PKCS#8 curve25519 keys.
// --------------------------------------------------------------------------
void
test__deserialize_public_key__curve25519_der__equals_to_curve25519_public_key(void) {
    vscf_key_asn1_deserializer_t *key_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_raw_public_key_t *raw_public_key = vscf_key_asn1_deserializer_deserialize_public_key(
            key_deserializer, test_curve25519_PUBLIC_KEY_PKCS8_DER, &error);

    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(raw_public_key);
    TEST_ASSERT_EQUAL(vscf_raw_public_key_alg_id(raw_public_key), vscf_alg_id_CURVE25519);
    TEST_ASSERT_EQUAL_DATA(test_curve25519_PUBLIC_KEY, vscf_raw_public_key_data(raw_public_key));

    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_key_asn1_deserializer_destroy(&key_deserializer);
}

void
test__deserialize_private_key__curve25519_der__equals_to_curve25519_private_key(void) {
    vscf_key_asn1_deserializer_t *key_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_raw_private_key_t *raw_private_key = vscf_key_asn1_deserializer_deserialize_private_key(
            key_deserializer, test_curve25519_PRIVATE_KEY_PKCS8_DER, &error);

    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(raw_private_key);
    TEST_ASSERT_EQUAL(vscf_raw_private_key_alg_id(raw_private_key), vscf_alg_id_CURVE25519);
    TEST_ASSERT_EQUAL_DATA(test_curve25519_PRIVATE_KEY, vscf_raw_private_key_data(raw_private_key));

    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_key_asn1_deserializer_destroy(&key_deserializer);
}

// --------------------------------------------------------------------------
// SEC1 secp256r1 keys.
// --------------------------------------------------------------------------
void
test__deserialize_public_key__secp256r1_der__equals_to_secp256r1_public_key(void) {
    vscf_key_asn1_deserializer_t *key_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_raw_public_key_t *raw_public_key = vscf_key_asn1_deserializer_deserialize_public_key(
            key_deserializer, test_secp256r1_PUBLIC_KEY_SEC1_DER, &error);

    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(raw_public_key);
    TEST_ASSERT_EQUAL(vscf_raw_public_key_alg_id(raw_public_key), vscf_alg_id_SECP256R1);
    TEST_ASSERT_EQUAL_DATA(test_secp256r1_PUBLIC_KEY, vscf_raw_public_key_data(raw_public_key));

    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_key_asn1_deserializer_destroy(&key_deserializer);
}

void
test__deserialize_public_key__secp256r1_pem__equals_to_secp256r1_public_key(void) {
    vscf_key_asn1_deserializer_t *key_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_raw_public_key_t *raw_public_key = vscf_key_asn1_deserializer_deserialize_public_key(
            key_deserializer, test_secp256r1_PUBLIC_KEY_SEC1_PEM, &error);

    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(raw_public_key);
    TEST_ASSERT_EQUAL(vscf_raw_public_key_alg_id(raw_public_key), vscf_alg_id_SECP256R1);
    TEST_ASSERT_EQUAL_DATA(test_secp256r1_PUBLIC_KEY, vscf_raw_public_key_data(raw_public_key));

    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_key_asn1_deserializer_destroy(&key_deserializer);
}

void
test__deserialize_private_key__secp256r1_der__equals_to_secp256r1_private_key(void) {
    vscf_key_asn1_deserializer_t *key_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_raw_private_key_t *raw_private_key = vscf_key_asn1_deserializer_deserialize_private_key(
            key_deserializer, test_secp256r1_PRIVATE_KEY_SEC1_PEM, &error);

    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(raw_private_key);
    TEST_ASSERT_EQUAL(vscf_raw_private_key_alg_id(raw_private_key), vscf_alg_id_SECP256R1);
    TEST_ASSERT_EQUAL_DATA(test_secp256r1_PRIVATE_KEY, vscf_raw_private_key_data(raw_private_key));

    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_key_asn1_deserializer_destroy(&key_deserializer);
}

void
test__deserialize_private_key__secp256r1_pem__equals_to_secp256r1_private_key(void) {
    vscf_key_asn1_deserializer_t *key_deserializer = vscf_key_asn1_deserializer_new();
    vscf_key_asn1_deserializer_setup_defaults(key_deserializer);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_raw_private_key_t *raw_private_key = vscf_key_asn1_deserializer_deserialize_private_key(
            key_deserializer, test_secp256r1_PRIVATE_KEY_SEC1_PEM, &error);

    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(raw_private_key);
    TEST_ASSERT_EQUAL(vscf_raw_private_key_alg_id(raw_private_key), vscf_alg_id_SECP256R1);
    TEST_ASSERT_EQUAL_DATA(test_secp256r1_PRIVATE_KEY, vscf_raw_private_key_data(raw_private_key));

    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_key_asn1_deserializer_destroy(&key_deserializer);
}


#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
//  Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__deserialize_public_key__rsa2048_der__equals_to_rsa_2048_public_key_pkcs1_der);
    RUN_TEST(test__deserialize_public_key__rsa2048_pem__equals_to_rsa_2048_public_key_pkcs1_der);
    RUN_TEST(test__deserialize_private_key__rsa2048_der__equals_to_rsa_2048_private_key_pkcs1_der);
    RUN_TEST(test__deserialize_private_key__rsa2048_pem__equals_to_rsa_2048_private_key_pkcs1_der);

    RUN_TEST(test__deserialize_public_key__ed25519_der__equals_to_ed25519_public_key);
    RUN_TEST(test__deserialize_public_key__ed25519_pem__equals_to_ed25519_public_key);
    RUN_TEST(test__deserialize_private_key__ed25519_der__equals_to_ed25519_private_key);
    RUN_TEST(test__deserialize_private_key__ed25519_pem__equals_to_ed25519_private_key);

    RUN_TEST(test__deserialize_public_key__curve25519_der__equals_to_curve25519_public_key);
    RUN_TEST(test__deserialize_private_key__curve25519_der__equals_to_curve25519_private_key);

    RUN_TEST(test__deserialize_public_key__secp256r1_der__equals_to_secp256r1_public_key);
    RUN_TEST(test__deserialize_public_key__secp256r1_pem__equals_to_secp256r1_public_key);
    RUN_TEST(test__deserialize_private_key__secp256r1_der__equals_to_secp256r1_private_key);
    RUN_TEST(test__deserialize_private_key__secp256r1_pem__equals_to_secp256r1_private_key);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
