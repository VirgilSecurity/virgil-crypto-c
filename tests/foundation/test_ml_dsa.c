//  Copyright (C) 2015-2026 Virgil Security, Inc.
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

#define TEST_DEPENDENCIES_AVAILABLE (VSCF_POST_QUANTUM && MLDSA_LIBRARY)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_ml_dsa.h"
#include "vscf_key.h"
#include "vscf_private_key.h"
#include "vscf_simple_alg_info.h"
#include "vscf_ctr_drbg.h"
#include "vscf_hash_based_alg_info.h"

/* Use SHA-256 hash of "hello" as a test digest */
static const byte test_digest[] = {
    0x2C, 0xF2, 0x4D, 0xBA, 0x5F, 0xB0, 0xA3, 0x0E,
    0x26, 0xE8, 0x3B, 0x2A, 0xC5, 0xB9, 0xE2, 0x9E,
    0x1B, 0x16, 0x1E, 0x5C, 0x1F, 0xA7, 0x42, 0x5E,
    0x73, 0x04, 0x33, 0x62, 0x93, 0x8B, 0x98, 0x24
};

void
test__generate_key__key_has_correct_alg_id(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_ml_dsa_t *ml_dsa = vscf_ml_dsa_new();
    vscf_ml_dsa_use_random(ml_dsa, vscf_ctr_drbg_impl(rng));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_ml_dsa_generate_key(ml_dsa, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    TEST_ASSERT_EQUAL(vscf_alg_id_ML_DSA_65, vscf_key_alg_id(private_key));

    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_NOT_NULL(public_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_ML_DSA_65, vscf_key_alg_id(public_key));

    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_ml_dsa_destroy(&ml_dsa);
    vscf_ctr_drbg_destroy(&rng);
}

void
test__export_import_public_key__round_trip(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_ml_dsa_t *ml_dsa = vscf_ml_dsa_new();
    vscf_ml_dsa_use_random(ml_dsa, vscf_ctr_drbg_impl(rng));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_ml_dsa_generate_key(ml_dsa, &error);
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    /* Export */
    vscf_raw_public_key_t *raw_pub = vscf_ml_dsa_export_public_key(ml_dsa, public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_EQUAL(vscf_ml_dsa_PUBLIC_KEY_LEN, vscf_raw_public_key_data(raw_pub).len);

    /* Import */
    vscf_impl_t *imported_pub = vscf_ml_dsa_import_public_key(ml_dsa, raw_pub, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(imported_pub);

    /* Exported data should match */
    vscf_raw_public_key_t *raw_pub2 = vscf_ml_dsa_export_public_key(ml_dsa, imported_pub, &error);
    TEST_ASSERT_EQUAL_DATA(vscf_raw_public_key_data(raw_pub), vscf_raw_public_key_data(raw_pub2));

    vscf_raw_public_key_destroy(&raw_pub2);
    vscf_impl_destroy(&imported_pub);
    vscf_raw_public_key_destroy(&raw_pub);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_ml_dsa_destroy(&ml_dsa);
    vscf_ctr_drbg_destroy(&rng);
}

void
test__export_import_private_key__round_trip(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_ml_dsa_t *ml_dsa = vscf_ml_dsa_new();
    vscf_ml_dsa_use_random(ml_dsa, vscf_ctr_drbg_impl(rng));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_ml_dsa_generate_key(ml_dsa, &error);

    /* Export */
    vscf_raw_private_key_t *raw_priv = vscf_ml_dsa_export_private_key(ml_dsa, private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_EQUAL(vscf_ml_dsa_SECRET_KEY_LEN, vscf_raw_private_key_data(raw_priv).len);

    /* Import */
    vscf_impl_t *imported_priv = vscf_ml_dsa_import_private_key(ml_dsa, raw_priv, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(imported_priv);

    /* Exported data should match */
    vscf_raw_private_key_t *raw_priv2 = vscf_ml_dsa_export_private_key(ml_dsa, imported_priv, &error);
    TEST_ASSERT_EQUAL_DATA(vscf_raw_private_key_data(raw_priv), vscf_raw_private_key_data(raw_priv2));

    vscf_raw_private_key_destroy(&raw_priv2);
    vscf_impl_destroy(&imported_priv);
    vscf_raw_private_key_destroy(&raw_priv);
    vscf_impl_destroy(&private_key);
    vscf_ml_dsa_destroy(&ml_dsa);
    vscf_ctr_drbg_destroy(&rng);
}

void
test__sign_hash_then_verify_hash__success(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_ml_dsa_t *ml_dsa = vscf_ml_dsa_new();
    vscf_ml_dsa_use_random(ml_dsa, vscf_ctr_drbg_impl(rng));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_ml_dsa_generate_key(ml_dsa, &error);
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    const vsc_data_t digest = vsc_data(test_digest, sizeof(test_digest));

    /* Sign */
    const size_t sig_len = vscf_ml_dsa_signature_len(ml_dsa, private_key);
    TEST_ASSERT_EQUAL(vscf_ml_dsa_SIGNATURE_LEN, sig_len);

    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(sig_len);
    vscf_status_t status = vscf_ml_dsa_sign_hash(ml_dsa, private_key, vscf_alg_id_SHA256, digest, signature);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    /* Verify */
    const bool verified = vscf_ml_dsa_verify_hash(ml_dsa, public_key, vscf_alg_id_SHA256, digest, vsc_buffer_data(signature));
    TEST_ASSERT_TRUE(verified);

    vsc_buffer_destroy(&signature);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_ml_dsa_destroy(&ml_dsa);
    vscf_ctr_drbg_destroy(&rng);
}

void
test__verify_hash__with_wrong_public_key__fails(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_ml_dsa_t *ml_dsa = vscf_ml_dsa_new();
    vscf_ml_dsa_use_random(ml_dsa, vscf_ctr_drbg_impl(rng));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key1 = vscf_ml_dsa_generate_key(ml_dsa, &error);
    vscf_impl_t *private_key2 = vscf_ml_dsa_generate_key(ml_dsa, &error);
    vscf_impl_t *public_key2 = vscf_private_key_extract_public_key(private_key2);

    const vsc_data_t digest = vsc_data(test_digest, sizeof(test_digest));

    /* Sign with key 1 */
    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_ml_dsa_SIGNATURE_LEN);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_ml_dsa_sign_hash(ml_dsa, private_key1, vscf_alg_id_SHA256, digest, signature));

    /* Verify with key 2 — must fail */
    const bool verified = vscf_ml_dsa_verify_hash(ml_dsa, public_key2, vscf_alg_id_SHA256, digest, vsc_buffer_data(signature));
    TEST_ASSERT_FALSE(verified);

    vsc_buffer_destroy(&signature);
    vscf_impl_destroy(&public_key2);
    vscf_impl_destroy(&private_key2);
    vscf_impl_destroy(&private_key1);
    vscf_ml_dsa_destroy(&ml_dsa);
    vscf_ctr_drbg_destroy(&rng);
}

void
test__sign_hash__deterministic__same_signature_twice(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_ml_dsa_t *ml_dsa = vscf_ml_dsa_new();
    vscf_ml_dsa_use_random(ml_dsa, vscf_ctr_drbg_impl(rng));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_ml_dsa_generate_key(ml_dsa, &error);
    const vsc_data_t digest = vsc_data(test_digest, sizeof(test_digest));

    vsc_buffer_t *sig1 = vsc_buffer_new_with_capacity(vscf_ml_dsa_SIGNATURE_LEN);
    vsc_buffer_t *sig2 = vsc_buffer_new_with_capacity(vscf_ml_dsa_SIGNATURE_LEN);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_ml_dsa_sign_hash(ml_dsa, private_key, vscf_alg_id_SHA256, digest, sig1));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_ml_dsa_sign_hash(ml_dsa, private_key, vscf_alg_id_SHA256, digest, sig2));

    /* Deterministic signing: same inputs produce identical signatures */
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(sig1), sig2);

    vsc_buffer_destroy(&sig2);
    vsc_buffer_destroy(&sig1);
    vscf_impl_destroy(&private_key);
    vscf_ml_dsa_destroy(&ml_dsa);
    vscf_ctr_drbg_destroy(&rng);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__generate_key__key_has_correct_alg_id);
    RUN_TEST(test__export_import_public_key__round_trip);
    RUN_TEST(test__export_import_private_key__round_trip);
    RUN_TEST(test__sign_hash_then_verify_hash__success);
    RUN_TEST(test__verify_hash__with_wrong_public_key__fails);
    RUN_TEST(test__sign_hash__deterministic__same_signature_twice);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
