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

#define TEST_DEPENDENCIES_AVAILABLE (VSCF_POST_QUANTUM && MLKEM_LIBRARY)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_ml_kem.h"
#include "vscf_key.h"
#include "vscf_private_key.h"
#include "vscf_simple_alg_info.h"
#include "vscf_ctr_drbg.h"

void
test__generate_key__key_has_correct_alg_id(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_ml_kem_t *ml_kem = vscf_ml_kem_new();
    vscf_ml_kem_use_random(ml_kem, vscf_ctr_drbg_impl(rng));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_ml_kem_generate_key(ml_kem, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    TEST_ASSERT_EQUAL(vscf_alg_id_ML_KEM_768, vscf_key_alg_id(private_key));

    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_NOT_NULL(public_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_ML_KEM_768, vscf_key_alg_id(public_key));

    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_ml_kem_destroy(&ml_kem);
    vscf_ctr_drbg_destroy(&rng);
}

void
test__export_import_public_key__round_trip(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_ml_kem_t *ml_kem = vscf_ml_kem_new();
    vscf_ml_kem_use_random(ml_kem, vscf_ctr_drbg_impl(rng));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_ml_kem_generate_key(ml_kem, &error);
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    /* Export */
    vscf_raw_public_key_t *raw_pub = vscf_ml_kem_export_public_key(ml_kem, public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_EQUAL(vscf_ml_kem_PUBLIC_KEY_LEN, vscf_raw_public_key_data(raw_pub).len);

    /* Import */
    vscf_impl_t *imported_pub = vscf_ml_kem_import_public_key(ml_kem, raw_pub, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(imported_pub);

    /* Exported data should match */
    vscf_raw_public_key_t *raw_pub2 = vscf_ml_kem_export_public_key(ml_kem, imported_pub, &error);
    TEST_ASSERT_EQUAL_DATA(vscf_raw_public_key_data(raw_pub), vscf_raw_public_key_data(raw_pub2));

    vscf_raw_public_key_destroy(&raw_pub2);
    vscf_impl_destroy(&imported_pub);
    vscf_raw_public_key_destroy(&raw_pub);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_ml_kem_destroy(&ml_kem);
    vscf_ctr_drbg_destroy(&rng);
}

void
test__export_import_private_key__round_trip(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_ml_kem_t *ml_kem = vscf_ml_kem_new();
    vscf_ml_kem_use_random(ml_kem, vscf_ctr_drbg_impl(rng));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_ml_kem_generate_key(ml_kem, &error);

    /* Export */
    vscf_raw_private_key_t *raw_priv = vscf_ml_kem_export_private_key(ml_kem, private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_EQUAL(vscf_ml_kem_SECRET_KEY_LEN, vscf_raw_private_key_data(raw_priv).len);

    /* Import */
    vscf_impl_t *imported_priv = vscf_ml_kem_import_private_key(ml_kem, raw_priv, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(imported_priv);

    /* Exported data should match */
    vscf_raw_private_key_t *raw_priv2 = vscf_ml_kem_export_private_key(ml_kem, imported_priv, &error);
    TEST_ASSERT_EQUAL_DATA(vscf_raw_private_key_data(raw_priv), vscf_raw_private_key_data(raw_priv2));

    vscf_raw_private_key_destroy(&raw_priv2);
    vscf_impl_destroy(&imported_priv);
    vscf_raw_private_key_destroy(&raw_priv);
    vscf_impl_destroy(&private_key);
    vscf_ml_kem_destroy(&ml_kem);
    vscf_ctr_drbg_destroy(&rng);
}

void
test__encapsulate_decapsulate__shared_keys_match(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_ml_kem_t *ml_kem = vscf_ml_kem_new();
    vscf_ml_kem_use_random(ml_kem, vscf_ctr_drbg_impl(rng));

    vscf_error_t error;
    vscf_error_reset(&error);

    /* Generate key pair */
    vscf_impl_t *private_key = vscf_ml_kem_generate_key(ml_kem, &error);
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    /* Encapsulate */
    const size_t enc_key_len = vscf_ml_kem_kem_encapsulated_key_len(ml_kem, public_key);
    const size_t shared_key_len = vscf_ml_kem_kem_shared_key_len(ml_kem, public_key);
    TEST_ASSERT_EQUAL(vscf_ml_kem_CIPHERTEXT_LEN, enc_key_len);
    TEST_ASSERT_EQUAL(vscf_ml_kem_SHARED_KEY_LEN, shared_key_len);

    vsc_buffer_t *encapsulated_key = vsc_buffer_new_with_capacity(enc_key_len);
    vsc_buffer_t *shared_key_enc = vsc_buffer_new_with_capacity(shared_key_len);

    vscf_status_t status = vscf_ml_kem_kem_encapsulate(ml_kem, public_key, shared_key_enc, encapsulated_key);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    /* Decapsulate */
    vsc_buffer_t *shared_key_dec = vsc_buffer_new_with_capacity(vscf_ml_kem_kem_shared_key_len(ml_kem, private_key));

    status = vscf_ml_kem_kem_decapsulate(ml_kem, vsc_buffer_data(encapsulated_key), private_key, shared_key_dec);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    /* Shared keys must match */
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(shared_key_enc), shared_key_dec);

    vsc_buffer_destroy(&shared_key_dec);
    vsc_buffer_destroy(&shared_key_enc);
    vsc_buffer_destroy(&encapsulated_key);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_ml_kem_destroy(&ml_kem);
    vscf_ctr_drbg_destroy(&rng);
}

void
test__decapsulate__with_wrong_private_key__shared_keys_differ(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_ml_kem_t *ml_kem = vscf_ml_kem_new();
    vscf_ml_kem_use_random(ml_kem, vscf_ctr_drbg_impl(rng));

    vscf_error_t error;
    vscf_error_reset(&error);

    /* Generate two distinct key pairs */
    vscf_impl_t *private_key1 = vscf_ml_kem_generate_key(ml_kem, &error);
    vscf_impl_t *public_key1 = vscf_private_key_extract_public_key(private_key1);
    vscf_impl_t *private_key2 = vscf_ml_kem_generate_key(ml_kem, &error);

    /* Encapsulate to key 1 */
    vsc_buffer_t *encapsulated_key =
            vsc_buffer_new_with_capacity(vscf_ml_kem_kem_encapsulated_key_len(ml_kem, public_key1));
    vsc_buffer_t *shared_key_enc = vsc_buffer_new_with_capacity(vscf_ml_kem_kem_shared_key_len(ml_kem, public_key1));
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
            vscf_ml_kem_kem_encapsulate(ml_kem, public_key1, shared_key_enc, encapsulated_key));

    /* Decapsulate with key 2 (wrong key) — must return different shared key (implicit rejection) */
    vsc_buffer_t *shared_key_wrong = vsc_buffer_new_with_capacity(vscf_ml_kem_SHARED_KEY_LEN);
    const vscf_status_t status =
            vscf_ml_kem_kem_decapsulate(ml_kem, vsc_buffer_data(encapsulated_key), private_key2, shared_key_wrong);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    /* Must not match the original shared key */
    TEST_ASSERT_FALSE(vsc_data_equal(vsc_buffer_data(shared_key_enc), vsc_buffer_data(shared_key_wrong)));

    vsc_buffer_destroy(&shared_key_wrong);
    vsc_buffer_destroy(&shared_key_enc);
    vsc_buffer_destroy(&encapsulated_key);
    vscf_impl_destroy(&private_key2);
    vscf_impl_destroy(&public_key1);
    vscf_impl_destroy(&private_key1);
    vscf_ml_kem_destroy(&ml_kem);
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
    RUN_TEST(test__encapsulate_decapsulate__shared_keys_match);
    RUN_TEST(test__decapsulate__with_wrong_private_key__shared_keys_differ);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
