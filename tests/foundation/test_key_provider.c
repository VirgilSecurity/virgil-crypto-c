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
    (VSCF_KEY_PROVIDER && VSCF_KEY_ALG_FACTORY && VSCF_KEY_CIPHER && VSCF_KEY_SIGNER && VSCF_KEY_MATERIAL_RNG)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_alg.h"
#include "vscf_key.h"
#include "vscf_key_alg.h"
#include "vscf_key_provider.h"
#include "vscf_private_key.h"
#include "vscf_key_cipher.h"
#include "vscf_key_signer.h"
#include "vscf_key_material_rng.h"
#include "vscf_key_alg_factory.h"
#include "vscf_compound_public_key.h"
#include "vscf_compound_private_key.h"
#include "vscf_hybrid_public_key.h"
#include "vscf_hybrid_private_key.h"

#include "test_data_deterministic_key.h"
#include "test_data_key_provider.h"
#include "test_data_curve25519.h"
#include "test_data_ed25519.h"
#include "test_data_rsa.h"
#include "test_data_secp256r1.h"
#include "test_data_round5.h"
#include "test_data_falcon.h"
#include "test_data_post_quantum.h"


// --------------------------------------------------------------------------
//  Generate deterministic key.
// --------------------------------------------------------------------------
static void
inner_test__generate_private_key__success(vscf_alg_id_t alg_id, size_t bitlen) {

    //
    //  Prepare algs.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_material_rng_t *key_material_rng = vscf_key_material_rng_new();
    vscf_key_material_rng_reset_key_material(key_material_rng, test_data_deterministic_key_KEY_MATERIAL);
    vscf_impl_t *random = vscf_key_material_rng_impl(key_material_rng);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, random);
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    //
    //  Generate key.
    //
    if (vscf_alg_id_RSA == alg_id) {
        vscf_key_provider_set_rsa_params(key_provider, bitlen); //  take place only for RSA
    }
    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, alg_id, &error);

    //
    //  Check.
    //
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);
    TEST_ASSERT_EQUAL(alg_id, vscf_key_alg_id(private_key));
    if (bitlen > 0) {
        TEST_ASSERT_EQUAL(bitlen, vscf_key_bitlen(private_key));
    }

    //
    //  Cleanup.
    //
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
    vscf_impl_destroy(&random);
}

void
test__generate_private_key__curve25519__success(void) {
    inner_test__generate_private_key__success(vscf_alg_id_CURVE25519, 256);
}

void
test__generate_private_key__ed25519__success(void) {
    inner_test__generate_private_key__success(vscf_alg_id_ED25519, 256);
}

void
test__generate_private_key__secp256r1__success(void) {
    inner_test__generate_private_key__success(vscf_alg_id_SECP256R1, 256);
}

void
test__generate_private_key__rsa2048__success(void) {
    inner_test__generate_private_key__success(vscf_alg_id_RSA, 2048);
}

void
test__generate_private_key__falcon__success(void) {
#if VSCF_POST_QUANTUM && VSCF_FALCON
    inner_test__generate_private_key__success(vscf_alg_id_FALCON, 10248);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM and/or VSCF_FALCON are disabled");
#endif
}

void
test__generate_private_key__round5__success(void) {
#if VSCF_POST_QUANTUM && VSCF_ROUND5
    inner_test__generate_private_key__success(vscf_alg_id_ROUND5_ND_1CCA_5D, 3944);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM and/or VSCF_ROUND5 are disabled");
#endif
}

// --------------------------------------------------------------------------
//  Generate post-quantum keys.
// --------------------------------------------------------------------------
void
test__generate_post_quantum_key__with_default_rng__success(void) {
#if VSCF_POST_QUANTUM
    //
    //  Create dependencies first.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    //
    //  Generate key
    //
    vscf_impl_t *private_key = vscf_key_provider_generate_post_quantum_private_key(key_provider, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    //
    //  Check private keys
    //
    TEST_ASSERT_EQUAL(vscf_impl_tag_COMPOUND_PRIVATE_KEY, vscf_impl_tag(private_key));
    vscf_compound_private_key_t *compound_private_key = (vscf_compound_private_key_t *)private_key;

    const vscf_impl_t *cipher_private_key = vscf_compound_private_key_cipher_key(compound_private_key);
    TEST_ASSERT_NOT_NULL(cipher_private_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_HYBRID_KEY, vscf_key_alg_id(cipher_private_key));

    TEST_ASSERT_EQUAL(vscf_impl_tag_HYBRID_PRIVATE_KEY, vscf_impl_tag(cipher_private_key));
    const vscf_hybrid_private_key_t *cipher_hybrid_private_key = (const vscf_hybrid_private_key_t *)cipher_private_key;

    const vscf_impl_t *hybrid_cipher_first_private_key = vscf_hybrid_private_key_first_key(cipher_hybrid_private_key);
    TEST_ASSERT_NOT_NULL(hybrid_cipher_first_private_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_CURVE25519, vscf_key_alg_id(hybrid_cipher_first_private_key));

    const vscf_impl_t *hybrid_cipher_second_private_key = vscf_hybrid_private_key_second_key(cipher_hybrid_private_key);
    TEST_ASSERT_NOT_NULL(hybrid_cipher_second_private_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_ROUND5_ND_1CCA_5D, vscf_key_alg_id(hybrid_cipher_second_private_key));

    const vscf_impl_t *signer_private_key = vscf_compound_private_key_signer_key(compound_private_key);
    TEST_ASSERT_NOT_NULL(signer_private_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_HYBRID_KEY, vscf_key_alg_id(cipher_private_key));

    TEST_ASSERT_EQUAL(vscf_impl_tag_HYBRID_PRIVATE_KEY, vscf_impl_tag(cipher_private_key));
    const vscf_hybrid_private_key_t *signer_hybrid_private_key = (const vscf_hybrid_private_key_t *)signer_private_key;

    const vscf_impl_t *hybrid_signer_first_private_key = vscf_hybrid_private_key_first_key(signer_hybrid_private_key);
    TEST_ASSERT_NOT_NULL(hybrid_signer_first_private_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_ED25519, vscf_key_alg_id(hybrid_signer_first_private_key));

    const vscf_impl_t *hybrid_signer_second_private_key = vscf_hybrid_private_key_second_key(signer_hybrid_private_key);
    TEST_ASSERT_NOT_NULL(hybrid_signer_second_private_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_FALCON, vscf_key_alg_id(hybrid_signer_second_private_key));

    //
    //  Check public keys
    //
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_EQUAL(vscf_impl_tag_COMPOUND_PUBLIC_KEY, vscf_impl_tag(public_key));
    vscf_compound_public_key_t *compound_public_key = (vscf_compound_public_key_t *)public_key;

    const vscf_impl_t *cipher_public_key = vscf_compound_public_key_cipher_key(compound_public_key);
    TEST_ASSERT_NOT_NULL(cipher_public_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_HYBRID_KEY, vscf_key_alg_id(cipher_public_key));

    TEST_ASSERT_EQUAL(vscf_impl_tag_HYBRID_PUBLIC_KEY, vscf_impl_tag(cipher_public_key));
    const vscf_hybrid_public_key_t *hybrid_public_key = (const vscf_hybrid_public_key_t *)cipher_public_key;

    const vscf_impl_t *hybrid_cipher_first_public_key = vscf_hybrid_public_key_first_key(hybrid_public_key);
    TEST_ASSERT_NOT_NULL(hybrid_cipher_first_public_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_CURVE25519, vscf_key_alg_id(hybrid_cipher_first_public_key));

    const vscf_impl_t *hybrid_cipher_second_public_key = vscf_hybrid_public_key_second_key(hybrid_public_key);
    TEST_ASSERT_NOT_NULL(hybrid_cipher_second_public_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_ROUND5_ND_1CCA_5D, vscf_key_alg_id(hybrid_cipher_second_public_key));

    const vscf_impl_t *signer_public_key = vscf_compound_public_key_signer_key(compound_public_key);
    TEST_ASSERT_NOT_NULL(signer_public_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_HYBRID_KEY, vscf_key_alg_id(signer_public_key));

    TEST_ASSERT_EQUAL(vscf_impl_tag_HYBRID_PUBLIC_KEY, vscf_impl_tag(signer_public_key));
    const vscf_hybrid_public_key_t *signer_hybrid_public_key = (const vscf_hybrid_public_key_t *)signer_public_key;

    const vscf_impl_t *hybrid_signer_first_public_key = vscf_hybrid_public_key_first_key(signer_hybrid_public_key);
    TEST_ASSERT_NOT_NULL(hybrid_signer_first_public_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_ED25519, vscf_key_alg_id(hybrid_signer_first_public_key));

    const vscf_impl_t *hybrid_signer_second_public_key = vscf_hybrid_public_key_second_key(signer_hybrid_public_key);
    TEST_ASSERT_NOT_NULL(hybrid_signer_second_public_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_FALCON, vscf_key_alg_id(hybrid_signer_second_public_key));

    //
    //  Cleanup
    //
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM is disabled");
#endif
}


// --------------------------------------------------------------------------
//  Encrypt / decrypt with a deterministic key.
// --------------------------------------------------------------------------
static void
inner_test__generate_private_key__and_then_do_encrypt_decrypt__plain_text_match(vscf_alg_id_t alg_id, size_t bitlen) {

    //
    //  Prepare algs.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_material_rng_t *key_material_rng = vscf_key_material_rng_new();
    vscf_key_material_rng_reset_key_material(key_material_rng, test_data_deterministic_key_KEY_MATERIAL);
    vscf_impl_t *random = vscf_key_material_rng_impl(key_material_rng);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, random);
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_alg_id(alg_id, random, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Generate key.
    //
    if (vscf_alg_id_RSA == alg_id) {
        vscf_key_provider_set_rsa_params(key_provider, bitlen); //  take place only for RSA
    }
    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, alg_id, &error);

    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Encrypt.
    //
    vsc_data_t plain_data = vsc_data_from_str("test data", 9);

    vsc_buffer_t *enc_data =
            vsc_buffer_new_with_capacity(vscf_key_cipher_encrypted_len(key_alg, public_key, plain_data.len));
    vscf_status_t enc_status = vscf_key_cipher_encrypt(key_alg, public_key, plain_data, enc_data);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, enc_status);

    //
    //  Decrypt.
    //
    vsc_buffer_t *dec_data =
            vsc_buffer_new_with_capacity(vscf_key_cipher_decrypted_len(key_alg, private_key, vsc_buffer_len(enc_data)));
    vscf_status_t dec_status = vscf_key_cipher_decrypt(key_alg, private_key, vsc_buffer_data(enc_data), dec_data);

    //
    //  Check.
    //
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, dec_status);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(plain_data, dec_data);

    // Cleanup
    vsc_buffer_destroy(&dec_data);
    vsc_buffer_destroy(&enc_data);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
    vscf_impl_destroy(&key_alg);
    vscf_impl_destroy(&random);
}

void
test__generate_private_key__curve25519_and_then_do_encrypt_decrypt__plain_text_match(void) {
    inner_test__generate_private_key__and_then_do_encrypt_decrypt__plain_text_match(vscf_alg_id_CURVE25519, 256);
}

void
test__generate_private_key__ed25519_and_then_do_encrypt_decrypt__plain_text_match(void) {
    inner_test__generate_private_key__and_then_do_encrypt_decrypt__plain_text_match(vscf_alg_id_ED25519, 256);
}

void
test__generate_private_key__secp256r1_and_then_do_encrypt_decrypt__plain_text_match(void) {
    inner_test__generate_private_key__and_then_do_encrypt_decrypt__plain_text_match(vscf_alg_id_SECP256R1, 256);
}

void
test__generate_private_key__rsa2048_and_then_do_encrypt_decrypt__plain_text_match(void) {
    inner_test__generate_private_key__and_then_do_encrypt_decrypt__plain_text_match(vscf_alg_id_RSA, 2048);
}

// --------------------------------------------------------------------------
//  Sign / verify with a deterministic key.
// --------------------------------------------------------------------------
static void
inner_test__generate_private_key__and_then_do_sign_verify__success(vscf_alg_id_t alg_id, size_t bitlen) {

    //
    //  Prepare algs.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_material_rng_t *key_material_rng = vscf_key_material_rng_new();
    vscf_key_material_rng_reset_key_material(key_material_rng, test_data_deterministic_key_KEY_MATERIAL);
    vscf_impl_t *random = vscf_key_material_rng_impl(key_material_rng);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, random);
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_alg_id(alg_id, random, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Generate key.
    //
    if (vscf_alg_id_RSA == alg_id) {
        vscf_key_provider_set_rsa_params(key_provider, bitlen); //  take place only for RSA
    }
    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, alg_id, &error);

    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Sign.
    //
    vsc_buffer_t *signature = vsc_buffer_new_with_capacity(vscf_key_signer_signature_len(key_alg, private_key));
    vscf_status_t sign_status = vscf_key_signer_sign_hash(
            key_alg, private_key, vscf_alg_id_SHA512, test_key_provider_MESSAGE_SHA512_DIGEST, signature);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, sign_status);

    //
    //  Verify
    //
    const bool verified = vscf_key_signer_verify_hash(key_alg, public_key, vscf_alg_id_SHA512,
            test_key_provider_MESSAGE_SHA512_DIGEST, vsc_buffer_data(signature));

    //
    //  Check.
    //
    TEST_ASSERT_TRUE(verified);

    //  Cleanup
    vsc_buffer_destroy(&signature);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
    vscf_impl_destroy(&key_alg);
    vscf_impl_destroy(&random);
}

void
test__generate_private_key__ed25519_and_then_do_sign_verify__success(void) {
    inner_test__generate_private_key__and_then_do_sign_verify__success(vscf_alg_id_ED25519, 256);
}

void
test__generate_private_key__secp256r1_and_then_do_sign_verify__success(void) {
    inner_test__generate_private_key__and_then_do_sign_verify__success(vscf_alg_id_SECP256R1, 256);
}

void
test__generate_private_key__rsa2048_and_then_do_sign_verify__success(void) {
    inner_test__generate_private_key__and_then_do_sign_verify__success(vscf_alg_id_RSA, 2048);
}

void
test__generate_private_key__falcon_and_then_do_sign_verify__success(void) {
#if VSCF_POST_QUANTUM && VSCF_FALCON
    inner_test__generate_private_key__and_then_do_sign_verify__success(vscf_alg_id_FALCON, 10248);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM and/or VSCF_FALCON are disabled");
#endif
}

// --------------------------------------------------------------------------
//  Generate key from a key material.
// --------------------------------------------------------------------------
static void
inner_test__generate_private_key__with_key_material_rng__match(
        vscf_alg_id_t alg_id, size_t bitlen, vsc_data_t det_key) {

    //
    //  Prepare algs.
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_material_rng_t *key_material_rng = vscf_key_material_rng_new();
    vscf_key_material_rng_reset_key_material(key_material_rng, test_data_deterministic_key_KEY_MATERIAL);
    vscf_impl_t *random = vscf_key_material_rng_impl(key_material_rng);

    vscf_impl_t *key_alg = vscf_key_alg_factory_create_from_alg_id(alg_id, random, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, random);
    vscf_status_t status = vscf_key_provider_setup_defaults(key_provider);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

    //
    //  Generate key.
    //
    if (vscf_alg_id_RSA == alg_id) {
        vscf_key_provider_set_rsa_params(key_provider, bitlen); //  take place only for RSA
    }
    vscf_impl_t *private_key = vscf_key_provider_generate_private_key(key_provider, alg_id, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Export key.
    //
    vscf_raw_private_key_t *exported_private_key = vscf_key_alg_export_private_key(key_alg, private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    //
    //  Check.
    //
    TEST_ASSERT_EQUAL_DATA(det_key, vscf_raw_private_key_data(exported_private_key));

    //
    //  Cleanup.
    //
    vscf_raw_private_key_destroy(&exported_private_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
    vscf_impl_destroy(&key_alg);
    vscf_impl_destroy(&random);
}

void
test__generate_private_key__ed25519_with_key_material_rng__match(void) {
    inner_test__generate_private_key__with_key_material_rng__match(
            vscf_alg_id_ED25519, 256, test_data_deterministic_key_ED25519_PRIVATE_KEY);
}

void
test__generate_private_key__rsa4096_with_key_material_rng__match(void) {
    inner_test__generate_private_key__with_key_material_rng__match(
            vscf_alg_id_RSA, 4096, test_data_deterministic_key_RSA4096_PRIVATE_KEY);
}

// --------------------------------------------------------------------------
//  Import / Export valid keys.
// --------------------------------------------------------------------------
static void
inner_test__import_public_key__then_export__are_equals(vsc_data_t public_key_data) {

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *public_key = vscf_key_provider_import_public_key(key_provider, public_key_data, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(vscf_key_alg_info(public_key));

    vsc_buffer_t *exported_public_key =
            vsc_buffer_new_with_capacity(vscf_key_provider_exported_public_key_len(key_provider, public_key));

    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_key_provider_export_public_key(key_provider, public_key, exported_public_key));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(public_key_data, exported_public_key);

    vsc_buffer_destroy(&exported_public_key);
    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

static void
inner_test__import_private_key__then_export__are_equals(vsc_data_t private_key_data) {

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *private_key = vscf_key_provider_import_private_key(key_provider, private_key_data, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(vscf_key_alg_info(private_key));

    vsc_buffer_t *exported_private_key =
            vsc_buffer_new_with_capacity(vscf_key_provider_exported_private_key_len(key_provider, private_key));
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_key_provider_export_private_key(key_provider, private_key, exported_private_key));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(private_key_data, exported_private_key);

    vsc_buffer_destroy(&exported_private_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

static void
inner_test__import_public_key__expect_status(vsc_data_t public_key_data, vscf_status_t status) {

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *public_key = vscf_key_provider_import_public_key(key_provider, public_key_data, &error);
    TEST_ASSERT_EQUAL(status, vscf_error_status(&error));

    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

static void
inner_test__import_private_key__expect_status(vsc_data_t private_key_data, vscf_status_t status) {

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *private_key = vscf_key_provider_import_private_key(key_provider, private_key_data, &error);
    TEST_ASSERT_EQUAL(status, vscf_error_status(&error));

    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

static void
inner_test__import_private_key__then_export_public_key__are_equals(
        vsc_data_t private_key_data, vsc_data_t public_key_data) {

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *private_key = vscf_key_provider_import_private_key(key_provider, private_key_data, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    TEST_ASSERT_NOT_NULL(vscf_key_alg_info(private_key));

    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    vsc_buffer_t *exported_public_key =
            vsc_buffer_new_with_capacity(vscf_key_provider_exported_public_key_len(key_provider, public_key));
    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_key_provider_export_public_key(key_provider, public_key, exported_public_key));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(public_key_data, exported_public_key);

    vsc_buffer_destroy(&exported_public_key);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

//
//  Public keys.
//
void
test__import_public_key__curve25519_and_then_export__are_equals(void) {
    inner_test__import_public_key__then_export__are_equals(test_curve25519_PUBLIC_KEY_PKCS8_DER);
}

void
test__import_public_key__ed25519_and_then_export__are_equals(void) {
    inner_test__import_public_key__then_export__are_equals(test_ed25519_PUBLIC_KEY_PKCS8_DER);
}

void
test__import_public_key__secp256r1_and_then_export__are_equals(void) {
    inner_test__import_public_key__then_export__are_equals(test_secp256r1_PUBLIC_KEY_SEC1_DER);
}

void
test__import_public_key__rsa2048_and_then_export__are_equals(void) {
    inner_test__import_public_key__then_export__are_equals(test_rsa_2048_PUBLIC_KEY_PKCS8_DER);
}

void
test__import_public_key__round5_and_then_export__are_equals(void) {
#if VSCF_POST_QUANTUM && VSCF_ROUND5
    inner_test__import_public_key__then_export__are_equals(test_data_round5_ND_1CCA_5D_PUBLIC_KEY_PKCS8_DER);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM and/or VSCF_ROUND5 are disabled");
#endif
}

void
test__import_public_key__falcon_and_then_export__are_equals(void) {
#if VSCF_POST_QUANTUM && VSCF_FALCON
    inner_test__import_public_key__then_export__are_equals(test_data_falcon_PUBLIC_KEY_512_PKCS8_DER);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM and/or VSCF_FALCON are disabled");
#endif
}

void
test__import_public_key__curve25519_round5_falcon_and_then_export__are_equals(void) {
#if VSCF_POST_QUANTUM && VSCF_ROUND5 && VSCF_FALCON
    inner_test__import_public_key__then_export__are_equals(
            test_data_pqc_CURVE25519_ROUND5_ND_1CCA_5D_FALCON_PUBLIC_KEY_PKCS8_DER);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM and/or VSCF_ROUND5 and/or VSCF_FALCON are disabled");
#endif
}

void
test__import_public_key__curve25519_round5_ed25519_falcon_and_then_export__are_equals(void) {
#if VSCF_POST_QUANTUM && VSCF_ROUND5 && VSCF_FALCON
    inner_test__import_public_key__then_export__are_equals(
            test_data_pqc_CURVE25519_ROUND5_ND_1CCA_5D_ED25519_FALCON_PUBLIC_KEY_PKCS8_DER);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM and/or VSCF_ROUND5 and/or VSCF_FALCON are disabled");
#endif
}

void
test__import_public_key__unsupported_old_pqc__error_error_bad_der_public_key(void) {
#if VSCF_POST_QUANTUM && VSCF_ROUND5 && VSCF_FALCON
    inner_test__import_public_key__expect_status(
            test_data_pqc_CURVE25519_ROUND5_ND_5KEM_5D_ED25519_FALCON_PUBLIC_KEY_PKCS8_DER,
            vscf_status_ERROR_BAD_DER_PUBLIC_KEY);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM and/or VSCF_ROUND5 and/or VSCF_FALCON are disabled");
#endif
}

//
//  Private keys.
//
void
test__import_private_key__curve25519_and_then_export__are_equals(void) {
    inner_test__import_private_key__then_export__are_equals(test_curve25519_PRIVATE_KEY_PKCS8_DER);
}

void
test__import_private_key__curve25519_and_then_export_public_key__are_equals(void) {
    inner_test__import_private_key__then_export_public_key__are_equals(
            test_curve25519_PRIVATE_KEY_PKCS8_DER, test_curve25519_PUBLIC_KEY_PKCS8_DER);
}

void
test__import_private_key__ed25519_and_then_export__are_equals(void) {
    inner_test__import_private_key__then_export__are_equals(test_ed25519_PRIVATE_KEY_PKCS8_DER);
}

void
test__import_private_key__secp256r1_and_then_export__are_equals(void) {
    inner_test__import_private_key__then_export__are_equals(test_secp256r1_PRIVATE_KEY_SEC1_DER);
}

void
test__import_private_key__rsa2048_and_then_export__are_equals(void) {
    inner_test__import_private_key__then_export__are_equals(test_rsa_2048_PRIVATE_KEY_PKCS8_DER);
}

void
test__import_private_key__round5_and_then_export__are_equals(void) {
#if VSCF_POST_QUANTUM && VSCF_ROUND5
    inner_test__import_private_key__then_export__are_equals(test_data_round5_ND_1CCA_5D_PRIVATE_KEY_PKCS8_DER);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM and/or VSCF_ROUND5 are disabled");
#endif
}

void
test__import_private_key__falcon_and_then_export__are_equals(void) {
#if VSCF_POST_QUANTUM && VSCF_FALCON
    inner_test__import_private_key__then_export__are_equals(test_data_falcon_PRIVATE_KEY_512_PKCS8_DER);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM and/or VSCF_FALCON are disabled");
#endif
}

void
test__import_private_key__curve25519_round5_falcon_and_then_export__are_equals(void) {
#if VSCF_POST_QUANTUM && VSCF_ROUND5 && VSCF_FALCON
    inner_test__import_private_key__then_export__are_equals(
            test_data_pqc_CURVE25519_ROUND5_ND_1CCA_5D_FALCON_PRIVATE_KEY_PKCS8_DER);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM and/or VSCF_ROUND5 and/or VSCF_FALCON are disabled");
#endif
}

void
test__import_private_key__curve25519_round5_ed25519_falcon_and_then_export__are_equals(void) {
#if VSCF_POST_QUANTUM && VSCF_ROUND5 && VSCF_FALCON
    inner_test__import_private_key__then_export__are_equals(
            test_data_pqc_CURVE25519_ROUND5_ND_1CCA_5D_ED25519_FALCON_PRIVATE_KEY_PKCS8_DER);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM and/or VSCF_ROUND5 and/or VSCF_FALCON are disabled");
#endif
}

void
test__import_private_key__curve25519_round5_ed25519_falcon_and_then_export_public_key__are_equals(void) {
#if VSCF_POST_QUANTUM && VSCF_ROUND5 && VSCF_FALCON
    inner_test__import_private_key__then_export_public_key__are_equals(
            test_data_pqc_CURVE25519_ROUND5_ND_1CCA_5D_ED25519_FALCON_PRIVATE_KEY_PKCS8_DER,
            test_data_pqc_CURVE25519_ROUND5_ND_1CCA_5D_ED25519_FALCON_PUBLIC_KEY_PKCS8_DER);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM and/or VSCF_ROUND5 and/or VSCF_FALCON are disabled");
#endif
}

void
test__import_private_key__unsupported_old_pqc__error_bad_pkcs8_private_key(void) {
#if VSCF_POST_QUANTUM && VSCF_ROUND5 && VSCF_FALCON
    inner_test__import_private_key__expect_status(
            test_data_pqc_CURVE25519_ROUND5_ND_5KEM_5D_ED25519_FALCON_PRIVATE_KEY_PKCS8_DER,
            vscf_status_ERROR_BAD_PKCS8_PRIVATE_KEY);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM and/or VSCF_ROUND5 and/or VSCF_FALCON are disabled");
#endif
}

// --------------------------------------------------------------------------
//  Import / Export invalid keys.
// --------------------------------------------------------------------------
void
test__import_public_key__invalid_public_key__expected_status_bad_der_public_key(void) {

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    const char str_message[] = "Lorem Ipsum is simply dummy text of the printing and typesetting industry.";

    vscf_impl_t *public_key = vscf_key_provider_import_public_key(
            key_provider, vsc_data_from_str(str_message, strlen(str_message)), &error);

    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_DER_PUBLIC_KEY, vscf_error_status(&error));

    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__import_private_key__invalid_private_key__expected_status_bad_der_private_key(void) {

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    const char str_message[] = "Lorem Ipsum is simply dummy text of the printing and typesetting industry.";

    vscf_impl_t *private_key = vscf_key_provider_import_private_key(
            key_provider, vsc_data_from_str(str_message, strlen(str_message)), &error);

    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_DER_PRIVATE_KEY, vscf_error_status(&error));

    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__import_private_key__invalid_private_key_valid_message_info_with_encrypted_data__expected_status_bad_pkcs8_private_key(
        void) {

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *private_key = vscf_key_provider_import_private_key(
            key_provider, test_key_provider_INVALID_KEY_VALID_MESSAGE_INFO_WITH_ENCRYPTED_DATA, &error);


    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_PKCS8_PRIVATE_KEY, vscf_error_status(&error));

    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__import_private_key__invalid_private_key_valid_message_info__expected_status_bad_pkcs8_private_key(void) {

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *private_key = vscf_key_provider_import_private_key(
            key_provider, test_key_provider_INVALID_KEY_VALID_MESSAGE_INFO, &error);


    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_PKCS8_PRIVATE_KEY, vscf_error_status(&error));

    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__import_public_key__invalid_public_key_valid_message_info_with_encrypted_data__expected_status_bad_der_public_key(
        void) {

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *public_key = vscf_key_provider_import_public_key(
            key_provider, test_key_provider_INVALID_KEY_VALID_MESSAGE_INFO_WITH_ENCRYPTED_DATA, &error);


    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_DER_PUBLIC_KEY, vscf_error_status(&error));

    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__import_public_key__invalid_public_key_valid_message_info__expected_status_bad_der_public_key(void) {

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    vscf_impl_t *public_key =
            vscf_key_provider_import_public_key(key_provider, test_key_provider_INVALID_KEY_VALID_MESSAGE_INFO, &error);


    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_DER_PUBLIC_KEY, vscf_error_status(&error));

    vscf_impl_destroy(&public_key);
    vscf_key_provider_destroy(&key_provider);
}

void
test__import_private_key__fuzzer_founded_NULL__expected_status_bad_pkcs8_private_key(void) {
    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_key_provider_setup_defaults(key_provider));

    const vsc_data_t test_data = vsc_data_empty();
    vscf_impl_t *private_key = vscf_key_provider_import_private_key(key_provider, test_data, &error);

    TEST_ASSERT_EQUAL(vscf_status_ERROR_BAD_DER_PRIVATE_KEY, vscf_error_status(&error));

    vscf_impl_destroy(&private_key);
    vscf_key_provider_destroy(&key_provider);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE

    RUN_TEST(test__generate_private_key__curve25519__success);
    RUN_TEST(test__generate_private_key__ed25519__success);
    RUN_TEST(test__generate_private_key__secp256r1__success);
    RUN_TEST(test__generate_private_key__rsa2048__success);
    RUN_TEST(test__generate_private_key__round5__success);
    RUN_TEST(test__generate_private_key__falcon__success);
    RUN_TEST(test__generate_post_quantum_key__with_default_rng__success);

    RUN_TEST(test__generate_private_key__curve25519_and_then_do_encrypt_decrypt__plain_text_match);
    RUN_TEST(test__generate_private_key__ed25519_and_then_do_encrypt_decrypt__plain_text_match);
    RUN_TEST(test__generate_private_key__secp256r1_and_then_do_encrypt_decrypt__plain_text_match);
    RUN_TEST(test__generate_private_key__rsa2048_and_then_do_encrypt_decrypt__plain_text_match);

    RUN_TEST(test__generate_private_key__ed25519_and_then_do_sign_verify__success);
    RUN_TEST(test__generate_private_key__secp256r1_and_then_do_sign_verify__success);
    RUN_TEST(test__generate_private_key__rsa2048_and_then_do_sign_verify__success);
    RUN_TEST(test__generate_private_key__falcon_and_then_do_sign_verify__success);

    RUN_TEST(test__generate_private_key__ed25519_with_key_material_rng__match);
    RUN_TEST(test__generate_private_key__rsa4096_with_key_material_rng__match);

    RUN_TEST(test__import_public_key__curve25519_and_then_export__are_equals);
    RUN_TEST(test__import_public_key__ed25519_and_then_export__are_equals);
    RUN_TEST(test__import_public_key__secp256r1_and_then_export__are_equals);
    RUN_TEST(test__import_public_key__rsa2048_and_then_export__are_equals);
    RUN_TEST(test__import_public_key__round5_and_then_export__are_equals);
    RUN_TEST(test__import_public_key__falcon_and_then_export__are_equals);
    RUN_TEST(test__import_public_key__curve25519_round5_falcon_and_then_export__are_equals);
    RUN_TEST(test__import_public_key__curve25519_round5_ed25519_falcon_and_then_export__are_equals);
    RUN_TEST(test__import_public_key__unsupported_old_pqc__error_error_bad_der_public_key);

    RUN_TEST(test__import_private_key__curve25519_and_then_export__are_equals);
    RUN_TEST(test__import_private_key__ed25519_and_then_export__are_equals);
    RUN_TEST(test__import_private_key__secp256r1_and_then_export__are_equals);
    RUN_TEST(test__import_private_key__rsa2048_and_then_export__are_equals);
    RUN_TEST(test__import_private_key__round5_and_then_export__are_equals);
    RUN_TEST(test__import_private_key__falcon_and_then_export__are_equals);
    RUN_TEST(test__import_private_key__curve25519_round5_falcon_and_then_export__are_equals);
    RUN_TEST(test__import_private_key__curve25519_round5_ed25519_falcon_and_then_export__are_equals);
    RUN_TEST(test__import_private_key__curve25519_round5_ed25519_falcon_and_then_export_public_key__are_equals);
    RUN_TEST(test__import_private_key__unsupported_old_pqc__error_bad_pkcs8_private_key);

    RUN_TEST(test__import_public_key__invalid_public_key__expected_status_bad_der_public_key);
    RUN_TEST(test__import_private_key__invalid_private_key__expected_status_bad_der_private_key);

    RUN_TEST(
            test__import_private_key__invalid_private_key_valid_message_info_with_encrypted_data__expected_status_bad_pkcs8_private_key);
    RUN_TEST(test__import_private_key__invalid_private_key_valid_message_info__expected_status_bad_pkcs8_private_key);
    RUN_TEST(
            test__import_public_key__invalid_public_key_valid_message_info_with_encrypted_data__expected_status_bad_der_public_key);
    RUN_TEST(test__import_public_key__invalid_public_key_valid_message_info__expected_status_bad_der_public_key);
    RUN_TEST(test__import_private_key__fuzzer_founded_NULL__expected_status_bad_pkcs8_private_key);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
