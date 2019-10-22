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


#define TEST_DEPENDENCIES_AVAILABLE (VSCF_COMPOUND_KEY_ALG && VSCF_FAKE_RANDOM)
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_compound_key_alg.h"
#include "vscf_compound_public_key.h"
#include "vscf_compound_private_key.h"
#include "vscf_key.h"
#include "vscf_private_key.h"
#include "vscf_fake_random.h"

#include "test_data_compound_key.h"

// --------------------------------------------------------------------------
//  Generate key
// --------------------------------------------------------------------------
void
test__generate_key__curve25519_and_ed25519_with_fake_rng__success(void) {

    //
    //  Create dependencies first
    //
    vscf_fake_random_t *fake_random = vscf_fake_random_new();
    vscf_fake_random_setup_source_byte(fake_random, 0xAB);

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Generate key
    //
    vscf_compound_key_alg_t *key_alg = vscf_compound_key_alg_new();
    vscf_compound_key_alg_take_random(key_alg, vscf_fake_random_impl(fake_random));

    vscf_impl_t *private_key =
            vscf_compound_key_alg_generate_key(key_alg, vscf_alg_id_CURVE25519, vscf_alg_id_ED25519, &error);
    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    //
    //  Check private keys
    //
    TEST_ASSERT_EQUAL(vscf_impl_tag_COMPOUND_PRIVATE_KEY, vscf_impl_tag(private_key));
    vscf_compound_private_key_t *compound_private_key = (vscf_compound_private_key_t *)private_key;

    const vscf_impl_t *decryption_key = vscf_compound_private_key_get_decryption_key(compound_private_key);
    TEST_ASSERT_NOT_NULL(decryption_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_CURVE25519, vscf_key_alg_id(decryption_key));

    const vscf_impl_t *signing_key = vscf_compound_private_key_get_signing_key(compound_private_key);
    TEST_ASSERT_NOT_NULL(signing_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_ED25519, vscf_key_alg_id(signing_key));

    //
    //  Check public keys
    //
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_EQUAL(vscf_impl_tag_COMPOUND_PUBLIC_KEY, vscf_impl_tag(public_key));
    vscf_compound_public_key_t *compound_public_key = (vscf_compound_public_key_t *)public_key;

    const vscf_impl_t *encryption_key = vscf_compound_public_key_get_encryption_key(compound_public_key);
    TEST_ASSERT_NOT_NULL(encryption_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_CURVE25519, vscf_key_alg_id(encryption_key));

    const vscf_impl_t *verifying_key = vscf_compound_public_key_get_verifying_key(compound_public_key);
    TEST_ASSERT_NOT_NULL(verifying_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_ED25519, vscf_key_alg_id(verifying_key));

    //
    //  Cleanup
    //
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_compound_key_alg_destroy(&key_alg);
}

void
test__generate_post_quantum_key__with_default_rng__success(void) {
#if VSCF_POST_QUANTUM
    //
    //  Create dependencies first
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Generate key
    //
    vscf_compound_key_alg_t *key_alg = vscf_compound_key_alg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_compound_key_alg_setup_defaults(key_alg));

    vscf_impl_t *private_key = vscf_compound_key_alg_generate_post_quantum_key(key_alg, &error);
    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    //
    //  Check private keys
    //
    TEST_ASSERT_EQUAL(vscf_impl_tag_COMPOUND_PRIVATE_KEY, vscf_impl_tag(private_key));
    vscf_compound_private_key_t *compound_private_key = (vscf_compound_private_key_t *)private_key;

    const vscf_impl_t *decryption_key = vscf_compound_private_key_get_decryption_key(compound_private_key);
    TEST_ASSERT_NOT_NULL(decryption_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_ROUND5, vscf_key_alg_id(decryption_key));

    const vscf_impl_t *signing_key = vscf_compound_private_key_get_signing_key(compound_private_key);
    TEST_ASSERT_NOT_NULL(signing_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_FALCON, vscf_key_alg_id(signing_key));

    //
    //  Check public keys
    //
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);
    TEST_ASSERT_EQUAL(vscf_impl_tag_COMPOUND_PUBLIC_KEY, vscf_impl_tag(public_key));
    vscf_compound_public_key_t *compound_public_key = (vscf_compound_public_key_t *)public_key;

    const vscf_impl_t *encryption_key = vscf_compound_public_key_get_encryption_key(compound_public_key);
    TEST_ASSERT_NOT_NULL(encryption_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_ROUND5, vscf_key_alg_id(encryption_key));

    const vscf_impl_t *verifying_key = vscf_compound_public_key_get_verifying_key(compound_public_key);
    TEST_ASSERT_NOT_NULL(verifying_key);
    TEST_ASSERT_EQUAL(vscf_alg_id_FALCON, vscf_key_alg_id(verifying_key));

    //
    //  Cleanup
    //
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_compound_key_alg_destroy(&key_alg);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM is disabled");
#endif
}

// --------------------------------------------------------------------------
//  Encrypt / Decrypt
// --------------------------------------------------------------------------
static void
inner_test__encrypt_decrypt__with_random_keys__message_match(vscf_alg_id_t cipher_alg_id, vscf_alg_id_t signer_alg_id) {
    //
    //  Create dependencies first
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Prepare keys
    //
    vscf_compound_key_alg_t *key_alg = vscf_compound_key_alg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_compound_key_alg_setup_defaults(key_alg));

    vscf_impl_t *private_key = vscf_compound_key_alg_generate_key(key_alg, cipher_alg_id, signer_alg_id, &error);
    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    //
    //  Encrypt
    //
    const size_t enc_buf_len =
            vscf_compound_key_alg_encrypted_len(key_alg, public_key, test_data_compound_key_MESSAGE.len);
    vsc_buffer_t *enc = vsc_buffer_new_with_capacity(enc_buf_len);
    const vscf_status_t enc_status =
            vscf_compound_key_alg_encrypt(key_alg, public_key, test_data_compound_key_MESSAGE, enc);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, enc_status);

    //
    //  Decrypt
    //
    const size_t dec_buf_len = vscf_compound_key_alg_decrypted_len(key_alg, private_key, vsc_buffer_len(enc));
    vsc_buffer_t *dec = vsc_buffer_new_with_capacity(dec_buf_len);
    const vscf_status_t dec_status = vscf_compound_key_alg_decrypt(key_alg, private_key, vsc_buffer_data(enc), dec);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, dec_status);

    //
    //  Compare message
    //
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_compound_key_MESSAGE, dec);

    //
    //  Cleanup
    //
    vsc_buffer_destroy(&dec);
    vsc_buffer_destroy(&enc);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_compound_key_alg_destroy(&key_alg);
}

void
test__encrypt_decrypt__with_random_curve25519_and_ed25519_keys__message_match(void) {
    inner_test__encrypt_decrypt__with_random_keys__message_match(vscf_alg_id_CURVE25519, vscf_alg_id_ED25519);
}

void
test__encrypt_decrypt__with_random_round5_and_falcon_keys__message_match(void) {
#if VSCF_POST_QUANTUM
    inner_test__encrypt_decrypt__with_random_keys__message_match(vscf_alg_id_ROUND5, vscf_alg_id_FALCON);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM is disabled");
#endif
}

// --------------------------------------------------------------------------
//  Sign / Verify
// --------------------------------------------------------------------------
static void
inner_test__sign_verify__with_random_keys__success(vscf_alg_id_t cipher_alg_id, vscf_alg_id_t signer_alg_id) {
    //
    //  Create dependencies first
    //
    vscf_error_t error;
    vscf_error_reset(&error);

    //
    //  Prepare keys
    //
    vscf_compound_key_alg_t *key_alg = vscf_compound_key_alg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_compound_key_alg_setup_defaults(key_alg));

    vscf_impl_t *private_key = vscf_compound_key_alg_generate_key(key_alg, cipher_alg_id, signer_alg_id, &error);
    TEST_ASSERT_FALSE(vscf_error_has_error(&error));
    TEST_ASSERT_NOT_NULL(private_key);

    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    //
    //  Sign
    //
    TEST_ASSERT_TRUE(vscf_compound_key_alg_can_sign(key_alg, private_key));
    const size_t signature_buf_len = vscf_compound_key_alg_signature_len(key_alg, private_key);
    vsc_buffer_t *signatrure = vsc_buffer_new_with_capacity(signature_buf_len);
    const vscf_status_t sign_status = vscf_compound_key_alg_sign_hash(
            key_alg, private_key, vscf_alg_id_SHA512, test_data_compound_key_MESSAGE_TBS_SHA512_DIGEST, signatrure);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, sign_status);

    //
    //  Verify
    //
    TEST_ASSERT_TRUE(vscf_compound_key_alg_can_verify(key_alg, public_key));
    const bool verified = vscf_compound_key_alg_verify_hash(key_alg, public_key, vscf_alg_id_SHA512,
            test_data_compound_key_MESSAGE_TBS_SHA512_DIGEST, vsc_buffer_data(signatrure));
    TEST_ASSERT_TRUE(verified);

    //
    //  Cleanup
    //
    vsc_buffer_destroy(&signatrure);
    vscf_impl_destroy(&public_key);
    vscf_impl_destroy(&private_key);
    vscf_compound_key_alg_destroy(&key_alg);
}

void
test__sign_verify__with_random_curve25519_and_ed25519_keys__success(void) {
    inner_test__sign_verify__with_random_keys__success(vscf_alg_id_CURVE25519, vscf_alg_id_ED25519);
}

void
test__sign_verify__with_random_round5_and_falcon_keys__success(void) {
#if VSCF_POST_QUANTUM
    inner_test__sign_verify__with_random_keys__success(vscf_alg_id_ROUND5, vscf_alg_id_FALCON);
#else
    TEST_IGNORE_MESSAGE("Feature VSCF_POST_QUANTUM is disabled");
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
    RUN_TEST(test__generate_key__curve25519_and_ed25519_with_fake_rng__success);
    RUN_TEST(test__generate_post_quantum_key__with_default_rng__success);
    RUN_TEST(test__encrypt_decrypt__with_random_curve25519_and_ed25519_keys__message_match);
    RUN_TEST(test__encrypt_decrypt__with_random_round5_and_falcon_keys__message_match);
    RUN_TEST(test__sign_verify__with_random_curve25519_and_ed25519_keys__success);
    RUN_TEST(test__sign_verify__with_random_round5_and_falcon_keys__success);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
