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

#define TEST_DEPENDENCIES_AVAILABLE VSCR_RATCHET
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscr_ratchet_message_defs.h"
#include "vscr_ratchet_session.h"
#include "vscf_private_key.h"
#include "vscf_key_provider.h"
#include "test_utils_ratchet.h"

// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------
void
test__initialize__fixed_values__should_not_fail(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    for (unsigned char i = 0; i < 4; i++) {
        bool enable_one_time = i % 2 == 0;
        bool enable_pqc = (i >> 1u) % 2 == 0;
        bool should_restore = (i >> 2u) % 2 == 0;

        vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
        vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();

        initialize(rng, &session_alice, &session_bob, enable_one_time, enable_pqc, should_restore);

        vscr_ratchet_session_destroy(&session_alice);
        vscr_ratchet_session_destroy(&session_bob);
    }

    vscf_ctr_drbg_destroy(&rng);
}

void
test__encrypt_decrypt_back_and_forth__fixed_plain_text__decrypted_should_match(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    for (unsigned char i = 0; i < 4; i++) {
        bool enable_one_time = i % 2 == 0;
        bool enable_pqc = (i >> 1u) % 2 == 0;
        bool should_restore = (i >> 2u) % 2 == 0;

        vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
        vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();

        initialize(rng, &session_alice, &session_bob, enable_one_time, enable_pqc, should_restore);

        vscr_error_t error;
        vscr_error_reset(&error);

        vsc_buffer_t *text1 = NULL, *text2 = NULL;

        generate_random_data(rng, &text1);
        generate_random_data(rng, &text2);

        vscr_ratchet_message_t *ratchet_message1 =
                vscr_ratchet_session_encrypt(session_alice, vsc_buffer_data(text1), &error);
        TEST_ASSERT_FALSE(vscr_error_has_error(&error));
        TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(ratchet_message1));

        size_t len1 = vscr_ratchet_session_decrypt_len(session_bob, ratchet_message1);
        vsc_buffer_t *plain_text1 = vsc_buffer_new_with_capacity(len1);

        vscr_status_t result = vscr_ratchet_session_decrypt(session_bob, ratchet_message1, plain_text1);
        TEST_ASSERT_EQUAL(vscr_status_SUCCESS, result);

        TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text1), plain_text1);

        vscr_ratchet_message_t *ratchet_message2 =
                vscr_ratchet_session_encrypt(session_bob, vsc_buffer_data(text2), &error);
        TEST_ASSERT_FALSE(vscr_error_has_error(&error));
        TEST_ASSERT_EQUAL(vscr_msg_type_REGULAR, vscr_ratchet_message_get_type(ratchet_message2));

        size_t len2 = vscr_ratchet_session_decrypt_len(session_alice, ratchet_message2);
        vsc_buffer_t *plain_text2 = vsc_buffer_new_with_capacity(len2);

        result = vscr_ratchet_session_decrypt(session_alice, ratchet_message2, plain_text2);
        TEST_ASSERT_EQUAL(vscr_status_SUCCESS, result);

        TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text2), plain_text2);

        vsc_buffer_destroy(&text1);
        vsc_buffer_destroy(&text2);
        vsc_buffer_destroy(&plain_text1);
        vsc_buffer_destroy(&plain_text2);
        vscr_ratchet_session_destroy(&session_alice);
        vscr_ratchet_session_destroy(&session_bob);
        vscr_ratchet_message_destroy(&ratchet_message1);
        vscr_ratchet_message_destroy(&ratchet_message2);
    }

    vscf_ctr_drbg_destroy(&rng);
}

void
test__encrypt_decrypt__100_plain_texts_random_order__decrypted_should_match(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    for (unsigned char i = 0; i < 4; i++) {
        bool enable_one_time = i % 2 == 0;
        bool enable_pqc = (i >> 1u) % 2 == 0;
        bool should_restore = (i >> 2u) % 2 == 0;

        vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
        vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();

        initialize(rng, &session_alice, &session_bob, enable_one_time, enable_pqc, should_restore);

        encrypt_decrypt__100_plain_texts_random_order(rng, session_alice, session_bob);

        vscr_ratchet_session_destroy(&session_alice);
        vscr_ratchet_session_destroy(&session_bob);
    }

    vscf_ctr_drbg_destroy(&rng);
}

void
test__encrypt_decrypt__1_out_of_order_msg__decrypted_should_match(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    for (unsigned char i = 0; i < 4; i++) {
        bool enable_one_time = i % 2 == 0;
        bool enable_pqc = (i >> 1u) % 2 == 0;
        bool should_restore = (i >> 2u) % 2 == 0;

        vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
        vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();

        initialize(rng, &session_alice, &session_bob, enable_one_time, enable_pqc, should_restore);

        vscr_error_t error;
        vscr_error_reset(&error);

        vsc_buffer_t *text1 = NULL, *text2 = NULL;

        generate_random_data(rng, &text1);
        generate_random_data(rng, &text2);

        vscr_ratchet_message_t *ratchet_message1 =
                vscr_ratchet_session_encrypt(session_alice, vsc_buffer_data(text1), &error);
        TEST_ASSERT_FALSE(vscr_error_has_error(&error));
        TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(ratchet_message1));

        vscr_ratchet_message_t *ratchet_message2 =
                vscr_ratchet_session_encrypt(session_alice, vsc_buffer_data(text2), &error);
        TEST_ASSERT_FALSE(vscr_error_has_error(&error));
        TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(ratchet_message2));

        size_t len2 = vscr_ratchet_session_decrypt_len(session_bob, ratchet_message2);
        vsc_buffer_t *plain_text2 = vsc_buffer_new_with_capacity(len2);

        vscr_status_t result = vscr_ratchet_session_decrypt(session_bob, ratchet_message2, plain_text2);
        TEST_ASSERT_EQUAL(vscr_status_SUCCESS, result);

        TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text2), plain_text2);

        size_t len1 = vscr_ratchet_session_decrypt_len(session_bob, ratchet_message1);
        vsc_buffer_t *plain_text1 = vsc_buffer_new_with_capacity(len1);

        result = vscr_ratchet_session_decrypt(session_bob, ratchet_message1, plain_text1);
        TEST_ASSERT_EQUAL(vscr_status_SUCCESS, result);

        TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text1), plain_text1);

        vsc_buffer_destroy(&text1);
        vsc_buffer_destroy(&text2);
        vsc_buffer_destroy(&plain_text1);
        vsc_buffer_destroy(&plain_text2);
        vscr_ratchet_session_destroy(&session_alice);
        vscr_ratchet_session_destroy(&session_bob);
        vscr_ratchet_message_destroy(&ratchet_message1);
        vscr_ratchet_message_destroy(&ratchet_message2);
    }

    vscf_ctr_drbg_destroy(&rng);
}

void
test__encrypt_decrypt__randomly_skipped_messages__decrypt_should_succeed(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    for (unsigned char i = 0; i < 4; i++) {
        bool enable_one_time = i % 2 == 0;
        bool enable_pqc = (i >> 1u) % 2 == 0;
        bool should_restore = (i >> 2u) % 2 == 0;

        vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
        vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();

        initialize(rng, &session_alice, &session_bob, enable_one_time, enable_pqc, should_restore);

        encrypt_decrypt__100_plain_texts_random_order_with_producers(rng, &session_alice, &session_bob, should_restore);

        vscr_ratchet_session_destroy(&session_alice);
        vscr_ratchet_session_destroy(&session_bob);
    }

    vscf_ctr_drbg_destroy(&rng);
}

void
test__pqc_ml_dsa_65__encrypt_decrypt_with_restore__should_succeed(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, vscf_ctr_drbg_impl(rng));

    vscf_impl_t *alice_priv = generate_identity_private_key_ml_dsa(key_provider);
    vscf_impl_t *alice_pub = vscf_private_key_extract_public_key(alice_priv);
    vscf_impl_t *bob_priv = generate_identity_private_key_ml_dsa(key_provider);
    vscf_impl_t *bob_pub = vscf_private_key_extract_public_key(bob_priv);
    vscf_impl_t *bob_lt_priv = generate_ephemeral_private_key(key_provider, true);
    vscf_impl_t *bob_lt_pub = vscf_private_key_extract_public_key(bob_lt_priv);

    vsc_buffer_t *alice_id = NULL, *bob_id = NULL, *bob_lt_id = NULL;
    generate_random_data_of_size(rng, &alice_id, 8);
    generate_random_data_of_size(rng, &bob_id, 8);
    generate_random_data_of_size(rng, &bob_lt_id, 8);
    vsc_buffer_t *no_ot_id = vsc_buffer_new_with_capacity(0);

    vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
    vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_setup_defaults(session_alice));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_setup_defaults(session_bob));

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
            vscr_ratchet_session_initiate(session_alice, alice_priv, vsc_buffer_data(alice_id), bob_pub,
                    vsc_buffer_data(bob_id), bob_lt_pub, vsc_buffer_data(bob_lt_id), NULL, vsc_buffer_data(no_ot_id)));

    vscr_error_t error;
    vscr_error_reset(&error);
    vsc_buffer_t *text1 = NULL;
    generate_random_data(rng, &text1);

    vscr_ratchet_message_t *msg1 = vscr_ratchet_session_encrypt(session_alice, vsc_buffer_data(text1), &error);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));
    TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(msg1));

    // Serialize Alice after encrypt — exercises serialize_public_key on imported ML-KEM key
    restore_session(rng, &session_alice);

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
            vscr_ratchet_session_respond(session_bob, alice_pub, bob_priv, bob_lt_priv, NULL, msg1));

    restore_session(rng, &session_bob);

    size_t len1 = vscr_ratchet_session_decrypt_len(session_bob, msg1);
    vsc_buffer_t *plain1 = vsc_buffer_new_with_capacity(len1);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_decrypt(session_bob, msg1, plain1));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text1), plain1);

    restore_session(rng, &session_alice);
    restore_session(rng, &session_bob);

    // Bob replies, Alice decrypts through another restore cycle
    vsc_buffer_t *text2 = NULL;
    generate_random_data(rng, &text2);
    vscr_ratchet_message_t *msg2 = vscr_ratchet_session_encrypt(session_bob, vsc_buffer_data(text2), &error);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));
    TEST_ASSERT_EQUAL(vscr_msg_type_REGULAR, vscr_ratchet_message_get_type(msg2));

    restore_session(rng, &session_alice);

    size_t len2 = vscr_ratchet_session_decrypt_len(session_alice, msg2);
    vsc_buffer_t *plain2 = vsc_buffer_new_with_capacity(len2);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_decrypt(session_alice, msg2, plain2));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text2), plain2);

    vscr_ratchet_message_destroy(&msg1);
    vscr_ratchet_message_destroy(&msg2);
    vsc_buffer_destroy(&text1);
    vsc_buffer_destroy(&text2);
    vsc_buffer_destroy(&plain1);
    vsc_buffer_destroy(&plain2);
    vscf_impl_destroy(&alice_priv);
    vscf_impl_destroy(&alice_pub);
    vscf_impl_destroy(&bob_priv);
    vscf_impl_destroy(&bob_pub);
    vscf_impl_destroy(&bob_lt_priv);
    vscf_impl_destroy(&bob_lt_pub);
    vsc_buffer_destroy(&alice_id);
    vsc_buffer_destroy(&bob_id);
    vsc_buffer_destroy(&bob_lt_id);
    vsc_buffer_destroy(&no_ot_id);
    vscr_ratchet_session_destroy(&session_alice);
    vscr_ratchet_session_destroy(&session_bob);
    vscf_key_provider_destroy(&key_provider);
    vscf_ctr_drbg_destroy(&rng);
}

void
test__pqc_ml_dsa_65__100_messages_with_restore__should_succeed(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, vscf_ctr_drbg_impl(rng));

    vscf_impl_t *alice_priv = generate_identity_private_key_ml_dsa(key_provider);
    vscf_impl_t *alice_pub = vscf_private_key_extract_public_key(alice_priv);
    vscf_impl_t *bob_priv = generate_identity_private_key_ml_dsa(key_provider);
    vscf_impl_t *bob_pub = vscf_private_key_extract_public_key(bob_priv);
    vscf_impl_t *bob_lt_priv = generate_ephemeral_private_key(key_provider, true);
    vscf_impl_t *bob_lt_pub = vscf_private_key_extract_public_key(bob_lt_priv);

    vsc_buffer_t *alice_id = NULL, *bob_id = NULL, *bob_lt_id = NULL;
    generate_random_data_of_size(rng, &alice_id, 8);
    generate_random_data_of_size(rng, &bob_id, 8);
    generate_random_data_of_size(rng, &bob_lt_id, 8);
    vsc_buffer_t *no_ot_id = vsc_buffer_new_with_capacity(0);

    vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
    vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_setup_defaults(session_alice));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_setup_defaults(session_bob));

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
            vscr_ratchet_session_initiate(session_alice, alice_priv, vsc_buffer_data(alice_id), bob_pub,
                    vsc_buffer_data(bob_id), bob_lt_pub, vsc_buffer_data(bob_lt_id), NULL, vsc_buffer_data(no_ot_id)));

    vscr_error_t error;
    vscr_error_reset(&error);
    vsc_buffer_t *init_text = NULL;
    generate_random_data(rng, &init_text);

    vscr_ratchet_message_t *init_msg = vscr_ratchet_session_encrypt(session_alice, vsc_buffer_data(init_text), &error);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
            vscr_ratchet_session_respond(session_bob, alice_pub, bob_priv, bob_lt_priv, NULL, init_msg));

    size_t init_len = vscr_ratchet_session_decrypt_len(session_bob, init_msg);
    vsc_buffer_t *init_plain = vsc_buffer_new_with_capacity(init_len);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_decrypt(session_bob, init_msg, init_plain));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(init_text), init_plain);

    vscr_ratchet_message_destroy(&init_msg);
    vsc_buffer_destroy(&init_text);
    vsc_buffer_destroy(&init_plain);

    encrypt_decrypt__100_plain_texts_random_order_with_producers(rng, &session_alice, &session_bob, true);

    vscf_impl_destroy(&alice_priv);
    vscf_impl_destroy(&alice_pub);
    vscf_impl_destroy(&bob_priv);
    vscf_impl_destroy(&bob_pub);
    vscf_impl_destroy(&bob_lt_priv);
    vscf_impl_destroy(&bob_lt_pub);
    vsc_buffer_destroy(&alice_id);
    vsc_buffer_destroy(&bob_id);
    vsc_buffer_destroy(&bob_lt_id);
    vsc_buffer_destroy(&no_ot_id);
    vscr_ratchet_session_destroy(&session_alice);
    vscr_ratchet_session_destroy(&session_bob);
    vscf_key_provider_destroy(&key_provider);
    vscf_ctr_drbg_destroy(&rng);
}

void
test__curve25519_ed25519_identity_key__non_pqc_lt_key__should_not_crash(void) {
    // Regression: curve25519Ed25519 compound identity keys (cipher=curve25519, signer=ed25519)
    // were crashing with VSCR_ASSERT in compute_initiator/responder_pqc_shared_secret because
    // the Ed25519 signer component was extracted and passed as second_signer even when no KEM
    // encapsulation occurred (non-PQC long-term key → enable_post_quantum=false).
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, vscf_ctr_drbg_impl(rng));

    vscf_impl_t *alice_priv = generate_identity_private_key_curve25519_ed25519(key_provider);
    vscf_impl_t *alice_pub = vscf_private_key_extract_public_key(alice_priv);
    vscf_impl_t *bob_priv = generate_identity_private_key_curve25519_ed25519(key_provider);
    vscf_impl_t *bob_pub = vscf_private_key_extract_public_key(bob_priv);
    vscf_impl_t *bob_lt_priv = generate_ephemeral_private_key(key_provider, false);
    vscf_impl_t *bob_lt_pub = vscf_private_key_extract_public_key(bob_lt_priv);

    vsc_buffer_t *alice_id = NULL, *bob_id = NULL, *bob_lt_id = NULL;
    generate_random_data_of_size(rng, &alice_id, 8);
    generate_random_data_of_size(rng, &bob_id, 8);
    generate_random_data_of_size(rng, &bob_lt_id, 8);
    vsc_buffer_t *no_ot_id = vsc_buffer_new_with_capacity(0);

    vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
    vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_setup_defaults(session_alice));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_setup_defaults(session_bob));

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
            vscr_ratchet_session_initiate(session_alice, alice_priv, vsc_buffer_data(alice_id), bob_pub,
                    vsc_buffer_data(bob_id), bob_lt_pub, vsc_buffer_data(bob_lt_id), NULL, vsc_buffer_data(no_ot_id)));

    vscr_error_t error;
    vscr_error_reset(&error);
    vsc_buffer_t *text1 = NULL;
    generate_random_data(rng, &text1);

    vscr_ratchet_message_t *msg1 = vscr_ratchet_session_encrypt(session_alice, vsc_buffer_data(text1), &error);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));
    TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(msg1));

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
            vscr_ratchet_session_respond(session_bob, alice_pub, bob_priv, bob_lt_priv, NULL, msg1));

    size_t len1 = vscr_ratchet_session_decrypt_len(session_bob, msg1);
    vsc_buffer_t *plain1 = vsc_buffer_new_with_capacity(len1);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_decrypt(session_bob, msg1, plain1));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text1), plain1);

    vsc_buffer_t *text2 = NULL;
    generate_random_data(rng, &text2);
    vscr_ratchet_message_t *msg2 = vscr_ratchet_session_encrypt(session_bob, vsc_buffer_data(text2), &error);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    size_t len2 = vscr_ratchet_session_decrypt_len(session_alice, msg2);
    vsc_buffer_t *plain2 = vsc_buffer_new_with_capacity(len2);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_decrypt(session_alice, msg2, plain2));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text2), plain2);

    vscr_ratchet_message_destroy(&msg1);
    vscr_ratchet_message_destroy(&msg2);
    vsc_buffer_destroy(&text1);
    vsc_buffer_destroy(&text2);
    vsc_buffer_destroy(&plain1);
    vsc_buffer_destroy(&plain2);
    vscf_impl_destroy(&alice_priv);
    vscf_impl_destroy(&alice_pub);
    vscf_impl_destroy(&bob_priv);
    vscf_impl_destroy(&bob_pub);
    vscf_impl_destroy(&bob_lt_priv);
    vscf_impl_destroy(&bob_lt_pub);
    vsc_buffer_destroy(&alice_id);
    vsc_buffer_destroy(&bob_id);
    vsc_buffer_destroy(&bob_lt_id);
    vsc_buffer_destroy(&no_ot_id);
    vscr_ratchet_session_destroy(&session_alice);
    vscr_ratchet_session_destroy(&session_bob);
    vscf_key_provider_destroy(&key_provider);
    vscf_ctr_drbg_destroy(&rng);
}

static void
test__non_pqc_identity_key__mlkem_lt_and_otk__should_not_crash(void) {
    // Regression: when the receiver has ML-KEM hybrid long-term/OTK keys but a non-PQC identity
    // key, enable_post_quantum=true but encapsulated_key_1 and decapsulated_keys_signature are
    // NULL. The encrypt and serialize paths were crashing at VSCR_ASSERT_PTR(buffer) because they
    // unconditionally called serialize_buffer for all PQC fields.
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, vscf_ctr_drbg_impl(rng));

    vscf_error_t error_ctx;
    vscf_error_reset(&error_ctx);

    // Both identity keys are plain ED25519 (no PQC component).
    vscf_impl_t *alice_priv = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ED25519, &error_ctx);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, error_ctx.status);
    vscf_impl_t *alice_pub = vscf_private_key_extract_public_key(alice_priv);

    vscf_impl_t *bob_priv = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ED25519, &error_ctx);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, error_ctx.status);
    vscf_impl_t *bob_pub = vscf_private_key_extract_public_key(bob_priv);

    // Bob's long-term and OTK are ML-KEM hybrid → enable_post_quantum=true.
    vscf_impl_t *bob_lt_priv = generate_ephemeral_private_key(key_provider, true);
    vscf_impl_t *bob_lt_pub = vscf_private_key_extract_public_key(bob_lt_priv);
    vscf_impl_t *bob_ot_priv = generate_ephemeral_private_key(key_provider, true);
    vscf_impl_t *bob_ot_pub = vscf_private_key_extract_public_key(bob_ot_priv);

    vsc_buffer_t *alice_id = NULL, *bob_id = NULL, *bob_lt_id = NULL, *bob_ot_id = NULL;
    generate_random_data_of_size(rng, &alice_id, 8);
    generate_random_data_of_size(rng, &bob_id, 8);
    generate_random_data_of_size(rng, &bob_lt_id, 8);
    generate_random_data_of_size(rng, &bob_ot_id, 8);

    vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
    vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_setup_defaults(session_alice));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_setup_defaults(session_bob));

    TEST_ASSERT_EQUAL(
            vscr_status_SUCCESS, vscr_ratchet_session_initiate(session_alice, alice_priv, vsc_buffer_data(alice_id),
                                         bob_pub, vsc_buffer_data(bob_id), bob_lt_pub, vsc_buffer_data(bob_lt_id),
                                         bob_ot_pub, vsc_buffer_data(bob_ot_id)));

    vscr_error_t error;
    vscr_error_reset(&error);
    vsc_buffer_t *text1 = NULL;
    generate_random_data(rng, &text1);

    // This used to crash at vscr_ratchet_pb_utils.c:267 VSCR_ASSERT_PTR(buffer).
    vscr_ratchet_message_t *msg1 = vscr_ratchet_session_encrypt(session_alice, vsc_buffer_data(text1), &error);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));
    TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(msg1));

    // Serialize and restore Alice's session (also crashed before the fix).
    vsc_buffer_t *alice_serialized = vscr_ratchet_session_serialize(session_alice);
    vscr_ratchet_session_destroy(&session_alice);
    vscr_error_reset(&error);
    session_alice = vscr_ratchet_session_deserialize(vsc_buffer_data(alice_serialized), &error);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));
    vscr_ratchet_session_use_rng(session_alice, vscf_ctr_drbg_impl(rng));

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
            vscr_ratchet_session_respond(session_bob, alice_pub, bob_priv, bob_lt_priv, bob_ot_priv, msg1));

    size_t len1 = vscr_ratchet_session_decrypt_len(session_bob, msg1);
    vsc_buffer_t *plain1 = vsc_buffer_new_with_capacity(len1);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_decrypt(session_bob, msg1, plain1));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text1), plain1);

    vsc_buffer_t *text2 = NULL;
    generate_random_data(rng, &text2);
    vscr_error_reset(&error);
    vscr_ratchet_message_t *msg2 = vscr_ratchet_session_encrypt(session_bob, vsc_buffer_data(text2), &error);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    size_t len2 = vscr_ratchet_session_decrypt_len(session_alice, msg2);
    vsc_buffer_t *plain2 = vsc_buffer_new_with_capacity(len2);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_decrypt(session_alice, msg2, plain2));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text2), plain2);

    vscr_ratchet_message_destroy(&msg1);
    vscr_ratchet_message_destroy(&msg2);
    vsc_buffer_destroy(&text1);
    vsc_buffer_destroy(&text2);
    vsc_buffer_destroy(&plain1);
    vsc_buffer_destroy(&plain2);
    vsc_buffer_destroy(&alice_serialized);
    vscf_impl_destroy(&alice_priv);
    vscf_impl_destroy(&alice_pub);
    vscf_impl_destroy(&bob_priv);
    vscf_impl_destroy(&bob_pub);
    vscf_impl_destroy(&bob_lt_priv);
    vscf_impl_destroy(&bob_lt_pub);
    vscf_impl_destroy(&bob_ot_priv);
    vscf_impl_destroy(&bob_ot_pub);
    vsc_buffer_destroy(&alice_id);
    vsc_buffer_destroy(&bob_id);
    vsc_buffer_destroy(&bob_lt_id);
    vsc_buffer_destroy(&bob_ot_id);
    vscr_ratchet_session_destroy(&session_alice);
    vscr_ratchet_session_destroy(&session_bob);
    vscf_key_provider_destroy(&key_provider);
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
    RUN_TEST(test__initialize__fixed_values__should_not_fail);
    RUN_TEST(test__encrypt_decrypt_back_and_forth__fixed_plain_text__decrypted_should_match);
    RUN_TEST(test__encrypt_decrypt__100_plain_texts_random_order__decrypted_should_match);
    RUN_TEST(test__encrypt_decrypt__1_out_of_order_msg__decrypted_should_match);
    RUN_TEST(test__encrypt_decrypt__randomly_skipped_messages__decrypt_should_succeed);
    RUN_TEST(test__pqc_ml_dsa_65__encrypt_decrypt_with_restore__should_succeed);
    RUN_TEST(test__pqc_ml_dsa_65__100_messages_with_restore__should_succeed);
    RUN_TEST(test__curve25519_ed25519_identity_key__non_pqc_lt_key__should_not_crash);
    RUN_TEST(test__non_pqc_identity_key__mlkem_lt_and_otk__should_not_crash);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
