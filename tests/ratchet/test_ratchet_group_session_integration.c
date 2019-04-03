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

#include <virgil/crypto/ratchet/vscr_memory.h>
#include <ed25519/ed25519.h>
#include <virgil/crypto/ratchet/private/vscr_ratchet_group_message_defs.h>
#include <virgil/crypto/ratchet/vscr_ratchet_key_utils.h>
#include <virgil/crypto/foundation/vscf_raw_key.h>
#include <vscf_pkcs8_der_deserializer_internal.h>
#include "unity.h"
#include "test_utils.h"

// --------------------------------------------------------------------------
//  Should have it to prevent linkage errors in MSVC.
// --------------------------------------------------------------------------
// clang-format off
void setUp(void) { }
void tearDown(void) { }
void suiteSetUp(void) { }
int suiteTearDown(int num_failures) { return num_failures; }
// clang-format on

#define TEST_DEPENDENCIES_AVAILABLE VSCR_RATCHET_GROUP_SESSION
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscr_ratchet_message_defs.h"
#include "vscr_ratchet_group_session.h"
#include "vscr_ratchet_group_ticket.h"
#include "test_utils_ratchet.h"
#include "msg_channel.h"

// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------

void
test__signature__ed_pair__should_verify(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vsc_buffer_t *ed_priv = NULL;
    vsc_buffer_t *ed_pub = NULL;

    generate_raw_keypair(rng, &ed_priv, &ed_pub, false);

    vsc_buffer_t *data = NULL;
    generate_random_data(rng, &data);

    byte signature[64];
    ed25519_sign(signature, vsc_buffer_bytes(ed_priv), vsc_buffer_bytes(data), vsc_buffer_len(data));

    int res = ed25519_verify(signature, vsc_buffer_bytes(ed_pub), vsc_buffer_bytes(data), vsc_buffer_len(data));

    TEST_ASSERT_EQUAL(0, res);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__signature__curve_pair__should_verify(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vsc_buffer_t *curve_priv = NULL;
    vsc_buffer_t *curve_pub = NULL;

    generate_raw_keypair(rng, &curve_priv, &curve_pub, true);

    vsc_buffer_t *data = NULL;
    generate_random_data(rng, &data);

    byte signature[64];
    curve25519_sign(signature, vsc_buffer_bytes(curve_priv), vsc_buffer_bytes(data), vsc_buffer_len(data));

    int res = curve25519_verify(signature, vsc_buffer_bytes(curve_pub), vsc_buffer_bytes(data), vsc_buffer_len(data));

    TEST_ASSERT_EQUAL(0, res);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__signature__curve_pkcs__should_verify(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vsc_buffer_t *curve_priv = NULL, *curve_pub = NULL;

    generate_PKCS8_curve_keypair(rng, &curve_priv, &curve_pub);

    vscf_pkcs8_der_deserializer_t *pkcs8 = vscf_pkcs8_der_deserializer_new();
    vscf_pkcs8_der_deserializer_setup_defaults(pkcs8);

    vscf_raw_key_t *raw_priv_key =
            vscf_pkcs8_der_deserializer_deserialize_private_key(pkcs8, vsc_buffer_data(curve_priv), NULL);
    vscf_raw_key_t *raw_pub_key =
            vscf_pkcs8_der_deserializer_deserialize_public_key(pkcs8, vsc_buffer_data(curve_pub), NULL);

    vsc_data_t curve_priv_raw = vsc_data_slice_beg(vscf_raw_key_data(raw_priv_key), 2, 32);
    vsc_data_t curve_pub_raw = vscf_raw_key_data(raw_pub_key);

    vsc_buffer_t *data = NULL;
    generate_random_data(rng, &data);

    byte signature[64];
    curve25519_sign(signature, curve_priv_raw.bytes, vsc_buffer_bytes(data), vsc_buffer_len(data));

    int res = curve25519_verify(signature, curve_pub_raw.bytes, vsc_buffer_bytes(data), vsc_buffer_len(data));

    TEST_ASSERT_EQUAL(0, res);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__signature__ed_pkcs_to_curve_pair__should_verify(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vsc_buffer_t *ed_priv = NULL, *ed_pub = NULL;

    generate_PKCS8_ed_keypair(rng, &ed_priv, &ed_pub);

    vscr_ratchet_key_utils_t *key_utils = vscr_ratchet_key_utils_new();

    vsc_buffer_t *curve_priv =
            vscr_ratchet_key_utils_extract_ratchet_private_key(key_utils, vsc_buffer_data(ed_priv), true, false, NULL);
    vsc_buffer_t *curve_pub =
            vscr_ratchet_key_utils_extract_ratchet_public_key(key_utils, vsc_buffer_data(ed_pub), true, false, NULL);

    vsc_buffer_t *data = NULL;
    generate_random_data(rng, &data);

    byte signature[64];
    curve25519_sign(signature, vsc_buffer_bytes(curve_priv), vsc_buffer_bytes(data), vsc_buffer_len(data));

    int res = curve25519_verify(signature, vsc_buffer_bytes(curve_pub), vsc_buffer_bytes(data), vsc_buffer_len(data));

    TEST_ASSERT_EQUAL(0, res);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__encrypt_decrypt__1_msg__decrypt_should_succeed(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_group_session_t **sessions = NULL;

    initialize_random_group_chat(rng, 2, &sessions);

    vscr_ratchet_group_session_t *session1 = sessions[0];
    vscr_ratchet_group_session_t *session2 = sessions[1];

    vsc_buffer_t *text = NULL;

    generate_random_data(rng, &text);

    vscr_error_t error_ctx;
    vscr_error_reset(&error_ctx);

    vscr_ratchet_group_message_t *group_msg =
            vscr_ratchet_group_session_encrypt(session1, vsc_buffer_data(text), &error_ctx);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, error_ctx.status);

    vsc_buffer_t *plain_text =
            vsc_buffer_new_with_capacity(vscr_ratchet_group_session_decrypt_len(session2, group_msg));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_decrypt(session2, group_msg, plain_text));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text), plain_text);

    vsc_buffer_destroy(&plain_text);

    vsc_buffer_destroy(&text);

    vscr_ratchet_group_message_destroy(&group_msg);

    vscr_ratchet_group_session_destroy(&sessions[0]);
    vscr_ratchet_group_session_destroy(&sessions[1]);

    vscr_dealloc(sessions);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__encrypt_decrypt__random_group_chat__decrypt_should_succeed(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_group_session_t **sessions = NULL;

    size_t group_size = generate_number(rng, 1, 100);

    initialize_random_group_chat(rng, group_size, &sessions);

    size_t number_of_msgs = generate_number(rng, 1, 1000);

    for (size_t i = 0; i < number_of_msgs; i++) {
        size_t sender = pick_element_uniform(rng, group_size);

        vscr_ratchet_group_session_t *session = sessions[sender];

        vsc_buffer_t *text = NULL;
        generate_random_data(rng, &text);

        vscr_error_t error_ctx;
        vscr_error_reset(&error_ctx);

        vscr_ratchet_group_message_t *group_msg =
                vscr_ratchet_group_session_encrypt(session, vsc_buffer_data(text), &error_ctx);
        TEST_ASSERT_EQUAL(vscr_status_SUCCESS, error_ctx.status);

        for (size_t receiver = 0; receiver < group_size; receiver++) {
            vsc_buffer_t *plain_text =
                    vsc_buffer_new_with_capacity(vscr_ratchet_group_session_decrypt_len(sessions[receiver], group_msg));

            if (receiver == sender) {
                TEST_ASSERT_EQUAL(vscr_status_ERROR_CANNOT_DECRYPT_OWN_MESSAGES,
                        vscr_ratchet_group_session_decrypt(sessions[receiver], group_msg, plain_text));
            } else {
                TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
                        vscr_ratchet_group_session_decrypt(sessions[receiver], group_msg, plain_text));

                TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text), plain_text);
            }

            vsc_buffer_destroy(&plain_text);
        }

        vsc_buffer_destroy(&text);
        vscr_ratchet_group_message_destroy(&group_msg);
    }

    for (size_t i = 0; i < group_size; i++) {
        vscr_ratchet_group_session_destroy(&sessions[i]);
    }

    vscr_dealloc(sessions);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__encrypt_decrypt__out_of_order__decrypt_should_succeed(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_group_session_t **sessions = NULL;

    initialize_random_group_chat(rng, 2, &sessions);

    vscr_ratchet_group_session_t *session1 = sessions[0];
    vscr_ratchet_group_session_t *session2 = sessions[1];

    vsc_buffer_t *text1 = NULL, *text2 = NULL;

    generate_random_data(rng, &text1);
    generate_random_data(rng, &text2);

    vscr_error_t error_ctx;
    vscr_error_reset(&error_ctx);

    vscr_ratchet_group_message_t *group_msg1 =
            vscr_ratchet_group_session_encrypt(session1, vsc_buffer_data(text1), &error_ctx);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, error_ctx.status);

    vscr_ratchet_group_message_t *group_msg2 =
            vscr_ratchet_group_session_encrypt(session1, vsc_buffer_data(text2), &error_ctx);

    vsc_buffer_t *plain_text2 =
            vsc_buffer_new_with_capacity(vscr_ratchet_group_session_decrypt_len(session2, group_msg2));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_decrypt(session2, group_msg2, plain_text2));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text2), plain_text2);

    vsc_buffer_t *plain_text1 =
            vsc_buffer_new_with_capacity(vscr_ratchet_group_session_decrypt_len(session2, group_msg1));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_decrypt(session2, group_msg1, plain_text1));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text1), plain_text1);

    vsc_buffer_destroy(&plain_text1);
    vsc_buffer_destroy(&plain_text2);

    vsc_buffer_destroy(&text1);
    vsc_buffer_destroy(&text2);

    vscr_ratchet_group_message_destroy(&group_msg1);
    vscr_ratchet_group_message_destroy(&group_msg2);

    vscr_ratchet_group_session_destroy(&sessions[0]);
    vscr_ratchet_group_session_destroy(&sessions[1]);

    vscr_dealloc(sessions);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__encrypt_decrypt__random_group_chat_bad_network__decrypt_should_succeed(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_group_session_t **sessions = NULL;

    size_t group_size = 10;

    initialize_random_group_chat(rng, group_size, &sessions);

    size_t number_of_iterations = 10000;

    encrypt_decrypt(rng, group_size, number_of_iterations, sessions, 0.75, 1.25, 0.25);

    for (size_t i = 0; i < group_size; i++) {
        vscr_ratchet_group_session_destroy(&sessions[i]);
    }

    vscr_dealloc(sessions);

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
    RUN_TEST(test__signature__ed_pair__should_verify);
    RUN_TEST(test__signature__curve_pair__should_verify);
    RUN_TEST(test__signature__curve_pkcs__should_verify);
    RUN_TEST(test__signature__ed_pkcs_to_curve_pair__should_verify);
//    RUN_TEST(test__encrypt_decrypt__1_msg__decrypt_should_succeed);
//    RUN_TEST(test__encrypt_decrypt__random_group_chat__decrypt_should_succeed);
//    RUN_TEST(test__encrypt_decrypt__out_of_order__decrypt_should_succeed);
//    RUN_TEST(test__encrypt_decrypt__random_group_chat_bad_network__decrypt_should_succeed);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
