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
#include <virgil/crypto/foundation/vscf_raw_key.h>
#include <vscr_ratchet_group_session_defs.h>
#include "unity.h"
#include "test_utils.h"

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
test__add_members__random_chat__should_continue_working(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_group_session_t **sessions = NULL;
    vsc_buffer_t **priv = NULL;

    size_t group_size = generate_number(rng, 5, 25);

    initialize_random_group_chat(rng, group_size, &sessions, &priv, NULL, NULL);

    encrypt_decrypt(rng, group_size, group_size * 50, sessions, 0.75, 1.25, 0.25, priv);

    size_t add_members_size = generate_number(rng, 5, 10);

    add_random_members(rng, group_size, add_members_size, &sessions, &priv);

    size_t new_size = group_size + add_members_size;

    encrypt_decrypt(rng, new_size, new_size * 50, sessions, 0.75, 1.25, 0.25, priv);

    for (size_t i = 0; i < new_size; i++) {
        vscr_ratchet_group_session_destroy(&sessions[i]);
        vsc_buffer_destroy(&priv[i]);
    }

    vscr_dealloc(sessions);
    vscr_dealloc(priv);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__remove_members__random_chat__should_continue_working(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_group_session_t **sessions = NULL;
    vsc_buffer_t **priv = NULL;

    size_t group_size = generate_number(rng, 5, 25);

    initialize_random_group_chat(rng, group_size, &sessions, &priv, NULL, NULL);

    encrypt_decrypt(rng, group_size, group_size * 50, sessions, 0.75, 1.25, 0.25, priv);

    size_t remove_members_size = generate_number(rng, 1, group_size - 2);

    remove_random_members(rng, group_size, remove_members_size, &sessions, &priv);

    size_t new_size = group_size - remove_members_size;

    encrypt_decrypt(rng, new_size, new_size * 50, sessions, 0.75, 1.25, 0.25, priv);

    for (size_t i = 0; i < new_size; i++) {
        vscr_ratchet_group_session_destroy(&sessions[i]);
        vsc_buffer_destroy(&priv[i]);
    }

    vscr_dealloc(sessions);
    vscr_dealloc(priv);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__ill_be_back__random_chat__should_continue_working(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_group_session_t **sessions = NULL;
    vsc_buffer_t **priv = NULL;
    vsc_buffer_t **pub = NULL;
    vsc_buffer_t **id = NULL;

    size_t group_size = 3;

    initialize_random_group_chat(rng, group_size, &sessions, &priv, &pub, &id);

    vsc_buffer_t *text1 = NULL, *text2 = NULL, *text3 = NULL;
    generate_random_data(rng, &text1);
    generate_random_data(rng, &text2);
    generate_random_data(rng, &text3);

    vscr_ratchet_group_message_t *encrypted1 =
            vscr_ratchet_group_session_encrypt(sessions[0], vsc_buffer_data(text1), NULL);

    vscr_ratchet_group_ticket_t *ticket1 =
            vscr_ratchet_group_session_create_group_ticket_for_adding_or_removing_participants(sessions[0], NULL);

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
            vscr_ratchet_group_ticket_remove_participant(ticket1, vscr_ratchet_group_session_get_my_id(sessions[2])));

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_session(
                                                   sessions[0], vscr_ratchet_group_ticket_get_ticket_message(ticket1)));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_session(
                                                   sessions[1], vscr_ratchet_group_ticket_get_ticket_message(ticket1)));

    vscr_ratchet_group_message_t *encrypted2 =
            vscr_ratchet_group_session_encrypt(sessions[0], vsc_buffer_data(text2), NULL);

    vscr_ratchet_group_ticket_t *ticket2 =
            vscr_ratchet_group_session_create_group_ticket_for_adding_participants(sessions[0]);

    TEST_ASSERT_EQUAL(
            vscr_status_SUCCESS, vscr_ratchet_group_ticket_add_new_participant(ticket2,
                                         vscr_ratchet_group_session_get_my_id(sessions[2]), vsc_buffer_data(pub[2])));

    vscr_ratchet_group_session_t *session = vscr_ratchet_group_session_new();
    vscr_ratchet_group_session_use_rng(session, vscf_ctr_drbg_impl(rng));

    TEST_ASSERT_EQUAL(
            vscr_status_SUCCESS, vscr_ratchet_group_session_set_private_key(session, vsc_buffer_data(priv[2])));
    vscr_ratchet_group_session_set_my_id(session, vsc_buffer_data(id[2]));

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_session(
                                                   sessions[0], vscr_ratchet_group_ticket_get_ticket_message(ticket2)));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_session(
                                                   sessions[1], vscr_ratchet_group_ticket_get_ticket_message(ticket2)));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
            vscr_ratchet_group_session_setup_session(session, vscr_ratchet_group_ticket_get_ticket_message(ticket2)));

    vscr_ratchet_group_message_t *encrypted3 =
            vscr_ratchet_group_session_encrypt(sessions[0], vsc_buffer_data(text3), NULL);

    size_t len1 = vscr_ratchet_group_session_decrypt_len(session, encrypted1);
    vsc_buffer_t *plain_text1 = vsc_buffer_new_with_capacity(len1);
    TEST_ASSERT_EQUAL(
            vscr_status_ERROR_EPOCH_NOT_FOUND, vscr_ratchet_group_session_decrypt(session, encrypted1, plain_text1));

    size_t len2 = vscr_ratchet_group_session_decrypt_len(session, encrypted2);
    vsc_buffer_t *plain_text2 = vsc_buffer_new_with_capacity(len2);
    TEST_ASSERT_EQUAL(vscr_status_ERROR_SKIPPED_MESSAGE_MISSING,
            vscr_ratchet_group_session_decrypt(session, encrypted2, plain_text2));

    size_t len3 = vscr_ratchet_group_session_decrypt_len(session, encrypted3);
    vsc_buffer_t *plain_text3 = vsc_buffer_new_with_capacity(len3);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_decrypt(session, encrypted3, plain_text3));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text3), plain_text3);

    for (size_t i = 0; i < group_size; i++) {
        vscr_ratchet_group_session_destroy(&sessions[i]);
        vsc_buffer_destroy(&priv[i]);
        vsc_buffer_destroy(&pub[i]);
        vsc_buffer_destroy(&id[i]);
    }

    vscr_ratchet_group_session_destroy(&session);

    vsc_buffer_destroy(&text1);
    vsc_buffer_destroy(&text2);
    vsc_buffer_destroy(&text3);

    vsc_buffer_destroy(&plain_text1);
    vsc_buffer_destroy(&plain_text2);
    vsc_buffer_destroy(&plain_text3);

    vscr_ratchet_group_message_destroy(&encrypted1);
    vscr_ratchet_group_message_destroy(&encrypted2);
    vscr_ratchet_group_message_destroy(&encrypted3);

    vscr_ratchet_group_ticket_destroy(&ticket1);
    vscr_ratchet_group_ticket_destroy(&ticket2);

    vscr_dealloc(sessions);
    vscr_dealloc(priv);
    vscr_dealloc(pub);
    vscr_dealloc(id);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__change_members__out_of_order_msgs__should_continue_working(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_group_session_t **sessions = NULL;
    vsc_buffer_t **priv = NULL;

    initialize_random_group_chat(rng, 2, &sessions, &priv, NULL, NULL);

    size_t number_of_iterations = 100;

    encrypt_decrypt(rng, 2, number_of_iterations, sessions, 0.75, 1.25, 0.25, priv);

    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_group_ticket_t *ticket1 =
            vscr_ratchet_group_session_create_group_ticket_for_adding_or_removing_participants(sessions[1], &error);

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, error.status);

    vscr_ratchet_group_session_t **new_sessions = vscr_alloc(4 * sizeof(vscr_ratchet_group_session_t *));
    vsc_buffer_t **new_privs = vscr_alloc(4 * sizeof(vsc_buffer_t *));

    new_sessions[0] = sessions[0];
    new_privs[0] = priv[0];
    new_sessions[1] = sessions[1];
    new_privs[1] = priv[1];

    vscr_dealloc(priv);
    vscr_dealloc(sessions);

    vsc_buffer_t *id3, *id4;
    vsc_buffer_t *pub3, *pub4;

    generate_random_participant_id(rng, &id3);
    generate_random_participant_id(rng, &id4);

    generate_PKCS8_ed_keypair(rng, &new_privs[2], &pub3);
    generate_PKCS8_ed_keypair(rng, &new_privs[3], &pub4);

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
            vscr_ratchet_group_ticket_add_new_participant(ticket1, vsc_buffer_data(id3), vsc_buffer_data(pub3)));

    const vscr_ratchet_group_message_t *msg1 = vscr_ratchet_group_ticket_get_ticket_message(ticket1);

    new_sessions[2] = vscr_ratchet_group_session_new();

    vscr_ratchet_group_session_use_rng(new_sessions[2], vscf_ctr_drbg_impl(rng));
    vscr_ratchet_group_session_set_my_id(new_sessions[2], vsc_buffer_data(id3));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
            vscr_ratchet_group_session_set_private_key(new_sessions[2], vsc_buffer_data(new_privs[2])));

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_session(new_sessions[2], msg1));

    restore_group_session(rng, &new_sessions[2], new_privs[2]);

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_session(new_sessions[1], msg1));

    restore_group_session(rng, &new_sessions[1], new_privs[1]);

    encrypt_decrypt(rng, 2, number_of_iterations, new_sessions + 1, 0.75, 1.25, 0.25, new_privs + 1);

    vscr_ratchet_group_ticket_t *ticket2 =
            vscr_ratchet_group_session_create_group_ticket_for_adding_or_removing_participants(new_sessions[1], &error);

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, error.status);

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
            vscr_ratchet_group_ticket_add_new_participant(ticket2, vsc_buffer_data(id4), vsc_buffer_data(pub4)));

    const vscr_ratchet_group_message_t *msg2 = vscr_ratchet_group_ticket_get_ticket_message(ticket2);

    new_sessions[3] = vscr_ratchet_group_session_new();

    vscr_ratchet_group_session_use_rng(new_sessions[3], vscf_ctr_drbg_impl(rng));
    vscr_ratchet_group_session_set_my_id(new_sessions[3], vsc_buffer_data(id4));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
            vscr_ratchet_group_session_set_private_key(new_sessions[3], vsc_buffer_data(new_privs[3])));

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_session(new_sessions[3], msg2));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_session(new_sessions[2], msg2));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_session(new_sessions[1], msg2));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_session(new_sessions[0], msg2));

    restore_group_session(rng, &new_sessions[0], new_privs[0]);
    restore_group_session(rng, &new_sessions[1], new_privs[1]);
    restore_group_session(rng, &new_sessions[2], new_privs[2]);
    restore_group_session(rng, &new_sessions[3], new_privs[3]);

    encrypt_decrypt(rng, 4, number_of_iterations, new_sessions, 0.75, 1.25, 0.25, new_privs);

    for (size_t i = 0; i < 4; i++) {
        vscr_ratchet_group_session_destroy(&new_sessions[i]);
        vsc_buffer_destroy(&new_privs[i]);
    }

    vscr_dealloc(new_sessions);
    vscr_dealloc(new_privs);

    vscr_ratchet_group_ticket_destroy(&ticket1);
    vscr_ratchet_group_ticket_destroy(&ticket2);

    vsc_buffer_destroy(&id3);
    vsc_buffer_destroy(&id4);
    vsc_buffer_destroy(&pub3);
    vsc_buffer_destroy(&pub4);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__remove_members__old_messages__should_continue_working(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_group_session_t **sessions = NULL;
    vsc_buffer_t **priv = NULL;

    initialize_random_group_chat(rng, 3, &sessions, &priv, NULL, NULL);

    size_t number_of_iterations = 150;

    encrypt_decrypt(rng, 3, number_of_iterations, sessions, 0.75, 1.25, 0.25, priv);

    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_group_ticket_t *ticket =
            vscr_ratchet_group_session_create_group_ticket_for_adding_or_removing_participants(sessions[0], &error);

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, error.status);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
            vscr_ratchet_group_ticket_remove_participant(ticket, vscr_ratchet_group_session_get_my_id(sessions[2])));

    const vscr_ratchet_group_message_t *info_msg = vscr_ratchet_group_ticket_get_ticket_message(ticket);

    vsc_buffer_t *text1 = NULL, *text2 = NULL;
    generate_random_data(rng, &text1);
    generate_random_data(rng, &text2);

    vscr_ratchet_group_message_t *msg1 =
            vscr_ratchet_group_session_encrypt(sessions[1], vsc_buffer_data(text1), &error);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, error.status);

    vscr_ratchet_group_message_t *msg2 =
            vscr_ratchet_group_session_encrypt(sessions[2], vsc_buffer_data(text2), &error);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, error.status);

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_session(sessions[0], info_msg));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_session(sessions[1], info_msg));

    encrypt_decrypt(rng, 2, number_of_iterations, sessions, 0.75, 1.25, 0.25, priv);

    size_t len1 = vscr_ratchet_group_session_decrypt_len(sessions[0], msg1);
    vsc_buffer_t *buffer1 = vsc_buffer_new_with_capacity(len1);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_decrypt(sessions[0], msg1, buffer1));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text1), buffer1);

    size_t len2 = vscr_ratchet_group_session_decrypt_len(sessions[0], msg2);
    vsc_buffer_t *buffer2 = vsc_buffer_new_with_capacity(len2);
    TEST_ASSERT_EQUAL(
            vscr_status_ERROR_SENDER_NOT_FOUND, vscr_ratchet_group_session_decrypt(sessions[0], msg2, buffer2));

    for (size_t i = 0; i < 3; i++) {
        vscr_ratchet_group_session_destroy(&sessions[i]);
        vsc_buffer_destroy(&priv[i]);
    }

    vscr_dealloc(sessions);
    vscr_dealloc(priv);

    vscr_ratchet_group_ticket_destroy(&ticket);

    vscr_ratchet_group_message_destroy(&msg1);
    vscr_ratchet_group_message_destroy(&msg2);

    vsc_buffer_destroy(&buffer1);
    vsc_buffer_destroy(&buffer2);

    vsc_buffer_destroy(&text1);
    vsc_buffer_destroy(&text2);

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
    RUN_TEST(test__add_members__random_chat__should_continue_working);
    RUN_TEST(test__remove_members__random_chat__should_continue_working);
    RUN_TEST(test__ill_be_back__random_chat__should_continue_working);
    RUN_TEST(test__change_members__out_of_order_msgs__should_continue_working);
    RUN_TEST(test__remove_members__old_messages__should_continue_working);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
