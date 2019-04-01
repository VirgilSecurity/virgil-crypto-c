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

    free(sessions);

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
    ;
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

    free(sessions);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__encrypt_decrypt__random_group_chat_bad_network__decrypt_should_succeed(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_group_session_t **sessions = NULL;

    size_t group_size = generate_number(rng, 1, 100);

    initialize_random_group_chat(rng, group_size, &sessions);

    size_t number_of_iterations = generate_number(rng, 100, 10000);

    msg_channel_t **channels = vscr_alloc(group_size * sizeof(msg_channel_t *));

    for (size_t i = 0; i < group_size; i++) {
        msg_channel_t *channel = vscr_alloc(sizeof(msg_channel_t));

        init_channel(channel, rng);
        channels[i] = channel;
    }

    size_t number_of_msgs = 0;
    size_t number_of_picks = 0;

    for (size_t i = 0; i < number_of_iterations; i++) {
        size_t event;

        if (number_of_msgs * (group_size - 1) < number_of_picks) {
            TEST_ASSERT(false);
        }

        if (number_of_msgs * (group_size - 1) == number_of_picks) {
            // Need to produce new msg
            event = group_size;
        } else {
            event = generate_number(rng, 0, group_size);
        }

        // New message produced
        if (event == group_size) {
            size_t sender = pick_element_uniform(rng, group_size);

            vscr_ratchet_group_session_t *session = sessions[sender];

            vsc_buffer_t *text = NULL;
            generate_random_data(rng, &text);

            vscr_error_t error_ctx;
            vscr_error_reset(&error_ctx);

            vscr_ratchet_group_message_t *group_msg =
                    vscr_ratchet_group_session_encrypt(session, vsc_buffer_data(text), &error_ctx);
            TEST_ASSERT_EQUAL(vscr_status_SUCCESS, error_ctx.status);

            size_t len = vscr_ratchet_group_message_serialize_len(group_msg);
            vsc_buffer_t *msg_buff = vsc_buffer_new_with_capacity(len);

            vscr_ratchet_group_message_serialize(group_msg, msg_buff);

            for (size_t receiver = 0; receiver < group_size; receiver++) {
                if (receiver == sender) {
                    continue;
                }

                push_msg(channels[receiver], vsc_buffer_data(text), vsc_buffer_data(msg_buff));
            }

            vsc_buffer_destroy(&text);
            vsc_buffer_destroy(&msg_buff);
            vscr_ratchet_group_message_destroy(&group_msg);

            number_of_msgs++;
        }
        // Old message pick
        else {
            size_t number_of_active_channels = 0;
            for (size_t j = 0; j < group_size; j++) {
                if (has_msg(channels[j])) {
                    number_of_active_channels++;
                }
            }

            TEST_ASSERT(number_of_active_channels > 0);

            size_t receiver_queue_num = generate_number(rng, 0, number_of_active_channels - 1);
            size_t receiver = 0;

            for (size_t j = 0; j < group_size; j++) {
                if (has_msg(channels[j])) {
                    if (receiver_queue_num == 0) {
                        receiver = j;
                        break;
                    } else {
                        receiver_queue_num--;
                    }
                }
            }

            TEST_ASSERT(receiver_queue_num == 0);
            TEST_ASSERT(has_msg(channels[receiver]));

            channel_msg_t *channel_msg = pop_msg(channels[receiver]);

            vscr_error_t error_ctx;
            vscr_error_reset(&error_ctx);

            vscr_ratchet_group_message_t *ratchet_msg =
                    vscr_ratchet_group_message_deserialize(vsc_buffer_data(channel_msg->cipher_text), &error_ctx);

            TEST_ASSERT_EQUAL(vscr_status_SUCCESS, error_ctx.status);

            size_t len = vscr_ratchet_group_session_decrypt_len(sessions[receiver], ratchet_msg);

            vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(len);

            TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
                    vscr_ratchet_group_session_decrypt(sessions[receiver], ratchet_msg, plain_text));

            TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(channel_msg->plain_text), plain_text);

            deinit_msg(channel_msg);

            number_of_picks++;
        }
    }

    for (size_t i = 0; i < group_size; i++) {
        vscr_ratchet_group_session_destroy(&sessions[i]);
    }

    free(sessions);

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
    RUN_TEST(test__encrypt_decrypt__random_group_chat__decrypt_should_succeed);
    RUN_TEST(test__encrypt_decrypt__out_of_order__decrypt_should_succeed);
    RUN_TEST(test__encrypt_decrypt__random_group_chat_bad_network__decrypt_should_succeed);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
