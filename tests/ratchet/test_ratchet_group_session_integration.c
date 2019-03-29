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

// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------
void
test__initialize__fixed_values__should_not_fail(void) {
    vscr_ratchet_group_ticket_t *ticket = vscr_ratchet_group_ticket_new();

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_ticket_setup_defaults(ticket));

    vsc_buffer_t *priv1, *priv2, *priv3;
    vsc_buffer_t *pub1, *pub2, *pub3;
    vsc_buffer_t *id1, *id2, *id3;

    generate_PKCS8_keypair(&priv1, &pub1);
    generate_PKCS8_keypair(&priv2, &pub2);
    generate_PKCS8_keypair(&priv3, &pub3);

    generate_random_participant_id(&id1);
    generate_random_participant_id(&id2);
    generate_random_participant_id(&id3);

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_ticket_set_credentials(ticket, vsc_buffer_data(id1)));

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_ticket_add_participant(ticket, vsc_buffer_data(id2)));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_ticket_add_participant(ticket, vsc_buffer_data(id3)));

    const vscr_ratchet_group_message_t *msg = vscr_ratchet_group_ticket_generate_ticket(ticket);

    TEST_ASSERT_EQUAL(vscr_group_msg_type_GROUP_INFO, vscr_ratchet_group_message_get_type(msg));

    vscr_ratchet_group_session_t *session1 = vscr_ratchet_group_session_new();
    vscr_ratchet_group_session_t *session2 = vscr_ratchet_group_session_new();
    vscr_ratchet_group_session_t *session3 = vscr_ratchet_group_session_new();

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_defaults(session1));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_defaults(session2));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_defaults(session3));

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_session(session1, vsc_buffer_data(id1),
                                                   vsc_buffer_data(priv1), vsc_buffer_data(id1), msg));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_session(session2, vsc_buffer_data(id2),
                                                   vsc_buffer_data(priv2), vsc_buffer_data(id1), msg));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_session(session3, vsc_buffer_data(id3),
                                                   vsc_buffer_data(priv3), vsc_buffer_data(id1), msg));

    TEST_ASSERT(vscr_ratchet_group_session_is_initialized(session1));
    TEST_ASSERT(vscr_ratchet_group_session_is_initialized(session2));
    TEST_ASSERT(vscr_ratchet_group_session_is_initialized(session3));

    TEST_ASSERT(vscr_ratchet_group_session_is_owner(session1));
    TEST_ASSERT(!vscr_ratchet_group_session_is_owner(session2));
    TEST_ASSERT(!vscr_ratchet_group_session_is_owner(session3));

    vsc_buffer_t *text1, *text2, *text3;

    generate_random_data(&text1);
    generate_random_data(&text2);
    generate_random_data(&text3);

    vscr_error_t error_ctx;
    vscr_error_reset(&error_ctx);

    vscr_ratchet_group_message_t *msg1 =
            vscr_ratchet_group_session_encrypt(session1, vsc_buffer_data(text1), &error_ctx);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, error_ctx.status);
    TEST_ASSERT_EQUAL(vscr_group_msg_type_REGULAR, vscr_ratchet_group_message_get_type(msg1));
    vscr_ratchet_group_message_t *msg2 =
            vscr_ratchet_group_session_encrypt(session2, vsc_buffer_data(text2), &error_ctx);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, error_ctx.status);
    TEST_ASSERT_EQUAL(vscr_group_msg_type_REGULAR, vscr_ratchet_group_message_get_type(msg2));
    vscr_ratchet_group_message_t *msg3 =
            vscr_ratchet_group_session_encrypt(session3, vsc_buffer_data(text3), &error_ctx);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, error_ctx.status);
    TEST_ASSERT_EQUAL(vscr_group_msg_type_REGULAR, vscr_ratchet_group_message_get_type(msg3));

    vsc_buffer_t *plain_text12 = vsc_buffer_new_with_capacity(vscr_ratchet_group_session_decrypt_len(session1, msg1));
    vsc_buffer_t *plain_text13 = vsc_buffer_new_with_capacity(vscr_ratchet_group_session_decrypt_len(session1, msg1));
    vsc_buffer_t *plain_text21 = vsc_buffer_new_with_capacity(vscr_ratchet_group_session_decrypt_len(session1, msg2));
    vsc_buffer_t *plain_text23 = vsc_buffer_new_with_capacity(vscr_ratchet_group_session_decrypt_len(session1, msg2));
    vsc_buffer_t *plain_text31 = vsc_buffer_new_with_capacity(vscr_ratchet_group_session_decrypt_len(session1, msg3));
    vsc_buffer_t *plain_text32 = vsc_buffer_new_with_capacity(vscr_ratchet_group_session_decrypt_len(session1, msg3));

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_decrypt(session1, msg2, plain_text12));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_decrypt(session1, msg3, plain_text13));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_decrypt(session2, msg1, plain_text21));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_decrypt(session2, msg3, plain_text23));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_decrypt(session3, msg1, plain_text31));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_decrypt(session3, msg2, plain_text32));

    vscr_ratchet_group_message_destroy(&msg1);
    vscr_ratchet_group_message_destroy(&msg2);
    vscr_ratchet_group_message_destroy(&msg3);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text1), plain_text21);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text1), plain_text31);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text2), plain_text12);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text2), plain_text32);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text3), plain_text13);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text3), plain_text23);

    vsc_buffer_destroy(&plain_text12);
    vsc_buffer_destroy(&plain_text13);
    vsc_buffer_destroy(&plain_text21);
    vsc_buffer_destroy(&plain_text23);
    vsc_buffer_destroy(&plain_text31);
    vsc_buffer_destroy(&plain_text32);

    vsc_buffer_destroy(&text1);
    vsc_buffer_destroy(&text2);
    vsc_buffer_destroy(&text3);

    vscr_ratchet_group_session_destroy(&session1);
    vscr_ratchet_group_session_destroy(&session2);
    vscr_ratchet_group_session_destroy(&session3);

    vscr_ratchet_group_ticket_destroy(&ticket);

    vsc_buffer_destroy(&priv1);
    vsc_buffer_destroy(&priv2);
    vsc_buffer_destroy(&priv3);
    vsc_buffer_destroy(&pub1);
    vsc_buffer_destroy(&pub2);
    vsc_buffer_destroy(&pub3);
    vsc_buffer_destroy(&id1);
    vsc_buffer_destroy(&id2);
    vsc_buffer_destroy(&id3);
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
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
