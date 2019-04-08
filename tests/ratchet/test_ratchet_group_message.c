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

#include "vscr_ratchet_common.h"
#include "vscr_ratchet_common_hidden.h"
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

#include "test_data_ratchet_group_message.h"
#include "vscr_ratchet_group_message.h"
#include "vscr_ratchet_group_message_defs.h"

// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------

static bool
reg_msg_cmp(RegularGroupMessage *msg1, RegularGroupMessage *msg2) {

    return msg1->version == msg2->version && msg1->counter == msg2->counter &&
           memcmp(msg1->sender_id, msg2->sender_id, sizeof(msg1->sender_id)) == 0 &&
           memcmp(msg1->signature, msg2->signature, sizeof(msg1->signature)) == 0 &&
           vsc_buffer_len(msg1->cipher_text.arg) == vsc_buffer_len(msg2->cipher_text.arg) &&
           memcmp(vsc_buffer_bytes(msg1->cipher_text.arg), vsc_buffer_bytes(msg2->cipher_text.arg),
                   vsc_buffer_len(msg1->cipher_text.arg)) == 0;
}

static bool
participant_cmp(ParticipantInfo *msg1, ParticipantInfo *msg2) {
    return msg1->version == msg2->version && memcmp(msg1->id, msg2->id, sizeof(msg1->id)) == 0 &&
           memcmp(msg1->key, msg2->key, sizeof(msg1->key)) == 0 &&
           memcmp(msg1->pub_key, msg2->pub_key, sizeof(msg1->pub_key)) == 0;
}

static bool
grp_info_msg_cmp(GroupInfo *msg1, GroupInfo *msg2) {

    if (msg1->version != msg2->version || msg1->participants_count != msg2->participants_count)
        return false;

    for (size_t i = 0; i < msg1->participants_count; i++) {
        if (!participant_cmp(&msg1->participants[i], &msg2->participants[i]))
            return false;
    }

    return true;
}

static bool
msg_cmp(vscr_ratchet_group_message_t *msg1, vscr_ratchet_group_message_t *msg2) {
    if (msg1->message_pb.version != msg2->message_pb.version ||
            msg1->message_pb.has_group_info != msg2->message_pb.has_group_info ||
            msg1->message_pb.has_regular_message != msg2->message_pb.has_regular_message)
        return false;

    if (msg1->message_pb.has_regular_message) {
        return reg_msg_cmp(&msg1->message_pb.regular_message, &msg2->message_pb.regular_message);
    } else if (msg1->message_pb.has_group_info) {
        return grp_info_msg_cmp(&msg1->message_pb.group_info, &msg2->message_pb.group_info);
    } else {
        TEST_ASSERT(false);
    }

    return false;
}

void
test__serialize_deserialize__fixed_regular_msg__should_be_equal(void) {
    vscr_ratchet_group_message_t *msg1 = vscr_ratchet_group_message_new();

    msg1->message_pb.has_regular_message = true;
    msg1->message_pb.version = 5;
    msg1->message_pb.regular_message.version = 11;
    msg1->message_pb.regular_message.counter = 17;

    memcpy(msg1->message_pb.regular_message.signature, test_data_ratchet_group_message_signature.bytes,
            test_data_ratchet_group_message_signature.len);
    memcpy(msg1->message_pb.regular_message.sender_id, test_data_ratchet_group_message_sender_id.bytes,
            test_data_ratchet_group_message_sender_id.len);
    msg1->message_pb.regular_message.cipher_text.arg = vsc_buffer_new_with_data(test_data_ratchet_group_message_data);

    size_t len = vscr_ratchet_group_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscr_ratchet_group_message_serialize(msg1, buff);

    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_group_message_t *msg2 = vscr_ratchet_group_message_deserialize(vsc_buffer_data(buff), &error);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    TEST_ASSERT(msg_cmp(msg1, msg2));

    vscr_ratchet_group_message_destroy(&msg1);
    vscr_ratchet_group_message_destroy(&msg2);
    vsc_buffer_destroy(&buff);
}

void
test__serialize_deserialize__fixed_group_info_msg__should_be_equal(void) {
    vscr_ratchet_group_message_t *msg1 = vscr_ratchet_group_message_new();

    msg1->message_pb.has_group_info = true;
    msg1->message_pb.version = 5;
    msg1->message_pb.group_info.version = 11;
    msg1->message_pb.group_info.participants_count = 2;

    msg1->message_pb.group_info.participants[0].version = 2;
    msg1->message_pb.group_info.participants[1].version = 2;
    memcpy(msg1->message_pb.group_info.participants[0].pub_key, test_data_ratchet_group_message_pub_key1.bytes,
            test_data_ratchet_group_message_pub_key1.len);
    memcpy(msg1->message_pb.group_info.participants[1].pub_key, test_data_ratchet_group_message_pub_key2.bytes,
            test_data_ratchet_group_message_pub_key2.len);
    memcpy(msg1->message_pb.group_info.participants[0].key, test_data_ratchet_group_message_pub_key1.bytes,
            test_data_ratchet_group_message_pub_key1.len);
    memcpy(msg1->message_pb.group_info.participants[1].key, test_data_ratchet_group_message_pub_key2.bytes,
            test_data_ratchet_group_message_pub_key2.len);
    memcpy(msg1->message_pb.group_info.participants[0].id, test_data_ratchet_group_message_id1.bytes,
            test_data_ratchet_group_message_id1.len);
    memcpy(msg1->message_pb.group_info.participants[1].id, test_data_ratchet_group_message_id2.bytes,
            test_data_ratchet_group_message_id2.len);

    size_t len = vscr_ratchet_group_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscr_ratchet_group_message_serialize(msg1, buff);

    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_group_message_t *msg2 = vscr_ratchet_group_message_deserialize(vsc_buffer_data(buff), &error);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    TEST_ASSERT(msg_cmp(msg1, msg2));

    vscr_ratchet_group_message_destroy(&msg1);
    vscr_ratchet_group_message_destroy(&msg2);
    vsc_buffer_destroy(&buff);
}

void
test__serialize_deserialize__group_info_overflow__should_be_equal(void) {
    vscr_ratchet_group_message_t *msg1 = vscr_ratchet_group_message_new();

    msg1->message_pb.has_group_info = true;
    msg1->message_pb.group_info.participants_count = vscr_ratchet_common_MAX_PARTICIPANTS_COUNT;

    size_t len = vscr_ratchet_group_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscr_ratchet_group_message_serialize(msg1, buff);

    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_group_message_t *msg2 = vscr_ratchet_group_message_deserialize(vsc_buffer_data(buff), &error);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    TEST_ASSERT(msg_cmp(msg1, msg2));

    vscr_ratchet_group_message_destroy(&msg1);
    vscr_ratchet_group_message_destroy(&msg2);
    vsc_buffer_destroy(&buff);
}

void
test__serialize_deserialize__regular_overflow__should_be_equal(void) {
    vscr_ratchet_group_message_t *msg1 = vscr_ratchet_group_message_new();

    msg1->message_pb.has_regular_message = true;
    msg1->message_pb.version = 5;
    msg1->message_pb.regular_message.version = 11;
    msg1->message_pb.regular_message.counter = 17;

    memcpy(msg1->message_pb.regular_message.signature, test_data_ratchet_group_message_signature.bytes,
            test_data_ratchet_group_message_signature.len);
    memcpy(msg1->message_pb.regular_message.sender_id, test_data_ratchet_group_message_sender_id.bytes,
            test_data_ratchet_group_message_sender_id.len);

    vsc_buffer_t *cipher_text = vsc_buffer_new_with_capacity(vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN);
    vsc_buffer_inc_used(cipher_text, vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN);

    msg1->message_pb.regular_message.cipher_text.arg = cipher_text;

    size_t len = vscr_ratchet_group_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscr_ratchet_group_message_serialize(msg1, buff);

    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_group_message_t *msg2 = vscr_ratchet_group_message_deserialize(vsc_buffer_data(buff), &error);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    TEST_ASSERT(msg_cmp(msg1, msg2));

    vscr_ratchet_group_message_destroy(&msg1);
    vscr_ratchet_group_message_destroy(&msg2);
    vsc_buffer_destroy(&buff);
}

#endif

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__serialize_deserialize__fixed_regular_msg__should_be_equal);
    RUN_TEST(test__serialize_deserialize__fixed_group_info_msg__should_be_equal);
    RUN_TEST(test__serialize_deserialize__group_info_overflow__should_be_equal);
    RUN_TEST(test__serialize_deserialize__regular_overflow__should_be_equal);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
