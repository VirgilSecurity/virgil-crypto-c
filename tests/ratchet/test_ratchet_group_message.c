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

#define TEST_DEPENDENCIES_AVAILABLE VSCR_RATCHET_GROUP_SESSION
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_ctr_drbg.h"
#include "vscr_memory.h"
#include "vscr_ratchet_group_message_internal.h"
#include "test_data_ratchet_group_message.h"
#include "vscr_ratchet_group_message.h"
#include "vscr_ratchet_group_message_defs.h"
#include "test_utils_ratchet.h"
#include "vscr_ratchet_common.h"
#include "vscr_ratchet_common_hidden.h"

// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------

static bool
reg_msg_cmp(RegularGroupMessage *msg1, RegularGroupMessage *msg2) {

    return vsc_buffer_len(msg1->cipher_text.arg) == vsc_buffer_len(msg2->cipher_text.arg) &&
           memcmp(&msg1->header, &msg2->header, sizeof(msg1->header)) == 0 &&
           memcmp(vsc_buffer_bytes(msg1->cipher_text.arg), vsc_buffer_bytes(msg2->cipher_text.arg),
                   vsc_buffer_len(msg1->cipher_text.arg)) == 0;
}

static bool
participant_cmp(MessageParticipantInfo *msg1, MessageParticipantInfo *msg2) {
    return memcmp(msg1->key, msg2->key, sizeof(msg1->key)) == 0 &&
           memcmp(msg1->pub_key, msg2->pub_key, sizeof(msg1->pub_key)) == 0;
}

static bool
grp_info_msg_cmp(MessageGroupInfo *msg1, MessageGroupInfo *msg2) {

    if (msg1->participants_count != msg2->participants_count)
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

    vscr_ratchet_group_message_set_type(msg1, vscr_group_msg_type_REGULAR);

    msg1->message_pb.version = 5;
    msg1->header_pb->counter = 17;
    msg1->header_pb->prev_epoch_msgs[0] = 24;
    msg1->header_pb->prev_epoch_msgs[1] = 78;
    msg1->header_pb->prev_epoch_msgs[2] = 32;
    msg1->header_pb->prev_epoch_msgs[3] = 22;
    msg1->header_pb->prev_epoch_msgs[4] = 7;
    msg1->header_pb->epoch = 3;

    memcpy(msg1->message_pb.regular_message.signature, test_data_ratchet_group_message_signature.bytes,
            test_data_ratchet_group_message_signature.len);
    memcpy(msg1->header_pb->sender_id, test_data_ratchet_group_message_sender_id.bytes,
            test_data_ratchet_group_message_sender_id.len);
    msg1->message_pb.regular_message.cipher_text.arg = vsc_buffer_new_with_data(test_data_ratchet_group_message_data);

    pb_ostream_t ostream = pb_ostream_from_buffer(
            msg1->message_pb.regular_message.header.bytes, sizeof(msg1->message_pb.regular_message.header.bytes));
    TEST_ASSERT(pb_encode(&ostream, RegularGroupMessageHeader_fields, msg1->header_pb));
    msg1->message_pb.regular_message.header.size = ostream.bytes_written;

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

    vscr_ratchet_group_message_set_type(msg1, vscr_group_msg_type_GROUP_INFO);

    msg1->message_pb.version = 5;
    msg1->message_pb.group_info.participants_count = 2;

    memcpy(msg1->message_pb.group_info.session_id, test_data_ratchet_group_message_id.bytes,
            test_data_ratchet_group_message_id.len);

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
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_group_message_t *msg1 = vscr_ratchet_group_message_new();
    vscr_ratchet_group_message_set_type(msg1, vscr_group_msg_type_GROUP_INFO);

    msg1->message_pb.version = UINT32_MAX;
    msg1->message_pb.group_info.epoch = UINT32_MAX;

    size_t number_of_participants = vscr_ratchet_common_MAX_PARTICIPANTS_COUNT;

    msg1->message_pb.group_info.participants_count = number_of_participants;

    for (size_t i = 0; i < number_of_participants; i++) {
        vsc_buffer_t *id;
        generate_random_participant_id(rng, &id);
        memcpy(msg1->message_pb.group_info.participants[i].id, vsc_buffer_bytes(id), vsc_buffer_len(id));
        msg1->message_pb.group_info.participants[i].index = UINT32_MAX;
        vsc_buffer_destroy(&id);
    }

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

    vscf_ctr_drbg_destroy(&rng);
}

void
test__serialize_deserialize__regular_overflow__should_be_equal(void) {
    vscr_ratchet_group_message_t *msg1 = vscr_ratchet_group_message_new();

    vscr_ratchet_group_message_set_type(msg1, vscr_group_msg_type_REGULAR);

    msg1->message_pb.version = UINT32_MAX;
    msg1->header_pb->counter = UINT32_MAX;
    msg1->header_pb->prev_epoch_msgs[0] = UINT32_MAX;
    msg1->header_pb->prev_epoch_msgs[1] = UINT32_MAX;
    msg1->header_pb->prev_epoch_msgs[2] = UINT32_MAX;
    msg1->header_pb->prev_epoch_msgs[3] = UINT32_MAX;
    msg1->header_pb->prev_epoch_msgs[4] = UINT32_MAX;
    msg1->header_pb->epoch = UINT32_MAX;

    memcpy(msg1->message_pb.regular_message.signature, test_data_ratchet_group_message_signature.bytes,
            test_data_ratchet_group_message_signature.len);
    memcpy(msg1->header_pb->sender_id, test_data_ratchet_group_message_sender_id.bytes,
            test_data_ratchet_group_message_sender_id.len);

    vsc_buffer_t *cipher_text = vsc_buffer_new_with_capacity(vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN);
    vsc_buffer_inc_used(cipher_text, vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN);

    pb_ostream_t ostream = pb_ostream_from_buffer(
            msg1->message_pb.regular_message.header.bytes, sizeof(msg1->message_pb.regular_message.header.bytes));
    TEST_ASSERT(pb_encode(&ostream, RegularGroupMessageHeader_fields, msg1->header_pb));
    msg1->message_pb.regular_message.header.size = ostream.bytes_written;

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
