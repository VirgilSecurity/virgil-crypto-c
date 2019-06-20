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
reg_msg_hdr_cmp(RegularGroupMessageHeader *msg1, RegularGroupMessageHeader *msg2) {
    return memcmp(msg1->session_id, msg2->session_id, sizeof(msg1->session_id)) == 0 &&
           memcmp(msg1->sender_id, msg2->sender_id, sizeof(msg1->sender_id)) == 0 && msg1->counter == msg2->counter &&
           msg1->prev_epochs_msgs[0] == msg2->prev_epochs_msgs[0] &&
           msg1->prev_epochs_msgs[1] == msg2->prev_epochs_msgs[1] &&
           msg1->prev_epochs_msgs[2] == msg2->prev_epochs_msgs[2] &&
           msg1->prev_epochs_msgs[3] == msg2->prev_epochs_msgs[3] && msg1->epoch == msg2->epoch;
}

static bool
reg_msg_cmp(RegularGroupMessage *msg1, RegularGroupMessage *msg2) {

    return vsc_buffer_len(msg1->cipher_text.arg) == vsc_buffer_len(msg2->cipher_text.arg) &&
           memcmp(&msg1->header, &msg2->header, sizeof(msg1->header)) == 0 &&
           memcmp(vsc_buffer_bytes(msg1->cipher_text.arg), vsc_buffer_bytes(msg2->cipher_text.arg),
                   vsc_buffer_len(msg1->cipher_text.arg)) == 0;
}

static bool
grp_info_msg_cmp(MessageGroupInfo *msg1, MessageGroupInfo *msg2) {

    if (memcmp(msg1->key, msg2->key, sizeof(msg1->key)) != 0)
        return false;

    if (msg1->epoch != msg2->epoch)
        return false;

    if (memcmp(msg1->session_id, msg2->session_id, sizeof(msg1->session_id)) != 0)
        return false;

    return true;
}

static bool
msg_cmp(vscr_ratchet_group_message_t *msg1, vscr_ratchet_group_message_t *msg2) {
    if (msg1->message_pb.version != msg2->message_pb.version ||
            msg1->message_pb.has_group_info != msg2->message_pb.has_group_info ||
            msg1->message_pb.has_regular_message != msg2->message_pb.has_regular_message)
        return false;

    if (msg1->message_pb.has_regular_message) {
        return reg_msg_cmp(&msg1->message_pb.regular_message, &msg2->message_pb.regular_message) &&
               reg_msg_hdr_cmp(msg1->header_pb, msg2->header_pb);
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
    msg1->header_pb->prev_epochs_msgs[0] = 24;
    msg1->header_pb->prev_epochs_msgs[1] = 78;
    msg1->header_pb->prev_epochs_msgs[2] = 32;
    msg1->header_pb->prev_epochs_msgs[3] = 22;
    msg1->header_pb->epoch = 3;

    memcpy(msg1->header_pb->session_id, test_data_ratchet_group_message_session_id.bytes,
            test_data_ratchet_group_message_session_id.len);
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

    msg1->message_pb.group_info.epoch = 3;
    memcpy(msg1->message_pb.group_info.session_id, test_data_ratchet_group_message_id.bytes,
            test_data_ratchet_group_message_id.len);
    memcpy(msg1->message_pb.group_info.key, test_data_ratchet_group_message_key1.bytes,
            test_data_ratchet_group_message_key1.len);

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

    memcpy(msg1->message_pb.group_info.session_id, test_data_ratchet_group_message_id.bytes,
            test_data_ratchet_group_message_id.len);
    memcpy(msg1->message_pb.group_info.key, test_data_ratchet_group_message_key1.bytes,
            test_data_ratchet_group_message_key1.len);

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
    msg1->header_pb->prev_epochs_msgs[0] = UINT32_MAX;
    msg1->header_pb->prev_epochs_msgs[1] = UINT32_MAX;
    msg1->header_pb->prev_epochs_msgs[2] = UINT32_MAX;
    msg1->header_pb->prev_epochs_msgs[3] = UINT32_MAX;
    msg1->header_pb->epoch = UINT32_MAX;

    memcpy(msg1->header_pb->session_id, test_data_ratchet_group_message_session_id.bytes,
            test_data_ratchet_group_message_session_id.len);
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

void
test__methods__fixed_regular_msg__should_return_correct_values(void) {
    vscr_ratchet_group_message_t *msg1 = vscr_ratchet_group_message_new();

    msg1->message_pb.version = 5;
    msg1->message_pb.has_regular_message = true;
    msg1->message_pb.has_group_info = false;

    msg1->header_pb = vscr_alloc(sizeof(RegularGroupMessageHeader));
    msg1->header_pb->counter = 7;
    msg1->header_pb->epoch = 18;
    memcpy(msg1->header_pb->session_id, test_data_ratchet_group_message_session_id.bytes,
            sizeof(msg1->header_pb->session_id));
    memcpy(msg1->header_pb->sender_id, test_data_ratchet_group_message_sender_id.bytes,
            sizeof(msg1->header_pb->sender_id));

    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_group_message_session_id, vscr_ratchet_group_message_get_session_id(msg1));
    TEST_ASSERT_EQUAL(vscr_group_msg_type_REGULAR, vscr_ratchet_group_message_get_type(msg1));
    TEST_ASSERT_EQUAL(msg1->header_pb->counter, vscr_ratchet_group_message_get_counter(msg1));
    TEST_ASSERT_EQUAL(msg1->header_pb->epoch, vscr_ratchet_group_message_get_epoch(msg1));
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_group_message_sender_id, vscr_ratchet_group_message_get_sender_id(msg1));

    vscr_ratchet_group_message_destroy(&msg1);
}

void
test__methods__fixed_group_info_msg__should_return_correct_values(void) {
    vscr_ratchet_group_message_t *msg1 = vscr_ratchet_group_message_new();

    msg1->message_pb.version = 5;
    msg1->message_pb.has_regular_message = false;
    msg1->message_pb.has_group_info = true;
    memcpy(msg1->message_pb.group_info.session_id, test_data_ratchet_group_message_session_id.bytes,
            sizeof(msg1->message_pb.group_info.session_id));

    msg1->message_pb.group_info.epoch = 39;

    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_group_message_session_id, vscr_ratchet_group_message_get_session_id(msg1));
    TEST_ASSERT_EQUAL(vscr_group_msg_type_GROUP_INFO, vscr_ratchet_group_message_get_type(msg1));
    TEST_ASSERT_EQUAL(0, vscr_ratchet_group_message_get_counter(msg1));
    TEST_ASSERT_EQUAL(msg1->message_pb.group_info.epoch, vscr_ratchet_group_message_get_epoch(msg1));
    TEST_ASSERT_EQUAL_DATA(vsc_data_empty(), vscr_ratchet_group_message_get_sender_id(msg1));

    vscr_ratchet_group_message_destroy(&msg1);
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
    RUN_TEST(test__methods__fixed_regular_msg__should_return_correct_values);
    RUN_TEST(test__methods__fixed_group_info_msg__should_return_correct_values);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
