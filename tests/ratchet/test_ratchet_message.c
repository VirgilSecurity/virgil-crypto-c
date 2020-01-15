//  Copyright (C) 2015-2020 Virgil Security, Inc.
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

#include "vscr_memory.h"
#include "vscr_ratchet_common_hidden.h"
#include "vscr_ratchet_message_defs.h"
#include "vscr_ratchet_message.h"
#include "test_data_ratchet_message.h"

// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------

static bool
reg_msg_cmp(vscr_RegularMessage *msg1, vscr_RegularMessage *msg2) {

    return msg1->header.size == msg2->header.size &&
           memcmp(msg1->header.bytes, msg2->header.bytes, msg1->header.size) == 0 &&
           msg1->cipher_text->size == msg2->cipher_text->size &&
           memcmp(msg1->cipher_text->bytes, msg2->cipher_text->bytes, msg1->cipher_text->size) == 0;
}

static bool
prekey_msg_cmp(vscr_PrekeyMessage *msg1, vscr_PrekeyMessage *msg2) {

    return memcmp(msg1->sender_identity_key, msg2->sender_identity_key, sizeof(msg1->sender_identity_key)) == 0 &&
           memcmp(msg1->sender_ephemeral_key, msg2->sender_ephemeral_key, sizeof(msg1->sender_ephemeral_key)) == 0 &&
           memcmp(msg1->receiver_long_term_key, msg2->receiver_long_term_key, sizeof(msg1->receiver_long_term_key)) ==
                   0 &&
           memcmp(msg1->receiver_one_time_key, msg2->receiver_one_time_key, sizeof(msg1->receiver_one_time_key)) == 0;
}

static bool
msg_cmp(vscr_ratchet_message_t *msg1, vscr_ratchet_message_t *msg2) {
    if (msg1->message_pb.version != msg2->message_pb.version ||
            msg1->message_pb.has_prekey_message != msg2->message_pb.has_prekey_message)
        return false;

    if (!reg_msg_cmp(&msg1->message_pb.regular_message, &msg2->message_pb.regular_message)) {
        return false;
    }

    return prekey_msg_cmp(&msg1->message_pb.prekey_message, &msg2->message_pb.prekey_message);
}

void
test__serialize_deserialize__fixed_regular_msg__should_be_equal(void) {
    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new();

    msg1->message_pb.has_prekey_message = false;
    msg1->message_pb.version = 5;
    msg1->message_pb.version = 11;

    msg1->header_pb->counter = 17;
    msg1->header_pb->prev_chain_count = 42;
    memcpy(msg1->header_pb->public_key, test_data_ratchet_message_raw_key1.bytes,
            test_data_ratchet_message_raw_key1.len);

    pb_ostream_t ostream = pb_ostream_from_buffer(
            msg1->message_pb.regular_message.header.bytes, sizeof(msg1->message_pb.regular_message.header.bytes));
    TEST_ASSERT(pb_encode(&ostream, vscr_RegularMessageHeader_fields, msg1->header_pb));
    msg1->message_pb.regular_message.header.size = ostream.bytes_written;

    msg1->message_pb.regular_message.cipher_text =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(test_data_ratchet_message_data.len));
    msg1->message_pb.regular_message.cipher_text->size = test_data_ratchet_message_data.len;
    memcpy(msg1->message_pb.regular_message.cipher_text->bytes, test_data_ratchet_message_data.bytes,
            test_data_ratchet_message_data.len);

    size_t len = vscr_ratchet_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscr_ratchet_message_serialize(msg1, buff);

    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_message_t *msg2 = vscr_ratchet_message_deserialize(vsc_buffer_data(buff), &error);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    TEST_ASSERT(msg_cmp(msg1, msg2));

    vscr_ratchet_message_destroy(&msg1);
    vscr_ratchet_message_destroy(&msg2);
    vsc_buffer_destroy(&buff);
}

void
test__serialize_deserialize__fixed_prekey_msg__should_be_equal(void) {
    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new();

    msg1->message_pb.has_prekey_message = true;
    msg1->message_pb.version = 5;

    memcpy(msg1->message_pb.prekey_message.receiver_one_time_key, test_data_ratchet_message_raw_key1.bytes,
            test_data_ratchet_message_raw_key1.len);
    msg1->message_pb.prekey_message.has_receiver_one_time_key = true;

    memcpy(msg1->message_pb.prekey_message.receiver_long_term_key, test_data_ratchet_message_raw_key2.bytes,
            test_data_ratchet_message_raw_key2.len);

    memcpy(msg1->message_pb.prekey_message.sender_identity_key, test_data_ratchet_message_raw_key3.bytes,
            test_data_ratchet_message_raw_key3.len);

    memcpy(msg1->message_pb.prekey_message.sender_ephemeral_key, test_data_ratchet_message_raw_key4.bytes,
            test_data_ratchet_message_raw_key4.len);

    msg1->header_pb->counter = 17;
    memcpy(msg1->header_pb->public_key, test_data_ratchet_message_raw_key5.bytes,
            test_data_ratchet_message_raw_key5.len);

    pb_ostream_t ostream = pb_ostream_from_buffer(
            msg1->message_pb.regular_message.header.bytes, sizeof(msg1->message_pb.regular_message.header.bytes));
    TEST_ASSERT(pb_encode(&ostream, vscr_RegularMessageHeader_fields, msg1->header_pb));
    msg1->message_pb.regular_message.header.size = ostream.bytes_written;

    msg1->message_pb.regular_message.cipher_text =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(test_data_ratchet_message_data.len));
    msg1->message_pb.regular_message.cipher_text->size = test_data_ratchet_message_data.len;
    memcpy(msg1->message_pb.regular_message.cipher_text->bytes, test_data_ratchet_message_data.bytes,
            test_data_ratchet_message_data.len);

    size_t len = vscr_ratchet_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscr_ratchet_message_serialize(msg1, buff);

    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_message_t *msg2 = vscr_ratchet_message_deserialize(vsc_buffer_data(buff), &error);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    TEST_ASSERT(msg_cmp(msg1, msg2));

    vscr_ratchet_message_destroy(&msg1);
    vscr_ratchet_message_destroy(&msg2);
    vsc_buffer_destroy(&buff);
}

void
test__serialize_deserialize__fixed_prekey_msg_no_one_time__should_be_equal(void) {
    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new();

    msg1->message_pb.has_prekey_message = true;
    msg1->message_pb.version = 5;

    msg1->message_pb.prekey_message.has_receiver_one_time_key = false;

    memcpy(msg1->message_pb.prekey_message.receiver_long_term_key, test_data_ratchet_message_raw_key1.bytes,
            test_data_ratchet_message_raw_key1.len);

    memcpy(msg1->message_pb.prekey_message.sender_identity_key, test_data_ratchet_message_raw_key2.bytes,
            test_data_ratchet_message_raw_key2.len);

    memcpy(msg1->message_pb.prekey_message.sender_ephemeral_key, test_data_ratchet_message_raw_key3.bytes,
            test_data_ratchet_message_raw_key3.len);

    memcpy(msg1->header_pb->public_key, test_data_ratchet_message_raw_key4.bytes,
            test_data_ratchet_message_raw_key4.len);

    msg1->header_pb->counter = 17;
    pb_ostream_t ostream = pb_ostream_from_buffer(
            msg1->message_pb.regular_message.header.bytes, sizeof(msg1->message_pb.regular_message.header.bytes));
    TEST_ASSERT(pb_encode(&ostream, vscr_RegularMessageHeader_fields, msg1->header_pb));
    msg1->message_pb.regular_message.header.size = ostream.bytes_written;

    msg1->message_pb.regular_message.cipher_text =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(test_data_ratchet_message_data.len));
    msg1->message_pb.regular_message.cipher_text->size = test_data_ratchet_message_data.len;
    memcpy(msg1->message_pb.regular_message.cipher_text->bytes, test_data_ratchet_message_data.bytes,
            test_data_ratchet_message_data.len);

    size_t len = vscr_ratchet_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscr_ratchet_message_serialize(msg1, buff);

    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_message_t *msg2 = vscr_ratchet_message_deserialize(vsc_buffer_data(buff), &error);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    TEST_ASSERT(msg_cmp(msg1, msg2));

    vscr_ratchet_message_destroy(&msg1);
    vscr_ratchet_message_destroy(&msg2);
    vsc_buffer_destroy(&buff);
}

void
test__methods__fixed_prekey_msg__should_return_correct_values(void) {
    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new();

    msg1->message_pb.has_prekey_message = true;
    msg1->message_pb.version = 5;
    msg1->header_pb->counter = 17;

    memcpy(msg1->message_pb.prekey_message.receiver_one_time_key, test_data_ratchet_message_raw_key1.bytes,
            test_data_ratchet_message_raw_key1.len);
    msg1->message_pb.prekey_message.has_receiver_one_time_key = true;

    memcpy(msg1->message_pb.prekey_message.receiver_long_term_key, test_data_ratchet_message_raw_key2.bytes,
            test_data_ratchet_message_raw_key2.len);

    memcpy(msg1->message_pb.prekey_message.sender_identity_key, test_data_ratchet_message_raw_key3.bytes,
            test_data_ratchet_message_raw_key3.len);

    memcpy(msg1->message_pb.prekey_message.sender_ephemeral_key, test_data_ratchet_message_raw_key4.bytes,
            test_data_ratchet_message_raw_key4.len);

    memcpy(msg1->header_pb->public_key, test_data_ratchet_message_raw_key5.bytes,
            test_data_ratchet_message_raw_key5.len);

    msg1->message_pb.regular_message.cipher_text =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(test_data_ratchet_message_data.len));
    msg1->message_pb.regular_message.cipher_text->size = test_data_ratchet_message_data.len;
    memcpy(msg1->message_pb.regular_message.cipher_text->bytes, test_data_ratchet_message_data.bytes,
            test_data_ratchet_message_data.len);

    TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(msg1));
    TEST_ASSERT_EQUAL(0, vscr_ratchet_message_get_counter(msg1));

    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_raw_key2, vscr_ratchet_message_get_long_term_public_key(msg1));
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_raw_key1, vscr_ratchet_message_get_one_time_public_key(msg1));

    vscr_ratchet_message_destroy(&msg1);
}

void
test__methods__fixed_prekey_msg_no_one_time__should_return_correct_values(void) {
    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new();

    msg1->message_pb.has_prekey_message = true;
    msg1->message_pb.version = 5;
    msg1->header_pb->counter = 17;

    msg1->message_pb.prekey_message.has_receiver_one_time_key = false;

    memcpy(msg1->message_pb.prekey_message.receiver_long_term_key, test_data_ratchet_message_raw_key1.bytes,
            test_data_ratchet_message_raw_key1.len);

    memcpy(msg1->message_pb.prekey_message.sender_identity_key, test_data_ratchet_message_raw_key2.bytes,
            test_data_ratchet_message_raw_key2.len);

    memcpy(msg1->message_pb.prekey_message.sender_ephemeral_key, test_data_ratchet_message_raw_key3.bytes,
            test_data_ratchet_message_raw_key3.len);

    memcpy(msg1->header_pb->public_key, test_data_ratchet_message_raw_key4.bytes,
            test_data_ratchet_message_raw_key4.len);

    msg1->message_pb.regular_message.cipher_text =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(test_data_ratchet_message_data.len));
    msg1->message_pb.regular_message.cipher_text->size = test_data_ratchet_message_data.len;
    memcpy(msg1->message_pb.regular_message.cipher_text->bytes, test_data_ratchet_message_data.bytes,
            test_data_ratchet_message_data.len);

    TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(msg1));
    TEST_ASSERT_EQUAL(0, vscr_ratchet_message_get_counter(msg1));

    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_raw_key1, vscr_ratchet_message_get_long_term_public_key(msg1));

    TEST_ASSERT_EQUAL(0, vscr_ratchet_message_get_one_time_public_key(msg1).len);

    vscr_ratchet_message_destroy(&msg1);
}

void
test__methods__fixed_regular_msg__should_return_correct_values(void) {
    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new();

    msg1->message_pb.has_prekey_message = false;
    msg1->message_pb.version = 5;
    msg1->header_pb->counter = 17;

    memcpy(msg1->header_pb->public_key, test_data_ratchet_message_raw_key1.bytes,
            test_data_ratchet_message_raw_key1.len);

    msg1->message_pb.regular_message.cipher_text =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(test_data_ratchet_message_data.len));
    msg1->message_pb.regular_message.cipher_text->size = test_data_ratchet_message_data.len;
    memcpy(msg1->message_pb.regular_message.cipher_text->bytes, test_data_ratchet_message_data.bytes,
            test_data_ratchet_message_data.len);

    TEST_ASSERT_EQUAL(vscr_msg_type_REGULAR, vscr_ratchet_message_get_type(msg1));
    TEST_ASSERT_EQUAL(0, vscr_ratchet_message_get_one_time_public_key(msg1).len);
    TEST_ASSERT_EQUAL(0, vscr_ratchet_message_get_long_term_public_key(msg1).len);
    TEST_ASSERT_EQUAL(msg1->header_pb->counter, vscr_ratchet_message_get_counter(msg1));

    vscr_ratchet_message_destroy(&msg1);
}

void
test__serialize_deserialize__prekey_msg_overflow__should_be_equal(void) {
    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new();

    msg1->message_pb.version = UINT32_MAX;
    msg1->message_pb.has_prekey_message = true;
    msg1->message_pb.prekey_message.has_receiver_one_time_key = true;

    msg1->message_pb.regular_message.cipher_text =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN));
    msg1->message_pb.regular_message.cipher_text->size = vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN;

    pb_ostream_t ostream = pb_ostream_from_buffer(
            msg1->message_pb.regular_message.header.bytes, sizeof(msg1->message_pb.regular_message.header.bytes));
    TEST_ASSERT(pb_encode(&ostream, vscr_RegularMessageHeader_fields, msg1->header_pb));
    msg1->message_pb.regular_message.header.size = ostream.bytes_written;

    size_t len = vscr_ratchet_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscr_ratchet_message_serialize(msg1, buff);

    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_message_t *msg2 = vscr_ratchet_message_deserialize(vsc_buffer_data(buff), &error);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    TEST_ASSERT(msg_cmp(msg1, msg2));

    vscr_ratchet_message_destroy(&msg1);
    vscr_ratchet_message_destroy(&msg2);
    vsc_buffer_destroy(&buff);
}

void
test__serialize_deserialize__regular_msg_overflow__should_be_equal(void) {
    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new();

    msg1->message_pb.version = UINT32_MAX;
    msg1->message_pb.has_prekey_message = false;

    msg1->message_pb.regular_message.cipher_text =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN));
    msg1->message_pb.regular_message.cipher_text->size = vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN;

    pb_ostream_t ostream = pb_ostream_from_buffer(
            msg1->message_pb.regular_message.header.bytes, sizeof(msg1->message_pb.regular_message.header.bytes));
    TEST_ASSERT(pb_encode(&ostream, vscr_RegularMessageHeader_fields, msg1->header_pb));
    msg1->message_pb.regular_message.header.size = ostream.bytes_written;

    size_t len = vscr_ratchet_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscr_ratchet_message_serialize(msg1, buff);

    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_message_t *msg2 = vscr_ratchet_message_deserialize(vsc_buffer_data(buff), &error);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    TEST_ASSERT(msg_cmp(msg1, msg2));

    vscr_ratchet_message_destroy(&msg1);
    vscr_ratchet_message_destroy(&msg2);
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
    RUN_TEST(test__serialize_deserialize__fixed_prekey_msg__should_be_equal);
    RUN_TEST(test__serialize_deserialize__fixed_prekey_msg_no_one_time__should_be_equal);
    RUN_TEST(test__methods__fixed_prekey_msg__should_return_correct_values);
    RUN_TEST(test__methods__fixed_prekey_msg_no_one_time__should_return_correct_values);
    RUN_TEST(test__methods__fixed_regular_msg__should_return_correct_values);
    RUN_TEST(test__serialize_deserialize__prekey_msg_overflow__should_be_equal);
    RUN_TEST(test__serialize_deserialize__regular_msg_overflow__should_be_equal);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
