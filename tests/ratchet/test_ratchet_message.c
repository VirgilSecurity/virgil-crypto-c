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

#define TEST_DEPENDENCIES_AVAILABLE VSCR_RATCHET
#if TEST_DEPENDENCIES_AVAILABLE

#include "virgil/crypto/ratchet/private/vscr_ratchet_message_defs.h"
#include "virgil/crypto/ratchet/vscr_ratchet_message.h"
#include "test_data_ratchet_message.h"

// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------

static bool
reg_msg_cmp(RegularMessage *msg1, RegularMessage *msg2) {

    return msg1->version == msg2->version && msg1->counter == msg2->counter &&
           memcmp(msg1->public_key, msg2->public_key, sizeof(msg1->public_key)) == 0 &&
           vsc_buffer_len(msg1->cipher_text.arg) == vsc_buffer_len(msg2->cipher_text.arg) &&
           memcmp(vsc_buffer_bytes(msg1->cipher_text.arg), vsc_buffer_bytes(msg2->cipher_text.arg),
                   vsc_buffer_len(msg1->cipher_text.arg)) == 0;
}

static bool
prekey_msg_cmp(PrekeyMessage *msg1, PrekeyMessage *msg2) {

    return msg1->version == msg2->version &&
           memcmp(msg1->sender_identity_key, msg2->sender_identity_key, sizeof(msg1->sender_identity_key)) == 0 &&
           memcmp(msg1->sender_ephemeral_key, msg2->sender_ephemeral_key, sizeof(msg1->sender_ephemeral_key)) == 0 &&
           memcmp(msg1->receiver_long_term_key, msg2->receiver_long_term_key, sizeof(msg1->receiver_long_term_key)) ==
                   0 &&
           memcmp(msg1->receiver_one_time_key, msg2->receiver_one_time_key, sizeof(msg1->receiver_one_time_key)) == 0 &&
           reg_msg_cmp(&msg1->regular_message, &msg2->regular_message);
}

static bool
msg_cmp(vscr_ratchet_message_t *msg1, vscr_ratchet_message_t *msg2) {
    if (msg1->message_pb.version != msg2->message_pb.version ||
            msg1->message_pb.has_prekey_message != msg2->message_pb.has_prekey_message ||
            msg1->message_pb.has_regular_message != msg2->message_pb.has_regular_message)
        return false;

    if (msg1->message_pb.has_regular_message) {
        return reg_msg_cmp(&msg1->message_pb.regular_message, &msg2->message_pb.regular_message);
    } else if (msg1->message_pb.has_prekey_message) {
        return prekey_msg_cmp(&msg1->message_pb.prekey_message, &msg2->message_pb.prekey_message);
    } else {
        TEST_ASSERT(false);
    }

    return false;
}

void
test__serialize_deserialize__fixed_regular_msg__should_be_equal(void) {
    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new();

    msg1->message_pb.has_regular_message = true;
    msg1->message_pb.version = 5;
    msg1->message_pb.regular_message.version = 11;
    msg1->message_pb.regular_message.counter = 17;

    memcpy(msg1->message_pb.regular_message.public_key, test_data_ratchet_message_raw_key1.bytes,
            test_data_ratchet_message_raw_key1.len);
    msg1->message_pb.regular_message.cipher_text.arg = vsc_buffer_new_with_data(test_data_ratchet_message_data);

    size_t len = vscr_ratchet_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscr_ratchet_message_serialize(msg1, buff);

    vscr_error_ctx_t error_ctx;
    vscr_error_ctx_reset(&error_ctx);

    vscr_ratchet_message_t *msg2 = vscr_ratchet_message_deserialize(vsc_buffer_data(buff), &error_ctx);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, error_ctx.error);

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
    msg1->message_pb.prekey_message.version = 11;
    msg1->message_pb.prekey_message.regular_message.version = 10;
    msg1->message_pb.prekey_message.regular_message.counter = 17;

    memcpy(msg1->message_pb.prekey_message.receiver_one_time_key, test_data_ratchet_message_raw_key1.bytes,
            test_data_ratchet_message_raw_key1.len);
    msg1->message_pb.prekey_message.has_receiver_one_time_key = true;

    memcpy(msg1->message_pb.prekey_message.receiver_long_term_key, test_data_ratchet_message_raw_key2.bytes,
            test_data_ratchet_message_raw_key2.len);

    memcpy(msg1->message_pb.prekey_message.sender_identity_key, test_data_ratchet_message_raw_key3.bytes,
            test_data_ratchet_message_raw_key3.len);

    memcpy(msg1->message_pb.prekey_message.sender_ephemeral_key, test_data_ratchet_message_raw_key4.bytes,
            test_data_ratchet_message_raw_key4.len);

    memcpy(msg1->message_pb.prekey_message.regular_message.public_key, test_data_ratchet_message_raw_key5.bytes,
            test_data_ratchet_message_raw_key5.len);
    msg1->message_pb.prekey_message.regular_message.cipher_text.arg =
            vsc_buffer_new_with_data(test_data_ratchet_message_data);

    size_t len = vscr_ratchet_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscr_ratchet_message_serialize(msg1, buff);

    vscr_error_ctx_t error_ctx;
    vscr_error_ctx_reset(&error_ctx);

    vscr_ratchet_message_t *msg2 = vscr_ratchet_message_deserialize(vsc_buffer_data(buff), &error_ctx);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, error_ctx.error);

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
    msg1->message_pb.prekey_message.version = 11;
    msg1->message_pb.prekey_message.regular_message.version = 10;
    msg1->message_pb.prekey_message.regular_message.counter = 17;

    msg1->message_pb.prekey_message.has_receiver_one_time_key = false;

    memcpy(msg1->message_pb.prekey_message.receiver_long_term_key, test_data_ratchet_message_raw_key1.bytes,
            test_data_ratchet_message_raw_key1.len);

    memcpy(msg1->message_pb.prekey_message.sender_identity_key, test_data_ratchet_message_raw_key2.bytes,
            test_data_ratchet_message_raw_key2.len);

    memcpy(msg1->message_pb.prekey_message.sender_ephemeral_key, test_data_ratchet_message_raw_key3.bytes,
            test_data_ratchet_message_raw_key3.len);

    memcpy(msg1->message_pb.prekey_message.regular_message.public_key, test_data_ratchet_message_raw_key4.bytes,
            test_data_ratchet_message_raw_key4.len);
    msg1->message_pb.prekey_message.regular_message.cipher_text.arg =
            vsc_buffer_new_with_data(test_data_ratchet_message_data);

    size_t len = vscr_ratchet_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscr_ratchet_message_serialize(msg1, buff);

    vscr_error_ctx_t error_ctx;
    vscr_error_ctx_reset(&error_ctx);

    vscr_ratchet_message_t *msg2 = vscr_ratchet_message_deserialize(vsc_buffer_data(buff), &error_ctx);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, error_ctx.error);

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
    msg1->message_pb.prekey_message.version = 11;
    msg1->message_pb.prekey_message.regular_message.version = 10;
    msg1->message_pb.prekey_message.regular_message.counter = 17;

    memcpy(msg1->message_pb.prekey_message.receiver_one_time_key, test_data_ratchet_message_raw_key1.bytes,
            test_data_ratchet_message_raw_key1.len);
    msg1->message_pb.prekey_message.has_receiver_one_time_key = true;

    memcpy(msg1->message_pb.prekey_message.receiver_long_term_key, test_data_ratchet_message_raw_key2.bytes,
            test_data_ratchet_message_raw_key2.len);

    memcpy(msg1->message_pb.prekey_message.sender_identity_key, test_data_ratchet_message_raw_key3.bytes,
            test_data_ratchet_message_raw_key3.len);

    memcpy(msg1->message_pb.prekey_message.sender_ephemeral_key, test_data_ratchet_message_raw_key4.bytes,
            test_data_ratchet_message_raw_key4.len);

    memcpy(msg1->message_pb.prekey_message.regular_message.public_key, test_data_ratchet_message_raw_key5.bytes,
            test_data_ratchet_message_raw_key5.len);
    msg1->message_pb.prekey_message.regular_message.cipher_text.arg =
            vsc_buffer_new_with_data(test_data_ratchet_message_data);

    TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(msg1));

    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_raw_key2, vscr_ratchet_message_get_long_term_public_key(msg1));
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_raw_key1, vscr_ratchet_message_get_one_time_public_key(msg1));

    vscr_ratchet_message_destroy(&msg1);
}

void
test__methods__fixed_prekey_msg_no_one_time__should_return_correct_values(void) {
    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new();

    msg1->message_pb.has_prekey_message = true;
    msg1->message_pb.version = 5;
    msg1->message_pb.prekey_message.version = 11;
    msg1->message_pb.prekey_message.regular_message.version = 10;
    msg1->message_pb.prekey_message.regular_message.counter = 17;

    msg1->message_pb.prekey_message.has_receiver_one_time_key = false;

    memcpy(msg1->message_pb.prekey_message.receiver_long_term_key, test_data_ratchet_message_raw_key1.bytes,
            test_data_ratchet_message_raw_key1.len);

    memcpy(msg1->message_pb.prekey_message.sender_identity_key, test_data_ratchet_message_raw_key2.bytes,
            test_data_ratchet_message_raw_key2.len);

    memcpy(msg1->message_pb.prekey_message.sender_ephemeral_key, test_data_ratchet_message_raw_key3.bytes,
            test_data_ratchet_message_raw_key3.len);

    memcpy(msg1->message_pb.prekey_message.regular_message.public_key, test_data_ratchet_message_raw_key4.bytes,
            test_data_ratchet_message_raw_key4.len);
    msg1->message_pb.prekey_message.regular_message.cipher_text.arg =
            vsc_buffer_new_with_data(test_data_ratchet_message_data);

    TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(msg1));

    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_raw_key1, vscr_ratchet_message_get_long_term_public_key(msg1));

    TEST_ASSERT_EQUAL(0, vscr_ratchet_message_get_one_time_public_key(msg1).len);

    vscr_ratchet_message_destroy(&msg1);
}

void
test__methods__fixed_regular_msg__should_return_correct_values(void) {
    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new();

    msg1->message_pb.has_regular_message = true;
    msg1->message_pb.version = 5;
    msg1->message_pb.regular_message.version = 11;
    msg1->message_pb.regular_message.counter = 17;

    memcpy(msg1->message_pb.regular_message.public_key, test_data_ratchet_message_raw_key1.bytes,
            test_data_ratchet_message_raw_key1.len);
    msg1->message_pb.regular_message.cipher_text.arg = vsc_buffer_new_with_data(test_data_ratchet_message_data);

    TEST_ASSERT_EQUAL(vscr_msg_type_REGULAR, vscr_ratchet_message_get_type(msg1));
    TEST_ASSERT_EQUAL(0, vscr_ratchet_message_get_one_time_public_key(msg1).len);
    TEST_ASSERT_EQUAL(0, vscr_ratchet_message_get_long_term_public_key(msg1).len);

    vscr_ratchet_message_destroy(&msg1);
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
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
