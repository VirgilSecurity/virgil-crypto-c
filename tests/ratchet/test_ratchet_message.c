//  Copyright (C) 2015-2018 Virgil Security Inc.
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

#include <vscr_ratchet.h>
#include <virgil/crypto/ratchet/private/vscr_ratchet_message_defs.h>
#include <virgil/crypto/ratchet/vscr_ratchet_message.h>
#include <RatchetModels.pb.h>
#include "test_data_ratchet_session.h"
#include "test_data_ratchet.h"

// --------------------------------------------------------------------------
//  Should have it to prevent linkage erros in MSVC.
// --------------------------------------------------------------------------
// clang-format off
void setUp(void) { }
void tearDown(void) { }
void suiteSetUp(void) { }
int suiteTearDown(int num_failures) { return num_failures; }
// clang-format on


// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------

static bool
reg_msg_cmp(RegularMessage *msg1, RegularMessage *msg2) {

    return msg1->version == msg2->version && msg1->counter == msg2->counter &&
           memcmp(msg1->public_key, msg2->public_key, sizeof(msg1->public_key)) == 0 &&
           msg1->cipher_text.size == msg2->cipher_text.size &&
           memcmp(msg1->cipher_text.bytes, msg2->cipher_text.bytes, msg1->cipher_text.size) == 0;
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
            msg1->message_pb.which_message != msg2->message_pb.which_message)
        return false;

    if (msg1->message_pb.which_message == Message_regular_message_tag) {
        return reg_msg_cmp(&msg1->message_pb.message.regular_message, &msg2->message_pb.message.regular_message);
    } else if (msg1->message_pb.which_message == Message_prekey_message_tag) {
        return prekey_msg_cmp(&msg1->message_pb.message.prekey_message, &msg2->message_pb.message.prekey_message);
    } else {
        TEST_ASSERT(false);
    }

    return false;
}

void
test__serialize_deserialize__fixed_fields__should_be_equal(void) {
    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new();

    msg1->message_pb.which_message = Message_regular_message_tag;
    msg1->message_pb.version = 5;
    msg1->message_pb.message.regular_message.version = 11;
    msg1->message_pb.message.regular_message.counter = 17;

    memcpy(msg1->message_pb.message.regular_message.public_key, test_ratchet_session_bob_one_time_public_key.bytes,
            test_ratchet_session_bob_one_time_public_key.len);
    memcpy(msg1->message_pb.message.regular_message.cipher_text.bytes, test_ratchet_plain_text1.bytes,
            test_ratchet_plain_text1.len);
    msg1->message_pb.message.regular_message.cipher_text.size = (pb_size_t)test_ratchet_plain_text1.len;

    size_t len = vscr_ratchet_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscr_ratchet_message_serialize(msg1, buff);

    vscr_error_ctx_t error_ctx;
    vscr_error_ctx_reset(&error_ctx);

    vscr_ratchet_message_t *msg2 = vscr_ratchet_message_deserialize(vsc_buffer_data(buff), &error_ctx);

    TEST_ASSERT(msg_cmp(msg1, msg2));

    vscr_ratchet_message_destroy(&msg1);
    vscr_ratchet_message_destroy(&msg2);
    vsc_buffer_destroy(&buff);
}

bool
buffer_decode_callback(pb_istream_t *stream, const pb_field_t *field, void **arg) {
    VSCR_UNUSED(stream);
    VSCR_UNUSED(field);
    VSCR_UNUSED(arg);

    *arg = vsc_buffer_new_with_capacity(stream->bytes_left);
    memcpy(vsc_buffer_unused_bytes(*arg), stream->state, stream->bytes_left);
    vsc_buffer_inc_used(*arg, stream->bytes_left);
    stream->bytes_left = 0;

    return true;
}

bool
buffer_encode_callback(pb_ostream_t *stream, const pb_field_t *field, void *const *arg) {
    VSCR_UNUSED(stream);
    VSCR_UNUSED(field);
    VSCR_UNUSED(arg);

    if (!pb_encode_tag_for_field(stream, field))
        return false;

    return pb_encode_string(stream, vsc_buffer_bytes(*arg), vsc_buffer_len(*arg));
}


// static void
// set_pb_encode_callback(Test *msg) {
//
//    msg->cipher_text.funcs.encode = buffer_encode_callback;
//}
//
// static void
// set_pb_decode_callback(Test *msg) {
//
//    msg->text1.funcs.decode = buffer_decode_callback;
//}
//
// void
// test__test(void) {
//    Test test1 = Test_init_zero;
//    //    set_pb_encode_callback(&test1);
//
//    memcpy(test1.text1.bytes, test_ratchet_plain_text1.bytes, test_ratchet_plain_text1.len);
//    test1.text1.size = test_ratchet_plain_text1.len;
//
//    memcpy(test1.text2.bytes, test_ratchet_plain_text2.bytes, test_ratchet_plain_text2.len);
//    test1.text2.size = test_ratchet_plain_text2.len;
//
//    Test test2 = Test_init_zero;
//    //    set_pb_decode_callback(&test2);
//
//
//    //            vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(test_ratchet_plain_text1.len);
//    //    test1.cipher_text.arg = buffer;
//    //    memcpy(vsc_buffer_unused_bytes(buffer), test_ratchet_plain_text1.bytes, test_ratchet_plain_text1.len);
//    //    vsc_buffer_inc_used(buffer, test_ratchet_plain_text1.len);
//
//    byte buff[500];
//
//    pb_ostream_t ostream = pb_ostream_from_buffer(buff, sizeof(buff));
//
//    TEST_ASSERT(pb_encode(&ostream, Test_fields, &test1));
//
//    pb_istream_t istream = pb_istream_from_buffer(buff, ostream.bytes_written);
//
//    TEST_ASSERT(pb_decode(&istream, Test_fields, &test2));
//
//    TEST_ASSERT_EQUAL(test1.text1.size, test2.text1.size);
//    TEST_ASSERT_EQUAL_MEMORY(test1.text1.bytes, test2.text1.bytes, test1.text1.size);
//
//    TEST_ASSERT_EQUAL(test1.text2.size, test2.text2.size);
//    TEST_ASSERT_EQUAL_MEMORY(test1.text2.bytes, test2.text2.bytes, test1.text2.size);
//
//    //    vsc_buffer_destroy(&buffer);
//}

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

    RUN_TEST(test__serialize_deserialize__fixed_fields__should_be_equal);
    //    RUN_TEST(test__test);

    return UNITY_END();
}
