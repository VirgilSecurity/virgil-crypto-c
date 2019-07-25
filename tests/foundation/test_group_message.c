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

#include <virgil/crypto/foundation/private/vscf_message_cipher.h>
#include "unity.h"
#include "test_utils.h"

#define TEST_DEPENDENCIES_AVAILABLE VSCF_GROUP_SESSION_MESSAGE
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_group_session.h"
#include "vscf_memory.h"
#include "test_data_group_session.h"
#include "vscf_ctr_drbg.h"
#include "vscf_group_session_message.h"
#include "vscf_group_session_message_internal.h"
#include "vscf_group_session_message_defs.h"
#include "pb_encode.h"
#include "pb_decode.h"

// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------

static bool
reg_msg_hdr_cmp(vscf_RegularGroupMessageHeader *msg1, vscf_RegularGroupMessageHeader *msg2) {
    return memcmp(msg1->session_id, msg2->session_id, sizeof(msg1->session_id)) == 0 &&
           memcmp(msg1->sender_id, msg2->sender_id, sizeof(msg1->sender_id)) == 0 &&
           memcmp(msg1->salt, msg2->salt, sizeof(msg1->salt)) == 0 && msg1->epoch == msg2->epoch;
}

static bool
reg_msg_cmp(vscf_RegularGroupMessage *msg1, vscf_RegularGroupMessage *msg2) {

    return msg1->cipher_text->size == msg2->cipher_text->size &&
           memcmp(&msg1->header, &msg2->header, sizeof(msg1->header)) == 0 &&
           memcmp(&msg1->signature, &msg2->signature, sizeof(msg1->signature)) == 0 &&
           memcmp(msg1->cipher_text->bytes, msg2->cipher_text->bytes, msg1->cipher_text->size) == 0;
}

static bool
grp_info_msg_cmp(vscf_MessageGroupInfo *msg1, vscf_MessageGroupInfo *msg2) {

    if (memcmp(msg1->key, msg2->key, sizeof(msg1->key)) != 0)
        return false;

    if (msg1->epoch != msg2->epoch)
        return false;

    if (memcmp(msg1->session_id, msg2->session_id, sizeof(msg1->session_id)) != 0)
        return false;

    return true;
}

static bool
msg_cmp(vscf_group_session_message_t *msg1, vscf_group_session_message_t *msg2) {
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
    vscf_group_session_message_t *msg1 = vscf_group_session_message_new();

    vscf_group_session_message_set_type(msg1, vscf_group_msg_type_REGULAR);

    msg1->message_pb.version = 5;
    msg1->header_pb->epoch = 17;

    memcpy(msg1->header_pb->session_id, test_data_group_session_session_id.bytes,
            test_data_group_session_session_id.len);
    memcpy(msg1->header_pb->salt, test_data_group_session_session_salt.bytes, test_data_group_session_session_salt.len);
    memcpy(msg1->message_pb.regular_message.signature, test_data_group_session_session_signature.bytes,
            test_data_group_session_session_signature.len);
    memcpy(msg1->header_pb->sender_id, test_data_group_session_session_sender_id.bytes,
            test_data_group_session_session_sender_id.len);

    msg1->message_pb.regular_message.cipher_text =
            vscf_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(test_data_group_session_session_cipher_text.len));
    msg1->message_pb.regular_message.cipher_text->size = test_data_group_session_session_cipher_text.len;
    memcpy(msg1->message_pb.regular_message.cipher_text->bytes, test_data_group_session_session_cipher_text.bytes,
            test_data_group_session_session_cipher_text.len);

    pb_ostream_t ostream = pb_ostream_from_buffer(
            msg1->message_pb.regular_message.header.bytes, sizeof(msg1->message_pb.regular_message.header.bytes));
    TEST_ASSERT(pb_encode(&ostream, vscf_RegularGroupMessageHeader_fields, msg1->header_pb));
    msg1->message_pb.regular_message.header.size = ostream.bytes_written;

    size_t len = vscf_group_session_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscf_group_session_message_serialize(msg1, buff);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_group_session_message_t *msg2 = vscf_group_session_message_deserialize(vsc_buffer_data(buff), &error);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_FALSE(vscf_error_has_error(&error));

    TEST_ASSERT(msg_cmp(msg1, msg2));

    vscf_group_session_message_destroy(&msg1);
    vscf_group_session_message_destroy(&msg2);
    vsc_buffer_destroy(&buff);
}

void
test__serialize_deserialize__fixed_group_info_msg__should_be_equal(void) {
    vscf_group_session_message_t *msg1 = vscf_group_session_message_new();

    vscf_group_session_message_set_type(msg1, vscf_group_msg_type_GROUP_INFO);

    msg1->message_pb.version = 5;

    msg1->message_pb.group_info.epoch = 3;
    memcpy(msg1->message_pb.group_info.session_id, test_data_group_session_session_id.bytes,
            test_data_group_session_session_id.len);
    memcpy(msg1->message_pb.group_info.key, test_data_group_session_session_key.bytes,
            test_data_group_session_session_key.len);

    size_t len = vscf_group_session_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscf_group_session_message_serialize(msg1, buff);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_group_session_message_t *msg2 = vscf_group_session_message_deserialize(vsc_buffer_data(buff), &error);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_FALSE(vscf_error_has_error(&error));

    TEST_ASSERT(msg_cmp(msg1, msg2));

    vscf_group_session_message_destroy(&msg1);
    vscf_group_session_message_destroy(&msg2);
    vsc_buffer_destroy(&buff);
}

void
test__serialize_deserialize__group_info_overflow__should_be_equal(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_group_session_message_t *msg1 = vscf_group_session_message_new();
    vscf_group_session_message_set_type(msg1, vscf_group_msg_type_GROUP_INFO);

    msg1->message_pb.version = UINT32_MAX;
    msg1->message_pb.group_info.epoch = UINT32_MAX;

    memcpy(msg1->message_pb.group_info.session_id, test_data_group_session_session_id.bytes,
            test_data_group_session_session_id.len);
    memcpy(msg1->message_pb.group_info.key, test_data_group_session_session_key.bytes,
            test_data_group_session_session_key.len);

    size_t len = vscf_group_session_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscf_group_session_message_serialize(msg1, buff);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_group_session_message_t *msg2 = vscf_group_session_message_deserialize(vsc_buffer_data(buff), &error);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_FALSE(vscf_error_has_error(&error));

    TEST_ASSERT(msg_cmp(msg1, msg2));

    vscf_group_session_message_destroy(&msg1);
    vscf_group_session_message_destroy(&msg2);
    vsc_buffer_destroy(&buff);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__serialize_deserialize__regular_overflow__should_be_equal(void) {
    vscf_group_session_message_t *msg1 = vscf_group_session_message_new();

    vscf_group_session_message_set_type(msg1, vscf_group_msg_type_REGULAR);

    msg1->message_pb.version = UINT32_MAX;
    msg1->header_pb->epoch = UINT32_MAX;

    memcpy(msg1->message_pb.group_info.session_id, test_data_group_session_session_id.bytes,
            test_data_group_session_session_id.len);
    memcpy(msg1->message_pb.group_info.key, test_data_group_session_session_key.bytes,
            test_data_group_session_session_key.len);

    msg1->message_pb.regular_message.cipher_text =
            vscf_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(vscf_group_session_MAX_PLAIN_TEXT_LEN + 32));
    msg1->message_pb.regular_message.cipher_text->size = vscf_group_session_MAX_PLAIN_TEXT_LEN + 32;

    pb_ostream_t ostream = pb_ostream_from_buffer(
            msg1->message_pb.regular_message.header.bytes, sizeof(msg1->message_pb.regular_message.header.bytes));
    TEST_ASSERT(pb_encode(&ostream, vscf_RegularGroupMessageHeader_fields, msg1->header_pb));
    msg1->message_pb.regular_message.header.size = ostream.bytes_written;

    size_t len = vscf_group_session_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscf_group_session_message_serialize(msg1, buff);

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_group_session_message_t *msg2 = vscf_group_session_message_deserialize(vsc_buffer_data(buff), &error);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_FALSE(vscf_error_has_error(&error));

    TEST_ASSERT(msg_cmp(msg1, msg2));

    vscf_group_session_message_destroy(&msg1);
    vscf_group_session_message_destroy(&msg2);
    vsc_buffer_destroy(&buff);
}

void
test__methods__fixed_regular_msg__should_return_correct_values(void) {
    vscf_group_session_message_t *msg1 = vscf_group_session_message_new();

    msg1->message_pb.version = 5;
    msg1->message_pb.has_regular_message = true;
    msg1->message_pb.has_group_info = false;

    msg1->header_pb = vscf_alloc(sizeof(vscf_RegularGroupMessageHeader));
    msg1->header_pb->epoch = 18;
    memcpy(msg1->header_pb->salt, test_data_group_session_session_salt.bytes, sizeof(msg1->header_pb->session_id));
    memcpy(msg1->header_pb->session_id, test_data_group_session_session_id.bytes, sizeof(msg1->header_pb->session_id));
    memcpy(msg1->header_pb->sender_id, test_data_group_session_session_sender_id.bytes,
            sizeof(msg1->header_pb->sender_id));

    TEST_ASSERT_EQUAL_DATA(test_data_group_session_session_id, vscf_group_session_message_get_session_id(msg1));
    TEST_ASSERT_EQUAL_DATA(test_data_group_session_session_sender_id, vscf_group_session_message_get_sender_id(msg1));
    TEST_ASSERT_EQUAL(vscf_group_msg_type_REGULAR, vscf_group_session_message_get_type(msg1));
    TEST_ASSERT_EQUAL(msg1->header_pb->epoch, vscf_group_session_message_get_epoch(msg1));

    vscf_group_session_message_destroy(&msg1);
}

void
test__methods__fixed_group_info_msg__should_return_correct_values(void) {
    vscf_group_session_message_t *msg1 = vscf_group_session_message_new();

    msg1->message_pb.version = 5;
    msg1->message_pb.has_regular_message = false;
    msg1->message_pb.has_group_info = true;
    memcpy(msg1->message_pb.group_info.session_id, test_data_group_session_session_id.bytes,
            sizeof(msg1->message_pb.group_info.session_id));

    msg1->message_pb.group_info.epoch = 39;

    TEST_ASSERT_EQUAL_DATA(test_data_group_session_session_id, vscf_group_session_message_get_session_id(msg1));
    TEST_ASSERT(vscf_group_session_message_get_sender_id(msg1).len == 0);
    TEST_ASSERT_EQUAL(vscf_group_msg_type_GROUP_INFO, vscf_group_session_message_get_type(msg1));
    TEST_ASSERT_EQUAL(msg1->message_pb.group_info.epoch, vscf_group_session_message_get_epoch(msg1));

    vscf_group_session_message_destroy(&msg1);
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
