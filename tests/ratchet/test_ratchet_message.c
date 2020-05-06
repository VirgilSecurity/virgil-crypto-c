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
pb_buffer_cmp(pb_bytes_array_t *arr1, pb_bytes_array_t *arr2) {
    if (arr1 == NULL && arr2 == NULL) {
        return true;
    }

    if (arr1 == NULL || arr2 == NULL) {
        return false;
    }

    if (arr1->size != arr2->size) {
        return false;
    }

    return memcmp(arr1->bytes, arr2->bytes, arr1->size) == 0;
}

static bool
reg_msg_cmp(vscr_RegularMessage *msg1, vscr_RegularMessage *msg2) {

    return msg1->header->size == msg2->header->size &&
           memcmp(msg1->header->bytes, msg2->header->bytes, msg1->header->size) == 0 &&
           msg1->cipher_text->size == msg2->cipher_text->size &&
           memcmp(msg1->cipher_text->bytes, msg2->cipher_text->bytes, msg1->cipher_text->size) == 0;
}

static bool
prekey_msg_cmp(vscr_PrekeyMessage *msg1, vscr_PrekeyMessage *msg2) {

    bool flag = msg1->has_receiver_one_time_key_id == msg2->has_receiver_one_time_key_id;

    flag = flag && msg1->has_pqc_info == msg2->has_pqc_info;

    if (msg1->has_pqc_info) {
        const vscr_PrekeyMessagePqcInfo *pqc_info1 = &msg1->pqc_info, *pqc_info2 = &msg2->pqc_info;

        flag = flag && pb_buffer_cmp(pqc_info1->encapsulated_key1, pqc_info2->encapsulated_key1) &&
               pb_buffer_cmp(pqc_info1->encapsulated_key2, pqc_info2->encapsulated_key2) &&
               pb_buffer_cmp(pqc_info1->encapsulated_key3, pqc_info2->encapsulated_key3) &&
               pb_buffer_cmp(pqc_info1->decapsulated_keys_signature, pqc_info2->decapsulated_keys_signature);
    }

    flag = flag &&
           memcmp(msg1->sender_identity_key_id, msg2->sender_identity_key_id, sizeof(msg1->sender_identity_key_id)) ==
                   0 &&
           memcmp(msg1->sender_ephemeral_key, msg2->sender_ephemeral_key, sizeof(msg1->sender_ephemeral_key)) == 0 &&
           memcmp(msg1->receiver_identity_key_id, msg2->receiver_identity_key_id,
                   sizeof(msg1->receiver_identity_key_id)) == 0 &&
           memcmp(msg1->receiver_long_term_key_id, msg2->receiver_long_term_key_id,
                   sizeof(msg1->receiver_long_term_key_id)) == 0 &&
           memcmp(msg1->receiver_one_time_key_id, msg2->receiver_one_time_key_id,
                   sizeof(msg1->receiver_one_time_key_id)) == 0;

    return flag;
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

    msg1->header_pb.counter = 17;
    msg1->header_pb.prev_chain_count = 42;
    memcpy(msg1->header_pb.public_key, test_data_ratchet_message_pub_key1.bytes,
            test_data_ratchet_message_pub_key1.len);

    size_t size = 0;
    pb_get_encoded_size(&size, vscr_RegularMessageHeader_fields, &msg1->header_pb);
    msg1->message_pb.regular_message.header = vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(size));

    pb_ostream_t ostream = pb_ostream_from_buffer(msg1->message_pb.regular_message.header->bytes, size);
    TEST_ASSERT(pb_encode(&ostream, vscr_RegularMessageHeader_fields, &msg1->header_pb));
    msg1->message_pb.regular_message.header->size = ostream.bytes_written;

    msg1->message_pb.regular_message.cipher_text =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(test_data_ratchet_message_data.len));
    msg1->message_pb.regular_message.cipher_text->size = test_data_ratchet_message_data.len;
    memcpy(msg1->message_pb.regular_message.cipher_text->bytes, test_data_ratchet_message_data.bytes,
            test_data_ratchet_message_data.len);

    size_t len = vscr_ratchet_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscr_ratchet_message_serialize(msg1, buff);

    TEST_ASSERT_EQUAL(vscr_msg_type_REGULAR, vscr_ratchet_message_get_type(msg1));
    TEST_ASSERT_EQUAL(17, vscr_ratchet_message_get_counter(msg1));

    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_message_t *msg2 = vscr_ratchet_message_deserialize(vsc_buffer_data(buff), &error);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    TEST_ASSERT(msg_cmp(msg1, msg2));

    TEST_ASSERT_EQUAL(vscr_msg_type_REGULAR, vscr_ratchet_message_get_type(msg2));
    TEST_ASSERT_EQUAL(17, vscr_ratchet_message_get_counter(msg2));

    vscr_ratchet_message_destroy(&msg1);
    vscr_ratchet_message_destroy(&msg2);
    vsc_buffer_destroy(&buff);
}

void
test__serialize_deserialize__fixed_prekey_msg__should_be_equal(void) {
    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new();

    msg1->message_pb.has_prekey_message = true;
    msg1->message_pb.version = 5;

    memcpy(msg1->message_pb.prekey_message.sender_identity_key_id, test_data_ratchet_message_id1.bytes,
            test_data_ratchet_message_id1.len);
    memcpy(msg1->message_pb.prekey_message.sender_ephemeral_key, test_data_ratchet_message_pub_key1.bytes,
            test_data_ratchet_message_pub_key1.len);
    memcpy(msg1->message_pb.prekey_message.receiver_identity_key_id, test_data_ratchet_message_id2.bytes,
            test_data_ratchet_message_id2.len);
    memcpy(msg1->message_pb.prekey_message.receiver_long_term_key_id, test_data_ratchet_message_id3.bytes,
            test_data_ratchet_message_id3.len);
    msg1->message_pb.prekey_message.has_receiver_one_time_key_id = true;
    memcpy(msg1->message_pb.prekey_message.receiver_one_time_key_id, test_data_ratchet_message_id4.bytes,
            test_data_ratchet_message_id4.len);

    msg1->header_pb.counter = 17;
    memcpy(msg1->header_pb.public_key, test_data_ratchet_message_pub_key2.bytes,
            test_data_ratchet_message_pub_key2.len);

    size_t size = 0;
    pb_get_encoded_size(&size, vscr_RegularMessageHeader_fields, &msg1->header_pb);
    msg1->message_pb.regular_message.header = vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(size));

    pb_ostream_t ostream = pb_ostream_from_buffer(msg1->message_pb.regular_message.header->bytes, size);
    TEST_ASSERT(pb_encode(&ostream, vscr_RegularMessageHeader_fields, &msg1->header_pb));
    msg1->message_pb.regular_message.header->size = ostream.bytes_written;

    msg1->message_pb.regular_message.cipher_text =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(test_data_ratchet_message_data.len));
    msg1->message_pb.regular_message.cipher_text->size = test_data_ratchet_message_data.len;
    memcpy(msg1->message_pb.regular_message.cipher_text->bytes, test_data_ratchet_message_data.bytes,
            test_data_ratchet_message_data.len);

    size_t len = vscr_ratchet_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscr_ratchet_message_serialize(msg1, buff);

    TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(msg1));
    TEST_ASSERT_EQUAL(0, vscr_ratchet_message_get_counter(msg1));
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_id1, vscr_ratchet_message_get_sender_identity_key_id(msg1));
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_id2, vscr_ratchet_message_get_receiver_identity_key_id(msg1));
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_id3, vscr_ratchet_message_get_receiver_long_term_key_id(msg1));
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_id4, vscr_ratchet_message_get_receiver_one_time_key_id(msg1));

    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_message_t *msg2 = vscr_ratchet_message_deserialize(vsc_buffer_data(buff), &error);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    TEST_ASSERT(msg_cmp(msg1, msg2));

    TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(msg2));
    TEST_ASSERT_EQUAL(0, vscr_ratchet_message_get_counter(msg2));
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_id1, vscr_ratchet_message_get_sender_identity_key_id(msg2));
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_id2, vscr_ratchet_message_get_receiver_identity_key_id(msg2));
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_id3, vscr_ratchet_message_get_receiver_long_term_key_id(msg2));
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_id4, vscr_ratchet_message_get_receiver_one_time_key_id(msg2));

    vscr_ratchet_message_destroy(&msg1);
    vscr_ratchet_message_destroy(&msg2);
    vsc_buffer_destroy(&buff);
}

void
test__serialize_deserialize__fixed_prekey_msg_no_one_time__should_be_equal(void) {
    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new();

    msg1->message_pb.has_prekey_message = true;
    msg1->message_pb.version = 5;

    memcpy(msg1->message_pb.prekey_message.sender_identity_key_id, test_data_ratchet_message_id1.bytes,
            test_data_ratchet_message_id1.len);
    memcpy(msg1->message_pb.prekey_message.sender_ephemeral_key, test_data_ratchet_message_pub_key1.bytes,
            test_data_ratchet_message_pub_key1.len);
    memcpy(msg1->message_pb.prekey_message.receiver_identity_key_id, test_data_ratchet_message_id2.bytes,
            test_data_ratchet_message_id2.len);
    memcpy(msg1->message_pb.prekey_message.receiver_long_term_key_id, test_data_ratchet_message_id3.bytes,
            test_data_ratchet_message_id3.len);
    msg1->message_pb.prekey_message.has_receiver_one_time_key_id = false;

    msg1->header_pb.counter = 17;

    size_t size = 0;
    pb_get_encoded_size(&size, vscr_RegularMessageHeader_fields, &msg1->header_pb);
    msg1->message_pb.regular_message.header = vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(size));

    pb_ostream_t ostream = pb_ostream_from_buffer(msg1->message_pb.regular_message.header->bytes, size);
    TEST_ASSERT(pb_encode(&ostream, vscr_RegularMessageHeader_fields, &msg1->header_pb));
    msg1->message_pb.regular_message.header->size = ostream.bytes_written;

    msg1->message_pb.regular_message.cipher_text =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(test_data_ratchet_message_data.len));
    msg1->message_pb.regular_message.cipher_text->size = test_data_ratchet_message_data.len;
    memcpy(msg1->message_pb.regular_message.cipher_text->bytes, test_data_ratchet_message_data.bytes,
            test_data_ratchet_message_data.len);

    size_t len = vscr_ratchet_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscr_ratchet_message_serialize(msg1, buff);

    TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(msg1));
    TEST_ASSERT_EQUAL(0, vscr_ratchet_message_get_counter(msg1));
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_id1, vscr_ratchet_message_get_sender_identity_key_id(msg1));
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_id2, vscr_ratchet_message_get_receiver_identity_key_id(msg1));
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_id3, vscr_ratchet_message_get_receiver_long_term_key_id(msg1));
    TEST_ASSERT(vsc_data_is_empty(vscr_ratchet_message_get_receiver_one_time_key_id(msg1)));

    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_message_t *msg2 = vscr_ratchet_message_deserialize(vsc_buffer_data(buff), &error);
    TEST_ASSERT(msg2 != NULL);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    TEST_ASSERT(msg_cmp(msg1, msg2));

    TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(msg2));
    TEST_ASSERT_EQUAL(0, vscr_ratchet_message_get_counter(msg2));
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_id1, vscr_ratchet_message_get_sender_identity_key_id(msg2));
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_id2, vscr_ratchet_message_get_receiver_identity_key_id(msg2));
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_message_id3, vscr_ratchet_message_get_receiver_long_term_key_id(msg2));
    TEST_ASSERT(vsc_data_is_empty(vscr_ratchet_message_get_receiver_one_time_key_id(msg2)));

    vscr_ratchet_message_destroy(&msg1);
    vscr_ratchet_message_destroy(&msg2);
    vsc_buffer_destroy(&buff);
}

void
test__serialize_deserialize__prekey_msg_overflow__should_be_equal(void) {
    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new();

    msg1->message_pb.version = UINT32_MAX;
    msg1->message_pb.has_prekey_message = true;
    msg1->message_pb.prekey_message.has_receiver_one_time_key_id = true;

    msg1->message_pb.regular_message.cipher_text =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN));
    msg1->message_pb.regular_message.cipher_text->size = vscr_ratchet_common_hidden_MAX_CIPHER_TEXT_LEN;

    msg1->header_pb.pqc_info.encapsulated_key =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(vscr_ratchet_common_hidden_ROUND5_ENCAPSULATED_KEY_LEN));
    msg1->header_pb.pqc_info.public_key =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(vscr_ratchet_common_hidden_ROUND5_PUBLIC_KEY_LEN));

    memcpy(msg1->header_pb.pqc_info.encapsulated_key->bytes, test_data_ratchet_message_encapsulated_key1_pqc.bytes,
            test_data_ratchet_message_encapsulated_key1_pqc.len);
    msg1->header_pb.pqc_info.encapsulated_key->size = test_data_ratchet_message_encapsulated_key1_pqc.len;
    memcpy(msg1->header_pb.pqc_info.public_key->bytes, test_data_ratchet_message_pub_key_pqc.bytes,
            test_data_ratchet_message_pub_key_pqc.len);
    msg1->header_pb.pqc_info.public_key->size = test_data_ratchet_message_pub_key_pqc.len;

    size_t size = 0;
    pb_get_encoded_size(&size, vscr_RegularMessageHeader_fields, &msg1->header_pb);
    msg1->message_pb.regular_message.header = vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(size));

    pb_ostream_t ostream = pb_ostream_from_buffer(msg1->message_pb.regular_message.header->bytes, size);
    TEST_ASSERT(pb_encode(&ostream, vscr_RegularMessageHeader_fields, &msg1->header_pb));
    msg1->message_pb.regular_message.header->size = ostream.bytes_written;

    msg1->message_pb.prekey_message.has_pqc_info = true;

    msg1->message_pb.prekey_message.pqc_info.encapsulated_key1 =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(vscr_ratchet_common_hidden_ROUND5_ENCAPSULATED_KEY_LEN));
    memcpy(msg1->message_pb.prekey_message.pqc_info.encapsulated_key1,
            test_data_ratchet_message_encapsulated_key2_pqc.bytes, test_data_ratchet_message_encapsulated_key2_pqc.len);
    msg1->message_pb.prekey_message.pqc_info.encapsulated_key1->size =
            test_data_ratchet_message_encapsulated_key2_pqc.len;

    msg1->message_pb.prekey_message.pqc_info.encapsulated_key2 =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(vscr_ratchet_common_hidden_ROUND5_ENCAPSULATED_KEY_LEN));
    memcpy(msg1->message_pb.prekey_message.pqc_info.encapsulated_key2,
            test_data_ratchet_message_encapsulated_key3_pqc.bytes, test_data_ratchet_message_encapsulated_key3_pqc.len);
    msg1->message_pb.prekey_message.pqc_info.encapsulated_key2->size =
            test_data_ratchet_message_encapsulated_key3_pqc.len;

    msg1->message_pb.prekey_message.pqc_info.encapsulated_key3 =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(vscr_ratchet_common_hidden_ROUND5_ENCAPSULATED_KEY_LEN));
    memcpy(msg1->message_pb.prekey_message.pqc_info.encapsulated_key3,
            test_data_ratchet_message_encapsulated_key4_pqc.bytes, test_data_ratchet_message_encapsulated_key4_pqc.len);
    msg1->message_pb.prekey_message.pqc_info.encapsulated_key3->size =
            test_data_ratchet_message_encapsulated_key4_pqc.len;

    msg1->message_pb.prekey_message.pqc_info.decapsulated_keys_signature =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(vscr_ratchet_common_hidden_FALCON_SIGNATURE_LEN));
    memcpy(msg1->message_pb.prekey_message.pqc_info.decapsulated_keys_signature,
            test_data_ratchet_message_decapsulated_keys_signature_pqc.bytes,
            test_data_ratchet_message_decapsulated_keys_signature_pqc.len);
    msg1->message_pb.prekey_message.pqc_info.decapsulated_keys_signature->size =
            test_data_ratchet_message_decapsulated_keys_signature_pqc.len;

    size_t len = vscr_ratchet_message_serialize_len(msg1);
    vsc_buffer_t *buff = vsc_buffer_new_with_capacity(len);
    vscr_ratchet_message_serialize(msg1, buff);

    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_message_t *msg2 = vscr_ratchet_message_deserialize(vsc_buffer_data(buff), &error);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_error_status(&error));
    TEST_ASSERT_NOT_NULL(msg2);

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

    msg1->header_pb.has_pqc_info = true;

    memcpy(msg1->header_pb.public_key, test_data_ratchet_message_pub_key1.bytes,
            test_data_ratchet_message_pub_key1.len);

    msg1->header_pb.pqc_info.encapsulated_key =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(vscr_ratchet_common_hidden_ROUND5_ENCAPSULATED_KEY_LEN));
    msg1->header_pb.pqc_info.public_key =
            vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(vscr_ratchet_common_hidden_ROUND5_PUBLIC_KEY_LEN));

    memcpy(msg1->header_pb.pqc_info.encapsulated_key->bytes, test_data_ratchet_message_encapsulated_key1_pqc.bytes,
            test_data_ratchet_message_encapsulated_key1_pqc.len);
    msg1->header_pb.pqc_info.encapsulated_key->size = test_data_ratchet_message_encapsulated_key1_pqc.len;
    memcpy(msg1->header_pb.pqc_info.public_key->bytes, test_data_ratchet_message_pub_key_pqc.bytes,
            test_data_ratchet_message_pub_key_pqc.len);
    msg1->header_pb.pqc_info.public_key->size = test_data_ratchet_message_pub_key_pqc.len;

    size_t size = 0;
    pb_get_encoded_size(&size, vscr_RegularMessageHeader_fields, &msg1->header_pb);
    msg1->message_pb.regular_message.header = vscr_alloc(PB_BYTES_ARRAY_T_ALLOCSIZE(size));

    pb_ostream_t ostream = pb_ostream_from_buffer(msg1->message_pb.regular_message.header->bytes, size);
    TEST_ASSERT(pb_encode(&ostream, vscr_RegularMessageHeader_fields, &msg1->header_pb));
    msg1->message_pb.regular_message.header->size = ostream.bytes_written;

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
    RUN_TEST(test__serialize_deserialize__prekey_msg_overflow__should_be_equal);
    RUN_TEST(test__serialize_deserialize__regular_msg_overflow__should_be_equal);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
