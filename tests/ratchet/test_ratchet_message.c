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

#include <vscr_ratchet.h>
#include "test_data_ratchet_message.h"
#include "test_data_ratchet_regular_message.h"
#include "test_data_ratchet_prekey_message.h"

void
test__serialization__serialize_deserialize__objects_are_equal(void) {
    vsc_buffer_t *sender_identity_key = vsc_buffer_new_with_data(test_ratchet_prekey_message_sender_identity_key);
    vsc_buffer_t *sender_ephemeral_key = vsc_buffer_new_with_data(test_ratchet_prekey_message_sender_ephemeral_key);
    vsc_buffer_t *receiver_longterm_key = vsc_buffer_new_with_data(test_ratchet_prekey_message_receiver_longterm_key);
    vsc_buffer_t *receiver_onetime_key = vsc_buffer_new_with_data(test_ratchet_prekey_message_receiver_onetime_key);

    vsc_buffer_t *public_key = vsc_buffer_new_with_data(test_ratchet_regular_message_public_key);
    vsc_buffer_t *cipher_text = vsc_buffer_new_with_data(test_ratchet_regular_message_cipher_text);

    RegularMessage regular_message = RegularMessage_init_zero;

    regular_message.version = test_ratchet_regular_message_version;
    regular_message.counter = test_ratchet_regular_message_counter;

    memcpy(regular_message.public_key, public_key->bytes, public_key->len);
    memcpy(regular_message.cipher_text.bytes, cipher_text->bytes, cipher_text->len);
    regular_message.cipher_text.size += cipher_text->len;

    PrekeyMessage prekey_message = PrekeyMessage_init_zero;

    prekey_message.version = test_ratchet_prekey_message_protocol_version;
    memcpy(prekey_message.sender_identity_key, sender_identity_key->bytes, sender_identity_key->len);
    memcpy(prekey_message.sender_ephemeral_key, sender_ephemeral_key->bytes, sender_ephemeral_key->len);
    memcpy(prekey_message.receiver_longterm_key, receiver_longterm_key->bytes, receiver_longterm_key->len);
    memcpy(prekey_message.receiver_onetime_key, receiver_onetime_key->bytes, receiver_onetime_key->len);
    prekey_message.regular_message = regular_message;

    Message ratchet_message = Message_init_zero;

    ratchet_message.version = test_ratchet_ratchet_message_version;
    ratchet_message.which_message = Message_prekey_message_tag;

    ratchet_message.message.prekey_message = prekey_message;

    size_t len = 0;
    bool status = true;
    status = pb_get_encoded_size(&len, Message_fields, &ratchet_message);

    TEST_ASSERT_EQUAL(status, true);

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(len);

    status = true;
    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_unused_bytes(buffer), vsc_buffer_capacity(buffer));

    status = pb_encode(&ostream, Message_fields, &ratchet_message);

    vsc_buffer_inc_used(buffer, ostream.bytes_written);

    TEST_ASSERT_EQUAL(status, true);
    TEST_ASSERT_EQUAL(ostream.bytes_written, len);

    Message decoded_ratchet_message = Message_init_zero;
    status = true;
    pb_istream_t istream = pb_istream_from_buffer(vsc_buffer_data(buffer).bytes, vsc_buffer_data(buffer).len);
    status = pb_decode(&istream, Message_fields, &decoded_ratchet_message);

    TEST_ASSERT_EQUAL(status, true);

    TEST_ASSERT_EQUAL_INT(test_ratchet_ratchet_message_version, decoded_ratchet_message.version);
    TEST_ASSERT_EQUAL(ratchet_message.which_message, decoded_ratchet_message.which_message);
    TEST_ASSERT_EQUAL(ratchet_message.which_message, Message_prekey_message_tag);

    PrekeyMessage decoded_prekey_message = decoded_ratchet_message.message.prekey_message;

    TEST_ASSERT_EQUAL_INT(test_ratchet_prekey_message_protocol_version, decoded_prekey_message.version);

    TEST_ASSERT_EQUAL_MEMORY(decoded_prekey_message.sender_identity_key,
            test_ratchet_prekey_message_sender_identity_key.bytes, test_ratchet_prekey_message_sender_identity_key.len);
    TEST_ASSERT_EQUAL_MEMORY(decoded_prekey_message.sender_ephemeral_key,
            test_ratchet_prekey_message_sender_ephemeral_key.bytes,
            test_ratchet_prekey_message_sender_identity_key.len);
    TEST_ASSERT_EQUAL_MEMORY(decoded_prekey_message.receiver_longterm_key,
            test_ratchet_prekey_message_receiver_longterm_key.bytes,
            test_ratchet_prekey_message_sender_identity_key.len);
    TEST_ASSERT_EQUAL_MEMORY(decoded_prekey_message.receiver_onetime_key,
            test_ratchet_prekey_message_receiver_onetime_key.bytes,
            test_ratchet_prekey_message_sender_identity_key.len);

    RegularMessage decoded_regular_message = decoded_prekey_message.regular_message;

    TEST_ASSERT_EQUAL_INT(test_ratchet_regular_message_version, decoded_regular_message.version);
    TEST_ASSERT_EQUAL_INT(test_ratchet_regular_message_counter, decoded_regular_message.counter);

    TEST_ASSERT_EQUAL_MEMORY(
            decoded_regular_message.public_key, vsc_buffer_bytes(public_key), vsc_buffer_len(public_key));
    TEST_ASSERT_EQUAL_INT(decoded_regular_message.cipher_text.size, vsc_buffer_len(cipher_text));
    TEST_ASSERT_EQUAL_MEMORY(
            decoded_regular_message.cipher_text.bytes, vsc_buffer_bytes(cipher_text), vsc_buffer_len(cipher_text));

    vsc_buffer_destroy(&buffer);
}

void
test__serialization__serialize_deserialize_big_object__objects_are_equal(void) {
    vsc_buffer_t *public_key = vsc_buffer_new_with_data(test_ratchet_regular_message_public_key);
    vsc_buffer_t *cipher_text = vsc_buffer_new_with_data(test_ratchet_regular_message_cipher_text_big);

    RegularMessage regular_message = RegularMessage_init_zero;

    regular_message.version = test_ratchet_regular_message_version_big;
    regular_message.counter = test_ratchet_regular_message_counter_big;

    memcpy(regular_message.public_key, public_key->bytes, public_key->len);
    memcpy(regular_message.cipher_text.bytes, cipher_text->bytes, cipher_text->len);
    regular_message.cipher_text.size += cipher_text->len;

    Message ratchet_message = Message_init_zero;

    ratchet_message.version = test_ratchet_ratchet_message_version_big;
    ratchet_message.which_message = Message_regular_message_tag;

    ratchet_message.message.regular_message = regular_message;

    size_t len = 0;
    bool status = true;
    status = pb_get_encoded_size(&len, Message_fields, &ratchet_message);

    TEST_ASSERT_EQUAL(status, true);

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(len);

    status = true;
    pb_ostream_t ostream = pb_ostream_from_buffer(vsc_buffer_unused_bytes(buffer), vsc_buffer_capacity(buffer));

    status = pb_encode(&ostream, Message_fields, &ratchet_message);

    vsc_buffer_inc_used(buffer, ostream.bytes_written);

    TEST_ASSERT_EQUAL(status, true);
    TEST_ASSERT_EQUAL(ostream.bytes_written, len);

    Message decoded_ratchet_message = Message_init_zero;
    status = true;
    pb_istream_t istream = pb_istream_from_buffer(vsc_buffer_data(buffer).bytes, vsc_buffer_data(buffer).len);
    status = pb_decode(&istream, Message_fields, &decoded_ratchet_message);

    TEST_ASSERT_EQUAL(status, true);

    TEST_ASSERT_EQUAL_INT(test_ratchet_ratchet_message_version_big, decoded_ratchet_message.version);
    TEST_ASSERT_EQUAL(ratchet_message.which_message, decoded_ratchet_message.which_message);
    TEST_ASSERT_EQUAL(ratchet_message.which_message, Message_regular_message_tag);

    RegularMessage decoded_regular_message = decoded_ratchet_message.message.regular_message;

    TEST_ASSERT_EQUAL_INT(test_ratchet_regular_message_version_big, decoded_regular_message.version);
    TEST_ASSERT_EQUAL_INT(test_ratchet_regular_message_counter_big, decoded_regular_message.counter);

    TEST_ASSERT_EQUAL_MEMORY(
            decoded_regular_message.public_key, vsc_buffer_bytes(public_key), vsc_buffer_len(public_key));
    TEST_ASSERT_EQUAL_INT(decoded_regular_message.cipher_text.size, vsc_buffer_len(cipher_text));
    TEST_ASSERT_EQUAL_MEMORY(
            decoded_regular_message.cipher_text.bytes, vsc_buffer_bytes(cipher_text), vsc_buffer_len(cipher_text));

    vsc_buffer_destroy(&buffer);
}


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

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

    RUN_TEST(test__serialization__serialize_deserialize__objects_are_equal);
    RUN_TEST(test__serialization__serialize_deserialize_big_object__objects_are_equal);

    return UNITY_END();
}
