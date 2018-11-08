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

#include <virgil/crypto/common/private/vsc_buffer_defs.h>
#include "unity.h"
#include "test_utils.h"

#define TEST_DEPENDENCIES_AVAILABLE VSCR_RATCHET_REGULAR_MESSAGE
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscr_ratchet_regular_message.h"
#include "test_data_ratchet_regular_message.h"

void
test__contructor__create_object__object_has_correct_values(void) {
    vsc_buffer_t *public_key = vsc_buffer_new_with_data(test_ratchet_regular_message_public_key);
    vsc_buffer_t *cipher_text = vsc_buffer_new_with_data(test_ratchet_regular_message_cipher_text);

    vscr_ratchet_regular_message_t *msg1 = vscr_ratchet_regular_message_new_with_members(
            test_ratchet_regular_message_version, test_ratchet_regular_message_counter, public_key, cipher_text);

    TEST_ASSERT_EQUAL_INT(test_ratchet_regular_message_version, msg1->version);
    TEST_ASSERT_EQUAL_INT(test_ratchet_regular_message_counter, msg1->counter);
    TEST_ASSERT_EQUAL_MEMORY(vsc_buffer_bytes(msg1->public_key), test_ratchet_regular_message_public_key.bytes,
            test_ratchet_regular_message_public_key.len);
    TEST_ASSERT_EQUAL_INT(32, vsc_buffer_len(msg1->public_key));
    TEST_ASSERT_EQUAL_MEMORY(vsc_buffer_bytes(msg1->cipher_text), test_ratchet_regular_message_cipher_text.bytes,
            test_ratchet_regular_message_cipher_text.len);
    TEST_ASSERT_EQUAL_INT(test_ratchet_regular_message_cipher_text.len, vsc_buffer_len(msg1->cipher_text));

    vscr_ratchet_regular_message_destroy(&msg1);

    vsc_buffer_destroy(&public_key);
    vsc_buffer_destroy(&cipher_text);
}

void
test__serialization__serialize_deserialize__objects_are_equal(void) {
    vsc_buffer_t *public_key = vsc_buffer_new_with_data(test_ratchet_regular_message_public_key);
    vsc_buffer_t *cipher_text = vsc_buffer_new_with_data(test_ratchet_regular_message_cipher_text);

    vscr_ratchet_regular_message_t *msg1 = vscr_ratchet_regular_message_new_with_members(
            test_ratchet_regular_message_version, test_ratchet_regular_message_counter, public_key, cipher_text);

    size_t len = vscr_ratchet_regular_message_serialize_len(msg1->cipher_text->len);
    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(len);

    TEST_ASSERT_EQUAL(vscr_ratchet_regular_message_serialize(msg1, buffer), vscr_SUCCESS);

    vscr_error_ctx_t err_ctx;
    vscr_error_ctx_reset(&err_ctx);
    vscr_ratchet_regular_message_t *msg2 = vscr_ratchet_regular_message_deserialize(vsc_buffer_data(buffer), &err_ctx);

    TEST_ASSERT_EQUAL(err_ctx.error, vscr_SUCCESS);

    TEST_ASSERT_EQUAL_INT(vsc_buffer_len(msg1->public_key), vsc_buffer_len(msg2->public_key));
    TEST_ASSERT_EQUAL_MEMORY(
            vsc_buffer_bytes(msg1->public_key), vsc_buffer_bytes(msg2->public_key), vsc_buffer_len(msg1->public_key));
    TEST_ASSERT_EQUAL_INT(vsc_buffer_len(msg1->cipher_text), vsc_buffer_len(msg2->cipher_text));
    TEST_ASSERT_EQUAL_MEMORY(vsc_buffer_bytes(msg1->cipher_text), vsc_buffer_bytes(msg2->cipher_text),
                             vsc_buffer_len(msg1->cipher_text));

    vscr_ratchet_regular_message_destroy(&msg1);
    vscr_ratchet_regular_message_destroy(&msg2);

    vsc_buffer_destroy(&public_key);
    vsc_buffer_destroy(&cipher_text);
    vsc_buffer_destroy(&buffer);
}

void
test__contructor__create_big_object__object_has_correct_values(void) {
    vsc_buffer_t *public_key = vsc_buffer_new_with_data(test_ratchet_regular_message_public_key);
    vsc_buffer_t *cipher_text = vsc_buffer_new_with_data(test_ratchet_regular_message_cipher_text_big);

    vscr_ratchet_regular_message_t *msg1 =
            vscr_ratchet_regular_message_new_with_members(test_ratchet_regular_message_version_big,
                    test_ratchet_regular_message_counter_big, public_key, cipher_text);

    TEST_ASSERT_EQUAL_INT(test_ratchet_regular_message_version_big, msg1->version);
    TEST_ASSERT_EQUAL_INT(test_ratchet_regular_message_counter_big, msg1->counter);
    TEST_ASSERT_EQUAL_MEMORY(vsc_buffer_bytes(msg1->public_key), test_ratchet_regular_message_public_key.bytes,
            test_ratchet_regular_message_public_key.len);
    TEST_ASSERT_EQUAL_INT(32, vsc_buffer_len(msg1->public_key));
    TEST_ASSERT_EQUAL_MEMORY(vsc_buffer_bytes(msg1->cipher_text), test_ratchet_regular_message_cipher_text_big.bytes,
            test_ratchet_regular_message_cipher_text_big.len);
    TEST_ASSERT_EQUAL_INT(test_ratchet_regular_message_cipher_text_big.len, vsc_buffer_len(msg1->cipher_text));

    vscr_ratchet_regular_message_destroy(&msg1);

    vsc_buffer_destroy(&public_key);
    vsc_buffer_destroy(&cipher_text);
}

void
test__serialization__serialize_deserialize_big_object__objects_are_equal(void) {
    vsc_buffer_t *public_key = vsc_buffer_new_with_data(test_ratchet_regular_message_public_key);
    vsc_buffer_t *cipher_text = vsc_buffer_new_with_data(test_ratchet_regular_message_cipher_text_big);

    vscr_ratchet_regular_message_t *msg1 =
            vscr_ratchet_regular_message_new_with_members(test_ratchet_regular_message_version_big,
                                                          test_ratchet_regular_message_counter_big, public_key, cipher_text);

    size_t len = vscr_ratchet_regular_message_serialize_len(msg1->cipher_text->len);
    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(len);

    TEST_ASSERT_EQUAL(vscr_ratchet_regular_message_serialize(msg1, buffer), vscr_SUCCESS);

    vscr_error_ctx_t err_ctx;
    vscr_error_ctx_reset(&err_ctx);
    vscr_ratchet_regular_message_t *msg2 = vscr_ratchet_regular_message_deserialize(vsc_buffer_data(buffer), &err_ctx);

    TEST_ASSERT_EQUAL(err_ctx.error, vscr_SUCCESS);

    TEST_ASSERT_EQUAL_INT(vsc_buffer_len(msg1->public_key), vsc_buffer_len(msg2->public_key));
    TEST_ASSERT_EQUAL_MEMORY(
            vsc_buffer_bytes(msg1->public_key), vsc_buffer_bytes(msg2->public_key), vsc_buffer_len(msg1->public_key));
    TEST_ASSERT_EQUAL_INT(vsc_buffer_len(msg1->cipher_text), vsc_buffer_len(msg2->cipher_text));
    TEST_ASSERT_EQUAL_MEMORY(vsc_buffer_bytes(msg1->cipher_text), vsc_buffer_bytes(msg2->cipher_text),
                             vsc_buffer_len(msg1->cipher_text));

    vscr_ratchet_regular_message_destroy(&msg1);
    vscr_ratchet_regular_message_destroy(&msg2);

    vsc_buffer_destroy(&public_key);
    vsc_buffer_destroy(&cipher_text);
    vsc_buffer_destroy(&buffer);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__contructor__create_object__object_has_correct_values);
    RUN_TEST(test__serialization__serialize_deserialize__objects_are_equal);
    RUN_TEST(test__contructor__create_big_object__object_has_correct_values);
    RUN_TEST(test__serialization__serialize_deserialize_big_object__objects_are_equal);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
