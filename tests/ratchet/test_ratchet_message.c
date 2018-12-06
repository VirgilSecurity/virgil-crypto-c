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

#define TEST_DEPENDENCIES_AVAILABLE VSCR_RATCHET_MESSAGE
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscr_ratchet_message.h"
#include "test_data_ratchet_message.h"

void
test__constructor__create_object__object_has_correct_values(void) {
    vsc_buffer_t *message = vsc_buffer_new_with_data(test_ratchet_ratchet_message_message);

    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new_with_members(test_ratchet_ratchet_message_version,
            vscr_ratchet_message_TYPE_PREKEY, message);

    TEST_ASSERT_EQUAL_INT(test_ratchet_ratchet_message_version, msg1->version);
    TEST_ASSERT_EQUAL_INT(vscr_ratchet_message_TYPE_PREKEY, msg1->type);
    TEST_ASSERT_EQUAL_MEMORY(vsc_buffer_bytes(msg1->message), test_ratchet_ratchet_message_message.bytes,
                             test_ratchet_ratchet_message_message.len);
    TEST_ASSERT_EQUAL_INT(test_ratchet_ratchet_message_message.len, vsc_buffer_len(msg1->message));

    vscr_ratchet_message_destroy(&msg1);

    vsc_buffer_destroy(&message);
}

void
test__serialization__serialize_deserialize__objects_are_equal(void) {
    vsc_buffer_t *message = vsc_buffer_new_with_data(test_ratchet_ratchet_message_message);

    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new_with_members(test_ratchet_ratchet_message_version,
                                                                         vscr_ratchet_message_TYPE_PREKEY, message);

    size_t len = vscr_ratchet_message_serialize_len_ext(msg1);
    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(len);

    TEST_ASSERT_EQUAL(vscr_ratchet_message_serialize(msg1, buffer), vscr_SUCCESS);

    vscr_error_ctx_t err_ctx;
    vscr_error_ctx_reset(&err_ctx);
    vscr_ratchet_message_t *msg2 = vscr_ratchet_message_deserialize(vsc_buffer_data(buffer), &err_ctx);

    TEST_ASSERT_EQUAL(err_ctx.error, vscr_SUCCESS);

    TEST_ASSERT_EQUAL_INT(vsc_buffer_len(msg1->message), vsc_buffer_len(msg2->message));
    TEST_ASSERT_EQUAL_MEMORY(
            vsc_buffer_bytes(msg1->message), vsc_buffer_bytes(msg2->message), vsc_buffer_len(msg1->message));
    TEST_ASSERT_EQUAL_INT(msg1->version, msg2->version);
    TEST_ASSERT_EQUAL_INT(msg1->type, msg2->type);

    vscr_ratchet_message_destroy(&msg1);
    vscr_ratchet_message_destroy(&msg2);

    vsc_buffer_destroy(&message);
    vsc_buffer_destroy(&buffer);
}

void
test__constructor__create_big_object__object_has_correct_values(void) {
    vsc_buffer_t *message = vsc_buffer_new_with_data(test_ratchet_ratchet_message_message_big);

    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new_with_members(test_ratchet_ratchet_message_version_big,
                                                                         vscr_ratchet_message_TYPE_REGULAR, message);

    TEST_ASSERT_EQUAL_INT(test_ratchet_ratchet_message_version_big, msg1->version);
    TEST_ASSERT_EQUAL_INT(vscr_ratchet_message_TYPE_REGULAR, msg1->type);
    TEST_ASSERT_EQUAL_MEMORY(vsc_buffer_bytes(msg1->message), test_ratchet_ratchet_message_message_big.bytes,
                             test_ratchet_ratchet_message_message_big.len);
    TEST_ASSERT_EQUAL_INT(test_ratchet_ratchet_message_message_big.len, vsc_buffer_len(msg1->message));

    vscr_ratchet_message_destroy(&msg1);

    vsc_buffer_destroy(&message);
}

void
test__serialization__serialize_deserialize_big_object__objects_are_equal(void) {
    vsc_buffer_t *message = vsc_buffer_new_with_data(test_ratchet_ratchet_message_message_big);

    vscr_ratchet_message_t *msg1 = vscr_ratchet_message_new_with_members(test_ratchet_ratchet_message_version_big,
                                                                         vscr_ratchet_message_TYPE_REGULAR, message);

    size_t len = vscr_ratchet_message_serialize_len_ext(msg1);
    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(len);

    TEST_ASSERT_EQUAL(vscr_ratchet_message_serialize(msg1, buffer), vscr_SUCCESS);

    vscr_error_ctx_t err_ctx;
    vscr_error_ctx_reset(&err_ctx);
    vscr_ratchet_message_t *msg2 = vscr_ratchet_message_deserialize(vsc_buffer_data(buffer), &err_ctx);

    TEST_ASSERT_EQUAL(err_ctx.error, vscr_SUCCESS);

    TEST_ASSERT_EQUAL_INT(vsc_buffer_len(msg1->message), vsc_buffer_len(msg2->message));
    TEST_ASSERT_EQUAL_MEMORY(
            vsc_buffer_bytes(msg1->message), vsc_buffer_bytes(msg2->message), vsc_buffer_len(msg1->message));
    TEST_ASSERT_EQUAL_INT(msg1->version, msg2->version);
    TEST_ASSERT_EQUAL_INT(msg1->type, msg2->type);

    vscr_ratchet_message_destroy(&msg1);
    vscr_ratchet_message_destroy(&msg2);

    vsc_buffer_destroy(&message);
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
    RUN_TEST(test__constructor__create_object__object_has_correct_values);
    RUN_TEST(test__serialization__serialize_deserialize__objects_are_equal);
    RUN_TEST(test__constructor__create_big_object__object_has_correct_values);
    RUN_TEST(test__serialization__serialize_deserialize_big_object__objects_are_equal);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
