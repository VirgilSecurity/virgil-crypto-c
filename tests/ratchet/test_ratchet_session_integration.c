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

#include "vscr_ratchet_message_defs.h"
#include "vscr_ratchet_session.h"
#include "test_utils_ratchet.h"

// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------
void
test__initialize__fixed_values__should_not_fail(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
    vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();

    initialize(rng, &session_alice, &session_bob, true, false);

    vscr_ratchet_session_destroy(&session_alice);
    vscr_ratchet_session_destroy(&session_bob);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__encrypt_decrypt_back_and_forth__fixed_plain_text__decrypted_should_match(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
    vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();

    initialize(rng, &session_alice, &session_bob, true, false);

    vscr_error_t error;
    vscr_error_reset(&error);

    vsc_buffer_t *text1 = NULL, *text2 = NULL;

    generate_random_data(rng, &text1);
    generate_random_data(rng, &text2);

    vscr_ratchet_message_t *ratchet_message1 =
            vscr_ratchet_session_encrypt(session_alice, vsc_buffer_data(text1), &error);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));
    TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(ratchet_message1));

    size_t len1 = vscr_ratchet_session_decrypt_len(session_bob, ratchet_message1);
    vsc_buffer_t *plain_text1 = vsc_buffer_new_with_capacity(len1);

    vscr_status_t result = vscr_ratchet_session_decrypt(session_bob, ratchet_message1, plain_text1);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, result);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text1), plain_text1);

    vscr_ratchet_message_t *ratchet_message2 =
            vscr_ratchet_session_encrypt(session_bob, vsc_buffer_data(text2), &error);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));
    TEST_ASSERT_EQUAL(vscr_msg_type_REGULAR, vscr_ratchet_message_get_type(ratchet_message2));

    size_t len2 = vscr_ratchet_session_decrypt_len(session_alice, ratchet_message2);
    vsc_buffer_t *plain_text2 = vsc_buffer_new_with_capacity(len2);

    result = vscr_ratchet_session_decrypt(session_alice, ratchet_message2, plain_text2);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, result);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text2), plain_text2);

    vsc_buffer_destroy(&text1);
    vsc_buffer_destroy(&text2);
    vsc_buffer_destroy(&plain_text1);
    vsc_buffer_destroy(&plain_text2);
    vscr_ratchet_session_destroy(&session_alice);
    vscr_ratchet_session_destroy(&session_bob);
    vscr_ratchet_message_destroy(&ratchet_message1);
    vscr_ratchet_message_destroy(&ratchet_message2);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__encrypt_decrypt__100_plain_texts_random_order__decrypted_should_match(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
    vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();

    initialize(rng, &session_alice, &session_bob, true, false);

    encrypt_decrypt__100_plain_texts_random_order(rng, session_alice, session_bob);

    vscr_ratchet_session_destroy(&session_alice);
    vscr_ratchet_session_destroy(&session_bob);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__encrypt_decrypt__100_plain_texts_random_order_no_one_time__decrypted_should_match(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
    vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();

    initialize(rng, &session_alice, &session_bob, false, false);

    encrypt_decrypt__100_plain_texts_random_order(rng, session_alice, session_bob);

    vscr_ratchet_session_destroy(&session_alice);
    vscr_ratchet_session_destroy(&session_bob);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__encrypt_decrypt__1_out_of_order_msg__decrypted_should_match(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
    vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();

    initialize(rng, &session_alice, &session_bob, true, false);

    vscr_error_t error;
    vscr_error_reset(&error);

    vsc_buffer_t *text1 = NULL, *text2 = NULL;

    generate_random_data(rng, &text1);
    generate_random_data(rng, &text2);

    vscr_ratchet_message_t *ratchet_message1 =
            vscr_ratchet_session_encrypt(session_alice, vsc_buffer_data(text1), &error);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));
    TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(ratchet_message1));

    vscr_ratchet_message_t *ratchet_message2 =
            vscr_ratchet_session_encrypt(session_alice, vsc_buffer_data(text2), &error);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));
    TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(ratchet_message2));

    size_t len2 = vscr_ratchet_session_decrypt_len(session_bob, ratchet_message2);
    vsc_buffer_t *plain_text2 = vsc_buffer_new_with_capacity(len2);

    vscr_status_t result = vscr_ratchet_session_decrypt(session_bob, ratchet_message2, plain_text2);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, result);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text2), plain_text2);

    size_t len1 = vscr_ratchet_session_decrypt_len(session_bob, ratchet_message1);
    vsc_buffer_t *plain_text1 = vsc_buffer_new_with_capacity(len1);

    result = vscr_ratchet_session_decrypt(session_bob, ratchet_message1, plain_text1);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, result);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text1), plain_text1);

    vsc_buffer_destroy(&text1);
    vsc_buffer_destroy(&text2);
    vsc_buffer_destroy(&plain_text1);
    vsc_buffer_destroy(&plain_text2);
    vscr_ratchet_session_destroy(&session_alice);
    vscr_ratchet_session_destroy(&session_bob);
    vscr_ratchet_message_destroy(&ratchet_message1);
    vscr_ratchet_message_destroy(&ratchet_message2);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__encrypt_decrypt__randomly_skipped_messages__decrypt_should_succeed(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
    vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();

    initialize(rng, &session_alice, &session_bob, true, false);

    encrypt_decrypt__100_plain_texts_random_order_with_producers(rng, &session_alice, &session_bob, false);

    vscr_ratchet_session_destroy(&session_alice);
    vscr_ratchet_session_destroy(&session_bob);

    vscf_ctr_drbg_destroy(&rng);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__initialize__fixed_values__should_not_fail);
    RUN_TEST(test__encrypt_decrypt_back_and_forth__fixed_plain_text__decrypted_should_match);
    RUN_TEST(test__encrypt_decrypt__100_plain_texts_random_order__decrypted_should_match);
    RUN_TEST(test__encrypt_decrypt__100_plain_texts_random_order_no_one_time__decrypted_should_match);
    RUN_TEST(test__encrypt_decrypt__1_out_of_order_msg__decrypted_should_match);
    RUN_TEST(test__encrypt_decrypt__randomly_skipped_messages__decrypt_should_succeed);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
