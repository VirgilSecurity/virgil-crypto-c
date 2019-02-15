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

#include <test_utils.h>
#include "unity.h"

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

#include <ed25519/ed25519.h>
#include "vscr_ratchet_x3dh.h"
#include "test_data_ratchet_x3dh.h"
#include "test_utils_ratchet.h"

void
test__initiator_x3dh__fixed_keys__should_match(void) {
    vsc_buffer_t *shared_secret = vsc_buffer_new_with_capacity(4 * ED25519_DH_LEN);

    vscr_error_t status = vscr_ratchet_x3dh_compute_initiator_x3dh_secret(
            test_data_ratchet_x3dh_sender_identity_private_key, test_data_ratchet_x3dh_sender_ephemeral_private_key,
            test_data_ratchet_x3dh_receiver_identity_public_key, test_data_ratchet_x3dh_receiver_long_term_public_key,
            test_data_ratchet_x3dh_receiver_one_time_public_key, shared_secret);

    TEST_ASSERT_EQUAL(vscr_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, vsc_buffer_unused_len(shared_secret));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_ratchet_x3dh_shared_secret, shared_secret);

    vsc_buffer_destroy(&shared_secret);
}

void
test__initiator_x3dh__fixed_keys_weak__should_match(void) {
    vsc_buffer_t *shared_secret = vsc_buffer_new_with_capacity(3 * ED25519_DH_LEN);

    vscr_error_t status = vscr_ratchet_x3dh_compute_initiator_x3dh_secret(
            test_data_ratchet_x3dh_sender_identity_private_key, test_data_ratchet_x3dh_sender_ephemeral_private_key,
            test_data_ratchet_x3dh_receiver_identity_public_key, test_data_ratchet_x3dh_receiver_long_term_public_key,
            vsc_data_empty(), shared_secret);

    TEST_ASSERT_EQUAL(vscr_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, vsc_buffer_unused_len(shared_secret));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_ratchet_x3dh_shared_secret_weak, shared_secret);

    vsc_buffer_destroy(&shared_secret);
}

void
test__responder_x3dh__fixed_keys__should_match(void) {
    vsc_buffer_t *shared_secret = vsc_buffer_new_with_capacity(4 * ED25519_DH_LEN);

    vscr_error_t status = vscr_ratchet_x3dh_compute_responder_x3dh_secret(
            test_data_ratchet_x3dh_sender_identity_public_key, test_data_ratchet_x3dh_sender_ephemeral_public_key,
            test_data_ratchet_x3dh_receiver_identity_private_key, test_data_ratchet_x3dh_receiver_long_term_private_key,
            test_data_ratchet_x3dh_receiver_one_time_private_key, shared_secret);

    TEST_ASSERT_EQUAL(vscr_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, vsc_buffer_unused_len(shared_secret));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_ratchet_x3dh_shared_secret, shared_secret);

    vsc_buffer_destroy(&shared_secret);
}

void
test__responder_x3dh__fixed_keys_weak__should_match(void) {
    vsc_buffer_t *shared_secret = vsc_buffer_new_with_capacity(3 * ED25519_DH_LEN);

    vscr_error_t status = vscr_ratchet_x3dh_compute_responder_x3dh_secret(
            test_data_ratchet_x3dh_sender_identity_public_key, test_data_ratchet_x3dh_sender_ephemeral_public_key,
            test_data_ratchet_x3dh_receiver_identity_private_key, test_data_ratchet_x3dh_receiver_long_term_private_key,
            vsc_data_empty(), shared_secret);

    TEST_ASSERT_EQUAL(vscr_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, vsc_buffer_unused_len(shared_secret));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_ratchet_x3dh_shared_secret_weak, shared_secret);

    vsc_buffer_destroy(&shared_secret);
}

void
test__x3dh__random_keys__should_match(void) {
    vsc_buffer_t *sender_identity_private_key, *sender_identity_public_key;
    vsc_buffer_t *sender_ephemeral_private_key, *sender_ephemeral_public_key;
    vsc_buffer_t *receiver_identity_private_key, *receiver_identity_public_key;
    vsc_buffer_t *receiver_long_term_private_key, *receiver_long_term_public_key;
    vsc_buffer_t *receiver_one_time_private_key, *receiver_one_time_public_key;

    generate_raw_keypair(&sender_identity_private_key, &sender_identity_public_key);
    generate_raw_keypair(&sender_ephemeral_private_key, &sender_ephemeral_public_key);
    generate_raw_keypair(&receiver_identity_private_key, &receiver_identity_public_key);
    generate_raw_keypair(&receiver_long_term_private_key, &receiver_long_term_public_key);
    generate_raw_keypair(&receiver_one_time_private_key, &receiver_one_time_public_key);

    vsc_buffer_t *shared_secret_sender = vsc_buffer_new_with_capacity(4 * ED25519_DH_LEN);
    vsc_buffer_t *shared_secret_receiver = vsc_buffer_new_with_capacity(4 * ED25519_DH_LEN);

    vscr_error_t status = vscr_ratchet_x3dh_compute_responder_x3dh_secret(vsc_buffer_data(sender_identity_public_key),
            vsc_buffer_data(sender_ephemeral_public_key), vsc_buffer_data(receiver_identity_private_key),
            vsc_buffer_data(receiver_long_term_private_key), vsc_buffer_data(receiver_one_time_private_key),
            shared_secret_sender);

    TEST_ASSERT_EQUAL(vscr_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, vsc_buffer_unused_len(shared_secret_sender));

    status = vscr_ratchet_x3dh_compute_responder_x3dh_secret(vsc_buffer_data(sender_identity_public_key),
            vsc_buffer_data(sender_ephemeral_public_key), vsc_buffer_data(receiver_identity_private_key),
            vsc_buffer_data(receiver_long_term_private_key), vsc_buffer_data(receiver_one_time_private_key),
            shared_secret_receiver);

    TEST_ASSERT_EQUAL(vscr_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, vsc_buffer_unused_len(shared_secret_receiver));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(shared_secret_sender), shared_secret_receiver);

    vsc_buffer_destroy(&shared_secret_sender);
    vsc_buffer_destroy(&shared_secret_receiver);

    vsc_buffer_destroy(&sender_identity_private_key);
    vsc_buffer_destroy(&sender_identity_public_key);
    vsc_buffer_destroy(&sender_ephemeral_private_key);
    vsc_buffer_destroy(&sender_ephemeral_public_key);
    vsc_buffer_destroy(&receiver_identity_private_key);
    vsc_buffer_destroy(&receiver_identity_public_key);
    vsc_buffer_destroy(&receiver_long_term_private_key);
    vsc_buffer_destroy(&receiver_long_term_public_key);
    vsc_buffer_destroy(&receiver_one_time_private_key);
    vsc_buffer_destroy(&receiver_one_time_public_key);
}

void
test__x3dh__random_keys_weak__should_match(void) {
    vsc_buffer_t *sender_identity_private_key, *sender_identity_public_key;
    vsc_buffer_t *sender_ephemeral_private_key, *sender_ephemeral_public_key;
    vsc_buffer_t *receiver_identity_private_key, *receiver_identity_public_key;
    vsc_buffer_t *receiver_long_term_private_key, *receiver_long_term_public_key;

    generate_raw_keypair(&sender_identity_private_key, &sender_identity_public_key);
    generate_raw_keypair(&sender_ephemeral_private_key, &sender_ephemeral_public_key);
    generate_raw_keypair(&receiver_identity_private_key, &receiver_identity_public_key);
    generate_raw_keypair(&receiver_long_term_private_key, &receiver_long_term_public_key);

    vsc_buffer_t *shared_secret_sender = vsc_buffer_new_with_capacity(3 * ED25519_DH_LEN);
    vsc_buffer_t *shared_secret_receiver = vsc_buffer_new_with_capacity(3 * ED25519_DH_LEN);

    vscr_error_t status = vscr_ratchet_x3dh_compute_responder_x3dh_secret(vsc_buffer_data(sender_identity_public_key),
            vsc_buffer_data(sender_ephemeral_public_key), vsc_buffer_data(receiver_identity_private_key),
            vsc_buffer_data(receiver_long_term_private_key), vsc_data_empty(), shared_secret_sender);

    TEST_ASSERT_EQUAL(vscr_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, vsc_buffer_unused_len(shared_secret_sender));

    status = vscr_ratchet_x3dh_compute_responder_x3dh_secret(vsc_buffer_data(sender_identity_public_key),
            vsc_buffer_data(sender_ephemeral_public_key), vsc_buffer_data(receiver_identity_private_key),
            vsc_buffer_data(receiver_long_term_private_key), vsc_data_empty(), shared_secret_receiver);

    TEST_ASSERT_EQUAL(vscr_SUCCESS, status);
    TEST_ASSERT_EQUAL(0, vsc_buffer_unused_len(shared_secret_receiver));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(shared_secret_sender), shared_secret_receiver);

    vsc_buffer_destroy(&shared_secret_sender);
    vsc_buffer_destroy(&shared_secret_receiver);

    vsc_buffer_destroy(&sender_identity_private_key);
    vsc_buffer_destroy(&sender_identity_public_key);
    vsc_buffer_destroy(&sender_ephemeral_private_key);
    vsc_buffer_destroy(&sender_ephemeral_public_key);
    vsc_buffer_destroy(&receiver_identity_private_key);
    vsc_buffer_destroy(&receiver_identity_public_key);
    vsc_buffer_destroy(&receiver_long_term_private_key);
    vsc_buffer_destroy(&receiver_long_term_public_key);
}

#endif

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__initiator_x3dh__fixed_keys__should_match);
    RUN_TEST(test__initiator_x3dh__fixed_keys_weak__should_match);
    RUN_TEST(test__responder_x3dh__fixed_keys__should_match);
    RUN_TEST(test__responder_x3dh__fixed_keys_weak__should_match);
    RUN_TEST(test__x3dh__random_keys__should_match);
    RUN_TEST(test__x3dh__random_keys_weak__should_match);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
