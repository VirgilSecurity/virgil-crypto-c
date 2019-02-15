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

#include "vscr_ratchet_skipped_messages.h"
#include "vscr_ratchet_common_hidden.h"
#include "test_utils_ratchet.h"

void
test__skipped_messages__adding_chains__should_be_correct(void) {
    vscr_ratchet_skipped_messages_t *msgs = vscr_ratchet_skipped_messages_new();

    vsc_buffer_t *priv1, *pub1;
    vsc_buffer_t *priv2, *pub2;
    vsc_buffer_t *priv3, *pub3;

    generate_raw_keypair(&priv1, &pub1);
    generate_raw_keypair(&priv2, &pub2);
    generate_raw_keypair(&priv3, &pub3);

    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 1, vsc_buffer_data(pub1)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, vsc_buffer_data(pub2)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 3, vsc_buffer_data(pub3)));

    vscr_ratchet_skipped_message_key_t *key1 = vscr_ratchet_skipped_message_key_new();
    key1->message_key = vscr_ratchet_message_key_new();
    key1->message_key->index = 1;
    memcpy(key1->public_key, vsc_buffer_bytes(pub1), sizeof(key1->public_key));

    vscr_ratchet_skipped_message_key_t *key2 = vscr_ratchet_skipped_message_key_new();
    key2->message_key = vscr_ratchet_message_key_new();
    key2->message_key->index = 2;
    memcpy(key2->public_key, vsc_buffer_bytes(pub2), sizeof(key2->public_key));

    vscr_ratchet_skipped_message_key_t *key3 = vscr_ratchet_skipped_message_key_new();
    key3->message_key = vscr_ratchet_message_key_new();
    key3->message_key->index = 3;
    memcpy(key3->public_key, vsc_buffer_bytes(pub3), sizeof(key3->public_key));

    vscr_ratchet_skipped_messages_add_key(msgs, key1);

    TEST_ASSERT_EQUAL(key1, vscr_ratchet_skipped_messages_find_key(msgs, 1, vsc_buffer_data(pub1)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, vsc_buffer_data(pub1)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, vsc_buffer_data(pub2)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 3, vsc_buffer_data(pub3)));

    vscr_ratchet_skipped_messages_add_key(msgs, key2);

    TEST_ASSERT_EQUAL(key1, vscr_ratchet_skipped_messages_find_key(msgs, 1, vsc_buffer_data(pub1)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, vsc_buffer_data(pub1)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 3, vsc_buffer_data(pub2)));
    TEST_ASSERT_EQUAL(key2, vscr_ratchet_skipped_messages_find_key(msgs, 2, vsc_buffer_data(pub2)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 3, vsc_buffer_data(pub3)));

    vscr_ratchet_skipped_messages_add_key(msgs, key3);

    TEST_ASSERT_EQUAL(key1, vscr_ratchet_skipped_messages_find_key(msgs, 1, vsc_buffer_data(pub1)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, vsc_buffer_data(pub1)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 3, vsc_buffer_data(pub2)));
    TEST_ASSERT_EQUAL(key2, vscr_ratchet_skipped_messages_find_key(msgs, 2, vsc_buffer_data(pub2)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 1, vsc_buffer_data(pub3)));
    TEST_ASSERT_EQUAL(key3, vscr_ratchet_skipped_messages_find_key(msgs, 3, vsc_buffer_data(pub3)));

    vscr_ratchet_skipped_messages_delete_key(msgs, key2);

    TEST_ASSERT_EQUAL(key1, vscr_ratchet_skipped_messages_find_key(msgs, 1, vsc_buffer_data(pub1)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, vsc_buffer_data(pub1)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, vsc_buffer_data(pub2)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 1, vsc_buffer_data(pub3)));
    TEST_ASSERT_EQUAL(key3, vscr_ratchet_skipped_messages_find_key(msgs, 3, vsc_buffer_data(pub3)));

    vscr_ratchet_skipped_messages_delete_key(msgs, key3);

    TEST_ASSERT_EQUAL(key1, vscr_ratchet_skipped_messages_find_key(msgs, 1, vsc_buffer_data(pub1)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, vsc_buffer_data(pub1)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, vsc_buffer_data(pub2)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 3, vsc_buffer_data(pub3)));

    vscr_ratchet_skipped_messages_delete_key(msgs, key1);

    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 1, vsc_buffer_data(pub1)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, vsc_buffer_data(pub2)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 3, vsc_buffer_data(pub3)));

    vsc_buffer_destroy(&priv1);
    vsc_buffer_destroy(&pub1);
    vsc_buffer_destroy(&priv2);
    vsc_buffer_destroy(&pub2);
    vsc_buffer_destroy(&priv3);
    vsc_buffer_destroy(&pub3);

    vscr_ratchet_skipped_messages_destroy(&msgs);
}

void
test__add_key__many_keys__keys_number_should_be_limited(void) {
    vscr_ratchet_skipped_messages_t *msgs = vscr_ratchet_skipped_messages_new();

    vsc_buffer_t *pub[vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES + 1];
    vscr_ratchet_skipped_message_key_t *keys_arr[vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES + 1];

    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES; i++) {
        vsc_buffer_t *priv;

        generate_raw_keypair(&priv, &pub[i]);

        vsc_buffer_destroy(&priv);

        vscr_ratchet_skipped_message_key_t *key = vscr_ratchet_skipped_message_key_new();
        key->message_key = vscr_ratchet_message_key_new();
        key->message_key->index = (uint32_t)i;
        memcpy(key->public_key, vsc_buffer_bytes(pub[i]), sizeof(key->public_key));
        keys_arr[i] = key;

        vscr_ratchet_skipped_messages_add_key(msgs, key);

        for (size_t j = 0; j <= i; j++) {
            TEST_ASSERT_EQUAL(keys_arr[j], vscr_ratchet_skipped_messages_find_key(msgs, j, vsc_buffer_data(pub[j])));
        }
    }

    vsc_buffer_t *priv;

    generate_raw_keypair(&priv, &pub[vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES]);

    vsc_buffer_destroy(&priv);

    vscr_ratchet_skipped_message_key_t *key = vscr_ratchet_skipped_message_key_new();
    key->message_key = vscr_ratchet_message_key_new();
    key->message_key->index = (uint32_t)vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES;
    memcpy(key->public_key, vsc_buffer_bytes(pub[vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES]),
            sizeof(key->public_key));
    keys_arr[vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES] = key;

    vscr_ratchet_skipped_messages_add_key(msgs, key);

    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 0, vsc_buffer_data(pub[0])));

    for (size_t j = 1; j <= vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES; j++) {
        TEST_ASSERT_EQUAL(keys_arr[j], vscr_ratchet_skipped_messages_find_key(msgs, j, vsc_buffer_data(pub[j])));
    }

    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES + 1; i++) {
        vsc_buffer_destroy(&pub[i]);
    }

    vscr_ratchet_skipped_messages_destroy(&msgs);
}

#endif

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__skipped_messages__adding_chains__should_be_correct);
    RUN_TEST(test__add_key__many_keys__keys_number_should_be_limited);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
