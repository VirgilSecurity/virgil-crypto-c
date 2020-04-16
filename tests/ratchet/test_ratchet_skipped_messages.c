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

#include "vscr_ratchet_skipped_messages.h"
#include "vscr_ratchet_common_hidden.h"
#include "test_utils_ratchet.h"

void
test__skipped_messages__adding_chains__should_be_correct(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_skipped_messages_t *msgs = vscr_ratchet_skipped_messages_new();

    vscr_ratchet_key_id_t id1, id2, id3;

    generate_random_key_id(rng, id1);
    generate_random_key_id(rng, id2);
    generate_random_key_id(rng, id3);

    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 1, id1));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, id2));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 3, id3));

    vscr_ratchet_message_key_t *key1 = vscr_ratchet_message_key_new();
    key1->index = 1;

    vscr_ratchet_message_key_t *key2 = vscr_ratchet_message_key_new();
    key2->index = 2;

    vscr_ratchet_message_key_t *key3 = vscr_ratchet_message_key_new();
    key3->index = 3;

    vscr_ratchet_skipped_messages_add_public_key(msgs, id1);
    vscr_ratchet_skipped_messages_add_public_key(msgs, id2);
    vscr_ratchet_skipped_messages_add_public_key(msgs, id3);

    vscr_ratchet_skipped_messages_add_key(msgs, id1, key1);

    TEST_ASSERT_EQUAL(key1, vscr_ratchet_skipped_messages_find_key(msgs, 1, id1));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, id1));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, id2));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 3, id3));

    vscr_ratchet_skipped_messages_add_key(msgs, id2, key2);

    TEST_ASSERT_EQUAL(key1, vscr_ratchet_skipped_messages_find_key(msgs, 1, id1));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, id1));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 3, id2));
    TEST_ASSERT_EQUAL(key2, vscr_ratchet_skipped_messages_find_key(msgs, 2, id2));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 3, id3));

    vscr_ratchet_skipped_messages_add_key(msgs, id3, key3);

    TEST_ASSERT_EQUAL(key1, vscr_ratchet_skipped_messages_find_key(msgs, 1, id1));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, id1));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 3, id2));
    TEST_ASSERT_EQUAL(key2, vscr_ratchet_skipped_messages_find_key(msgs, 2, id2));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 1, id3));
    TEST_ASSERT_EQUAL(key3, vscr_ratchet_skipped_messages_find_key(msgs, 3, id3));

    vscr_ratchet_skipped_messages_delete_key(msgs, id2, key2);

    TEST_ASSERT_EQUAL(key1, vscr_ratchet_skipped_messages_find_key(msgs, 1, id1));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, id1));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, id2));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 1, id3));
    TEST_ASSERT_EQUAL(key3, vscr_ratchet_skipped_messages_find_key(msgs, 3, id3));

    vscr_ratchet_skipped_messages_delete_key(msgs, id3, key3);

    TEST_ASSERT_EQUAL(key1, vscr_ratchet_skipped_messages_find_key(msgs, 1, id1));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, id1));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, id2));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 3, id3));

    vscr_ratchet_skipped_messages_delete_key(msgs, id1, key1);

    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 1, id1));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 2, id2));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 3, id3));

    vscr_ratchet_skipped_messages_destroy(&msgs);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__add_key__many_keys__keys_number_should_be_limited(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_skipped_messages_t *msgs = vscr_ratchet_skipped_messages_new();

    vscr_ratchet_key_id_t id;
    generate_random_key_id(rng, id);

    vscr_ratchet_skipped_messages_add_public_key(msgs, id);

    vscr_ratchet_message_key_t *keys_arr[vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES + 1];

    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES; i++) {
        vscr_ratchet_message_key_t *key = vscr_ratchet_message_key_new();
        key->index = (uint32_t)i;
        keys_arr[i] = key;

        vscr_ratchet_skipped_messages_add_key(msgs, id, key);

        for (size_t j = 0; j <= i; j++) {
            TEST_ASSERT_EQUAL(keys_arr[j], vscr_ratchet_skipped_messages_find_key(msgs, j, id));
        }
    }

    vscr_ratchet_message_key_t *key = vscr_ratchet_message_key_new();
    key->index = (uint32_t)vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES;
    keys_arr[vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES] = key;

    vscr_ratchet_skipped_messages_add_key(msgs, id, key);

    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 0, id));

    for (size_t j = 1; j <= vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES; j++) {
        TEST_ASSERT_EQUAL(keys_arr[j], vscr_ratchet_skipped_messages_find_key(msgs, j, id));
    }

    vscr_ratchet_skipped_messages_destroy(&msgs);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__add_chains__many_keys__chains_number_should_be_limited(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_skipped_messages_t *msgs = vscr_ratchet_skipped_messages_new();

    vscr_ratchet_key_id_t id[vscr_ratchet_common_hidden_MAX_SKIPPED_DH + 1];

    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_SKIPPED_DH + 1; i++) {
        generate_random_key_id(rng, id[i]);
    }

    vscr_ratchet_message_key_t *keys_arr[vscr_ratchet_common_hidden_MAX_SKIPPED_DH + 1];

    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_SKIPPED_DH + 1; i++) {
        vscr_ratchet_message_key_t *key = vscr_ratchet_message_key_new();

        vscr_ratchet_skipped_messages_add_public_key(msgs, id[i]);
        vscr_ratchet_skipped_messages_add_key(msgs, id[i], key);

        keys_arr[i] = key;

        for (size_t j = 0; j <= i; j++) {
            if (j == 0 && i == vscr_ratchet_common_hidden_MAX_SKIPPED_DH) {
                TEST_ASSERT_EQUAL(NULL, vscr_ratchet_skipped_messages_find_key(msgs, 0, id[j]));
            } else {
                TEST_ASSERT_EQUAL(keys_arr[j], vscr_ratchet_skipped_messages_find_key(msgs, 0, id[j]));
            }
        }
    }

    vscr_ratchet_skipped_messages_destroy(&msgs);

    vscf_ctr_drbg_destroy(&rng);
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
    RUN_TEST(test__add_chains__many_keys__chains_number_should_be_limited);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
