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

#include <virgil/crypto/ratchet/vscr_memory.h>
#include <ed25519/ed25519.h>
#include <virgil/crypto/ratchet/private/vscr_ratchet_group_message_defs.h>
#include <virgil/crypto/foundation/vscf_raw_key.h>
#include <vscf_pkcs8_der_deserializer_internal.h>
#include <vscr_ratchet_skipped_group_messages.h>
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

#define TEST_DEPENDENCIES_AVAILABLE VSCR_RATCHET_GROUP_SESSION
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscr_ratchet_message_defs.h"
#include "vscr_ratchet_group_session.h"
#include "vscr_ratchet_group_ticket.h"
#include "test_utils_ratchet.h"
#include "msg_channel.h"

// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------

void
test__all_funcs__fixed_members__should_not_fail(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    size_t size1 = generate_number(rng, 1, 100);
    size_t size2 = generate_number(rng, 1, 100);
    size_t size = size1 + size2;

    vsc_buffer_t **ids = vscr_alloc(size * sizeof(vsc_buffer_t *));

    for (size_t i = 0; i < size; i++) {
        generate_random_participant_id(rng, &ids[i]);
    }

    vscr_ratchet_skipped_group_messages_t *msgs = vscr_ratchet_skipped_group_messages_new();

    vscr_ratchet_skipped_group_messages_setup(msgs, size1);

    for (size_t i = 0; i < size1; i++) {
        vscr_ratchet_skipped_group_messages_add_participant(msgs, vsc_buffer_bytes(ids[i]));
    }

    size_t number_of_keys = 10;
    for (size_t i = 0; i < size1; i++) {
        for (size_t j = 0; j < number_of_keys; j++) {
            vscr_ratchet_message_key_t *key = vscr_ratchet_message_key_new();

            key->index = j;
            vscr_ratchet_skipped_group_messages_add_key(msgs, vsc_buffer_bytes(ids[i]), key);
        }
    }

    for (size_t i = 0; i < size1; i++) {
        for (size_t j = 0; j < number_of_keys; j++) {
            TEST_ASSERT(vscr_ratchet_skipped_group_messages_find_key(msgs, vsc_buffer_bytes(ids[i]), j) != NULL);
        }
    }

    vscr_ratchet_skipped_group_messages_setup(msgs, size);

    for (size_t i = 0; i < size2; i++) {
        vscr_ratchet_skipped_group_messages_add_participant(msgs, vsc_buffer_bytes(ids[size1 + i]));
    }

    for (size_t i = 0; i < size2; i++) {
        for (size_t j = 0; j < number_of_keys; j++) {
            vscr_ratchet_message_key_t *key = vscr_ratchet_message_key_new();

            key->index = j;
            vscr_ratchet_skipped_group_messages_add_key(msgs, vsc_buffer_bytes(ids[size1 + i]), key);
        }
    }

    for (size_t i = 0; i < size; i++) {
        for (size_t j = number_of_keys; j != 0; j--) {

            vscr_ratchet_message_key_t *key =
                    vscr_ratchet_skipped_group_messages_find_key(msgs, vsc_buffer_bytes(ids[i]), j - 1);
            TEST_ASSERT(key != NULL);
            vscr_ratchet_skipped_group_messages_delete_key(msgs, vsc_buffer_bytes(ids[i]), key);
        }
    }

    for (size_t i = 0; i < size; i++) {
        for (size_t j = 0; j < number_of_keys; j++) {

            vscr_ratchet_message_key_t *key =
                    vscr_ratchet_skipped_group_messages_find_key(msgs, vsc_buffer_bytes(ids[i]), j);
            TEST_ASSERT(key == NULL);
        }
    }

    vscr_ratchet_skipped_group_messages_destroy(&msgs);

    for (size_t i = 0; i < size; i++) {
        vsc_buffer_destroy(&ids[i]);
    }

    vscr_dealloc(ids);

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
    RUN_TEST(test__all_funcs__fixed_members__should_not_fail);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
