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

#define TEST_DEPENDENCIES_AVAILABLE VSCR_RATCHET_GROUP_SESSION
#if TEST_DEPENDENCIES_AVAILABLE

#include <virgil/crypto/ratchet/vscr_memory.h>
#include <ed25519/ed25519.h>
#include <virgil/crypto/ratchet/private/vscr_ratchet_group_message_defs.h>
#include <virgil/crypto/foundation/vscf_raw_key.h>
#include "vscr_ratchet_group_session_defs.h"
#include "vscr_ratchet.h"
#include "vscr_ratchet_message_defs.h"
#include "vscr_ratchet_group_session.h"
#include "vscr_ratchet_group_ticket.h"
#include "test_utils_ratchet.h"
#include "msg_channel.h"

// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------

void
test__serialization__random_group_chat_bad_network__decrypt_should_succeed(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_group_session_t **sessions = NULL;
    vsc_buffer_t **priv = NULL;

    size_t group_size = generate_number(rng, 2, 10);

    initialize_random_group_chat(rng, group_size, &sessions, &priv, NULL);

    size_t number_of_iterations = group_size * generate_number(rng, 5, 10);

    encrypt_decrypt(rng, group_size, number_of_iterations, sessions, 0.75, 1.25, 0.25, priv);

    for (size_t i = 0; i < group_size; i++) {
        vscr_ratchet_group_session_destroy(&sessions[i]);
        vsc_buffer_destroy(&priv[i]);
    }

    vscr_dealloc(sessions);
    vscr_dealloc(priv);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__serialization__big_session__overflow_doesnt_happen(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    size_t participants_count = vscr_ratchet_common_MAX_PARTICIPANTS_COUNT;

    vscr_ratchet_group_session_t **sessions = NULL;
    vsc_buffer_t **priv = NULL;

    initialize_random_group_chat(rng, participants_count, &sessions, &priv, NULL);

    vscr_ratchet_group_session_t *session = sessions[0];

    for (size_t i = 0; i < participants_count - 1; i++) {
        vscr_ratchet_group_participant_t *participant = session->participants[i];

        for (size_t j = 0; j < vscr_ratchet_common_hidden_MAX_EPOCHS_COUNT; j++) {
            vscr_ratchet_group_participant_epoch_destroy(&participant->epochs[j]);
            participant->epochs[j] = generate_full_epoch(rng, true);
        }
    }

    vscr_ratchet_chain_key_destroy(&session->my_chain_key);
    session->my_chain_key = generate_full_chain_key();
    session->my_epoch = UINT32_MAX;

    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_SKIPPED_DH - 1; i++) {
        session->messages_count[i] = UINT32_MAX;
    }

    restore_group_session(rng, &session, priv[0]);

    for (size_t i = 0; i < participants_count; i++) {
        if (i > 0) {
            vscr_ratchet_group_session_destroy(&sessions[i]);
        } else {
            vscr_ratchet_group_session_destroy(&session);
        }
        vsc_buffer_destroy(&priv[i]);
    }

    vscr_dealloc(sessions);
    vscr_dealloc(priv);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__serialization__random_big_session__overflow_doesnt_happen(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    size_t participants_count = generate_number(
            rng, vscr_ratchet_common_MIN_PARTICIPANTS_COUNT, vscr_ratchet_common_MAX_PARTICIPANTS_COUNT);

    vscr_ratchet_group_session_t **sessions = NULL;
    vsc_buffer_t **priv = NULL;

    initialize_random_group_chat(rng, participants_count, &sessions, &priv, NULL);

    vscr_ratchet_group_session_t *session = sessions[0];

    for (size_t i = 0; i < participants_count - 1; i++) {
        vscr_ratchet_group_participant_t *participant = session->participants[i];

        for (size_t j = 0; j < vscr_ratchet_common_hidden_MAX_EPOCHS_COUNT; j++) {
            vscr_ratchet_group_participant_epoch_destroy(&participant->epochs[j]);

            if (generate_prob(rng) < 0.5)
                continue;

            participant->epochs[j] = generate_full_epoch(rng, false);
        }
    }

    vscr_ratchet_chain_key_destroy(&session->my_chain_key);
    session->my_chain_key = generate_full_chain_key();
    session->my_epoch = UINT32_MAX;

    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_SKIPPED_DH - 1; i++) {
        session->messages_count[i] = UINT32_MAX;
    }

    restore_group_session(rng, &session, priv[0]);

    for (size_t i = 0; i < participants_count; i++) {
        if (i > 0) {
            vscr_ratchet_group_session_destroy(&sessions[i]);
        } else {
            vscr_ratchet_group_session_destroy(&session);
        }
        vsc_buffer_destroy(&priv[i]);
    }

    vscr_dealloc(sessions);
    vscr_dealloc(priv);

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
    RUN_TEST(test__serialization__random_group_chat_bad_network__decrypt_should_succeed);
    RUN_TEST(test__serialization__big_session__overflow_doesnt_happen);
    RUN_TEST(test__serialization__random_big_session__overflow_doesnt_happen);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
