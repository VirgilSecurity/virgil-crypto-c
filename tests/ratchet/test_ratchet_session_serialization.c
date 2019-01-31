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

#define TEST_DEPENDENCIES_AVAILABLE VSCR_RATCHET
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscr_ratchet_session.h"
#include "unreliable_msg_producer.h"

#include "test_data_ratchet_session.h"

#include <ed25519/ed25519.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <virgil/crypto/ratchet/private/vscr_ratchet_message_defs.h>
#include <virgil/crypto/ratchet/vscr_memory.h>
#include <vscr_ratchet_chain_key.h>
#include <vscr_ratchet_receiver_chain_list_node.h>
#include <vscr_ratchet_skipped_message_key_list_node.h>

// --------------------------------------------------------------------------
//  Should have it to prevent linkage errors in MSVC.
// --------------------------------------------------------------------------
// clang-format off
void setUp(void) { }
void tearDown(void) { }
void suiteSetUp(void) { }
int suiteTearDown(int num_failures) { return num_failures; }
// clang-format on

typedef struct ratchet_sender_chain {
    //
    //  Function do deallocate self context.
    //
    vscr_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    size_t refcnt;

    byte private_key[vscr_ratchet_common_RATCHET_KEY_LENGTH];

    byte public_key[vscr_ratchet_common_RATCHET_KEY_LENGTH];

    vscr_ratchet_chain_key_t chain_key;
} ratchet_sender_chain_t;

typedef struct ratchet {
    //
    //  Function do deallocate self context.
    //
    vscr_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    size_t refcnt;
    //
    //  Dependency to the interface 'random'.
    //
    vscf_impl_t *rng;
    //
    //  Dependency to the class 'ratchet cipher'.
    //
    void *cipher;

    ratchet_sender_chain_t *sender_chain;

    vscr_ratchet_receiver_chain_list_node_t *receiver_chains;

    vscr_ratchet_skipped_message_key_list_node_t *skipped_message_keys;

    byte root_key[vscr_ratchet_common_RATCHET_SHARED_KEY_LENGTH];
} ratchet_t;

typedef struct ratchet_session {
    //
    //  Function do deallocate self context.
    //
    vscr_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    size_t refcnt;
    //
    //  Dependency to the interface 'random'.
    //
    vscf_impl_t *rng;

    bool is_initiator;

    ratchet_t *ratchet;

    bool received_first_response;

    byte sender_identity_public_key[vscr_ratchet_common_RATCHET_KEY_LENGTH];

    byte sender_ephemeral_public_key[vscr_ratchet_common_RATCHET_KEY_LENGTH];

    byte receiver_long_term_public_key[vscr_ratchet_common_RATCHET_KEY_LENGTH];

    byte receiver_one_time_public_key[vscr_ratchet_common_RATCHET_KEY_LENGTH];
} ratchet_session_t;

// --------------------------------------------------------------------------
//  Test functions.
// --------------------------------------------------------------------------
static bool
ratchet_chain_key_cmp(vscr_ratchet_chain_key_t *chain_key1, vscr_ratchet_chain_key_t *chain_key2) {
    return chain_key1->index == chain_key2->index &&
           memcmp(chain_key1->key, chain_key2->key, sizeof(chain_key1->key)) == 0;
}

static bool
ratchet_msg_key_cmp(vscr_ratchet_message_key_t *msg_key1, vscr_ratchet_message_key_t *msg_key2) {
    return msg_key1->index == msg_key2->index && memcmp(msg_key1->key, msg_key2->key, sizeof(msg_key1->key)) == 0;
}

static bool
ratchet_skipped_msg_cmp(
        vscr_ratchet_skipped_message_key_list_node_t *msg1, vscr_ratchet_skipped_message_key_list_node_t *msg2) {
    if (msg1 == NULL && msg2 == NULL)
        return true;

    return memcmp(msg1->value->public_key, msg1->value->public_key, sizeof(msg1->value->public_key)) == 0 &&
           ratchet_msg_key_cmp(msg1->value->message_key, msg2->value->message_key) &&
           ratchet_skipped_msg_cmp(msg1->next, msg2->next);
}

static bool
ratchet_receiver_chain_cmp(
        vscr_ratchet_receiver_chain_list_node_t *chain1, vscr_ratchet_receiver_chain_list_node_t *chain2) {
    if (chain1 == NULL && chain2 == NULL)
        return true;

    return memcmp(chain1->value->public_key, chain2->value->public_key, sizeof(chain1->value->public_key)) == 0 &&
           ratchet_chain_key_cmp(&chain1->value->chain_key, &chain2->value->chain_key) &&
           ratchet_receiver_chain_cmp(chain1->next, chain2->next);
}

static bool
ratchet_sender_chain_cmp(ratchet_sender_chain_t *sender_chain1, ratchet_sender_chain_t *sender_chain2) {
    if (sender_chain1 == NULL && sender_chain2 == NULL)
        return true;

    return memcmp(sender_chain1->private_key, sender_chain2->private_key, sizeof(sender_chain1->private_key)) == 0 &&
           memcmp(sender_chain1->public_key, sender_chain2->public_key, sizeof(sender_chain1->public_key)) == 0 &&
           ratchet_chain_key_cmp(&sender_chain1->chain_key, &sender_chain2->chain_key);
}

static bool
ratchet_cmp(ratchet_t *ratchet1, ratchet_t *ratchet2) {

    return memcmp(ratchet1->root_key, ratchet2->root_key, sizeof(ratchet1->root_key)) == 0 &&
           ratchet_sender_chain_cmp(ratchet1->sender_chain, ratchet2->sender_chain) &&
           ratchet_receiver_chain_cmp(ratchet1->receiver_chains, ratchet2->receiver_chains) &&
           ratchet_skipped_msg_cmp(ratchet1->skipped_message_keys, ratchet2->skipped_message_keys);
}

static bool
ratchet_session_cmp(ratchet_session_t *ratchet_session1, ratchet_session_t *ratchet_session2) {

    return memcmp(ratchet_session1->sender_identity_public_key, ratchet_session2->sender_identity_public_key,
                   sizeof(ratchet_session1->sender_identity_public_key)) == 0 &&
           memcmp(ratchet_session1->sender_ephemeral_public_key, ratchet_session2->sender_ephemeral_public_key,
                   sizeof(ratchet_session1->sender_ephemeral_public_key)) == 0 &&
           memcmp(ratchet_session1->receiver_long_term_public_key, ratchet_session2->receiver_long_term_public_key,
                   sizeof(ratchet_session1->receiver_long_term_public_key)) == 0 &&
           memcmp(ratchet_session1->receiver_one_time_public_key, ratchet_session2->receiver_one_time_public_key,
                   sizeof(ratchet_session1->receiver_one_time_public_key)) == 0 &&
           ratchet_session1->is_initiator == ratchet_session2->is_initiator &&
           ratchet_session1->received_first_response == ratchet_session2->received_first_response &&
           ratchet_cmp(ratchet_session1->ratchet, ratchet_session2->ratchet);
}

static void
restore_session(vscr_ratchet_session_t **session) {
    vscr_error_ctx_t error_ctx;
    vscr_error_ctx_reset(&error_ctx);

    vscr_ratchet_session_t *session_ref = *session;

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(vscr_ratchet_session_serialize_len(*session));

    vscr_ratchet_session_serialize(*session, buffer);

    *session = vscr_ratchet_session_deserialize(vsc_buffer_data(buffer), &error_ctx);

    vsc_buffer_destroy(&buffer);

    TEST_ASSERT_EQUAL(vscr_SUCCESS, error_ctx.error);

    vscr_ratchet_session_setup_defaults(*session);

    bool flag = ratchet_session_cmp((ratchet_session_t *)session_ref, (ratchet_session_t *)*session);

    if (!flag) {
        TEST_ASSERT(false);
    }

    vscr_ratchet_session_destroy(&session_ref);
}

void
test__serialization__randomly_skipped_messages__should_work_after_restore(void) {
    vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
    vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();

    vscr_ratchet_session_setup_defaults(session_alice);
    vscr_ratchet_session_setup_defaults(session_bob);

    restore_session(&session_alice);
    restore_session(&session_bob);

    TEST_ASSERT_EQUAL_INT(vscr_SUCCESS,
            vscr_ratchet_session_initiate(session_alice, test_ratchet_session_alice_identity_private_key,
                    test_ratchet_session_bob_identity_public_key, test_ratchet_session_bob_long_term_public_key,
                    test_ratchet_session_bob_one_time_public_key));

    restore_session(&session_alice);

    vscr_error_ctx_t error_ctx;
    vscr_error_ctx_reset(&error_ctx);


    vscr_ratchet_message_t *ratchet_message =
            vscr_ratchet_session_encrypt(session_alice, test_ratchet_session_plain_text1, &error_ctx);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, error_ctx.error);

    restore_session(&session_alice);

    TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(ratchet_message));

    TEST_ASSERT_EQUAL_INT(vscr_SUCCESS,
            vscr_ratchet_session_respond(session_bob, test_ratchet_session_alice_identity_public_key,
                    test_ratchet_session_bob_identity_private_key, test_ratchet_session_bob_long_term_private_key,
                    test_ratchet_session_bob_one_time_private_key, ratchet_message));

    restore_session(&session_bob);

    size_t len2 = vscr_ratchet_session_decrypt_len(session_bob, ratchet_message);
    vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(len2);

    vscr_error_t result = vscr_ratchet_session_decrypt(session_bob, ratchet_message, plain_text);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, result);

    vscr_ratchet_message_destroy(&ratchet_message);

    TEST_ASSERT_EQUAL_INT(test_ratchet_session_plain_text1.len, vsc_buffer_len(plain_text));
    TEST_ASSERT_EQUAL_MEMORY(
            test_ratchet_session_plain_text1.bytes, vsc_buffer_bytes(plain_text), test_ratchet_session_plain_text1.len);

    vsc_buffer_destroy(&plain_text);

    restore_session(&session_bob);

    unreliable_msg_producer_t producer_alice, producer_bob;
    init_producer(&producer_alice, session_alice, 0.2, 0.3);
    init_producer(&producer_bob, session_bob, 0.2, 0.3);

    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng);

    for (int i = 0; i < 100; i++) {
        restore_session(&producer_alice.session);
        restore_session(&producer_bob.session);

        byte dice_rnd;
        vsc_buffer_t *fake_buffer = vsc_buffer_new();
        vsc_buffer_use(fake_buffer, &dice_rnd, sizeof(dice_rnd));
        vscf_ctr_drbg_random(rng, sizeof(dice_rnd), fake_buffer);
        bool dice = dice_rnd % 2 == 0;

        vsc_buffer_destroy(&fake_buffer);

        vscr_ratchet_session_t *receiver;
        unreliable_msg_producer_t *producer;

        // Alice sends msg
        if (dice) {
            receiver = producer_bob.session;
            producer = &producer_alice;
        } else {
            receiver = producer_alice.session;
            producer = &producer_bob;
        }

        produce_msg(producer, &plain_text, &ratchet_message);

        size_t plain_text_len = vscr_ratchet_session_decrypt_len(receiver, ratchet_message);
        vsc_buffer_t *decrypted = vsc_buffer_new_with_capacity(plain_text_len);
        result = vscr_ratchet_session_decrypt(receiver, ratchet_message, decrypted);
        TEST_ASSERT_EQUAL(vscr_SUCCESS, result);

        TEST_ASSERT_EQUAL_INT(vsc_buffer_len(plain_text), vsc_buffer_len(decrypted));
        TEST_ASSERT_EQUAL_MEMORY(vsc_buffer_bytes(plain_text), vsc_buffer_bytes(decrypted), vsc_buffer_len(plain_text));
        vsc_buffer_destroy(&decrypted);

        vsc_buffer_destroy(&plain_text);
        vscr_ratchet_message_destroy(&ratchet_message);
    }

    vscf_ctr_drbg_destroy(&rng);

    vscr_ratchet_session_destroy(&producer_alice.session);
    vscr_ratchet_session_destroy(&producer_bob.session);

    deinit_producer(&producer_alice);
    deinit_producer(&producer_bob);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__serialization__randomly_skipped_messages__should_work_after_restore);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
