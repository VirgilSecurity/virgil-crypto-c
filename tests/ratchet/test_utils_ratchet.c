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

#include "test_utils_ratchet.h"
#include <test_utils.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <unity.h>
#include <virgil/crypto/foundation/private/vscf_pkcs8_der_serializer_defs.h>
#include <virgil/crypto/foundation/private/vscf_ed25519_private_key_defs.h>
#include <virgil/crypto/foundation/vscf_ed25519_public_key.h>
#include "unreliable_msg_producer.h"
#include "privateAPI.h"

void
generate_random_data(vsc_buffer_t **buffer) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng);

    size_t size = 0;

    vsc_buffer_t *size_buf = vsc_buffer_new();
    vsc_buffer_use(size_buf, (byte *)&size, sizeof(size));

    TEST_ASSERT_EQUAL(vscf_SUCCESS, vscf_ctr_drbg_random(rng, sizeof(size), size_buf));

    // Do not exceed maximum value
    size %= UINT16_MAX / 64;
    if (size == 0)
        size = UINT16_MAX / 64;

    TEST_ASSERT(*buffer == NULL);

    *buffer = vsc_buffer_new_with_capacity(size);

    TEST_ASSERT_EQUAL(vscf_SUCCESS, vscf_ctr_drbg_random(rng, size, *buffer));

    vscf_ctr_drbg_destroy(&rng);
    vsc_buffer_destroy(&size_buf);
}

void
generate_PKCS8_keypair(vsc_buffer_t **priv, vsc_buffer_t **pub) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng);

    vscf_pkcs8_der_serializer_t *pkcs8 = vscf_pkcs8_der_serializer_new();
    vscf_pkcs8_der_serializer_setup_defaults(pkcs8);

    vscf_ed25519_private_key_t *ed25519_private_key = vscf_ed25519_private_key_new();
    vscf_impl_t *private_key = vscf_ed25519_private_key_impl(ed25519_private_key);
    vscf_ed25519_private_key_use_random(ed25519_private_key, vscf_ctr_drbg_impl(rng));

    TEST_ASSERT_EQUAL(vscf_SUCCESS, vscf_ed25519_private_key_generate_key(ed25519_private_key));

    size_t len_private = vscf_pkcs8_der_serializer_serialized_private_key_len(pkcs8, private_key);

    *priv = vsc_buffer_new_with_capacity(len_private);

    TEST_ASSERT_EQUAL(vscf_SUCCESS, vscf_pkcs8_der_serializer_serialize_private_key(pkcs8, private_key, *priv));

    vscf_impl_t *public_key = vscf_ed25519_private_key_extract_public_key(ed25519_private_key);

    size_t len_public = vscf_pkcs8_der_serializer_serialized_public_key_len(pkcs8, public_key);

    *pub = vsc_buffer_new_with_capacity(len_public);

    TEST_ASSERT_EQUAL(vscf_SUCCESS, vscf_pkcs8_der_serializer_serialize_public_key(pkcs8, public_key, *pub));

    vscf_pkcs8_der_serializer_destroy(&pkcs8);

    vscf_ctr_drbg_destroy(&rng);

    vscf_ed25519_public_key_destroy((vscf_ed25519_public_key_t **)&public_key);
    vscf_ed25519_private_key_destroy((vscf_ed25519_private_key_t **)&private_key);
}

void
generate_raw_keypair(vsc_buffer_t **priv, vsc_buffer_t **pub) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng);

    *priv = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);

    TEST_ASSERT_EQUAL(vscf_SUCCESS, vscf_ctr_drbg_random(rng, ED25519_KEY_LEN, *priv));

    *pub = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);

    TEST_ASSERT_EQUAL(0, curve25519_get_pubkey(vsc_buffer_unused_bytes(*pub), vsc_buffer_bytes(*priv)));
    vsc_buffer_inc_used(*pub, ED25519_KEY_LEN);

    vscf_ctr_drbg_destroy(&rng);
}

void
initialize(vscr_ratchet_session_t **session_alice, vscr_ratchet_session_t **session_bob, bool enable_one_time,
        bool should_restore) {
    vscr_ratchet_session_setup_defaults(*session_alice);
    vscr_ratchet_session_setup_defaults(*session_bob);

    if (should_restore) {
        restore_session(session_alice);
        restore_session(session_bob);
    }

    vsc_buffer_t *alice_priv, *alice_pub;
    generate_PKCS8_keypair(&alice_priv, &alice_pub);

    vsc_buffer_t *bob_priv, *bob_pub;
    generate_PKCS8_keypair(&bob_priv, &bob_pub);

    vsc_buffer_t *bob_lt_priv, *bob_lt_pub;
    generate_PKCS8_keypair(&bob_lt_priv, &bob_lt_pub);

    vsc_buffer_t *bob_ot_priv, *bob_ot_pub;
    generate_PKCS8_keypair(&bob_ot_priv, &bob_ot_pub);

    TEST_ASSERT_EQUAL_INT(vscr_SUCCESS,
            vscr_ratchet_session_initiate(*session_alice, vsc_buffer_data(alice_priv), vsc_buffer_data(bob_pub),
                    vsc_buffer_data(bob_lt_pub), enable_one_time ? vsc_buffer_data(bob_ot_pub) : vsc_data_empty()));

    TEST_ASSERT((*session_alice)->is_initiator);
    TEST_ASSERT(!(*session_alice)->received_first_response);
    TEST_ASSERT((*session_alice)->receiver_has_one_time_public_key == enable_one_time);

    if (should_restore) {
        restore_session(session_alice);
    }

    vscr_error_ctx_t error_ctx;
    vscr_error_ctx_reset(&error_ctx);

    vsc_buffer_t *text = NULL;

    generate_random_data(&text);

    vscr_ratchet_message_t *ratchet_message =
            vscr_ratchet_session_encrypt(*session_alice, vsc_buffer_data(text), &error_ctx);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, error_ctx.error);
    TEST_ASSERT((vscr_ratchet_message_get_one_time_public_key(ratchet_message).len == 0) == !enable_one_time);
    TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(ratchet_message));

    if (should_restore) {
        restore_session(session_alice);
    }

    TEST_ASSERT_EQUAL_INT(
            vscr_SUCCESS, vscr_ratchet_session_respond(*session_bob, vsc_buffer_data(alice_pub),
                                  vsc_buffer_data(bob_priv), vsc_buffer_data(bob_lt_priv),
                                  enable_one_time ? vsc_buffer_data(bob_ot_priv) : vsc_data_empty(), ratchet_message));

    TEST_ASSERT(!(*session_bob)->is_initiator);
    TEST_ASSERT(!(*session_bob)->received_first_response);
    TEST_ASSERT((*session_bob)->receiver_has_one_time_public_key == enable_one_time);

    if (should_restore) {
        restore_session(session_bob);
    }

    size_t len = vscr_ratchet_session_decrypt_len(*session_bob, ratchet_message);
    vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(len);

    vscr_error_t result = vscr_ratchet_session_decrypt(*session_bob, ratchet_message, plain_text);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, result);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text), plain_text);

    if (should_restore) {
        restore_session(session_bob);
    }

    vscr_ratchet_message_destroy(&ratchet_message);

    vsc_buffer_destroy(&text);
    vsc_buffer_destroy(&plain_text);

    vsc_buffer_destroy(&alice_priv);
    vsc_buffer_destroy(&alice_pub);

    vsc_buffer_destroy(&bob_priv);
    vsc_buffer_destroy(&bob_pub);

    vsc_buffer_destroy(&bob_lt_priv);
    vsc_buffer_destroy(&bob_lt_pub);

    vsc_buffer_destroy(&bob_ot_priv);
    vsc_buffer_destroy(&bob_ot_pub);
}

void
encrypt_decrypt__100_plain_texts_random_order(
        vscr_ratchet_session_t *session_alice, vscr_ratchet_session_t *session_bob) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng);

    bool sent_first_response = false;

    for (int i = 0; i < 100; i++) {
        byte dice_rnd;
        vsc_buffer_t *fake_buffer = vsc_buffer_new();
        vsc_buffer_use(fake_buffer, &dice_rnd, sizeof(dice_rnd));
        vscf_ctr_drbg_random(rng, sizeof(dice_rnd), fake_buffer);
        bool dice = dice_rnd % 2 == 0;

        vsc_buffer_destroy(&fake_buffer);

        vsc_buffer_t *text = NULL;
        generate_random_data(&text);

        vscr_ratchet_session_t *sender, *receiver;

        // Alice sends msg
        if (dice) {
            sender = session_alice;
            receiver = session_bob;
        } else {
            sender = session_bob;
            receiver = session_alice;
        }

        vscr_error_ctx_t error_ctx;
        vscr_error_ctx_reset(&error_ctx);

        vscr_ratchet_message_t *ratchet_message =
                vscr_ratchet_session_encrypt(sender, vsc_buffer_data(text), &error_ctx);
        TEST_ASSERT_EQUAL(vscr_SUCCESS, error_ctx.error);
        TEST_ASSERT_EQUAL(dice && !sent_first_response ? vscr_msg_type_PREKEY : vscr_msg_type_REGULAR,
                vscr_ratchet_message_get_type(ratchet_message));

        size_t len = vscr_ratchet_session_decrypt_len(receiver, ratchet_message);
        vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(len);
        vscr_error_t result = vscr_ratchet_session_decrypt(receiver, ratchet_message, plain_text);
        TEST_ASSERT_EQUAL(vscr_SUCCESS, result);

        TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text), plain_text);

        if (!dice)
            sent_first_response = true;

        vsc_buffer_destroy(&text);
        vsc_buffer_destroy(&plain_text);
        vscr_ratchet_message_destroy(&ratchet_message);
    }

    vscf_ctr_drbg_destroy(&rng);
}

void
encrypt_decrypt__100_plain_texts_random_order_with_producers(
        vscr_ratchet_session_t **session_alice, vscr_ratchet_session_t **session_bob, bool should_restore) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    vscf_ctr_drbg_setup_defaults(rng);

    unreliable_msg_producer_t producer_alice, producer_bob;
    init_producer(&producer_alice, session_alice, 0.2, 0.3);
    init_producer(&producer_bob, session_bob, 0.2, 0.3);

    for (int i = 0; i < 100; i++) {
        byte dice_rnd;
        vsc_buffer_t *fake_buffer = vsc_buffer_new();
        vsc_buffer_use(fake_buffer, &dice_rnd, sizeof(dice_rnd));
        vscf_ctr_drbg_random(rng, sizeof(dice_rnd), fake_buffer);
        bool dice = dice_rnd % 2 == 0;

        vsc_buffer_destroy(&fake_buffer);

        vscr_ratchet_session_t **receiver;
        unreliable_msg_producer_t *producer;

        // Alice sends msg
        if (dice) {
            receiver = session_bob;
            producer = &producer_alice;
        } else {
            receiver = session_alice;
            producer = &producer_bob;
        }

        vscr_ratchet_message_t *ratchet_message;
        vsc_buffer_t *text;

        produce_msg(producer, &text, &ratchet_message, should_restore);

        vscr_error_ctx_t error_ctx;
        vscr_error_ctx_reset(&error_ctx);

        size_t len = vscr_ratchet_session_decrypt_len(*receiver, ratchet_message);
        vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(len);
        vscr_error_t result = vscr_ratchet_session_decrypt(*receiver, ratchet_message, plain_text);
        TEST_ASSERT_EQUAL(vscr_SUCCESS, result);

        TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text), plain_text);

        if (!dice)
            producer_alice.sent_first_response = true;

        vsc_buffer_destroy(&text);
        vsc_buffer_destroy(&plain_text);
        vscr_ratchet_message_destroy(&ratchet_message);

        if (should_restore) {
            restore_session(receiver);
        }
    }

    vscf_ctr_drbg_destroy(&rng);

    deinit_producer(&producer_alice);
    deinit_producer(&producer_bob);
}

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
ratchet_sender_chain_cmp(vscr_ratchet_sender_chain_t *sender_chain1, vscr_ratchet_sender_chain_t *sender_chain2) {
    if (sender_chain1 == NULL && sender_chain2 == NULL)
        return true;

    return memcmp(sender_chain1->private_key, sender_chain2->private_key, sizeof(sender_chain1->private_key)) == 0 &&
           memcmp(sender_chain1->public_key, sender_chain2->public_key, sizeof(sender_chain1->public_key)) == 0 &&
           ratchet_chain_key_cmp(&sender_chain1->chain_key, &sender_chain2->chain_key);
}

static bool
ratchet_cmp(vscr_ratchet_t *ratchet1, vscr_ratchet_t *ratchet2) {

    return memcmp(ratchet1->root_key, ratchet2->root_key, sizeof(ratchet1->root_key)) == 0 &&
           ratchet_sender_chain_cmp(ratchet1->sender_chain, ratchet2->sender_chain) &&
           ratchet1->prev_sender_chain_count == ratchet2->prev_sender_chain_count &&
           ratchet_receiver_chain_cmp(ratchet1->receiver_chains, ratchet2->receiver_chains) &&
           ratchet_skipped_msg_cmp(ratchet1->skipped_message_keys, ratchet2->skipped_message_keys);
}

static bool
ratchet_session_cmp(vscr_ratchet_session_t *ratchet_session1, vscr_ratchet_session_t *ratchet_session2) {

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
           ratchet_session1->receiver_has_one_time_public_key == ratchet_session2->receiver_has_one_time_public_key &&
           ratchet_cmp(ratchet_session1->ratchet, ratchet_session2->ratchet);
}

void
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

    bool flag = ratchet_session_cmp(session_ref, *session);

    if (!flag) {
        TEST_ASSERT(false);
    }

    vscr_ratchet_session_destroy(&session_ref);
}