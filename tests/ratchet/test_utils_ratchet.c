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

#include <unity.h>
#include <test_utils.h>
#include <virgil/crypto/ratchet/vscr_ratchet_group_ticket.h>
#include <virgil/crypto/ratchet/vscr_memory.h>
#include <virgil/crypto/foundation/vscf_curve25519_private_key.h>
#include <virgil/crypto/foundation/vscf_curve25519_public_key.h>

#define TEST_DEPENDENCIES_AVAILABLE VSCR_RATCHET
#if TEST_DEPENDENCIES_AVAILABLE

#include "virgil/crypto/foundation/vscf_ctr_drbg.h"
#include "virgil/crypto/foundation/private/vscf_pkcs8_der_serializer_defs.h"
#include "virgil/crypto/foundation/private/vscf_ed25519_private_key_defs.h"
#include "virgil/crypto/foundation/vscf_ed25519_public_key.h"
#include "virgil/crypto/ratchet/vscr_ratchet_group_session.h"
#include "test_utils_ratchet.h"
#include "unreliable_msg_producer.h"
#include "privateAPI.h"
#include "msg_channel.h"

size_t
pick_element_uniform(vscf_ctr_drbg_t *rng, size_t size) {
    return generate_number(rng, 0, size - 1);
}

size_t
pick_element_queue(vscf_ctr_drbg_t *rng, size_t size, double distribution_factor) {
    if (distribution_factor == 0) {
        return 0;
    }

    double r = generate_prob(rng);

    double f_n = distribution_factor;
    for (size_t j = 1; j < size; j++) {
        f_n *= distribution_factor;
    }

    double p = (1 - distribution_factor) / (1 - f_n);
    double p_sum = p;

    size_t i = 0;
    for (; i < size - i && r > p_sum; i++) {
        p *= distribution_factor;
        p_sum += p;
    }

    return i;
}

size_t
generate_number(vscf_ctr_drbg_t *rng, size_t min, size_t max) {
    size_t size = 0;

    vsc_buffer_t *size_buf = vsc_buffer_new();
    vsc_buffer_use(size_buf, (byte *)&size, sizeof(size));

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_random(rng, sizeof(size), size_buf));

    vsc_buffer_destroy(&size_buf);

    // Do not exceed maximum value
    size %= max - min + 1;
    size += min;

    return size;
}

double
generate_prob(vscf_ctr_drbg_t *rng) {
    size_t max = 1000000;
    double num = (double)generate_number(rng, 0, max);

    return num / (double)max;
}

size_t
generate_size(vscf_ctr_drbg_t *rng) {
    return generate_number(rng, 1, UINT16_MAX / 64);
}

void
generate_random_data(vscf_ctr_drbg_t *rng, vsc_buffer_t **buffer) {
    size_t size = generate_size(rng);

    TEST_ASSERT(*buffer == NULL);

    *buffer = vsc_buffer_new_with_capacity(size);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_random(rng, size, *buffer));
}

void
generate_permutation(vscf_ctr_drbg_t *rng, size_t n, size_t *buffer) {

    for (size_t i = 0; i < n - 1; i++) {
        size_t j = generate_number(rng, i, n - 1);
        size_t t = buffer[i];
        buffer[i] = buffer[j];
        buffer[j] = t;
    }
}

void
generate_PKCS8_ed_keypair(vscf_ctr_drbg_t *rng, vsc_buffer_t **priv, vsc_buffer_t **pub) {
    vscf_pkcs8_der_serializer_t *pkcs8 = vscf_pkcs8_der_serializer_new();
    vscf_pkcs8_der_serializer_setup_defaults(pkcs8);

    vscf_ed25519_private_key_t *ed25519_private_key = vscf_ed25519_private_key_new();
    vscf_impl_t *private_key = vscf_ed25519_private_key_impl(ed25519_private_key);
    vscf_ed25519_private_key_use_random(ed25519_private_key, vscf_ctr_drbg_impl(rng));

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ed25519_private_key_generate_key(ed25519_private_key));

    size_t len_private = vscf_pkcs8_der_serializer_serialized_private_key_len(pkcs8, private_key);

    *priv = vsc_buffer_new_with_capacity(len_private);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_pkcs8_der_serializer_serialize_private_key(pkcs8, private_key, *priv));

    vscf_impl_t *public_key = vscf_ed25519_private_key_extract_public_key(ed25519_private_key);

    size_t len_public = vscf_pkcs8_der_serializer_serialized_public_key_len(pkcs8, public_key);

    *pub = vsc_buffer_new_with_capacity(len_public);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_pkcs8_der_serializer_serialize_public_key(pkcs8, public_key, *pub));

    vscf_pkcs8_der_serializer_destroy(&pkcs8);

    vscf_ed25519_public_key_destroy((vscf_ed25519_public_key_t **)&public_key);
    vscf_ed25519_private_key_destroy((vscf_ed25519_private_key_t **)&private_key);
}

void
generate_PKCS8_curve_keypair(vscf_ctr_drbg_t *rng, vsc_buffer_t **priv, vsc_buffer_t **pub) {
    vscf_pkcs8_der_serializer_t *pkcs8 = vscf_pkcs8_der_serializer_new();
    vscf_pkcs8_der_serializer_setup_defaults(pkcs8);

    vscf_curve25519_private_key_t *curve25519_private_key = vscf_curve25519_private_key_new();
    vscf_impl_t *private_key = vscf_curve25519_private_key_impl(curve25519_private_key);
    vscf_curve25519_private_key_use_random(curve25519_private_key, vscf_ctr_drbg_impl(rng));

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_curve25519_private_key_generate_key(curve25519_private_key));

    size_t len_private = vscf_pkcs8_der_serializer_serialized_private_key_len(pkcs8, private_key);

    *priv = vsc_buffer_new_with_capacity(len_private);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_pkcs8_der_serializer_serialize_private_key(pkcs8, private_key, *priv));

    vscf_impl_t *public_key = vscf_curve25519_private_key_extract_public_key(curve25519_private_key);

    size_t len_public = vscf_pkcs8_der_serializer_serialized_public_key_len(pkcs8, public_key);

    *pub = vsc_buffer_new_with_capacity(len_public);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_pkcs8_der_serializer_serialize_public_key(pkcs8, public_key, *pub));

    vscf_pkcs8_der_serializer_destroy(&pkcs8);

    vscf_curve25519_public_key_destroy((vscf_curve25519_public_key_t **)&public_key);
    vscf_curve25519_private_key_destroy((vscf_curve25519_private_key_t **)&private_key);
}

void
generate_random_participant_id(vscf_ctr_drbg_t *rng, vsc_buffer_t **id) {
    *id = vsc_buffer_new_with_capacity(vscr_ratchet_common_PARTICIPANT_ID_LEN);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_random(rng, vscr_ratchet_common_PARTICIPANT_ID_LEN, *id));
}

void
generate_raw_keypair(vscf_ctr_drbg_t *rng, vsc_buffer_t **priv, vsc_buffer_t **pub, bool curve25519) {
    *priv = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_random(rng, ED25519_KEY_LEN, *priv));

    *pub = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);

    if (curve25519) {
        TEST_ASSERT_EQUAL(0, curve25519_get_pubkey(vsc_buffer_unused_bytes(*pub), vsc_buffer_bytes(*priv)));
    } else {
        TEST_ASSERT_EQUAL(0, ed25519_get_pubkey(vsc_buffer_unused_bytes(*pub), vsc_buffer_bytes(*priv)));
    }
    vsc_buffer_inc_used(*pub, ED25519_KEY_LEN);
}

void
initialize(vscf_ctr_drbg_t *rng, vscr_ratchet_session_t **session_alice, vscr_ratchet_session_t **session_bob,
        bool enable_one_time, bool should_restore) {
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_setup_defaults(*session_alice));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_setup_defaults(*session_bob));

    if (should_restore) {
        restore_session(rng, session_alice);
        restore_session(rng, session_bob);
    }

    vsc_buffer_t *alice_priv, *alice_pub;
    generate_PKCS8_ed_keypair(rng, &alice_priv, &alice_pub);

    vsc_buffer_t *bob_priv, *bob_pub;
    generate_PKCS8_ed_keypair(rng, &bob_priv, &bob_pub);

    vsc_buffer_t *bob_lt_priv, *bob_lt_pub;
    generate_PKCS8_curve_keypair(rng, &bob_lt_priv, &bob_lt_pub);

    vsc_buffer_t *bob_ot_priv, *bob_ot_pub;
    generate_PKCS8_curve_keypair(rng, &bob_ot_priv, &bob_ot_pub);

    TEST_ASSERT_EQUAL_INT(vscr_status_SUCCESS,
            vscr_ratchet_session_initiate(*session_alice, vsc_buffer_data(alice_priv), vsc_buffer_data(bob_pub),
                    vsc_buffer_data(bob_lt_pub), enable_one_time ? vsc_buffer_data(bob_ot_pub) : vsc_data_empty()));

    TEST_ASSERT((*session_alice)->is_initiator);
    TEST_ASSERT(!(*session_alice)->received_first_response);
    TEST_ASSERT((*session_alice)->receiver_has_one_time_public_key == enable_one_time);

    if (should_restore) {
        restore_session(rng, session_alice);
    }

    vscr_error_t error;
    vscr_error_reset(&error);

    vsc_buffer_t *text = NULL;

    generate_random_data(rng, &text);

    vscr_ratchet_message_t *ratchet_message =
            vscr_ratchet_session_encrypt(*session_alice, vsc_buffer_data(text), &error);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));
    TEST_ASSERT((vscr_ratchet_message_get_one_time_public_key(ratchet_message).len == 0) == !enable_one_time);
    TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(ratchet_message));

    if (should_restore) {
        restore_session(rng, session_alice);
    }

    TEST_ASSERT_EQUAL_INT(vscr_status_SUCCESS,
            vscr_ratchet_session_respond(*session_bob, vsc_buffer_data(alice_pub), vsc_buffer_data(bob_priv),
                    vsc_buffer_data(bob_lt_priv), enable_one_time ? vsc_buffer_data(bob_ot_priv) : vsc_data_empty(),
                    ratchet_message));

    TEST_ASSERT(!(*session_bob)->is_initiator);
    TEST_ASSERT(!(*session_bob)->received_first_response);
    TEST_ASSERT((*session_bob)->receiver_has_one_time_public_key == enable_one_time);

    if (should_restore) {
        restore_session(rng, session_bob);
    }

    size_t len = vscr_ratchet_session_decrypt_len(*session_bob, ratchet_message);
    vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(len);

    vscr_status_t result = vscr_ratchet_session_decrypt(*session_bob, ratchet_message, plain_text);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, result);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text), plain_text);

    if (should_restore) {
        restore_session(rng, session_bob);
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
        vscf_ctr_drbg_t *rng, vscr_ratchet_session_t *session_alice, vscr_ratchet_session_t *session_bob) {
    bool sent_first_response = false;

    for (int i = 0; i < 100; i++) {
        byte dice_rnd;
        vsc_buffer_t *fake_buffer = vsc_buffer_new();
        vsc_buffer_use(fake_buffer, &dice_rnd, sizeof(dice_rnd));
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_random(rng, sizeof(dice_rnd), fake_buffer));
        bool dice = dice_rnd % 2 == 0;

        vsc_buffer_destroy(&fake_buffer);

        vsc_buffer_t *text = NULL;
        generate_random_data(rng, &text);

        vscr_ratchet_session_t *sender, *receiver;

        // Alice sends msg
        if (dice) {
            sender = session_alice;
            receiver = session_bob;
        } else {
            sender = session_bob;
            receiver = session_alice;
        }

        vscr_error_t error;
        vscr_error_reset(&error);

        vscr_ratchet_message_t *ratchet_message = vscr_ratchet_session_encrypt(sender, vsc_buffer_data(text), &error);
        TEST_ASSERT_FALSE(vscr_error_has_error(&error));
        TEST_ASSERT_EQUAL(dice && !sent_first_response ? vscr_msg_type_PREKEY : vscr_msg_type_REGULAR,
                vscr_ratchet_message_get_type(ratchet_message));

        size_t len = vscr_ratchet_session_decrypt_len(receiver, ratchet_message);
        vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(len);
        vscr_status_t result = vscr_ratchet_session_decrypt(receiver, ratchet_message, plain_text);
        TEST_ASSERT_EQUAL(vscr_status_SUCCESS, result);

        TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text), plain_text);

        if (!dice)
            sent_first_response = true;

        vsc_buffer_destroy(&text);
        vsc_buffer_destroy(&plain_text);
        vscr_ratchet_message_destroy(&ratchet_message);
    }
}

void
encrypt_decrypt__100_plain_texts_random_order_with_producers(vscf_ctr_drbg_t *rng,
        vscr_ratchet_session_t **session_alice, vscr_ratchet_session_t **session_bob, bool should_restore) {
    unreliable_msg_producer_t producer_alice, producer_bob;
    init_producer(&producer_alice, session_alice, 0.2, 0.3);
    init_producer(&producer_bob, session_bob, 0.2, 0.3);

    for (int i = 0; i < 100; i++) {
        byte dice_rnd;
        vsc_buffer_t *fake_buffer = vsc_buffer_new();
        vsc_buffer_use(fake_buffer, &dice_rnd, sizeof(dice_rnd));
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_random(rng, sizeof(dice_rnd), fake_buffer));
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

        vscr_error_t error;
        vscr_error_reset(&error);

        size_t len = vscr_ratchet_session_decrypt_len(*receiver, ratchet_message);
        vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(len);
        vscr_status_t result = vscr_ratchet_session_decrypt(*receiver, ratchet_message, plain_text);
        TEST_ASSERT_EQUAL(vscr_status_SUCCESS, result);

        TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(text), plain_text);

        if (!dice)
            producer_alice.sent_first_response = true;

        vsc_buffer_destroy(&text);
        vsc_buffer_destroy(&plain_text);
        vscr_ratchet_message_destroy(&ratchet_message);

        if (should_restore) {
            restore_session(rng, receiver);
        }
    }

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
ratchet_skipped_msg_cmp(vscr_ratchet_skipped_message_key_t *msg1, vscr_ratchet_skipped_message_key_t *msg2) {
    if (msg1 == NULL && msg2 == NULL)
        return true;

    if (msg1 == NULL || msg2 == NULL) {
        TEST_ASSERT(false);
    }

    return memcmp(msg1->public_key, msg1->public_key, sizeof(msg1->public_key)) == 0 &&
           ratchet_msg_key_cmp(msg1->message_key, msg2->message_key);
}

static bool
ratchet_skipped_msgs_cmp(vscr_ratchet_skipped_messages_t *msgs1, vscr_ratchet_skipped_messages_t *msgs2) {
    vscr_ratchet_skipped_message_key_list_node_t *node1 = msgs1->keys;
    vscr_ratchet_skipped_message_key_list_node_t *node2 = msgs2->keys;

    while (true) {

        if (node1 == NULL && node2 == NULL)
            return true;

        if (node1 == NULL || node2 == NULL) {
            TEST_ASSERT(false);
        }

        if (!ratchet_skipped_msg_cmp(node1->value, node2->value))
            return false;

        node1 = node1->next;
        node2 = node2->next;
    }
}

static bool
ratchet_receiver_chain_cmp(vscr_ratchet_receiver_chain_t *chain1, vscr_ratchet_receiver_chain_t *chain2) {
    if (chain1 == NULL && chain2 == NULL)
        return true;

    if (chain1 == NULL || chain2 == NULL) {
        TEST_ASSERT(false);
    }

    return memcmp(chain1->public_key, chain2->public_key, sizeof(chain1->public_key)) == 0 &&
           ratchet_chain_key_cmp(&chain1->chain_key, &chain2->chain_key);
}

static bool
ratchet_receiver_chains_cmp(vscr_ratchet_receiver_chains_t *chains1, vscr_ratchet_receiver_chains_t *chains2) {

    vscr_ratchet_receiver_chain_list_node_t *node1 = chains1->chains;
    vscr_ratchet_receiver_chain_list_node_t *node2 = chains2->chains;

    while (true) {

        if (node1 == NULL && node2 == NULL)
            return true;

        if (node1 == NULL || node2 == NULL) {
            TEST_ASSERT(false);
        }

        if (!ratchet_receiver_chain_cmp(node1->value, node2->value))
            return false;

        node1 = node1->next;
        node2 = node2->next;
    }
}

static bool
ratchet_sender_chain_cmp(vscr_ratchet_sender_chain_t *sender_chain1, vscr_ratchet_sender_chain_t *sender_chain2) {
    if (sender_chain1 == NULL && sender_chain2 == NULL)
        return true;

    if (sender_chain1 == NULL || sender_chain2 == NULL) {
        TEST_ASSERT(false);
    }

    return memcmp(sender_chain1->private_key, sender_chain2->private_key, sizeof(sender_chain1->private_key)) == 0 &&
           memcmp(sender_chain1->public_key, sender_chain2->public_key, sizeof(sender_chain1->public_key)) == 0 &&
           ratchet_chain_key_cmp(&sender_chain1->chain_key, &sender_chain2->chain_key);
}

static bool
ratchet_cmp(vscr_ratchet_t *ratchet1, vscr_ratchet_t *ratchet2) {

    return memcmp(ratchet1->root_key, ratchet2->root_key, sizeof(ratchet1->root_key)) == 0 &&
           ratchet_sender_chain_cmp(ratchet1->sender_chain, ratchet2->sender_chain) &&
           ratchet1->prev_sender_chain_count == ratchet2->prev_sender_chain_count &&
           ratchet_receiver_chains_cmp(ratchet1->receiver_chains, ratchet2->receiver_chains) &&
           ratchet_skipped_msgs_cmp(ratchet1->skipped_messages, ratchet2->skipped_messages);
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
restore_session(vscf_ctr_drbg_t *rng, vscr_ratchet_session_t **session) {
    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_session_t *session_ref = *session;

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(vscr_ratchet_session_serialize_len(*session));

    vscr_ratchet_session_serialize(*session, buffer);

    *session = vscr_ratchet_session_deserialize(vsc_buffer_data(buffer), &error);

    vsc_buffer_destroy(&buffer);

    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    vscr_ratchet_session_use_rng(*session, vscf_ctr_drbg_impl(rng));

    bool flag = ratchet_session_cmp(session_ref, *session);

    if (!flag) {
        TEST_ASSERT(false);
    }

    vscr_ratchet_session_destroy(&session_ref);
}

void
initialize_random_group_chat(
        vscf_ctr_drbg_t *rng, size_t group_size, vscr_ratchet_group_session_t ***sessions, vsc_buffer_t ***priv) {
    TEST_ASSERT(*sessions == NULL);

    vscr_ratchet_group_ticket_t *ticket = vscr_ratchet_group_ticket_new();
    vscr_ratchet_group_ticket_use_rng(ticket, vscf_ctr_drbg_impl(rng));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_ticket_setup_ticket_as_new(ticket));

    *sessions = vscr_alloc(group_size * sizeof(vscr_ratchet_group_session_t *));
    vsc_buffer_t **ids = vscr_alloc(group_size * sizeof(vsc_buffer_t *));

    vsc_buffer_t **private_keys = vscr_alloc(group_size * sizeof(vsc_buffer_t *));

    for (size_t i = 0; i < group_size; i++) {
        vsc_buffer_t *pub;
        generate_PKCS8_ed_keypair(rng, &private_keys[i], &pub);

        vsc_buffer_t *id;
        generate_random_participant_id(rng, &id);

        TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
                vscr_ratchet_group_ticket_add_new_participant(ticket, vsc_buffer_data(id), vsc_buffer_data(pub)));

        ids[i] = id;

        vsc_buffer_destroy(&pub);
    }

    const vscr_ratchet_group_message_t *msg_start = vscr_ratchet_group_ticket_get_full_ticket_message(ticket);

    for (size_t i = 0; i < group_size; i++) {
        vscr_ratchet_group_session_t *session = vscr_ratchet_group_session_new();

        vscr_ratchet_group_session_use_rng(session, vscf_ctr_drbg_impl(rng));

        TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
                vscr_ratchet_group_session_set_private_key(session, vsc_buffer_data(private_keys[i])));

        vscr_ratchet_group_session_set_id(session, vsc_buffer_data(ids[i]));

        TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_session(session, msg_start));

        TEST_ASSERT_EQUAL_DATA(
                vscr_ratchet_group_session_get_id(session), vscr_ratchet_group_message_get_session_id(msg_start));

        (*sessions)[i] = session;
    }

    for (size_t i = 0; i < group_size; i++) {
        vsc_buffer_destroy(&ids[i]);
        if (!priv) {
            vsc_buffer_destroy(&private_keys[i]);
        }
    }

    vscr_dealloc(ids);

    if (priv) {
        *priv = private_keys;
    } else {
        vscr_dealloc(private_keys);
    }


    vscr_ratchet_group_ticket_destroy(&ticket);
}

void
add_random_members(vscf_ctr_drbg_t *rng, size_t size, size_t add_size, vscr_ratchet_group_session_t ***sessions) {
    vscr_ratchet_group_session_t **old_sessions = *sessions;

    vsc_buffer_t *session_id = vsc_buffer_new_with_data(vscr_ratchet_group_session_get_id((*sessions)[0]));

    *sessions = vscr_alloc((size + add_size) * sizeof(vscr_ratchet_group_session_t *));

    for (size_t i = 0; i < size; i++) {
        (*sessions)[i] = old_sessions[i];
    }

    size_t admin = generate_number(rng, 0, size - 1);

    vscr_ratchet_group_ticket_t *ticket =
            vscr_ratchet_group_session_create_group_ticket_for_adding_members((*sessions)[admin]);

    vsc_buffer_t **ids = vscr_alloc(add_size * sizeof(vsc_buffer_t *));

    for (size_t i = 0; i < add_size; i++) {
        vscr_ratchet_group_session_t *session = vscr_ratchet_group_session_new();

        vsc_buffer_t *priv, *pub;
        generate_PKCS8_ed_keypair(rng, &priv, &pub);

        vsc_buffer_t *id;
        generate_random_participant_id(rng, &id);

        vscr_ratchet_group_session_use_rng(session, vscf_ctr_drbg_impl(rng));
        TEST_ASSERT_EQUAL(
                vscr_status_SUCCESS, vscr_ratchet_group_session_set_private_key(session, vsc_buffer_data(priv)));

        vscr_ratchet_group_session_set_id(session, vsc_buffer_data(id));

        TEST_ASSERT_EQUAL(vscr_status_SUCCESS,
                vscr_ratchet_group_ticket_add_new_participant(ticket, vsc_buffer_data(id), vsc_buffer_data(pub)));

        vsc_buffer_destroy(&priv);
        vsc_buffer_destroy(&pub);

        ids[i] = id;
        (*sessions)[size + i] = session;
    }

    const vscr_ratchet_group_message_t *msg_start = vscr_ratchet_group_ticket_get_full_ticket_message(ticket);
    const vscr_ratchet_group_message_t *msg_add = vscr_ratchet_group_ticket_get_complementary_ticket_message(ticket);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vscr_ratchet_group_message_get_session_id(msg_start), session_id);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vscr_ratchet_group_message_get_session_id(msg_add), session_id);

    for (size_t i = 0; i < size + add_size; i++) {
        vscr_ratchet_group_session_t *session = (*sessions)[i];

        const vscr_ratchet_group_message_t *msg = i >= size ? msg_start : msg_add;

        TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_group_session_setup_session(session, msg));

        TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vscr_ratchet_group_session_get_id(session), session_id);
    }

    for (size_t i = 0; i < add_size; i++) {
        vsc_buffer_destroy(&ids[i]);
    }

    vscr_dealloc(ids);
    vscr_dealloc(old_sessions);
    vscr_ratchet_group_ticket_destroy(&ticket);
    vsc_buffer_destroy(&session_id);
}

void
remove_random_members(vscf_ctr_drbg_t *rng, size_t size, size_t remove_size, vscr_ratchet_group_session_t ***sessions) {
    vscr_ratchet_group_session_t **old_sessions = *sessions;

    vsc_buffer_t *session_id = vsc_buffer_new_with_data(vscr_ratchet_group_session_get_id((*sessions)[0]));

    *sessions = vscr_alloc((size - remove_size) * sizeof(vscr_ratchet_group_session_t *));

    size_t *permut = vscr_alloc(size * sizeof(size_t));

    for (size_t i = 0; i < size; i++) {
        permut[i] = i;
    }

    generate_permutation(rng, size, permut);

    size_t admin = permut[remove_size];

    vscr_ratchet_group_session_t *admin_session = old_sessions[admin];

    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_group_ticket_t *ticket =
            vscr_ratchet_group_session_create_group_ticket_for_adding_or_removing_members(admin_session, &error);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, error.status);

    size_t counter = 0;
    for (size_t i = 0; i < size; i++) {
        bool remove = false;
        for (size_t j = 0; j < remove_size; j++) {
            if (i == permut[j]) {
                remove = true;
                break;
            }
        }

        vscr_ratchet_group_session_t *session = old_sessions[i];

        if (remove) {
            vscr_status_t status =
                    vscr_ratchet_group_ticket_remove_participant(ticket, vscr_ratchet_group_session_get_id(session));
            TEST_ASSERT_EQUAL(vscr_status_SUCCESS, status);
            vscr_ratchet_group_session_destroy(&session);
        } else {
            (*sessions)[counter++] = session;
        }
    }

    const vscr_ratchet_group_message_t *msg = vscr_ratchet_group_ticket_get_full_ticket_message(ticket);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vscr_ratchet_group_message_get_session_id(msg), session_id);

    for (size_t i = 0; i < counter; i++) {
        vscr_ratchet_group_session_t *session = (*sessions)[i];
        vscr_status_t status = vscr_ratchet_group_session_setup_session(session, msg);
        TEST_ASSERT_EQUAL(vscr_status_SUCCESS, status);
        TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vscr_ratchet_group_session_get_id(session), session_id);
    }

    vscr_dealloc(permut);
    vscr_dealloc(old_sessions);
    vscr_ratchet_group_ticket_destroy(&ticket);
    vsc_buffer_destroy(&session_id);
}

void
encrypt_decrypt(vscf_ctr_drbg_t *rng, size_t group_size, size_t number_of_iterations,
        vscr_ratchet_group_session_t **sessions, double lost_rate, double distribution_factor,
        double generate_distribution, vsc_buffer_t **priv) {
    if (group_size < 2) {
        TEST_ASSERT(false);
    }

    msg_channel_t **channels = vscr_alloc(group_size * sizeof(msg_channel_t *));

    for (size_t i = 0; i < group_size; i++) {
        msg_channel_t *channel = vscr_alloc(sizeof(msg_channel_t));

        init_channel(channel, rng, lost_rate, distribution_factor);
        channels[i] = channel;
    }

    size_t number_of_msgs = 0;
    size_t number_of_picks = 0;

    bool is_empty = false;

    for (size_t i = 0; i < number_of_iterations || !is_empty; i++) {
        size_t event;

        if (number_of_msgs < number_of_picks) {
            TEST_ASSERT(false);
        }

        bool generate_msg;
        if (i >= number_of_iterations) {
            generate_msg = false;
        } else if (number_of_msgs == number_of_picks) {
            generate_msg = true;
        } else {
            double prob = generate_prob(rng);

            if (prob > 1 - generate_distribution) {
                // Produce new msg
                generate_msg = true;
            } else {
                generate_msg = false;
            }
        }

        if (generate_msg) {
            event = group_size;
        } else {
            event = generate_number(rng, 0, group_size - 1);
        }

        size_t active_session;

        // New message produced
        if (event == group_size) {
            size_t sender = pick_element_uniform(rng, group_size);

            active_session = sender;
            vscr_ratchet_group_session_t *session = sessions[sender];

            vsc_buffer_t *text = NULL;
            generate_random_data(rng, &text);

            vscr_error_t error_ctx;
            vscr_error_reset(&error_ctx);

            vscr_ratchet_group_message_t *group_msg =
                    vscr_ratchet_group_session_encrypt(session, vsc_buffer_data(text), &error_ctx);
            TEST_ASSERT_EQUAL(vscr_status_SUCCESS, error_ctx.status);

            size_t len = vscr_ratchet_group_message_serialize_len(group_msg);
            vsc_buffer_t *msg_buff = vsc_buffer_new_with_capacity(len);

            vscr_ratchet_group_message_serialize(group_msg, msg_buff);

            for (size_t receiver = 0; receiver < group_size; receiver++) {
                if (receiver == sender) {
                    continue;
                }

                if (push_msg(channels[receiver], vsc_buffer_data(text), vsc_buffer_data(msg_buff), sender)) {
                    number_of_msgs++;
                }
            }

            vsc_buffer_destroy(&text);
            vsc_buffer_destroy(&msg_buff);
            vscr_ratchet_group_message_destroy(&group_msg);
        }
        // Old message pick
        else {
            size_t number_of_active_channels = 0;
            for (size_t j = 0; j < group_size; j++) {
                if (has_msg(channels[j])) {
                    number_of_active_channels++;
                }
            }

            if (number_of_active_channels <= 0) {
                TEST_ASSERT(false);
            }

            size_t receiver_queue_num = generate_number(rng, 0, number_of_active_channels - 1);
            size_t receiver = 0;

            for (size_t j = 0; j < group_size; j++) {
                if (has_msg(channels[j])) {
                    if (receiver_queue_num == 0) {
                        receiver = j;
                        break;
                    } else {
                        receiver_queue_num--;
                    }
                }
            }

            if (receiver_queue_num != 0) {
                TEST_ASSERT(false);
            }
            if (!has_msg(channels[receiver])) {
                TEST_ASSERT(false);
            }

            channel_msg_t *channel_msg = pop_msg(channels[receiver]);

            vscr_error_t error_ctx;
            vscr_error_reset(&error_ctx);

            vscr_ratchet_group_message_t *ratchet_msg =
                    vscr_ratchet_group_message_deserialize(vsc_buffer_data(channel_msg->cipher_text), &error_ctx);

            TEST_ASSERT_EQUAL(vscr_status_SUCCESS, error_ctx.status);

            active_session = receiver;
            vscr_ratchet_group_session_t *session = sessions[receiver];

            size_t len = vscr_ratchet_group_session_decrypt_len(session, ratchet_msg);

            vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(len);

            TEST_ASSERT_EQUAL(
                    vscr_status_SUCCESS, vscr_ratchet_group_session_decrypt(session, ratchet_msg, plain_text));

            TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(channel_msg->plain_text), plain_text);

            vsc_buffer_destroy(&plain_text);
            vscr_ratchet_group_message_destroy(&ratchet_msg);

            deinit_msg(channel_msg);

            number_of_picks++;

            is_empty = number_of_msgs == number_of_picks;
        }

        if (priv) {
            vscr_ratchet_group_session_t **session_ref = &sessions[active_session];

            size_t len = vscr_ratchet_group_session_serialize_len(*session_ref);

            vsc_buffer_t *buf = vsc_buffer_new_with_capacity(len);

            vscr_ratchet_group_session_serialize(*session_ref, buf);

            vscr_ratchet_group_session_delete(*session_ref);

            vscr_error_t err_ctx;
            vscr_error_reset(&err_ctx);

            *session_ref = vscr_ratchet_group_session_deserialize(vsc_buffer_data(buf), &err_ctx);

            TEST_ASSERT_EQUAL(vscr_status_SUCCESS, err_ctx.status);

            vscr_ratchet_group_session_use_rng(*session_ref, vscf_ctr_drbg_impl(rng));
            vscr_status_t status =
                    vscr_ratchet_group_session_set_private_key(*session_ref, vsc_buffer_data(priv[active_session]));

            TEST_ASSERT_EQUAL(vscr_status_SUCCESS, status);

            vsc_buffer_destroy(&buf);
        }
    }

    for (size_t i = 0; i < group_size; i++) {
        deinit_channel(channels[i]);
        vscr_dealloc(channels[i]);
    }

    vscr_dealloc(channels);
}

#endif
