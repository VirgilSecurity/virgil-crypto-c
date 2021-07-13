//  Copyright (C) 2015-2021 Virgil Security, Inc.
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

#define TEST_DEPENDENCIES_AVAILABLE VSCR_RATCHET
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscr_memory.h"
#include "vscr_ratchet_skipped_messages_defs.h"
#include "vscf_ctr_drbg.h"
#include "vscf_pkcs8_serializer.h"
#include "vscf_ed25519.h"
#include "vscf_curve25519.h"
#include "vscf_private_key.h"
#include "test_utils_ratchet.h"
#include "unreliable_msg_producer.h"
#include "msg_channel.h"
#include "vscr_ratchet_session_defs.h"
#include "vscr_ratchet_chain_key.h"
#include "vscr_ratchet_skipped_messages.h"
#include "vscr_ratchet_skipped_messages_defs.h"
#include "vscr_ratchet_receiver_chain.h"
#include "vscr_ratchet_sender_chain.h"
#include "vscr_ratchet.h"
#include "vscr_ratchet_defs.h"

#include <ed25519/ed25519.h>
#include <virgil/crypto/ratchet/vscr_assert.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

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

    vscf_status_t status = vscf_ctr_drbg_random(rng, sizeof(size), size_buf);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);

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

    vscf_status_t status = vscf_ctr_drbg_random(rng, size, *buffer);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
}

void
generate_random_data_of_size(vscf_ctr_drbg_t *rng, vsc_buffer_t **buffer, size_t size) {
    TEST_ASSERT(*buffer == NULL);

    *buffer = vsc_buffer_new_with_capacity(size);

    vscf_status_t status = vscf_ctr_drbg_random(rng, size, *buffer);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, status);
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
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_ed25519_t *ed25519 = vscf_ed25519_new();
    vscf_ed25519_use_random(ed25519, vscf_ctr_drbg_impl(rng));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_ed25519_generate_key(ed25519, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    vscf_raw_private_key_t *raw_private_key = vscf_ed25519_export_private_key(ed25519, private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_raw_public_key_t *raw_public_key = vscf_ed25519_export_public_key(ed25519, public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    size_t len_private = vscf_pkcs8_serializer_serialized_private_key_len(pkcs8, raw_private_key);
    *priv = vsc_buffer_new_with_capacity(len_private);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_pkcs8_serializer_serialize_private_key(pkcs8, raw_private_key, *priv));


    size_t len_public = vscf_pkcs8_serializer_serialized_public_key_len(pkcs8, raw_public_key);
    *pub = vsc_buffer_new_with_capacity(len_public);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_pkcs8_serializer_serialize_public_key(pkcs8, raw_public_key, *pub));

    vscf_pkcs8_serializer_destroy(&pkcs8);

    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_ed25519_destroy((&ed25519));
}

void
generate_PKCS8_curve_keypair(vscf_ctr_drbg_t *rng, vsc_buffer_t **priv, vsc_buffer_t **pub) {
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_curve25519_t *curve25519 = vscf_curve25519_new();
    vscf_curve25519_use_random(curve25519, vscf_ctr_drbg_impl(rng));

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_impl_t *private_key = vscf_curve25519_generate_key(curve25519, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));
    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    vscf_raw_private_key_t *raw_private_key = vscf_curve25519_export_private_key(curve25519, private_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    vscf_raw_public_key_t *raw_public_key = vscf_curve25519_export_public_key(curve25519, public_key, &error);
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_error_status(&error));

    size_t len_private = vscf_pkcs8_serializer_serialized_private_key_len(pkcs8, raw_private_key);
    *priv = vsc_buffer_new_with_capacity(len_private);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_pkcs8_serializer_serialize_private_key(pkcs8, raw_private_key, *priv));


    size_t len_public = vscf_pkcs8_serializer_serialized_public_key_len(pkcs8, raw_public_key);
    *pub = vsc_buffer_new_with_capacity(len_public);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_pkcs8_serializer_serialize_public_key(pkcs8, raw_public_key, *pub));

    vscf_pkcs8_serializer_destroy(&pkcs8);

    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
    vscf_raw_private_key_destroy(&raw_private_key);
    vscf_raw_public_key_destroy(&raw_public_key);
    vscf_curve25519_destroy((&curve25519));
}

void
generate_random_participant_id(vscf_ctr_drbg_t *rng, vsc_buffer_t **id) {
    *id = vsc_buffer_new_with_capacity(vscr_ratchet_common_PARTICIPANT_ID_LEN);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_random(rng, vscr_ratchet_common_PARTICIPANT_ID_LEN, *id));
}

vscf_impl_t *
generate_identity_private_key(vscf_key_provider_t *key_provider, bool enable_pqc) {

    vscf_impl_t *private_key;
    vscf_error_t error_ctx;
    vscf_error_reset(&error_ctx);

    if (enable_pqc) {
        private_key = vscf_key_provider_generate_compound_hybrid_private_key(key_provider, vscf_alg_id_CURVE25519,
                vscf_alg_id_ROUND5_ND_1CCA_5D, vscf_alg_id_ED25519, vscf_alg_id_FALCON, &error_ctx);
    } else {
        private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ED25519, &error_ctx);
    }

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, error_ctx.status);

    return private_key;
}

vscf_impl_t *
generate_ephemeral_private_key(vscf_key_provider_t *key_provider, bool enable_pqc) {

    vscf_impl_t *private_key;
    vscf_error_t error_ctx;
    vscf_error_reset(&error_ctx);

    if (enable_pqc) {
        private_key = vscf_key_provider_generate_hybrid_private_key(
                key_provider, vscf_alg_id_CURVE25519, vscf_alg_id_ROUND5_ND_1CCA_5D, &error_ctx);
    } else {
        private_key = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_CURVE25519, &error_ctx);
    }

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, error_ctx.status);

    return private_key;
}

void
generate_falcon_keypair(vscf_ctr_drbg_t *rng, vscf_impl_t **priv, vscf_impl_t **pub) {
    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, vscf_ctr_drbg_impl(rng));

    vscf_error_t error_ctx;
    vscf_error_reset(&error_ctx);

    *priv = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_FALCON, &error_ctx);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, error_ctx.status);

    *pub = vscf_private_key_extract_public_key(*priv);

    vscf_key_provider_destroy(&key_provider);
}

void
generate_round5_keypair(vscf_ctr_drbg_t *rng, vscf_impl_t **priv, vscf_impl_t **pub) {
    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, vscf_ctr_drbg_impl(rng));

    vscf_error_t error_ctx;
    vscf_error_reset(&error_ctx);

    *priv = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ROUND5_ND_1CCA_5D, &error_ctx);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, error_ctx.status);

    *pub = vscf_private_key_extract_public_key(*priv);

    vscf_key_provider_destroy(&key_provider);
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
generate_random_key_id(vscf_ctr_drbg_t *rng, vscr_ratchet_key_id_t id) {
    vsc_buffer_t *buffer = vsc_buffer_new();
    vsc_buffer_use(buffer, id, vscr_ratchet_common_KEY_ID_LEN);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_random(rng, vscr_ratchet_common_KEY_ID_LEN, buffer));

    vsc_buffer_destroy(&buffer);
}

void
initialize(vscf_ctr_drbg_t *rng, vscr_ratchet_session_t **session_alice, vscr_ratchet_session_t **session_bob,
        bool enable_one_time, bool enable_pqc, bool should_restore) {
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_setup_defaults(*session_alice));
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, vscr_ratchet_session_setup_defaults(*session_bob));

    if (should_restore) {
        restore_session(rng, session_alice);
        restore_session(rng, session_bob);
    }

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, vscf_ctr_drbg_impl(rng));

    vscf_impl_t *alice_priv = generate_identity_private_key(key_provider, enable_pqc);
    vscf_impl_t *alice_pub = vscf_private_key_extract_public_key(alice_priv);
    vsc_buffer_t *alice_id = NULL;
    generate_random_data_of_size(rng, &alice_id, 8);
    vscf_impl_t *bob_priv = generate_identity_private_key(key_provider, enable_pqc);
    vscf_impl_t *bob_pub = vscf_private_key_extract_public_key(bob_priv);
    vsc_buffer_t *bob_id = NULL;
    generate_random_data_of_size(rng, &bob_id, 8);
    vscf_impl_t *bob_lt_priv = generate_ephemeral_private_key(key_provider, enable_pqc);
    vscf_impl_t *bob_lt_pub = vscf_private_key_extract_public_key(bob_lt_priv);
    vsc_buffer_t *bob_lt_id = NULL;
    generate_random_data_of_size(rng, &bob_lt_id, 8);
    vscf_impl_t *bob_ot_priv = enable_one_time ? generate_ephemeral_private_key(key_provider, enable_pqc) : NULL;
    vscf_impl_t *bob_ot_pub = enable_one_time ? vscf_private_key_extract_public_key(bob_ot_priv) : NULL;
    vsc_buffer_t *bob_ot_id = NULL;
    if (enable_one_time) {
        generate_random_data_of_size(rng, &bob_ot_id, 8);
    } else {
        bob_ot_id = vsc_buffer_new_with_capacity(0);
    }

    TEST_ASSERT_EQUAL_INT(
            vscr_status_SUCCESS, vscr_ratchet_session_initiate(*session_alice, alice_priv, vsc_buffer_data(alice_id),
                                         bob_pub, vsc_buffer_data(bob_id), bob_lt_pub, vsc_buffer_data(bob_lt_id),
                                         bob_ot_pub, vsc_buffer_data(bob_ot_id), enable_pqc));

    TEST_ASSERT((*session_alice)->is_initiator);
    TEST_ASSERT(!(*session_alice)->received_first_response);
    TEST_ASSERT((*session_alice)->receiver_has_one_time_key_first == enable_one_time);

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

    TEST_ASSERT_EQUAL(vscr_msg_type_PREKEY, vscr_ratchet_message_get_type(ratchet_message));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vscr_ratchet_message_get_sender_identity_key_id(ratchet_message), alice_id);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vscr_ratchet_message_get_receiver_identity_key_id(ratchet_message), bob_id);
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vscr_ratchet_message_get_receiver_long_term_key_id(ratchet_message), bob_lt_id);

    if (enable_one_time) {
        TEST_ASSERT_EQUAL_DATA_AND_BUFFER(
                vscr_ratchet_message_get_receiver_one_time_key_id(ratchet_message), bob_ot_id);
    } else {
        TEST_ASSERT((vscr_ratchet_message_get_receiver_one_time_key_id(ratchet_message).len == 0));
    }


    if (should_restore) {
        restore_session(rng, session_alice);
    }

    TEST_ASSERT_EQUAL_INT(vscr_status_SUCCESS, vscr_ratchet_session_respond(*session_bob, alice_pub, bob_priv,
                                                       bob_lt_priv, bob_ot_priv, ratchet_message, enable_pqc));

    TEST_ASSERT(!(*session_bob)->is_initiator);
    TEST_ASSERT(!(*session_bob)->received_first_response);
    TEST_ASSERT((*session_bob)->receiver_has_one_time_key_first == enable_one_time);

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

    vscf_key_provider_destroy(&key_provider);

    vscr_ratchet_message_destroy(&ratchet_message);

    vsc_buffer_destroy(&alice_id);
    vsc_buffer_destroy(&bob_id);
    vsc_buffer_destroy(&bob_lt_id);
    vsc_buffer_destroy(&bob_ot_id);

    vsc_buffer_destroy(&text);
    vsc_buffer_destroy(&plain_text);

    vscf_impl_destroy(&alice_priv);
    vscf_impl_destroy(&alice_pub);

    vscf_impl_destroy(&bob_priv);
    vscf_impl_destroy(&bob_pub);

    vscf_impl_destroy(&bob_lt_priv);
    vscf_impl_destroy(&bob_lt_pub);

    vscf_impl_destroy(&bob_ot_priv);
    vscf_impl_destroy(&bob_ot_pub);
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
    if (chain_key1 == NULL && chain_key2 == NULL)
        return true;

    return chain_key1->index == chain_key2->index &&
           memcmp(chain_key1->key, chain_key2->key, sizeof(chain_key1->key)) == 0;
}

static bool
ratchet_msg_key_cmp(vscr_ratchet_message_key_t *msg_key1, vscr_ratchet_message_key_t *msg_key2) {
    return msg_key1->index == msg_key2->index && memcmp(msg_key1->key, msg_key2->key, sizeof(msg_key1->key)) == 0;
}

static bool
ratchet_skipped_root_cmp(
        vscr_ratchet_skipped_messages_root_node_t *root1, vscr_ratchet_skipped_messages_root_node_t *root2) {
    if (root1->count != root2->count)
        return false;

    vscr_ratchet_message_key_node_t *node1 = root1->first;
    vscr_ratchet_message_key_node_t *node2 = root2->first;

    for (size_t i = 0; i < root1->count; i++) {
        if (!ratchet_msg_key_cmp(node1->value, node2->value))
            return false;

        node1 = node1->next;
        node2 = node2->next;
    }

    return true;
}

static bool
private_key_equal(vscf_impl_t *private_key1, vscf_impl_t *private_key2) {
    if (private_key1 == NULL && private_key2 == NULL) {
        return true;
    }

    if (private_key1 == NULL || private_key2 == NULL) {
        return false;
    }

    TEST_ASSERT_EQUAL(vscf_impl_tag_RAW_PRIVATE_KEY, vscf_impl_tag(private_key1));
    TEST_ASSERT_EQUAL(vscf_impl_tag_RAW_PRIVATE_KEY, vscf_impl_tag(private_key2));

    return vsc_data_equal(vscf_raw_private_key_data((vscf_raw_private_key_t *)private_key1),
            vscf_raw_private_key_data((vscf_raw_private_key_t *)private_key2));
}

static bool
public_key_equal(vscf_impl_t *public_key1, vscf_impl_t *public_key2) {
    if (public_key1 == NULL && public_key2 == NULL) {
        return true;
    }

    if (public_key1 == NULL || public_key2 == NULL) {
        return false;
    }

    TEST_ASSERT_EQUAL(vscf_impl_tag_RAW_PUBLIC_KEY, vscf_impl_tag(public_key1));
    TEST_ASSERT_EQUAL(vscf_impl_tag_RAW_PUBLIC_KEY, vscf_impl_tag(public_key2));

    return vsc_data_equal(vscf_raw_public_key_data((vscf_raw_public_key_t *)public_key1),
            vscf_raw_public_key_data((vscf_raw_public_key_t *)public_key2));
}

static bool
buffer_equal_or_null(vsc_buffer_t *buffer1, vsc_buffer_t *buffer2) {
    if (buffer1 == NULL && buffer2 == NULL)
        return true;

    if (buffer1 == NULL || buffer2 == NULL)
        return false;

    return vsc_buffer_equal(buffer1, buffer2);
}

static bool
ratchet_skipped_msgs_cmp(vscr_ratchet_skipped_messages_t *msgs1, vscr_ratchet_skipped_messages_t *msgs2) {
    if (msgs1->roots_count != msgs2->roots_count) {
        return false;
    }

    for (size_t i = 0; i < msgs1->roots_count; i++) {

        if (memcmp(msgs1->key_ids[i], msgs2->key_ids[i], sizeof(msgs1->key_ids[i])) != 0) {
            return false;
        }

        if (!ratchet_skipped_root_cmp(msgs1->root_nodes[i], msgs2->root_nodes[i])) {
            return false;
        }
    }

    return true;
}

static bool
ratchet_receiver_chain_cmp(vscr_ratchet_receiver_chain_t *chain1, vscr_ratchet_receiver_chain_t *chain2) {
    if (chain1 == NULL && chain2 == NULL)
        return true;

    if (chain1 == NULL || chain2 == NULL) {
        return false;
    }

    return memcmp(chain1->public_key_first, chain2->public_key_first, sizeof(chain1->public_key_first)) == 0 &&
           memcmp(chain1->public_key_id, chain2->public_key_id, sizeof(chain1->public_key_id)) == 0 &&
           ratchet_chain_key_cmp(&chain1->chain_key, &chain2->chain_key) &&
           public_key_equal(chain1->public_key_second, chain2->public_key_second);
}

static bool
ratchet_sender_chain_cmp(vscr_ratchet_sender_chain_t *sender_chain1, vscr_ratchet_sender_chain_t *sender_chain2) {
    if (sender_chain1 == NULL && sender_chain2 == NULL)
        return true;

    if (sender_chain1 == NULL || sender_chain2 == NULL) {
        return false;
    }

    return memcmp(sender_chain1->private_key_first, sender_chain2->private_key_first,
                   sizeof(sender_chain1->private_key_first)) == 0 &&
           memcmp(sender_chain1->public_key_first, sender_chain2->public_key_first,
                   sizeof(sender_chain1->public_key_first)) == 0 &&
           buffer_equal_or_null(sender_chain1->encapsulated_key, sender_chain2->encapsulated_key) &&
           public_key_equal(sender_chain1->public_key_second, sender_chain2->public_key_second) &&
           private_key_equal(sender_chain1->private_key_second, sender_chain2->private_key_second) &&
           ratchet_chain_key_cmp(&sender_chain1->chain_key, &sender_chain2->chain_key);
}

static bool
ratchet_cmp(vscr_ratchet_t *ratchet1, vscr_ratchet_t *ratchet2) {
    return ratchet1->enable_post_quantum == ratchet2->enable_post_quantum &&
           memcmp(ratchet1->root_key, ratchet2->root_key, sizeof(ratchet1->root_key)) == 0 &&
           ratchet_sender_chain_cmp(ratchet1->sender_chain, ratchet2->sender_chain) &&
           ratchet1->prev_sender_chain_count == ratchet2->prev_sender_chain_count &&
           ratchet_receiver_chain_cmp(ratchet1->receiver_chain, ratchet2->receiver_chain) &&
           ratchet_skipped_msgs_cmp(ratchet1->skipped_messages, ratchet2->skipped_messages);
}

static bool
ratchet_session_cmp(vscr_ratchet_session_t *ratchet_session1, vscr_ratchet_session_t *ratchet_session2) {

    bool flag =
            ratchet_session1->is_initiator == ratchet_session2->is_initiator &&
            ratchet_session1->received_first_response == ratchet_session2->received_first_response &&
            ratchet_session1->receiver_has_one_time_key_first == ratchet_session2->receiver_has_one_time_key_first &&
            ratchet_session1->enable_post_quantum == ratchet_session2->enable_post_quantum;

    bool flag2 = memcmp(ratchet_session1->sender_identity_key_id, ratchet_session2->sender_identity_key_id,
                         sizeof(ratchet_session1->sender_identity_key_id)) == 0 &&
                 memcmp(ratchet_session1->sender_ephemeral_public_key_first,
                         ratchet_session2->sender_ephemeral_public_key_first,
                         sizeof(ratchet_session1->sender_ephemeral_public_key_first)) == 0 &&
                 memcmp(ratchet_session1->receiver_identity_key_id, ratchet_session2->receiver_identity_key_id,
                         sizeof(ratchet_session1->receiver_identity_key_id)) == 0 &&
                 memcmp(ratchet_session1->receiver_long_term_key_id, ratchet_session2->receiver_long_term_key_id,
                         sizeof(ratchet_session1->receiver_long_term_key_id)) == 0 &&
                 memcmp(ratchet_session1->receiver_one_time_key_id, ratchet_session2->receiver_one_time_key_id,
                         sizeof(ratchet_session1->receiver_one_time_key_id)) == 0 &&
                 buffer_equal_or_null(ratchet_session1->encapsulated_key_1, ratchet_session2->encapsulated_key_1) &&
                 buffer_equal_or_null(ratchet_session1->encapsulated_key_2, ratchet_session2->encapsulated_key_2) &&
                 buffer_equal_or_null(ratchet_session1->encapsulated_key_3, ratchet_session2->encapsulated_key_3) &&
                 buffer_equal_or_null(
                         ratchet_session1->decapsulated_keys_signature, ratchet_session2->decapsulated_keys_signature);

    if (ratchet_session1->is_initiator && !ratchet_session1->received_first_response) {
        flag = flag && flag2;
    }

    return flag && ratchet_cmp(ratchet_session1->ratchet, ratchet_session2->ratchet);
}

void
restore_session(vscf_ctr_drbg_t *rng, vscr_ratchet_session_t **session) {
    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_session_t *session_ref = *session;

    vsc_buffer_t *buffer = vscr_ratchet_session_serialize(*session);

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

vscr_ratchet_skipped_messages_t *
generate_full_skipped_messages(vscf_ctr_drbg_t *rng) {
    vscr_ratchet_skipped_messages_t *skipped_messages = vscr_ratchet_skipped_messages_new();

    skipped_messages->roots_count = vscr_ratchet_common_hidden_MAX_SKIPPED_DH;
    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_SKIPPED_DH; i++) {
        generate_random_c(rng, skipped_messages->key_ids[i], vscr_ratchet_common_KEY_ID_LEN);
        skipped_messages->root_nodes[i] = generate_full_root_node(rng, true);
    }

    return skipped_messages;
}

vscr_ratchet_t *
generate_full_ratchet(vscf_ctr_drbg_t *rng) {
    vscr_ratchet_t *ratchet = vscr_ratchet_new();

    vscr_ratchet_receiver_chain_destroy(&ratchet->receiver_chain);
    ratchet->receiver_chain = generate_full_receiver_chain(rng);
    ratchet->prev_sender_chain_count = UINT32_MAX;
    generate_random_c(rng, ratchet->root_key, vscr_ratchet_common_hidden_SHARED_KEY_LEN);

    vscr_ratchet_sender_chain_destroy(&ratchet->sender_chain);
    ratchet->sender_chain = generate_full_sender_chain(rng);

    vscr_ratchet_skipped_messages_destroy(&ratchet->skipped_messages);
    ratchet->skipped_messages = generate_full_skipped_messages(rng);

    return ratchet;
}

vscf_impl_t *
generate_public_key(vscf_ctr_drbg_t *rng) {
    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, vscf_ctr_drbg_impl(rng));

    vscf_error_t error_ctx;
    vscf_error_reset(&error_ctx);

    vscf_impl_t *priv = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ROUND5_ND_1CCA_5D, &error_ctx);

    TEST_ASSERT(!vscf_error_has_error(&error_ctx));

    vscf_impl_t *pub = vscf_private_key_extract_public_key(priv);

    vscf_key_provider_destroy(&key_provider);
    vscf_impl_destroy(&priv);

    return pub;
}

vscf_impl_t *
generate_private_key(vscf_ctr_drbg_t *rng) {
    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, vscf_ctr_drbg_impl(rng));

    vscf_error_t error_ctx;
    vscf_error_reset(&error_ctx);

    vscf_impl_t *priv = vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ROUND5_ND_1CCA_5D, &error_ctx);

    TEST_ASSERT(!vscf_error_has_error(&error_ctx));

    vscf_key_provider_destroy(&key_provider);

    return priv;
}

void
generate_random_c(vscf_ctr_drbg_t *rng, byte *data, size_t len) {
    vsc_buffer_t buffer;
    vsc_buffer_init(&buffer);
    vsc_buffer_use(&buffer, data, len);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_random(rng, len, &buffer));

    vsc_buffer_delete(&buffer);
}

vscr_ratchet_session_t *
generate_full_session(vscf_ctr_drbg_t *rng) {
    vscr_ratchet_session_t *session = vscr_ratchet_session_new();

    generate_random_c(rng, session->sender_identity_key_id, vscr_ratchet_common_KEY_ID_LEN);
    generate_random_c(rng, session->sender_ephemeral_public_key_first, vscr_ratchet_common_hidden_KEY_LEN);
    generate_random_c(rng, session->receiver_identity_key_id, vscr_ratchet_common_KEY_ID_LEN);
    generate_random_c(rng, session->receiver_long_term_key_id, vscr_ratchet_common_KEY_ID_LEN);
    session->receiver_has_one_time_key_first = true;
    generate_random_c(rng, session->receiver_one_time_key_id, vscr_ratchet_common_KEY_ID_LEN);

    session->decapsulated_keys_signature = generate_random_buff(rng, vscr_ratchet_common_hidden_FALCON_SIGNATURE_LEN);
    session->encapsulated_key_1 = generate_random_buff(rng, vscr_ratchet_common_hidden_ROUND5_ENCAPSULATED_KEY_LEN);
    session->encapsulated_key_2 = generate_random_buff(rng, vscr_ratchet_common_hidden_ROUND5_ENCAPSULATED_KEY_LEN);
    session->encapsulated_key_3 = generate_random_buff(rng, vscr_ratchet_common_hidden_ROUND5_ENCAPSULATED_KEY_LEN);

    vscr_ratchet_destroy(&session->ratchet);
    session->ratchet = generate_full_ratchet(rng);

    return session;
}

vscr_ratchet_message_key_t *
generate_full_message_key(vscf_ctr_drbg_t *rng) {
    vscr_ratchet_message_key_t *message_key = vscr_ratchet_message_key_new();

    message_key->index = UINT32_MAX;

    generate_random_c(rng, message_key->key, sizeof(message_key->key));

    return message_key;
}

vsc_buffer_t *
generate_random_buff(vscf_ctr_drbg_t *rng, size_t len) {
    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(len);

    while (len != 0) {
        size_t requested = len > 1024 ? 1024 : len;
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_random(rng, requested, buffer));
        len -= requested;
    }

    return buffer;
}

vscr_ratchet_sender_chain_t *
generate_full_sender_chain(vscf_ctr_drbg_t *rng) {
    vscr_ratchet_sender_chain_t *sender_chain = vscr_ratchet_sender_chain_new();

    sender_chain->public_key_second = generate_public_key(rng);
    sender_chain->private_key_second = generate_private_key(rng);
    generate_random_c(rng, sender_chain->public_key_first, sizeof(sender_chain->public_key_first));
    generate_random_c(rng, sender_chain->private_key_first, sizeof(sender_chain->private_key_first));

    sender_chain->encapsulated_key = generate_random_buff(rng, vscr_ratchet_common_hidden_ROUND5_ENCAPSULATED_KEY_LEN);
    generate_full_chain_key_s(rng, &sender_chain->chain_key);

    return sender_chain;
}


vscr_ratchet_receiver_chain_t *
generate_full_receiver_chain(vscf_ctr_drbg_t *rng) {
    vscr_ratchet_receiver_chain_t *receiver_chain = vscr_ratchet_receiver_chain_new();

    generate_full_chain_key_s(rng, &receiver_chain->chain_key);

    generate_random_c(rng, receiver_chain->public_key_id, sizeof(receiver_chain->public_key_id));
    generate_random_c(rng, receiver_chain->public_key_first, sizeof(receiver_chain->public_key_first));
    receiver_chain->public_key_second = generate_public_key(rng);

    return receiver_chain;
}

void
generate_full_chain_key_s(vscf_ctr_drbg_t *rng, vscr_ratchet_chain_key_t *chain_key) {
    chain_key->index = UINT32_MAX;

    vsc_buffer_t buffer;
    vsc_buffer_init(&buffer);
    vsc_buffer_use(&buffer, chain_key->key, sizeof(chain_key->key));

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_random(rng, sizeof(chain_key->key), &buffer));

    vsc_buffer_delete(&buffer);
}

vscr_ratchet_chain_key_t *
generate_full_chain_key(vscf_ctr_drbg_t *rng) {
    vscr_ratchet_chain_key_t *chain_key = vscr_ratchet_chain_key_new();

    generate_full_chain_key_s(rng, chain_key);

    return chain_key;
}

vscr_ratchet_skipped_messages_root_node_t *
generate_full_root_node(vscf_ctr_drbg_t *rng, bool max) {
    vscr_ratchet_skipped_messages_root_node_t *skipped_messages = vscr_ratchet_skipped_messages_root_node_new();

    size_t number;
    if (max) {
        number = vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES;
    } else {
        number = generate_number(rng, 0, vscr_ratchet_common_hidden_MAX_SKIPPED_MESSAGES);
    }

    for (size_t i = 0; i < number; i++) {
        vscr_ratchet_message_key_t *key = generate_full_message_key(rng);
        vscr_ratchet_skipped_messages_root_node_add_key(skipped_messages, key);
    }

    return skipped_messages;
}

#endif
