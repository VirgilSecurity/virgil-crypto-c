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

#define TEST_DEPENDENCIES_AVAILABLE VSCF_GROUP_SESSION
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscf_ed25519_private_key.h"
#include "vscf_ed25519_public_key.h"
#include "vscf_pkcs8_der_serializer.h"
#include "vscf_memory.h"
#include "vscf_ctr_drbg.h"
#include "vscf_group_session.h"
#include "vscf_group_session_typedefs.h"

void
generate_PKCS8_ed_keypair(vscf_ctr_drbg_t *rng, vsc_buffer_t **priv, vsc_buffer_t **pub) {
    vscf_pkcs8_serializer_t *pkcs8 = vscf_pkcs8_serializer_new();
    vscf_pkcs8_serializer_setup_defaults(pkcs8);

    vscf_ed25519_private_key_t *ed25519_private_key = vscf_ed25519_private_key_new();
    vscf_impl_t *private_key = vscf_ed25519_private_key_impl(ed25519_private_key);
    vscf_ed25519_private_key_use_random(ed25519_private_key, vscf_ctr_drbg_impl(rng));

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ed25519_private_key_generate_key(ed25519_private_key));

    size_t len_private = vscf_pkcs8_serializer_serialized_private_key_len(pkcs8, private_key);

    *priv = vsc_buffer_new_with_capacity(len_private);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_pkcs8_serializer_serialize_private_key(pkcs8, private_key, *priv));

    vscf_impl_t *public_key = vscf_ed25519_private_key_extract_public_key(ed25519_private_key);

    size_t len_public = vscf_pkcs8_serializer_serialized_public_key_len(pkcs8, public_key);

    *pub = vsc_buffer_new_with_capacity(len_public);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_pkcs8_serializer_serialize_public_key(pkcs8, public_key, *pub));

    vscf_pkcs8_serializer_destroy(&pkcs8);

    vscf_ed25519_public_key_destroy((vscf_ed25519_public_key_t **)&public_key);
    vscf_ed25519_private_key_destroy((vscf_ed25519_private_key_t **)&private_key);
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
generate_random_participant_id(vscf_ctr_drbg_t *rng, vsc_buffer_t **id) {
    *id = vsc_buffer_new_with_capacity(vscf_group_session_SENDER_ID_LEN);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_random(rng, 32, *id));
}

void
encrypt_decrypt(vscf_ctr_drbg_t *rng, vscf_group_session_t **sessions, vsc_buffer_t **priv, vsc_buffer_t **pub,
        vsc_buffer_t **ids, size_t group_size, size_t iterations, bool not_sync) {
    for (size_t i = 0; i < iterations; i++) {
        size_t sender = generate_number(rng, 0, group_size - 1);

        vsc_buffer_t *plain_text = NULL;
        generate_random_data(rng, &plain_text);

        vscf_error_t error;
        vscf_error_reset(&error);

        vscf_group_session_message_t *msg = vscf_group_session_encrypt(sessions[sender], vsc_buffer_data(plain_text),
                vsc_buffer_data(priv[sender]), vsc_buffer_data(ids[sender]), &error);

        TEST_ASSERT(msg != NULL);
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, error.status);

        for (size_t j = 0; j < (not_sync ? group_size / 2 : group_size); j++) {
            size_t len = vscf_group_session_decrypt_len(sessions[j], msg);
            vsc_buffer_t *decrypted = vsc_buffer_new_with_capacity(len);

            TEST_ASSERT_EQUAL(
                    vscf_status_SUCCESS, vscf_group_session_decrypt(sessions[j], msg, vsc_buffer_data(pub[sender]),
                                                 vsc_buffer_data(ids[sender]), decrypted));

            TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_buffer_data(plain_text), decrypted);

            vsc_buffer_destroy(&decrypted);
        }

        vscf_group_session_message_destroy(&msg);
        vsc_buffer_destroy(&plain_text);
    }
}

void
initialize_random_group_session(vscf_ctr_drbg_t *rng, vscf_group_session_t ***sessions, vsc_buffer_t ***priv,
        vsc_buffer_t ***pub, vsc_buffer_t ***ids, size_t group_size) {
    *sessions = vscf_alloc(group_size * sizeof(vscf_group_session_t *));
    *priv = vscf_alloc(group_size * sizeof(vsc_buffer_t *));
    *pub = vscf_alloc(group_size * sizeof(vsc_buffer_t *));
    *ids = vscf_alloc(group_size * sizeof(vsc_buffer_t *));

    vscf_group_session_ticket_t *ticket = vscf_group_session_ticket_new();

    vscf_group_session_ticket_use_rng(ticket, vscf_ctr_drbg_impl(rng));

    vsc_buffer_t *session_id = vsc_buffer_new_with_capacity(sizeof(vscf_group_session_id_t));

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_random(rng, sizeof(vscf_group_session_id_t), session_id));

    TEST_ASSERT_EQUAL(
            vscf_status_SUCCESS, vscf_group_session_ticket_setup_ticket_as_new(ticket, vsc_buffer_data(session_id)));

    for (size_t i = 0; i < group_size; i++) {
        vscf_group_session_t *session = vscf_group_session_new();

        vscf_group_session_use_rng(session, vscf_ctr_drbg_impl(rng));

        TEST_ASSERT_EQUAL(vscf_status_SUCCESS,
                vscf_group_session_add_epoch(session, vscf_group_session_ticket_get_ticket_message(ticket)));

        (*sessions)[i] = session;

        generate_PKCS8_ed_keypair(rng, &(*priv)[i], &(*pub)[i]);
        generate_random_participant_id(rng, &(*ids)[i]);
    }

    vscf_group_session_ticket_destroy(&ticket);
    vsc_buffer_destroy(&session_id);
}

void
test__encrypt_decrypt__random_group__should_match(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_group_session_t **sessions;
    vsc_buffer_t **priv;
    vsc_buffer_t **pub;
    vsc_buffer_t **ids;

    size_t group_size = 10;

    initialize_random_group_session(rng, &sessions, &priv, &pub, &ids, group_size);

    encrypt_decrypt(rng, sessions, priv, pub, ids, group_size, 1000, false);

    for (size_t i = 0; i < group_size; i++) {
        vscf_group_session_destroy(&sessions[i]);
        vsc_buffer_destroy(&priv[i]);
        vsc_buffer_destroy(&pub[i]);
        vsc_buffer_destroy(&ids[i]);
    }

    vscf_dealloc(sessions);
    vscf_dealloc(priv);
    vscf_dealloc(pub);
    vscf_dealloc(ids);

    vscf_ctr_drbg_destroy(&rng);
}

void
add_epoch_to_half(vscf_group_session_t **sessions, size_t group_size) {

    vscf_error_t error;
    vscf_error_reset(&error);

    vscf_group_session_ticket_t *ticket = vscf_group_session_create_group_ticket(sessions[0], &error);
    const vscf_group_session_message_t *msg = vscf_group_session_ticket_get_ticket_message(ticket);

    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, error.status);

    for (size_t i = 0; i < group_size / 2; i++) {
        TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_group_session_add_epoch(sessions[i], msg));
    }

    vscf_group_session_ticket_destroy(&ticket);
}

void
test__encrypt_decrypt__new_epoch__should_decrypt(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscf_group_session_t **sessions;
    vsc_buffer_t **priv;
    vsc_buffer_t **pub;
    vsc_buffer_t **ids;

    size_t group_size = 10;

    initialize_random_group_session(rng, &sessions, &priv, &pub, &ids, group_size);

    encrypt_decrypt(rng, sessions, priv, pub, ids, group_size, 1000, false);

    add_epoch_to_half(sessions, group_size);

    encrypt_decrypt(rng, sessions, priv, pub, ids, group_size, 1000, true);

    for (size_t i = 0; i < group_size; i++) {
        vscf_group_session_destroy(&sessions[i]);
        vsc_buffer_destroy(&priv[i]);
        vsc_buffer_destroy(&pub[i]);
        vsc_buffer_destroy(&ids[i]);
    }

    vscf_dealloc(sessions);
    vscf_dealloc(priv);
    vscf_dealloc(pub);
    vscf_dealloc(ids);

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
    RUN_TEST(test__encrypt_decrypt__random_group__should_match);
    RUN_TEST(test__encrypt_decrypt__new_epoch__should_decrypt);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
