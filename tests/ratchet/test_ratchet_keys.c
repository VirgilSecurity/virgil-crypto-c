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

#include <virgil/crypto/ratchet/vscr_memory.h>
#include <virgil/crypto/foundation/vscf_key_provider.h>
#include <virgil/crypto/foundation/vscf_fake_random.h>
#include <virgil/crypto/foundation/vscf_private_key.h>
#include "unity.h"
#include "test_utils.h"

#define TEST_DEPENDENCIES_AVAILABLE VSCR_RATCHET
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscr_ratchet_keys.h"
#include "test_data_ratchet_keys.h"

void
test__create_chain_key__fixed_keys__should_match(void) {
    vscr_ratchet_keys_t *keys = vscr_ratchet_keys_new();

    byte new_root_key[vscr_ratchet_common_hidden_SHARED_KEY_LEN];

    vscr_ratchet_chain_key_t *chain_key = vscr_ratchet_chain_key_new();

    vscr_status_t status = vscr_ratchet_keys_create_chain_key_sender(keys, test_data_ratchet_keys_root_key.bytes,
            test_data_ratchet_keys_private_key.bytes, test_data_ratchet_keys_public.bytes, NULL, NULL, new_root_key,
            chain_key);

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_keys_new_root_key, vsc_data(new_root_key, sizeof(new_root_key)));
    TEST_ASSERT_EQUAL(0, chain_key->index);
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_keys_new_chain_key, vsc_data(chain_key->key, sizeof(chain_key->key)));
    vscr_ratchet_chain_key_destroy(&chain_key);
    vscr_zeroize(new_root_key, sizeof(new_root_key));

    chain_key = vscr_ratchet_chain_key_new();

    status = vscr_ratchet_keys_create_chain_key_receiver(keys, test_data_ratchet_keys_root_key.bytes,
            test_data_ratchet_keys_private_key.bytes, test_data_ratchet_keys_public.bytes, NULL, vsc_data_empty(),
            new_root_key, chain_key);
    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_keys_new_root_key, vsc_data(new_root_key, sizeof(new_root_key)));
    TEST_ASSERT_EQUAL(0, chain_key->index);
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_keys_new_chain_key, vsc_data(chain_key->key, sizeof(chain_key->key)));
    vscr_ratchet_chain_key_destroy(&chain_key);

    vscr_ratchet_keys_destroy(&keys);
}

void
test__create_chain_key_pqc__fixed_keys__should_match(void) {
    vscf_fake_random_t *rng = vscf_fake_random_new();
    vscf_fake_random_setup_source_data(rng, test_data_ratchet_keys_random);

    vscr_ratchet_keys_t *keys = vscr_ratchet_keys_new();
    vscr_ratchet_keys_use_rng(keys, vscf_fake_random_impl(rng));

    byte new_root_key[vscr_ratchet_common_hidden_SHARED_KEY_LEN];

    vscf_key_provider_t *key_provider = vscf_key_provider_new();
    vscf_key_provider_use_random(key_provider, vscf_fake_random_impl(rng));

    vscf_error_t error_ctx;
    vscf_error_reset(&error_ctx);

    vscf_impl_t *private_key =
            vscf_key_provider_generate_private_key(key_provider, vscf_alg_id_ROUND5_ND_1CCA_5D, &error_ctx);

    TEST_ASSERT(!vscf_error_has_error(&error_ctx));

    vscf_impl_t *public_key = vscf_private_key_extract_public_key(private_key);

    vsc_buffer_t *encapsulated_key;

    vscr_ratchet_chain_key_t *chain_key = vscr_ratchet_chain_key_new();

    vscr_status_t status = vscr_ratchet_keys_create_chain_key_sender(keys, test_data_ratchet_keys_root_key.bytes,
            test_data_ratchet_keys_private_key.bytes, test_data_ratchet_keys_public.bytes, public_key,
            &encapsulated_key, new_root_key, chain_key);

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_keys_root_key_pqc, vsc_data(new_root_key, sizeof(new_root_key)));
    TEST_ASSERT_EQUAL(0, chain_key->index);
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_keys_chain_key_pqc, vsc_data(chain_key->key, sizeof(chain_key->key)));
    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_data_ratchet_keys_encapsulated_key_pqc, encapsulated_key);
    vscr_ratchet_chain_key_destroy(&chain_key);
    vscr_zeroize(new_root_key, sizeof(new_root_key));

    chain_key = vscr_ratchet_chain_key_new();

    status = vscr_ratchet_keys_create_chain_key_receiver(keys, test_data_ratchet_keys_root_key.bytes,
            test_data_ratchet_keys_private_key.bytes, test_data_ratchet_keys_public.bytes, private_key,
            vsc_buffer_data(encapsulated_key), new_root_key, chain_key);

    TEST_ASSERT_EQUAL(vscr_status_SUCCESS, status);
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_keys_root_key_pqc, vsc_data(new_root_key, sizeof(new_root_key)));
    TEST_ASSERT_EQUAL(0, chain_key->index);
    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_keys_chain_key_pqc, vsc_data(chain_key->key, sizeof(chain_key->key)));
    vscr_ratchet_chain_key_destroy(&chain_key);

    vscf_key_provider_destroy(&key_provider);
    vscf_fake_random_destroy(&rng);
    vscr_ratchet_keys_destroy(&keys);

    vsc_buffer_destroy(&encapsulated_key);

    vscf_impl_destroy(&private_key);
    vscf_impl_destroy(&public_key);
}

void
test__create_msg_key__fixed_keys__should_match(void) {
    vscr_ratchet_keys_t *keys = vscr_ratchet_keys_new();

    vscr_ratchet_chain_key_t *chain_key = vscr_ratchet_chain_key_new();

    memcpy(chain_key->key, test_data_ratchet_keys_new_chain_key.bytes, test_data_ratchet_keys_new_chain_key.len);
    chain_key->index = test_data_ratchet_keys_message_key_index;

    vscr_ratchet_message_key_t *message_key = vscr_ratchet_keys_create_message_key(chain_key);

    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_keys_message_key, vsc_data(message_key->key, sizeof(message_key->key)));
    TEST_ASSERT_EQUAL(test_data_ratchet_keys_message_key_index, message_key->index);

    vscr_ratchet_message_key_destroy(&message_key);

    vscr_ratchet_chain_key_destroy(&chain_key);

    vscr_ratchet_keys_destroy(&keys);
}

void
test__advance_chain_key__fixed_keys__should_match(void) {
    vscr_ratchet_keys_t *keys = vscr_ratchet_keys_new();

    vscr_ratchet_chain_key_t *chain_key = vscr_ratchet_chain_key_new();

    memcpy(chain_key->key, test_data_ratchet_keys_chain_key.bytes, test_data_ratchet_keys_chain_key.len);
    chain_key->index = test_data_ratchet_keys_chain_key_index;

    vscr_ratchet_keys_advance_chain_key(chain_key);

    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_keys_next_chain_key, vsc_data(chain_key->key, sizeof(chain_key->key)));
    TEST_ASSERT_EQUAL(test_data_ratchet_keys_chain_key_index + 1, chain_key->index);

    vscr_ratchet_keys_advance_chain_key(chain_key);

    TEST_ASSERT_EQUAL_DATA(test_data_ratchet_keys_next_chain_key2, vsc_data(chain_key->key, sizeof(chain_key->key)));
    TEST_ASSERT_EQUAL(test_data_ratchet_keys_chain_key_index + 2, chain_key->index);

    vscr_ratchet_chain_key_destroy(&chain_key);

    vscr_ratchet_keys_destroy(&keys);
}

#endif

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__create_chain_key__fixed_keys__should_match);
    RUN_TEST(test__create_chain_key_pqc__fixed_keys__should_match);
    RUN_TEST(test__create_msg_key__fixed_keys__should_match);
    RUN_TEST(test__advance_chain_key__fixed_keys__should_match);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
