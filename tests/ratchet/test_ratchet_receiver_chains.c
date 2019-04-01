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

#include "vscr_ratchet_receiver_chains.h"
#include "vscr_ratchet_common_hidden.h"
#include "test_utils_ratchet.h"

void
test__receiver_chains__adding_chains__should_be_correct(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_receiver_chains_t *chains = vscr_ratchet_receiver_chains_new();

    vsc_buffer_t *priv1, *pub1;
    vsc_buffer_t *priv2, *pub2;
    vsc_buffer_t *priv3, *pub3;

    generate_raw_keypair(rng, &priv1, &pub1);
    generate_raw_keypair(rng, &priv2, &pub2);
    generate_raw_keypair(rng, &priv3, &pub3);

    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_receiver_chains_first_chain(chains));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_receiver_chains_find_chain(chains, vsc_buffer_data(pub1)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_receiver_chains_find_chain(chains, vsc_buffer_data(pub2)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_receiver_chains_find_chain(chains, vsc_buffer_data(pub3)));

    vscr_ratchet_receiver_chain_t *chain1 = vscr_ratchet_receiver_chain_new();
    vscr_ratchet_receiver_chain_t *chain2 = vscr_ratchet_receiver_chain_new();

    memcpy(chain1->public_key, vsc_buffer_bytes(pub1), sizeof(chain1->public_key));
    memcpy(chain2->public_key, vsc_buffer_bytes(pub2), sizeof(chain2->public_key));

    vscr_ratchet_receiver_chains_add_chain(chains, chain1);

    TEST_ASSERT_EQUAL(chain1, vscr_ratchet_receiver_chains_first_chain(chains));
    TEST_ASSERT_EQUAL(chain1, vscr_ratchet_receiver_chains_find_chain(chains, vsc_buffer_data(pub1)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_receiver_chains_find_chain(chains, vsc_buffer_data(pub2)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_receiver_chains_find_chain(chains, vsc_buffer_data(pub3)));

    vscr_ratchet_receiver_chains_add_chain(chains, chain2);

    TEST_ASSERT_EQUAL(chain2, vscr_ratchet_receiver_chains_first_chain(chains));
    TEST_ASSERT_EQUAL(chain1, vscr_ratchet_receiver_chains_find_chain(chains, vsc_buffer_data(pub1)));
    TEST_ASSERT_EQUAL(chain2, vscr_ratchet_receiver_chains_find_chain(chains, vsc_buffer_data(pub2)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_receiver_chains_find_chain(chains, vsc_buffer_data(pub3)));

    vsc_buffer_destroy(&priv1);
    vsc_buffer_destroy(&pub1);
    vsc_buffer_destroy(&priv2);
    vsc_buffer_destroy(&pub2);
    vsc_buffer_destroy(&priv3);
    vsc_buffer_destroy(&pub3);

    vscr_ratchet_receiver_chains_destroy(&chains);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__delete_next__adding_chains__should_be_correct(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_receiver_chains_t *chains = vscr_ratchet_receiver_chains_new();

    vsc_buffer_t *priv1, *pub1;
    vsc_buffer_t *priv2, *pub2;
    vsc_buffer_t *priv3, *pub3;

    generate_raw_keypair(rng, &priv1, &pub1);
    generate_raw_keypair(rng, &priv2, &pub2);
    generate_raw_keypair(rng, &priv3, &pub3);

    vscr_ratchet_receiver_chain_t *chain1 = vscr_ratchet_receiver_chain_new();
    vscr_ratchet_receiver_chain_t *chain2 = vscr_ratchet_receiver_chain_new();
    vscr_ratchet_receiver_chain_t *chain3 = vscr_ratchet_receiver_chain_new();

    chain2->chain_key.index = 5;
    memcpy(chain1->public_key, vsc_buffer_bytes(pub1), sizeof(chain1->public_key));
    memcpy(chain2->public_key, vsc_buffer_bytes(pub2), sizeof(chain2->public_key));
    memcpy(chain3->public_key, vsc_buffer_bytes(pub3), sizeof(chain3->public_key));

    vscr_ratchet_receiver_chains_add_chain(chains, chain3);
    vscr_ratchet_receiver_chains_add_chain(chains, chain2);
    vscr_ratchet_receiver_chains_add_chain(chains, chain1);

    vscr_ratchet_receiver_chains_delete_next_chain_if_possible(chains, chain3, 5);

    vscr_ratchet_receiver_chains_delete_next_chain_if_possible(chains, chain1, 2);
    TEST_ASSERT_EQUAL(chain1, vscr_ratchet_receiver_chains_find_chain(chains, vsc_buffer_data(pub1)));
    TEST_ASSERT_EQUAL(chain2, vscr_ratchet_receiver_chains_find_chain(chains, vsc_buffer_data(pub2)));
    TEST_ASSERT_EQUAL(chain3, vscr_ratchet_receiver_chains_find_chain(chains, vsc_buffer_data(pub3)));

    vscr_ratchet_receiver_chains_delete_next_chain_if_possible(chains, chain1, 5);
    TEST_ASSERT_EQUAL(chain1, vscr_ratchet_receiver_chains_find_chain(chains, vsc_buffer_data(pub1)));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_receiver_chains_find_chain(chains, vsc_buffer_data(pub2)));
    TEST_ASSERT_EQUAL(chain3, vscr_ratchet_receiver_chains_find_chain(chains, vsc_buffer_data(pub3)));

    vsc_buffer_destroy(&priv1);
    vsc_buffer_destroy(&pub1);
    vsc_buffer_destroy(&priv2);
    vsc_buffer_destroy(&pub2);
    vsc_buffer_destroy(&priv3);
    vsc_buffer_destroy(&pub3);

    vscr_ratchet_receiver_chains_destroy(&chains);

    vscf_ctr_drbg_destroy(&rng);
}

void
test__add_chain__many_chains__chains_number_should_be_limited(void) {
    vscf_ctr_drbg_t *rng = vscf_ctr_drbg_new();
    TEST_ASSERT_EQUAL(vscf_status_SUCCESS, vscf_ctr_drbg_setup_defaults(rng));

    vscr_ratchet_receiver_chains_t *chains = vscr_ratchet_receiver_chains_new();

    vsc_buffer_t *pub[vscr_ratchet_common_hidden_MAX_RECEIVERS_CHAINS + 1];
    vscr_ratchet_receiver_chain_t *chain_arr[vscr_ratchet_common_hidden_MAX_RECEIVERS_CHAINS + 1];

    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_RECEIVERS_CHAINS; i++) {
        vsc_buffer_t *priv;

        generate_raw_keypair(rng, &priv, &pub[i]);

        vsc_buffer_destroy(&priv);

        vscr_ratchet_receiver_chain_t *chain = vscr_ratchet_receiver_chain_new();
        memcpy(chain->public_key, vsc_buffer_bytes(pub[i]), sizeof(chain->public_key));
        chain_arr[i] = chain;

        vscr_ratchet_receiver_chains_add_chain(chains, chain);

        TEST_ASSERT_EQUAL(chain, vscr_ratchet_receiver_chains_first_chain(chains));

        for (size_t j = 0; j <= i; j++) {
            TEST_ASSERT_EQUAL(chain_arr[j], vscr_ratchet_receiver_chains_find_chain(chains, vsc_buffer_data(pub[j])));
        }
    }

    vsc_buffer_t *priv;

    generate_raw_keypair(rng, &priv, &pub[vscr_ratchet_common_hidden_MAX_RECEIVERS_CHAINS]);

    vsc_buffer_destroy(&priv);

    vscr_ratchet_receiver_chain_t *chain = vscr_ratchet_receiver_chain_new();
    memcpy(chain->public_key, vsc_buffer_bytes(pub[vscr_ratchet_common_hidden_MAX_RECEIVERS_CHAINS]),
            sizeof(chain->public_key));
    chain_arr[vscr_ratchet_common_hidden_MAX_RECEIVERS_CHAINS] = chain;

    vscr_ratchet_receiver_chains_add_chain(chains, chain);

    TEST_ASSERT_EQUAL(chain, vscr_ratchet_receiver_chains_first_chain(chains));
    TEST_ASSERT_EQUAL(NULL, vscr_ratchet_receiver_chains_find_chain(chains, vsc_buffer_data(pub[0])));

    for (size_t j = 1; j <= vscr_ratchet_common_hidden_MAX_RECEIVERS_CHAINS; j++) {
        TEST_ASSERT_EQUAL(chain_arr[j], vscr_ratchet_receiver_chains_find_chain(chains, vsc_buffer_data(pub[j])));
    }

    for (size_t i = 0; i < vscr_ratchet_common_hidden_MAX_RECEIVERS_CHAINS + 1; i++) {
        vsc_buffer_destroy(&pub[i]);
    }

    vscr_ratchet_receiver_chains_destroy(&chains);

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
    RUN_TEST(test__receiver_chains__adding_chains__should_be_correct);
    RUN_TEST(test__delete_next__adding_chains__should_be_correct);
    RUN_TEST(test__add_chain__many_chains__chains_number_should_be_limited);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
