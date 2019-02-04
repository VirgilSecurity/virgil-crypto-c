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

#include <virgil/crypto/common/vsc_buffer.h>
#include <virgil/crypto/ratchet/vscr_error_ctx.h>
#include <virgil/crypto/ratchet/vscr_ratchet_common.h>
#include <test_data_ratchet_session.h>
#include <ed25519/ed25519.h>
#include <virgil/crypto/ratchet/vscr_ratchet_key_extractor.h>

void
test__key_format__fixed_curve_keypair__should_match(void) {
    vscr_error_ctx_t error_ctx;
    vscr_error_ctx_reset(&error_ctx);

    vscr_ratchet_key_extractor_t *extractor = vscr_ratchet_key_extractor_new();

    vsc_buffer_t *sender_identity_private_key_raw = vscr_ratchet_key_extractor_extract_ratchet_private_key(
            extractor, test_ratchet_session_alice_identity_private_key, &error_ctx);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, error_ctx.error);

    vsc_buffer_t *sender_identity_public_key_raw = vscr_ratchet_key_extractor_extract_ratchet_public_key(
            extractor, test_ratchet_session_alice_identity_public_key, &error_ctx);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, error_ctx.error);

    byte sender_identity_public_key[ED25519_KEY_LEN];

    TEST_ASSERT_EQUAL(
            0, curve25519_get_pubkey(sender_identity_public_key, vsc_buffer_bytes(sender_identity_private_key_raw)));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(
            vsc_data(sender_identity_public_key, ED25519_KEY_LEN), sender_identity_public_key_raw);

    vsc_buffer_destroy(&sender_identity_private_key_raw);
    vsc_buffer_destroy(&sender_identity_public_key_raw);

    vscr_ratchet_key_extractor_destroy(&extractor);
}

void
test__key_format__fixed_ed_keypair__should_match(void) {
    vscr_error_ctx_t error_ctx;
    vscr_error_ctx_reset(&error_ctx);

    vscr_ratchet_key_extractor_t *extractor = vscr_ratchet_key_extractor_new();

    vsc_buffer_t *sender_identity_private_key_raw =
            vscr_ratchet_key_extractor_extract_ratchet_private_key(extractor, test_ratchet_ed_private_key, &error_ctx);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, error_ctx.error);

    vsc_buffer_t *sender_identity_public_key_raw =
            vscr_ratchet_key_extractor_extract_ratchet_public_key(extractor, test_ratchet_ed_public_key, &error_ctx);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, error_ctx.error);

    byte sender_identity_public_key[ED25519_KEY_LEN];

    TEST_ASSERT_EQUAL(
            0, curve25519_get_pubkey(sender_identity_public_key, vsc_buffer_bytes(sender_identity_private_key_raw)));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(
            vsc_data(sender_identity_public_key, ED25519_KEY_LEN), sender_identity_public_key_raw);

    vsc_buffer_destroy(&sender_identity_private_key_raw);
    vsc_buffer_destroy(&sender_identity_public_key_raw);

    vscr_ratchet_key_extractor_destroy(&extractor);
}

void
test__key_id__raw_key__should_match(void) {
    vscr_ratchet_key_extractor_t *extractor = vscr_ratchet_key_extractor_new();

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(vscr_ratchet_common_KEY_ID_LEN);

    vscr_ratchet_key_extractor_compute_public_key_id(extractor, test_ratchet_ed_public_key2_raw, buffer);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_ratchet_ed_public_key2_id, buffer);

    vsc_buffer_destroy(&buffer);
    vscr_ratchet_key_extractor_destroy(&extractor);
}

void
test__key_id__key__should_match(void) {
    vscr_ratchet_key_extractor_t *extractor = vscr_ratchet_key_extractor_new();

    vsc_buffer_t *buffer = vsc_buffer_new_with_capacity(vscr_ratchet_common_KEY_ID_LEN);

    vscr_ratchet_key_extractor_compute_public_key_id(extractor, test_ratchet_ed_public_key2, buffer);

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(test_ratchet_ed_public_key2_id, buffer);

    vsc_buffer_destroy(&buffer);
    vscr_ratchet_key_extractor_destroy(&extractor);
}

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

    RUN_TEST(test__key_format__fixed_curve_keypair__should_match);
    RUN_TEST(test__key_format__fixed_ed_keypair__should_match);
    RUN_TEST(test__key_id__raw_key__should_match);
    RUN_TEST(test__key_id__key__should_match);

    return UNITY_END();
}
