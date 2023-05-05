//  Copyright (C) 2015-2022 Virgil Security, Inc.
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

#include <ed25519/ed25519.h>
#include <virgil/crypto/common/vsc_buffer.h>
#include "vscr_error.h"
#include "vscr_ratchet_common.h"
#include "vscr_ratchet_key_utils.h"
#include "test_data_ratchet_key_utils.h"

void
test__extract__fixed_curve_keypair__should_match(void) {
    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_key_utils_t *key_utils = vscr_ratchet_key_utils_new();

    vsc_buffer_t *private_key_raw = vscr_ratchet_key_utils_extract_ratchet_private_key(
            key_utils, test_data_ratchet_curve_private_key, false, true, false, &error);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    vsc_buffer_t *public_key_raw = vscr_ratchet_key_utils_extract_ratchet_public_key(
            key_utils, test_data_ratchet_curve_public_key, false, true, false, &error);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    byte public_key[ED25519_KEY_LEN];

    TEST_ASSERT_EQUAL(0, curve25519_get_pubkey(public_key, vsc_buffer_bytes(private_key_raw)));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_data(public_key, ED25519_KEY_LEN), public_key_raw);

    vsc_buffer_destroy(&private_key_raw);
    vsc_buffer_destroy(&public_key_raw);

    vscr_ratchet_key_utils_destroy(&key_utils);
}

void
test__extract__fixed_ed_keypair__should_match(void) {
    vscr_error_t error;
    vscr_error_reset(&error);

    vscr_ratchet_key_utils_t *key_utils = vscr_ratchet_key_utils_new();

    vsc_buffer_t *private_key_raw = vscr_ratchet_key_utils_extract_ratchet_private_key(
            key_utils, test_data_ratchet_ed_private_key, true, false, true, &error);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    vsc_buffer_t *public_key_raw = vscr_ratchet_key_utils_extract_ratchet_public_key(
            key_utils, test_data_ratchet_ed_public_key, true, false, true, &error);
    TEST_ASSERT_FALSE(vscr_error_has_error(&error));

    byte public_key[ED25519_KEY_LEN];

    TEST_ASSERT_EQUAL(0, curve25519_get_pubkey(public_key, vsc_buffer_bytes(private_key_raw)));

    TEST_ASSERT_EQUAL_DATA_AND_BUFFER(vsc_data(public_key, ED25519_KEY_LEN), public_key_raw);

    vsc_buffer_destroy(&private_key_raw);
    vsc_buffer_destroy(&public_key_raw);

    vscr_ratchet_key_utils_destroy(&key_utils);
}

#endif

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__extract__fixed_curve_keypair__should_match);
    RUN_TEST(test__extract__fixed_ed_keypair__should_match);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
