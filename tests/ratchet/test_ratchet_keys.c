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
#include <vscf_pkcs8_der_deserializer_internal.h>
#include <virgil/crypto/ratchet/vscr_ratchet_common.h>
#include <virgil/crypto/foundation/private/vscf_endianness.h>
#include <test_data_ratchet_session.h>
#include <ed25519/ed25519.h>

static vsc_buffer_t *
vscr_ratchet_session_get_raw_public_key(vsc_data_t data, vscr_error_ctx_t *err_ctx) {

    vscf_pkcs8_der_deserializer_t *pkcs8 = vscf_pkcs8_der_deserializer_new();
    vscf_pkcs8_der_deserializer_setup_defaults(pkcs8);

    vscf_error_ctx_t error_ctx;
    vscf_error_ctx_reset(&error_ctx);

    vsc_buffer_t *result = NULL;

    vscf_raw_key_t *raw_key = vscf_pkcs8_der_deserializer_deserialize_public_key(pkcs8, data, &error_ctx);

    if (error_ctx.error != vscf_SUCCESS) {
        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_error_KEY_DESERIALIZATION);

        goto err;
    }

    if (vscf_raw_key_data(raw_key).len != vscr_ratchet_common_RATCHET_KEY_LENGTH ||
            vscf_raw_key_alg_id(raw_key) != vscf_alg_id_X25519) {
        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_error_INVALID_KEY_TYPE);

        goto err;
    }

    result = vsc_buffer_new_with_data(vscf_raw_key_data(raw_key));

err:
    vscf_raw_key_destroy(&raw_key);

    vscf_pkcs8_der_deserializer_destroy(&pkcs8);

    return result;
}

static vsc_buffer_t *
vscr_ratchet_session_get_raw_private_key(vsc_data_t data, vscr_error_ctx_t *err_ctx) {

    vscf_pkcs8_der_deserializer_t *pkcs8 = vscf_pkcs8_der_deserializer_new();
    vscf_pkcs8_der_deserializer_setup_defaults(pkcs8);

    vscf_error_ctx_t error_ctx;
    vscf_error_ctx_reset(&error_ctx);

    vsc_buffer_t *result = NULL;

    vscf_raw_key_t *raw_key = vscf_pkcs8_der_deserializer_deserialize_private_key(pkcs8, data, &error_ctx);

    if (error_ctx.error != vscf_SUCCESS) {
        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_error_KEY_DESERIALIZATION);

        goto err;
    }

    if (vscf_raw_key_data(raw_key).len != vscr_ratchet_common_RATCHET_KEY_LENGTH + 2 ||
            vscf_raw_key_alg_id(raw_key) != vscf_alg_id_X25519) {
        VSCR_ERROR_CTX_SAFE_UPDATE(err_ctx, vscr_error_INVALID_KEY_TYPE);

        goto err;
    }

    result = vsc_buffer_new_with_data(
            vsc_data_slice_beg(vscf_raw_key_data(raw_key), 2, vscr_ratchet_common_RATCHET_KEY_LENGTH));

err:
    vscf_raw_key_destroy(&raw_key);

    vscf_pkcs8_der_deserializer_destroy(&pkcs8);

    return result;
}

void
test__key_format__fixed_keypair__should_match(void) {
    vscr_error_ctx_t error_ctx;
    vscr_error_ctx_reset(&error_ctx);

    vsc_buffer_t *sender_identity_private_key_raw =
            vscr_ratchet_session_get_raw_private_key(test_ratchet_session_alice_identity_private_key, &error_ctx);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, error_ctx.error);

    vsc_buffer_t *sender_identity_public_key_raw =
            vscr_ratchet_session_get_raw_public_key(test_ratchet_session_alice_identity_public_key, &error_ctx);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, error_ctx.error);


    byte sender_identity_public_key[ED25519_KEY_LEN];


    TEST_ASSERT_EQUAL(
            0, curve25519_get_pubkey(sender_identity_public_key, vsc_buffer_bytes(sender_identity_private_key_raw)));

    TEST_ASSERT_EQUAL(ED25519_KEY_LEN, vsc_buffer_len(sender_identity_public_key_raw));
    TEST_ASSERT_EQUAL_MEMORY(
            sender_identity_public_key, vsc_buffer_bytes(sender_identity_public_key_raw), ED25519_KEY_LEN);

    vsc_buffer_destroy(&sender_identity_private_key_raw);
    vsc_buffer_destroy(&sender_identity_public_key_raw);
}

// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

    RUN_TEST(test__key_format__fixed_keypair__should_match);

    return UNITY_END();
}