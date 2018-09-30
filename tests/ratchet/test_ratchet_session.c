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

#include <ed25519/ed25519.h>
#include <test_data_ratchet_session.h>
#include <test_data_ratchet.h>
#include <virgil/ratchet/private/vscr_ratchet_session_defs.h>
#include "unity.h"
#include "test_utils.h"

#define TEST_DEPENDENCIES_AVAILABLE VSCR_RATCHET
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscr_ratchet_session.h"
#include "vscr_virgil_ratchet_fake_rng_impl.h"

static void initialize(vscr_ratchet_session_t *session_alice, vscr_ratchet_session_t *session_bob) {
    vscr_ratchet_session_take_rng(session_alice, vscr_virgil_ratchet_fake_rng_impl(vscr_virgil_ratchet_fake_rng_new()));
    vscr_ratchet_session_take_rng(session_bob, vscr_virgil_ratchet_fake_rng_impl(vscr_virgil_ratchet_fake_rng_new()));

    vscr_ratchet_t *ratchet_alice = vscr_ratchet_new();
    vscr_ratchet_t *ratchet_bob = vscr_ratchet_new();

    vscr_ratchet_session_use_ratchet(session_alice, ratchet_alice);
    vscr_ratchet_session_use_ratchet(session_bob, ratchet_bob);

    vscr_ratchet_kdf_info_t *kdf_info = vscr_ratchet_kdf_info_new();
    kdf_info->root_info = vsc_buffer_new_with_capacity(test_ratchet_kdf_info_root.len);
    memcpy(vsc_buffer_ptr(kdf_info->root_info), test_ratchet_kdf_info_root.bytes, test_ratchet_kdf_info_root.len);
    vsc_buffer_reserve(kdf_info->root_info, test_ratchet_kdf_info_root.len);
    kdf_info->ratchet_info = vsc_buffer_new_with_capacity(test_ratchet_kdf_info_ratchet.len);
    memcpy(vsc_buffer_ptr(kdf_info->ratchet_info), test_ratchet_kdf_info_ratchet.bytes, test_ratchet_kdf_info_ratchet.len);
    vsc_buffer_reserve(kdf_info->ratchet_info, test_ratchet_kdf_info_ratchet.len);
    kdf_info->ratchet_info = vsc_buffer_new_with_capacity(test_ratchet_kdf_info_ratchet.len);
    memcpy(vsc_buffer_ptr(kdf_info->ratchet_info), test_ratchet_kdf_info_ratchet.bytes, test_ratchet_kdf_info_ratchet.len);
    vsc_buffer_reserve(kdf_info->ratchet_info, test_ratchet_kdf_info_ratchet.len);

    vscr_ratchet_cipher_t *ratchet_cipher = vscr_ratchet_cipher_new();
    ratchet_cipher->kdf_info= vsc_buffer_new_with_capacity(test_ratchet_kdf_info_cipher.len);
    memcpy(vsc_buffer_ptr(ratchet_cipher->kdf_info), test_ratchet_kdf_info_cipher.bytes, test_ratchet_kdf_info_cipher.len);
    vsc_buffer_reserve(ratchet_cipher->kdf_info, test_ratchet_kdf_info_cipher.len);
    vscr_ratchet_use_cipher(ratchet_alice, ratchet_cipher);
    vscr_ratchet_use_cipher(ratchet_bob, ratchet_cipher);
    vscr_ratchet_cipher_destroy(&ratchet_cipher);
    vscr_ratchet_use_kdf_info(ratchet_alice, kdf_info);
    vscr_ratchet_use_kdf_info(ratchet_bob, kdf_info);
    vscr_ratchet_kdf_info_destroy(&kdf_info);

    vscr_ratchet_take_rng(ratchet_alice, vscr_virgil_ratchet_fake_rng_impl(vscr_virgil_ratchet_fake_rng_new()));
    vscr_ratchet_take_rng(ratchet_bob, vscr_virgil_ratchet_fake_rng_impl(vscr_virgil_ratchet_fake_rng_new()));
}

void
test__1(void) {
    vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
    vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();

    initialize(session_alice, session_bob);

    vsc_buffer_t *alice_identity_private_key = vsc_buffer_new_with_capacity(test_ratchet_session_alice_identity_private_key.len);
    memcpy(vsc_buffer_ptr(alice_identity_private_key), test_ratchet_session_alice_identity_private_key.bytes, test_ratchet_session_alice_identity_private_key.len);
    vsc_buffer_reserve(alice_identity_private_key, ED25519_KEY_LEN);

    vsc_buffer_t *alice_identity_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    curve25519_get_pubkey(vsc_buffer_ptr(alice_identity_public_key), vsc_buffer_bytes(alice_identity_private_key));
    vsc_buffer_reserve(alice_identity_public_key, ED25519_KEY_LEN);

    vsc_buffer_t *bob_identity_private_key = vsc_buffer_new_with_capacity(test_ratchet_session_bob_identity_private_key.len);
    memcpy(vsc_buffer_ptr(bob_identity_private_key), test_ratchet_session_bob_identity_private_key.bytes, test_ratchet_session_bob_identity_private_key.len);
    vsc_buffer_reserve(bob_identity_private_key, ED25519_KEY_LEN);

    vsc_buffer_t *bob_identity_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    curve25519_get_pubkey(vsc_buffer_ptr(bob_identity_public_key), vsc_buffer_bytes(bob_identity_private_key));
    vsc_buffer_reserve(bob_identity_public_key, ED25519_KEY_LEN);

    vsc_buffer_t *bob_longterm_private_key = vsc_buffer_new_with_capacity(test_ratchet_session_bob_longterm_private_key.len);
    memcpy(vsc_buffer_ptr(bob_longterm_private_key), test_ratchet_session_bob_longterm_private_key.bytes, test_ratchet_session_bob_longterm_private_key.len);
    vsc_buffer_reserve(bob_longterm_private_key, ED25519_KEY_LEN);

    vsc_buffer_t *bob_longterm_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    curve25519_get_pubkey(vsc_buffer_ptr(bob_longterm_public_key), vsc_buffer_bytes(bob_longterm_private_key));
    vsc_buffer_reserve(bob_longterm_public_key, ED25519_KEY_LEN);

    vsc_buffer_t *bob_onetime_private_key = vsc_buffer_new_with_capacity(test_ratchet_session_bob_onetime_private_key.len);
    memcpy(vsc_buffer_ptr(bob_onetime_private_key), test_ratchet_session_bob_onetime_private_key.bytes, test_ratchet_session_bob_onetime_private_key.len);
    vsc_buffer_reserve(bob_onetime_private_key, ED25519_KEY_LEN);

    vsc_buffer_t *bob_onetime_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    curve25519_get_pubkey(vsc_buffer_ptr(bob_onetime_public_key), vsc_buffer_bytes(bob_onetime_private_key));
    vsc_buffer_reserve(bob_onetime_public_key, ED25519_KEY_LEN);

    vscr_ratchet_session_initiate(session_alice,
                                  alice_identity_private_key,
                                  bob_identity_public_key,
                                  bob_longterm_public_key,
                                  bob_onetime_public_key);

    size_t len1 = vscr_ratchet_session_encrypt_len(session_alice, test_ratchet_plain_text1.len);
    vsc_buffer_t *cipher_text = vsc_buffer_new_with_capacity(len1);

    vscr_error_t result = vscr_ratchet_session_encrypt(session_alice, test_ratchet_plain_text1, cipher_text);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, result);

    vscr_ratchet_session_respond(session_bob,
                                 alice_identity_public_key,
                                 session_alice->sender_ephemeral_public_key,
                                 bob_identity_private_key,
                                 bob_longterm_private_key,
                                 bob_onetime_private_key);

    size_t len2 = vscr_ratchet_session_decrypt_len(session_bob, vsc_buffer_len(cipher_text));
    vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(len2);

    result = vscr_ratchet_session_decrypt(session_bob, vsc_buffer_data(cipher_text), plain_text);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, result);

    TEST_ASSERT_EQUAL_INT(test_ratchet_plain_text1.len, vsc_buffer_len(plain_text));
    TEST_ASSERT_EQUAL_MEMORY(test_ratchet_plain_text1.bytes, vsc_buffer_bytes(plain_text), test_ratchet_plain_text1.len);

    vsc_buffer_destroy(&alice_identity_private_key);
    vsc_buffer_destroy(&alice_identity_public_key);
    vsc_buffer_destroy(&bob_identity_private_key);
    vsc_buffer_destroy(&bob_longterm_private_key);
    vsc_buffer_destroy(&bob_onetime_private_key);
    vsc_buffer_destroy(&bob_identity_public_key);
    vsc_buffer_destroy(&bob_longterm_public_key);
    vsc_buffer_destroy(&bob_onetime_public_key);
    vsc_buffer_destroy(&cipher_text);
    vsc_buffer_destroy(&plain_text);
}

#endif // TEST_DEPENDENCIES_AVAILABLE


// --------------------------------------------------------------------------
// Entrypoint.
// --------------------------------------------------------------------------
int
main(void) {
    UNITY_BEGIN();

#if TEST_DEPENDENCIES_AVAILABLE
    RUN_TEST(test__1);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
