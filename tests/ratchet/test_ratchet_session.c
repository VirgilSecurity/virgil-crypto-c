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


#define UNITY_BEGIN() UnityBegin(__FILENAME__)

#include "unity.h"
#include "test_utils.h"

#define TEST_DEPENDENCIES_AVAILABLE VSCR_RATCHET
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscr_ratchet_defs.h"
#include "vscr_ratchet_rng.h"
#include "vscr_ratchet_session.h"
#include "vscr_ratchet_session_defs.h"
#include "vscr_virgil_ratchet_fake_rng_impl.h"

#include "test_data_ratchet_session.h"
#include "test_data_ratchet.h"

#include <ed25519/ed25519.h>


static void
initialize(vscr_ratchet_session_t *session_alice, vscr_ratchet_session_t *session_bob) {
    vscr_ratchet_session_take_rng(session_alice, vscr_virgil_ratchet_fake_rng_impl(vscr_virgil_ratchet_fake_rng_new()));
    vscr_ratchet_session_take_rng(session_bob, vscr_virgil_ratchet_fake_rng_impl(vscr_virgil_ratchet_fake_rng_new()));

    vscr_ratchet_t *ratchet_alice = vscr_ratchet_new();
    vscr_ratchet_t *ratchet_bob = vscr_ratchet_new();

    vscr_ratchet_session_take_ratchet(session_alice, ratchet_alice);
    vscr_ratchet_session_take_ratchet(session_bob, ratchet_bob);

    vscr_ratchet_kdf_info_t *kdf_info = vscr_ratchet_kdf_info_new();
    kdf_info->root_info = vsc_buffer_new_with_capacity(test_ratchet_kdf_info_root.len);
    memcpy(vsc_buffer_ptr(kdf_info->root_info), test_ratchet_kdf_info_root.bytes, test_ratchet_kdf_info_root.len);
    vsc_buffer_reserve(kdf_info->root_info, test_ratchet_kdf_info_root.len);
    kdf_info->ratchet_info = vsc_buffer_new_with_capacity(test_ratchet_kdf_info_ratchet.len);
    memcpy(vsc_buffer_ptr(kdf_info->ratchet_info), test_ratchet_kdf_info_ratchet.bytes,
            test_ratchet_kdf_info_ratchet.len);
    vsc_buffer_reserve(kdf_info->ratchet_info, test_ratchet_kdf_info_ratchet.len);

    vscr_ratchet_cipher_t *ratchet_cipher = vscr_ratchet_cipher_new();
    ratchet_cipher->kdf_info = vsc_buffer_new_with_capacity(test_ratchet_kdf_info_cipher.len);
    memcpy(vsc_buffer_ptr(ratchet_cipher->kdf_info), test_ratchet_kdf_info_cipher.bytes,
            test_ratchet_kdf_info_cipher.len);
    vsc_buffer_reserve(ratchet_cipher->kdf_info, test_ratchet_kdf_info_cipher.len);
    vscr_ratchet_use_cipher(ratchet_alice, ratchet_cipher);
    vscr_ratchet_use_cipher(ratchet_bob, ratchet_cipher);
    vscr_ratchet_cipher_destroy(&ratchet_cipher);
    vscr_ratchet_use_kdf_info(ratchet_alice, kdf_info);
    vscr_ratchet_use_kdf_info(ratchet_bob, kdf_info);
    vscr_ratchet_kdf_info_destroy(&kdf_info);

    vscr_ratchet_take_rng(ratchet_alice, vscr_virgil_ratchet_fake_rng_impl(vscr_virgil_ratchet_fake_rng_new()));
    vscr_ratchet_take_rng(ratchet_bob, vscr_virgil_ratchet_fake_rng_impl(vscr_virgil_ratchet_fake_rng_new()));

    vsc_buffer_t *alice_identity_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    TEST_ASSERT_EQUAL_INT(0, curve25519_get_pubkey(vsc_buffer_ptr(alice_identity_public_key),
                                     test_ratchet_session_alice_identity_private_key.bytes));
    vsc_buffer_reserve(alice_identity_public_key, ED25519_KEY_LEN);

    vsc_buffer_t *bob_identity_private_key =
            vsc_buffer_new_with_capacity(test_ratchet_session_bob_identity_private_key.len);
    memcpy(vsc_buffer_ptr(bob_identity_private_key), test_ratchet_session_bob_identity_private_key.bytes,
            test_ratchet_session_bob_identity_private_key.len);
    vsc_buffer_reserve(bob_identity_private_key, ED25519_KEY_LEN);

    vsc_buffer_t *bob_identity_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    TEST_ASSERT_EQUAL_INT(0,
            curve25519_get_pubkey(vsc_buffer_ptr(bob_identity_public_key), vsc_buffer_bytes(bob_identity_private_key)));
    vsc_buffer_reserve(bob_identity_public_key, ED25519_KEY_LEN);

    vsc_buffer_t *bob_longterm_private_key =
            vsc_buffer_new_with_capacity(test_ratchet_session_bob_longterm_private_key.len);
    memcpy(vsc_buffer_ptr(bob_longterm_private_key), test_ratchet_session_bob_longterm_private_key.bytes,
            test_ratchet_session_bob_longterm_private_key.len);
    vsc_buffer_reserve(bob_longterm_private_key, ED25519_KEY_LEN);

    vsc_buffer_t *bob_longterm_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    TEST_ASSERT_EQUAL_INT(0,
            curve25519_get_pubkey(vsc_buffer_ptr(bob_longterm_public_key), vsc_buffer_bytes(bob_longterm_private_key)));
    vsc_buffer_reserve(bob_longterm_public_key, ED25519_KEY_LEN);

    vsc_buffer_t *bob_onetime_private_key =
            vsc_buffer_new_with_capacity(test_ratchet_session_bob_onetime_private_key.len);
    memcpy(vsc_buffer_ptr(bob_onetime_private_key), test_ratchet_session_bob_onetime_private_key.bytes,
            test_ratchet_session_bob_onetime_private_key.len);
    vsc_buffer_reserve(bob_onetime_private_key, ED25519_KEY_LEN);

    vsc_buffer_t *bob_onetime_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    TEST_ASSERT_EQUAL_INT(0,
            curve25519_get_pubkey(vsc_buffer_ptr(bob_onetime_public_key), vsc_buffer_bytes(bob_onetime_private_key)));
    vsc_buffer_reserve(bob_onetime_public_key, ED25519_KEY_LEN);

    TEST_ASSERT_EQUAL_INT(vscr_SUCCESS,
            vscr_ratchet_session_initiate(session_alice, test_ratchet_session_alice_identity_private_key,
                    vsc_buffer_data(bob_identity_public_key), bob_longterm_public_key, bob_onetime_public_key));

    TEST_ASSERT_EQUAL_INT(
            vscr_SUCCESS, vscr_ratchet_session_respond(session_bob, alice_identity_public_key,
                                  session_alice->sender_ephemeral_public_key,
                                  // FIXME
                                  session_alice->ratchet->sender_chain->public_key, bob_identity_private_key,
                                  bob_longterm_private_key, bob_onetime_private_key));

    vsc_buffer_destroy(&alice_identity_public_key);
    vsc_buffer_destroy(&bob_identity_private_key);
    vsc_buffer_destroy(&bob_identity_public_key);
    vsc_buffer_destroy(&bob_longterm_private_key);
    vsc_buffer_destroy(&bob_longterm_public_key);
    vsc_buffer_destroy(&bob_onetime_private_key);
    vsc_buffer_destroy(&bob_onetime_public_key);
}

void
test__1(void) {
    vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
    vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();

    initialize(session_alice, session_bob);

    size_t len1 = vscr_ratchet_session_encrypt_len(session_alice, test_ratchet_plain_text1.len);
    vsc_buffer_t *cipher_text = vsc_buffer_new_with_capacity(len1);

    vscr_error_t result = vscr_ratchet_session_encrypt(session_alice, test_ratchet_plain_text1, cipher_text);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, result);

    vscr_error_ctx_t error_ctx;
    vscr_error_ctx_reset(&error_ctx);

    vscr_ratchet_message_t *ratchet_message =
            vscr_ratchet_message_deserialize(vsc_buffer_data(cipher_text), &error_ctx);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, error_ctx.error);

    size_t len2 = vscr_ratchet_session_decrypt_len(session_bob, ratchet_message);
    vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(len2);

    result = vscr_ratchet_session_decrypt(session_bob, ratchet_message, plain_text);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, result);

    TEST_ASSERT_EQUAL_INT(test_ratchet_plain_text1.len, vsc_buffer_len(plain_text));
    TEST_ASSERT_EQUAL_MEMORY(
            test_ratchet_plain_text1.bytes, vsc_buffer_bytes(plain_text), test_ratchet_plain_text1.len);

    vsc_buffer_destroy(&cipher_text);
    vsc_buffer_destroy(&plain_text);

    vscr_ratchet_message_destroy(&ratchet_message);

    vscr_ratchet_session_destroy(&session_alice);
    vscr_ratchet_session_destroy(&session_bob);
}

void
test__2(void) {
    vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
    vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();

    initialize(session_alice, session_bob);

    size_t len1 = vscr_ratchet_session_encrypt_len(session_alice, test_ratchet_plain_text1.len);
    vsc_buffer_t *cipher_text1 = vsc_buffer_new_with_capacity(len1);

    vscr_error_t result = vscr_ratchet_session_encrypt(session_alice, test_ratchet_plain_text1, cipher_text1);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, result);

    vscr_error_ctx_t error_ctx;
    vscr_error_ctx_reset(&error_ctx);

    vscr_ratchet_message_t *ratchet_message1 =
            vscr_ratchet_message_deserialize(vsc_buffer_data(cipher_text1), &error_ctx);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, error_ctx.error);

    size_t len2 = vscr_ratchet_session_decrypt_len(session_bob, ratchet_message1);
    vsc_buffer_t *plain_text1 = vsc_buffer_new_with_capacity(len2);

    result = vscr_ratchet_session_decrypt(session_bob, ratchet_message1, plain_text1);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, result);

    TEST_ASSERT_EQUAL_INT(test_ratchet_plain_text1.len, vsc_buffer_len(plain_text1));
    TEST_ASSERT_EQUAL_MEMORY(
            test_ratchet_plain_text1.bytes, vsc_buffer_bytes(plain_text1), test_ratchet_plain_text1.len);

    size_t len3 = vscr_ratchet_session_encrypt_len(session_bob, test_ratchet_plain_text2.len);
    vsc_buffer_t *cipher_text2 = vsc_buffer_new_with_capacity(len3);

    result = vscr_ratchet_session_encrypt(session_bob, test_ratchet_plain_text2, cipher_text2);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, result);

    vscr_error_ctx_reset(&error_ctx);

    vscr_ratchet_message_t *ratchet_message2 =
            vscr_ratchet_message_deserialize(vsc_buffer_data(cipher_text2), &error_ctx);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, error_ctx.error);

    size_t len4 = vscr_ratchet_session_decrypt_len(session_alice, ratchet_message2);
    vsc_buffer_t *plain_text2 = vsc_buffer_new_with_capacity(len4);

    result = vscr_ratchet_session_decrypt(session_alice, ratchet_message2, plain_text2);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, result);

    TEST_ASSERT_EQUAL_INT(test_ratchet_plain_text2.len, vsc_buffer_len(plain_text2));
    TEST_ASSERT_EQUAL_MEMORY(
            test_ratchet_plain_text2.bytes, vsc_buffer_bytes(plain_text2), test_ratchet_plain_text2.len);

    vsc_buffer_destroy(&cipher_text1);
    vsc_buffer_destroy(&plain_text1);
    vsc_buffer_destroy(&cipher_text2);
    vsc_buffer_destroy(&plain_text2);

    vscr_ratchet_message_destroy(&ratchet_message1);
    vscr_ratchet_message_destroy(&ratchet_message2);

    vscr_ratchet_session_destroy(&session_alice);
    vscr_ratchet_session_destroy(&session_bob);
}

void
test__3(void) {
    vscr_ratchet_session_t *session_alice = vscr_ratchet_session_new();
    vscr_ratchet_session_t *session_bob = vscr_ratchet_session_new();

    initialize(session_alice, session_bob);

    // FIXME
    vscr_impl_t *rng = vscr_virgil_ratchet_fake_rng_impl(vscr_virgil_ratchet_fake_rng_new());

    for (int i = 0; i < 100; i++) {
        byte rnd_plain_text_len;
        vsc_buffer_t *fake_buffer1 = vsc_buffer_new();
        vsc_buffer_use(fake_buffer1, &rnd_plain_text_len, sizeof(rnd_plain_text_len));
        vscr_ratchet_rng_generate_random_data(rng, sizeof(rnd_plain_text_len), fake_buffer1);

        if (rnd_plain_text_len == 0)
            rnd_plain_text_len = 10;

        byte dice_rnd;
        vsc_buffer_t *fake_buffer2 = vsc_buffer_new();
        vsc_buffer_use(fake_buffer2, &dice_rnd, sizeof(dice_rnd));
        vscr_ratchet_rng_generate_random_data(rng, sizeof(dice_rnd), fake_buffer2);
        bool dice = dice_rnd % 2 == 0;

        if (i == 0)
            dice = true;

        vsc_buffer_destroy(&fake_buffer1);
        vsc_buffer_destroy(&fake_buffer2);

        vsc_buffer_t *plain_text = vsc_buffer_new_with_capacity(rnd_plain_text_len);
        vscr_ratchet_rng_generate_random_data(rng, vsc_buffer_capacity(plain_text), plain_text);

        vscr_ratchet_session_t *sender, *receiver;

        // Alice sends msg
        if (dice) {
            sender = session_alice;
            receiver = session_bob;
        } else {
            sender = session_bob;
            receiver = session_alice;
        }

        size_t cipher_text_len = vscr_ratchet_session_encrypt_len(sender, vsc_buffer_len(plain_text));
        vsc_buffer_t *cipher_text = vsc_buffer_new_with_capacity(cipher_text_len);

        vscr_error_t result = vscr_ratchet_session_encrypt(sender, vsc_buffer_data(plain_text), cipher_text);
        TEST_ASSERT_EQUAL(vscr_SUCCESS, result);

        vscr_error_ctx_t error_ctx;
        vscr_error_ctx_reset(&error_ctx);

        vscr_ratchet_message_t *ratchet_message =
                vscr_ratchet_message_deserialize(vsc_buffer_data(cipher_text), &error_ctx);
        TEST_ASSERT_EQUAL(vscr_SUCCESS, error_ctx.error);

        size_t plain_text_len = vscr_ratchet_session_decrypt_len(receiver, ratchet_message);
        vsc_buffer_t *decrypted = vsc_buffer_new_with_capacity(plain_text_len);
        result = vscr_ratchet_session_decrypt(receiver, ratchet_message, decrypted);
        TEST_ASSERT_EQUAL(vscr_SUCCESS, result);

        TEST_ASSERT_EQUAL_INT(vsc_buffer_len(plain_text), vsc_buffer_len(decrypted));
        TEST_ASSERT_EQUAL_MEMORY(vsc_buffer_bytes(plain_text), vsc_buffer_bytes(decrypted), vsc_buffer_len(plain_text));

        vsc_buffer_destroy(&plain_text);
        vsc_buffer_destroy(&cipher_text);
        vsc_buffer_destroy(&decrypted);
        vscr_ratchet_message_destroy(&ratchet_message);
    }

    vscr_impl_destroy(&rng);

    vscr_ratchet_session_destroy(&session_alice);
    vscr_ratchet_session_destroy(&session_bob);
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
    RUN_TEST(test__2);
    RUN_TEST(test__3);
#else
    RUN_TEST(test__nothing__feature_disabled__must_be_ignored);
#endif

    return UNITY_END();
}
