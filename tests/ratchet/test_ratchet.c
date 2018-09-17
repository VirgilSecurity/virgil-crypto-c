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

#include <virgil/common/private/vsc_buffer_defs.h>
#include <ed25519/ed25519.h>
#include "unity.h"
#include "test_utils.h"

#define TEST_DEPENDENCIES_AVAILABLE VSCR_RATCHET
#if TEST_DEPENDENCIES_AVAILABLE

#include "vscr_ratchet.h"
#include "test_data_ratchet.h"

static void initialize(vscr_ratchet_t *ratchet_alice, vscr_ratchet_t *ratchet_bob) {
    vscr_olm_kdf_info_t *kdf_info = vscr_olm_kdf_info_new();
    kdf_info->root_info = vsc_buffer_new_with_capacity(test_ratchet_kdf_info_root.len);
    memcpy(vsc_buffer_ptr(kdf_info->root_info), test_ratchet_kdf_info_root.bytes, test_ratchet_kdf_info_root.len);
    vsc_buffer_reserve(kdf_info->root_info, test_ratchet_kdf_info_root.len);
    kdf_info->ratchet_info = vsc_buffer_new_with_capacity(test_ratchet_kdf_info_ratchet.len);
    memcpy(vsc_buffer_ptr(kdf_info->ratchet_info), test_ratchet_kdf_info_ratchet.bytes, test_ratchet_kdf_info_ratchet.len);
    vsc_buffer_reserve(kdf_info->ratchet_info, test_ratchet_kdf_info_ratchet.len);

    ratchet_alice->kdf_info = vscr_olm_kdf_info_copy(kdf_info);
    ratchet_bob->kdf_info = vscr_olm_kdf_info_copy(kdf_info);
    vscr_olm_kdf_info_destroy(&kdf_info);
}

void
test__1(void) {
    vscr_ratchet_t *ratchet_alice = vscr_ratchet_new();
    vscr_ratchet_t *ratchet_bob = vscr_ratchet_new();

    initialize(ratchet_alice, ratchet_bob);

    byte plain_text_str[5] = "test";
    vsc_data_t plain_text = vsc_data(plain_text_str, 4);

    vsc_buffer_t *ratchet_private_key = vsc_buffer_new_with_capacity(test_ratchet_ratchet_private_key.len);
    memcpy(vsc_buffer_ptr(ratchet_private_key), test_ratchet_ratchet_private_key.bytes, test_ratchet_ratchet_private_key.len);
    vsc_buffer_reserve(ratchet_private_key, test_ratchet_ratchet_private_key.len);

    vsc_buffer_t *ratchet_public_key = vsc_buffer_new_with_capacity(ED25519_KEY_LEN);
    curve25519_get_pubkey(vsc_buffer_ptr(ratchet_public_key), test_ratchet_ratchet_private_key.bytes);
    vsc_buffer_reserve(ratchet_public_key, test_ratchet_ratchet_private_key.len);

    size_t cipher_text_len = vscr_ratchet_encrypt_len(ratchet_alice, plain_text);
    vsc_buffer_t *cipher_text = vsc_buffer_new_with_capacity(cipher_text_len);

    vscr_ratchet_initiate(ratchet_alice, test_ratchet_shared_secret, ratchet_private_key);
    vscr_error_t result = vscr_ratchet_encrypt(ratchet_alice, plain_text, cipher_text);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, result);

    vscr_ratchet_respond(ratchet_bob, test_ratchet_shared_secret, ratchet_public_key);
    size_t plain_text_len = vscr_ratchet_decrypt_len(ratchet_bob, vsc_buffer_data(cipher_text));
    vsc_buffer_t *decrypted = vsc_buffer_new_with_capacity(plain_text_len);
    result = vscr_ratchet_decrypt(ratchet_bob, vsc_buffer_data(cipher_text), decrypted);
    TEST_ASSERT_EQUAL(vscr_SUCCESS, result);

    TEST_ASSERT_EQUAL_INT(plain_text.len, vsc_buffer_len(decrypted));
    TEST_ASSERT_EQUAL_MEMORY(plain_text.bytes, vsc_buffer_bytes(decrypted), plain_text.len);

    vscr_ratchet_destroy(&ratchet_alice);
    vscr_ratchet_destroy(&ratchet_bob);
    vsc_buffer_destroy(&cipher_text);
    vsc_buffer_destroy(&ratchet_private_key);
    vsc_buffer_destroy(&ratchet_public_key);
    vsc_buffer_destroy(&decrypted);
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
