//  @license
// --------------------------------------------------------------------------
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
// --------------------------------------------------------------------------
// clang-format off


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_message_cipher.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_sha512.h"
#include "vscf_hkdf.h"
#include "vscf_aes256_gcm.h"

#include <virgil/crypto/common/private/vsc_buffer_defs.h>

// clang-format on
//  @end


// clang-format off

// VIRGIL_GROUP_SESSION_KDF_CIPHER_INFO
static const byte group_session_kdf_cipher_info[] = {
        0x56, 0x49, 0x52, 0x47, 0x49, 0x4c, 0x5f, 0x47,
        0x52, 0x4f, 0x55, 0x50, 0x5f, 0x53, 0x45, 0x53,
        0x53, 0x49, 0x4f, 0x4e, 0x5f, 0x4b, 0x44, 0x46,
        0x5f, 0x43, 0x49, 0x50, 0x48, 0x45, 0x52, 0x5f,
        0x49, 0x4e, 0x46, 0x4f, 0x00
};

// clang-format on


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Configure given symmetric cipher.
//
static void
vscf_message_cipher_configure_cipher(vscf_aes256_gcm_t *cipher, const vscf_group_session_symmetric_key_t key,
        const vscf_group_session_salt_t salt);

static vscf_status_t
vscf_message_cipher_encrypt(const vscf_group_session_symmetric_key_t key, const vscf_group_session_salt_t salt,
        vsc_data_t plain_text, vsc_data_t additional_data, vsc_buffer_t *buffer) VSCF_NODISCARD;

static vscf_status_t
vscf_message_cipher_decrypt(const vscf_group_session_symmetric_key_t key, const vscf_group_session_salt_t salt,
        vsc_data_t cipher_text, vsc_data_t additional_data, vsc_buffer_t *buffer) VSCF_NODISCARD;


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


VSCF_PUBLIC size_t
vscf_message_cipher_encrypt_len(size_t plain_text_len) {

    //
    //  In-lined vscf_aes256_gcm_encrypted_len()
    //
    return plain_text_len + vscf_aes256_gcm_BLOCK_LEN + vscf_aes256_gcm_AUTH_TAG_LEN;
}

VSCF_PUBLIC size_t
vscf_message_cipher_decrypt_len(size_t cipher_text_len) {

    //
    //  In-lined vscf_aes256_gcm_auth_decrypted_len()
    //
    return cipher_text_len + vscf_aes256_gcm_BLOCK_LEN;
}

//
//  Configure given symmetric cipher.
//
static void
vscf_message_cipher_configure_cipher(
        vscf_aes256_gcm_t *cipher, const vscf_group_session_symmetric_key_t key, const vscf_group_session_salt_t salt) {

    VSCF_ASSERT_PTR(cipher);

    vscf_hkdf_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    byte derived_secret[vscf_aes256_gcm_KEY_LEN + vscf_aes256_gcm_NONCE_LEN];

    vsc_buffer_t buffer;
    vsc_buffer_init(&buffer);
    vsc_buffer_use(&buffer, derived_secret, sizeof(derived_secret));

    vscf_hkdf_set_info(hkdf, vsc_data(group_session_kdf_cipher_info, sizeof(group_session_kdf_cipher_info)));
    vscf_hkdf_reset(hkdf, vsc_data(salt, sizeof(vscf_group_session_salt_t)), 0);
    vscf_hkdf_derive(hkdf, vsc_data(key, sizeof(vscf_group_session_symmetric_key_t)), sizeof(derived_secret), &buffer);

    vscf_hkdf_destroy(&hkdf);

    vscf_aes256_gcm_set_key(cipher, vsc_data(derived_secret, vscf_aes256_gcm_KEY_LEN));
    vscf_aes256_gcm_set_nonce(cipher, vsc_data(derived_secret + vscf_aes256_gcm_KEY_LEN, vscf_aes256_gcm_NONCE_LEN));

    vsc_buffer_delete(&buffer);
    vscf_zeroize(derived_secret, sizeof(derived_secret));
}

static vscf_status_t
vscf_message_cipher_encrypt(const vscf_group_session_symmetric_key_t key, const vscf_group_session_salt_t salt,
        vsc_data_t plain_text, vsc_data_t additional_data, vsc_buffer_t *buffer) {

    VSCF_ASSERT(vsc_buffer_unused_len(buffer) >= vscf_message_cipher_encrypt_len(plain_text.len));

    vscf_aes256_gcm_t *cipher = vscf_aes256_gcm_new();

    vscf_message_cipher_configure_cipher(cipher, salt, key);

    vscf_status_t result = vscf_aes256_gcm_auth_encrypt(cipher, plain_text, additional_data, buffer, NULL);

    vscf_aes256_gcm_destroy(&cipher);

    return result;
}

static vscf_status_t
vscf_message_cipher_decrypt(const vscf_group_session_symmetric_key_t key, const vscf_group_session_salt_t salt,
        vsc_data_t cipher_text, vsc_data_t additional_data, vsc_buffer_t *buffer) {

    VSCF_ASSERT(vsc_buffer_unused_len(buffer) >= vscf_message_cipher_decrypt_len(cipher_text.len));

    vscf_aes256_gcm_t *cipher = vscf_aes256_gcm_new();

    vscf_message_cipher_configure_cipher(cipher, salt, key);

    vscf_status_t result = vscf_aes256_gcm_auth_decrypt(cipher, cipher_text, additional_data, vsc_data_empty(), buffer);

    vscf_aes256_gcm_destroy(&cipher);

    return result;
}

VSCF_PUBLIC vscf_status_t
vscf_message_cipher_pad_then_encrypt(vscf_message_padding_t *padding, vsc_data_t data,
        const vscf_group_session_symmetric_key_t key, const vscf_group_session_salt_t salt, vsc_data_t ad,
        vsc_buffer_t *cipher_text) {

    VSCF_ASSERT_PTR(padding);
    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT_PTR(cipher_text);

    size_t size = vscf_message_padding_padded_len(data.len);
    vsc_buffer_t *temp = vsc_buffer_new_with_capacity(size);
    vsc_buffer_make_secure(temp);

    vsc_buffer_write_data(temp, data);

    vscf_status_t result = vscf_message_padding_add_padding(padding, temp);

    if (result != vscf_status_SUCCESS) {
        goto err;
    }

    result = vscf_message_cipher_encrypt(salt, key, vsc_buffer_data(temp), ad, cipher_text);

err:
    vsc_buffer_destroy(&temp);

    return result;
}

VSCF_PUBLIC vscf_status_t
vscf_message_cipher_decrypt_then_remove_pad(vsc_data_t data, const vscf_group_session_symmetric_key_t key,
        const vscf_group_session_salt_t salt, vsc_data_t ad, vsc_buffer_t *plain_text) {

    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT_PTR(plain_text);

    size_t size = vscf_message_cipher_decrypt_len(data.len);
    vsc_buffer_t *temp = vsc_buffer_new_with_capacity(size);
    vsc_buffer_make_secure(temp);

    vscf_status_t result = vscf_message_cipher_decrypt(salt, key, data, ad, temp);

    if (result != vscf_status_SUCCESS) {
        goto err;
    }

    result = vscf_message_padding_remove_padding(vsc_buffer_data(temp), plain_text);

err:
    vsc_buffer_destroy(&temp);

    return result;
}
