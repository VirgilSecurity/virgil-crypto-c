//  @license
// --------------------------------------------------------------------------
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
#include "vscf_message_cipher_defs.h"
#include "vscf_sha512.h"
#include "vscf_hkdf.h"

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
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_message_cipher_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_message_cipher_init_ctx(vscf_message_cipher_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_message_cipher_cleanup_ctx(vscf_message_cipher_t *self);

static void
vscf_message_cipher_setup_cipher(vscf_message_cipher_t *self, const vscf_group_session_symmetric_key_t key);

static vscf_status_t
vscf_message_cipher_encrypt(vscf_message_cipher_t *self, const vscf_group_session_symmetric_key_t key,
        vsc_data_t plain_text, vsc_data_t additional_data, vsc_buffer_t *buffer) VSCF_NODISCARD;

static vscf_status_t
vscf_message_cipher_decrypt(vscf_message_cipher_t *self, const vscf_group_session_symmetric_key_t key,
        vsc_data_t cipher_text, vsc_data_t additional_data, vsc_buffer_t *buffer) VSCF_NODISCARD;

//
//  Return size of 'vscf_message_cipher_t'.
//
VSCF_PUBLIC size_t
vscf_message_cipher_ctx_size(void) {

    return sizeof(vscf_message_cipher_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_message_cipher_init(vscf_message_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_message_cipher_t));

    self->refcnt = 1;

    vscf_message_cipher_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_message_cipher_cleanup(vscf_message_cipher_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_message_cipher_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_message_cipher_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_message_cipher_t *
vscf_message_cipher_new(void) {

    vscf_message_cipher_t *self = (vscf_message_cipher_t *) vscf_alloc(sizeof (vscf_message_cipher_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_message_cipher_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_message_cipher_delete(vscf_message_cipher_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCF_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCF_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscf_message_cipher_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_message_cipher_new ()'.
//
VSCF_PUBLIC void
vscf_message_cipher_destroy(vscf_message_cipher_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_message_cipher_t *self = *self_ref;
    *self_ref = NULL;

    vscf_message_cipher_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_message_cipher_t *
vscf_message_cipher_shallow_copy(vscf_message_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_message_cipher_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_message_cipher_init_ctx(vscf_message_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    self->aes256_gcm = vscf_aes256_gcm_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_message_cipher_cleanup_ctx(vscf_message_cipher_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_aes256_gcm_destroy(&self->aes256_gcm);
}

VSCF_PUBLIC size_t
vscf_message_cipher_encrypt_len(vscf_message_cipher_t *self, size_t plain_text_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->aes256_gcm);

    return vscf_aes256_gcm_encrypted_len(self->aes256_gcm, plain_text_len);
}

VSCF_PUBLIC size_t
vscf_message_cipher_decrypt_len(vscf_message_cipher_t *self, size_t cipher_text_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->aes256_gcm);

    return vscf_aes256_gcm_auth_decrypted_len(self->aes256_gcm, cipher_text_len);
}

static void
vscf_message_cipher_setup_cipher(vscf_message_cipher_t *self, const vscf_group_session_symmetric_key_t key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->aes256_gcm);

    vscf_hkdf_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    byte derived_secret[vscf_aes256_gcm_KEY_LEN + vscf_aes256_gcm_NONCE_LEN];

    vsc_buffer_t buffer;
    vsc_buffer_init(&buffer);
    vsc_buffer_use(&buffer, derived_secret, sizeof(derived_secret));

    vscf_hkdf_set_info(hkdf, vsc_data(group_session_kdf_cipher_info, sizeof(group_session_kdf_cipher_info)));
    vscf_hkdf_derive(hkdf, vsc_data(key, sizeof(vscf_group_session_symmetric_key_t)), sizeof(derived_secret), &buffer);

    vscf_hkdf_destroy(&hkdf);

    vscf_aes256_gcm_set_key(self->aes256_gcm, vsc_data(derived_secret, vscf_aes256_gcm_KEY_LEN));
    vscf_aes256_gcm_set_nonce(
            self->aes256_gcm, vsc_data(derived_secret + vscf_aes256_gcm_KEY_LEN, vscf_aes256_gcm_NONCE_LEN));

    vsc_buffer_delete(&buffer);
    vscf_zeroize(derived_secret, sizeof(derived_secret));
}

static vscf_status_t
vscf_message_cipher_encrypt(vscf_message_cipher_t *self, const vscf_group_session_symmetric_key_t key,
        vsc_data_t plain_text, vsc_data_t additional_data, vsc_buffer_t *buffer) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->aes256_gcm);

    VSCF_ASSERT(vsc_buffer_unused_len(buffer) >= vscf_message_cipher_encrypt_len(self, plain_text.len));

    vscf_message_cipher_setup_cipher(self, key);

    vscf_status_t result = vscf_aes256_gcm_auth_encrypt(self->aes256_gcm, plain_text, additional_data, buffer, NULL);

    if (result != vscf_status_SUCCESS) {
        //        return vscr_status_ERROR_AES;
        // FIXME
        return vscf_status_ERROR_BRAINKEY_INTERNAL;
    }

    return vscf_status_SUCCESS;
}

static vscf_status_t
vscf_message_cipher_decrypt(vscf_message_cipher_t *self, const vscf_group_session_symmetric_key_t key,
        vsc_data_t cipher_text, vsc_data_t additional_data, vsc_buffer_t *buffer) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->aes256_gcm);

    VSCF_ASSERT(vsc_buffer_unused_len(buffer) >= vscf_message_cipher_decrypt_len(self, cipher_text.len));

    vscf_message_cipher_setup_cipher(self, key);

    vscf_status_t f_result =
            vscf_aes256_gcm_auth_decrypt(self->aes256_gcm, cipher_text, additional_data, vsc_data_empty(), buffer);

    if (f_result != vscf_status_SUCCESS) {
        //        return vscr_status_ERROR_AES;
        // FIXME
        return vscf_status_ERROR_BRAINKEY_INTERNAL;
    }

    return vscf_status_SUCCESS;
}

VSCF_PUBLIC vscf_status_t
vscf_message_cipher_pad_then_encrypt(vscf_message_cipher_t *self, vscf_message_padding_t *padding, vsc_data_t data,
        const vscf_group_session_symmetric_key_t key, vsc_data_t ad, vsc_buffer_t *cipher_text) {

    VSCF_ASSERT_PTR(self);
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

    result = vscf_message_cipher_encrypt(self, key, vsc_buffer_data(temp), ad, cipher_text);

err:
    vsc_buffer_destroy(&temp);

    return result;
}

VSCF_PUBLIC vscf_status_t
vscf_message_cipher_decrypt_then_remove_pad(vscf_message_cipher_t *self, vsc_data_t data,
        const vscf_group_session_symmetric_key_t key, vsc_data_t ad, vsc_buffer_t *plain_text) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(key);
    VSCF_ASSERT_PTR(plain_text);

    size_t size = vscf_message_cipher_decrypt_len(self, data.len);
    vsc_buffer_t *temp = vsc_buffer_new_with_capacity(size);
    vsc_buffer_make_secure(temp);

    vscf_status_t result = vscf_message_cipher_decrypt(self, key, data, ad, temp);

    if (result != vscf_status_SUCCESS) {
        goto err;
    }

    result = vscf_message_padding_remove_padding(vsc_buffer_data(temp), plain_text);

err:
    vsc_buffer_destroy(&temp);

    return result;
}
