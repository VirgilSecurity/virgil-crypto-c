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

#include "vscr_ratchet_cipher.h"
#include "vscr_memory.h"
#include "vscr_assert.h"
#include "vscr_ratchet_cipher_defs.h"

#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_hkdf.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

// clang-format on
//  @end


// clang-format off

// VIRGIL_RATCHET_KDF_CIPHER_INFO
static const byte ratchet_kdf_cipher_info[] = {
        0x56, 0x49, 0x52, 0x47, 0x49, 0x4c, 0x5f, 0x52,
        0x41, 0x54, 0x43, 0x48, 0x45, 0x54, 0x5f, 0x4b,
        0x44, 0x46, 0x5f, 0x43, 0x49, 0x50, 0x48, 0x45,
        0x52, 0x5f, 0x49, 0x4e, 0x46, 0x4f, 0x00,
};

// clang-format on


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_cipher_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_cipher_init_ctx(vscr_ratchet_cipher_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_cipher_cleanup_ctx(vscr_ratchet_cipher_t *self);

static void
vscr_ratchet_cipher_setup_cipher(vscr_ratchet_cipher_t *self, const vscr_ratchet_symmetric_key_t key);

//
//  Return size of 'vscr_ratchet_cipher_t'.
//
VSCR_PUBLIC size_t
vscr_ratchet_cipher_ctx_size(void) {

    return sizeof(vscr_ratchet_cipher_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_init(vscr_ratchet_cipher_t *self) {

    VSCR_ASSERT_PTR(self);

    vscr_zeroize(self, sizeof(vscr_ratchet_cipher_t));

    self->refcnt = 1;

    vscr_ratchet_cipher_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_cleanup(vscr_ratchet_cipher_t *self) {

    if (self == NULL) {
        return;
    }

    if (self->refcnt == 0) {
        return;
    }

    if (--self->refcnt == 0) {
        vscr_ratchet_cipher_cleanup_ctx(self);

        vscr_zeroize(self, sizeof(vscr_ratchet_cipher_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_cipher_t *
vscr_ratchet_cipher_new(void) {

    vscr_ratchet_cipher_t *self = (vscr_ratchet_cipher_t *) vscr_alloc(sizeof (vscr_ratchet_cipher_t));
    VSCR_ASSERT_ALLOC(self);

    vscr_ratchet_cipher_init(self);

    self->self_dealloc_cb = vscr_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_delete(vscr_ratchet_cipher_t *self) {

    if (self == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vscr_ratchet_cipher_cleanup(self);

    if (self->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_cipher_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_destroy(vscr_ratchet_cipher_t **self_ref) {

    VSCR_ASSERT_PTR(self_ref);

    vscr_ratchet_cipher_t *self = *self_ref;
    *self_ref = NULL;

    vscr_ratchet_cipher_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_cipher_t *
vscr_ratchet_cipher_shallow_copy(vscr_ratchet_cipher_t *self) {

    VSCR_ASSERT_PTR(self);

    ++self->refcnt;

    return self;
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscr_ratchet_cipher_init() is called.
//  Note, that context is already zeroed.
//
static void
vscr_ratchet_cipher_init_ctx(vscr_ratchet_cipher_t *self) {

    VSCR_ASSERT_PTR(self);

    self->aes256_gcm = vscf_aes256_gcm_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_cipher_cleanup_ctx(vscr_ratchet_cipher_t *self) {

    VSCR_ASSERT_PTR(self);

    vscf_aes256_gcm_destroy(&self->aes256_gcm);
}

VSCR_PUBLIC size_t
vscr_ratchet_cipher_encrypt_len(vscr_ratchet_cipher_t *self, size_t plain_text_len) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->aes256_gcm);

    return vscf_aes256_gcm_encrypted_len(self->aes256_gcm, plain_text_len);
}

VSCR_PUBLIC size_t
vscr_ratchet_cipher_decrypt_len(vscr_ratchet_cipher_t *self, size_t cipher_text_len) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->aes256_gcm);

    return vscf_aes256_gcm_auth_decrypted_len(self->aes256_gcm, cipher_text_len);
}

static void
vscr_ratchet_cipher_setup_cipher(vscr_ratchet_cipher_t *self, const vscr_ratchet_symmetric_key_t key) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->aes256_gcm);

    vscf_hkdf_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    byte derived_secret[vscf_aes256_gcm_KEY_LEN + vscf_aes256_gcm_NONCE_LEN];

    vsc_buffer_t buffer;
    vsc_buffer_init(&buffer);
    vsc_buffer_use(&buffer, derived_secret, sizeof(derived_secret));

    vscf_hkdf_set_info(hkdf, vsc_data(ratchet_kdf_cipher_info, sizeof(ratchet_kdf_cipher_info)));
    vscf_hkdf_derive(hkdf, vsc_data(key, sizeof(vscr_ratchet_symmetric_key_t)), sizeof(derived_secret), &buffer);

    vscf_hkdf_destroy(&hkdf);

    vscf_aes256_gcm_set_key(self->aes256_gcm, vsc_data(derived_secret, vscf_aes256_gcm_KEY_LEN));
    vscf_aes256_gcm_set_nonce(
            self->aes256_gcm, vsc_data(derived_secret + vscf_aes256_gcm_KEY_LEN, vscf_aes256_gcm_NONCE_LEN));

    vsc_buffer_delete(&buffer);
    vscr_zeroize(derived_secret, sizeof(derived_secret));
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_cipher_encrypt(vscr_ratchet_cipher_t *self, const vscr_ratchet_symmetric_key_t key, vsc_data_t plain_text,
        vsc_data_t additional_data, vsc_buffer_t *buffer) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->aes256_gcm);

    VSCR_ASSERT(vsc_buffer_unused_len(buffer) >= vscr_ratchet_cipher_encrypt_len(self, plain_text.len));

    vscr_ratchet_cipher_setup_cipher(self, key);

    vscf_status_t result = vscf_aes256_gcm_auth_encrypt(self->aes256_gcm, plain_text, additional_data, buffer, NULL);

    if (result != vscf_status_SUCCESS) {
        return vscr_status_ERROR_AES;
    }

    return vscr_status_SUCCESS;
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_cipher_decrypt(vscr_ratchet_cipher_t *self, const vscr_ratchet_symmetric_key_t key, vsc_data_t cipher_text,
        vsc_data_t additional_data, vsc_buffer_t *buffer) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->aes256_gcm);

    VSCR_ASSERT(vsc_buffer_unused_len(buffer) >= vscr_ratchet_cipher_decrypt_len(self, cipher_text.len));

    vscr_ratchet_cipher_setup_cipher(self, key);

    vscf_status_t f_result =
            vscf_aes256_gcm_auth_decrypt(self->aes256_gcm, cipher_text, additional_data, vsc_data_empty(), buffer);

    if (f_result != vscf_status_SUCCESS) {
        return vscr_status_ERROR_AES;
    }

    return vscr_status_SUCCESS;
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_cipher_pad_then_encrypt(vscr_ratchet_cipher_t *self, vscr_ratchet_padding_t *padding, vsc_data_t data,
        const vscr_ratchet_message_key_t *key, vsc_data_t ad, vsc_buffer_t *cipher_text) {

    VSCR_ASSERT_PTR(self);
        VSCR_ASSERT_PTR(padding);
        VSCR_ASSERT_PTR(key);
        VSCR_ASSERT_PTR(cipher_text);

        size_t size = vscr_ratchet_padding_padded_len(data.len);
        vsc_buffer_t *temp = vsc_buffer_new_with_capacity(size);
        vsc_buffer_make_secure(temp);

        vsc_buffer_write_data(temp, data);

        vscr_status_t result = vscr_ratchet_padding_add_padding(padding, temp);

        if (result != vscr_status_SUCCESS) {
            goto err;
        }

        result = vscr_ratchet_cipher_encrypt(self, key->key, vsc_buffer_data(temp), ad, cipher_text);

    err:
        vsc_buffer_destroy(&temp);

        return result;
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_cipher_decrypt_then_remove_pad(vscr_ratchet_cipher_t *self, vsc_data_t data,
        const vscr_ratchet_message_key_t *key, vsc_data_t ad, vsc_buffer_t *plain_text) {

    VSCR_ASSERT_PTR(self);
        VSCR_ASSERT_PTR(key);
        VSCR_ASSERT_PTR(plain_text);

        size_t size = vscr_ratchet_cipher_decrypt_len(self, data.len);
        vsc_buffer_t *temp = vsc_buffer_new_with_capacity(size);
        vsc_buffer_make_secure(temp);

        vscr_status_t result = vscr_ratchet_cipher_decrypt(self, key->key, data, ad, temp);

        if (result != vscr_status_SUCCESS) {
            goto err;
        }

        result = vscr_ratchet_padding_remove_padding(vsc_buffer_data(temp), plain_text);

    err:
        vsc_buffer_destroy(&temp);

        return result;
}
