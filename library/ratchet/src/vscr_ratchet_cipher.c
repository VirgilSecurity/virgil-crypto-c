//  @license
// --------------------------------------------------------------------------
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

#include <virgil/crypto/foundation/vscf_sha256.h>
#include <virgil/crypto/foundation/vscf_hkdf.h>

// clang-format on
//  @end


static const uint8_t ratchet_kdf_cipher_info[] = {"VIRGIL_RATCHET_KDF_CIPHER_INFO"};

static void
vscr_ratchet_cipher_setup_cipher(vscr_ratchet_cipher_t *ratchet_cipher, vsc_data_t key) {

    VSCR_ASSERT_PTR(ratchet_cipher);
    VSCR_ASSERT_PTR(ratchet_cipher->aes256_gcm);

    vscf_hkdf_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_take_hash(hkdf, vscf_sha256_impl(vscf_sha256_new()));

    vsc_buffer_t *derived_secret = vsc_buffer_new_with_capacity(vscf_aes256_gcm_KEY_LEN + vscf_aes256_gcm_NONCE_LEN);
    vsc_buffer_make_secure(derived_secret);
    vscf_hkdf_derive(hkdf, key, vsc_data_empty(), vsc_data(ratchet_kdf_cipher_info, sizeof(ratchet_kdf_cipher_info)),
            derived_secret, vsc_buffer_capacity(derived_secret));

    vscf_hkdf_destroy(&hkdf);

    vscf_aes256_gcm_set_key(ratchet_cipher->aes256_gcm,
            vsc_data_slice_beg(vsc_buffer_data(derived_secret), 0, vscf_aes256_gcm_KEY_LEN));
    vscf_aes256_gcm_set_nonce(ratchet_cipher->aes256_gcm,
            vsc_data_slice_beg(vsc_buffer_data(derived_secret), vscf_aes256_gcm_KEY_LEN, vscf_aes256_gcm_NONCE_LEN));

    vsc_buffer_destroy(&derived_secret);
}


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
vscr_ratchet_cipher_init_ctx(vscr_ratchet_cipher_t *ratchet_cipher);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_cipher_cleanup_ctx(vscr_ratchet_cipher_t *ratchet_cipher);

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
vscr_ratchet_cipher_init(vscr_ratchet_cipher_t *ratchet_cipher) {

    VSCR_ASSERT_PTR(ratchet_cipher);

    vscr_zeroize(ratchet_cipher, sizeof(vscr_ratchet_cipher_t));

    ratchet_cipher->refcnt = 1;

    vscr_ratchet_cipher_init_ctx(ratchet_cipher);
}

//
//  Release all inner resources including class dependencies.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_cleanup(vscr_ratchet_cipher_t *ratchet_cipher) {

    if (ratchet_cipher == NULL) {
        return;
    }

    if (ratchet_cipher->refcnt == 0) {
        return;
    }

    if (--ratchet_cipher->refcnt == 0) {
        vscr_ratchet_cipher_cleanup_ctx(ratchet_cipher);

        vscr_ratchet_cipher_release_aes256_gcm(ratchet_cipher);

        vscr_zeroize(ratchet_cipher, sizeof(vscr_ratchet_cipher_t));
    }
}

//
//  Allocate context and perform it's initialization.
//
VSCR_PUBLIC vscr_ratchet_cipher_t *
vscr_ratchet_cipher_new(void) {

    vscr_ratchet_cipher_t *ratchet_cipher = (vscr_ratchet_cipher_t *) vscr_alloc(sizeof (vscr_ratchet_cipher_t));
    VSCR_ASSERT_ALLOC(ratchet_cipher);

    vscr_ratchet_cipher_init(ratchet_cipher);

    ratchet_cipher->self_dealloc_cb = vscr_dealloc;

    return ratchet_cipher;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if context was allocated by the caller.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_delete(vscr_ratchet_cipher_t *ratchet_cipher) {

    if (ratchet_cipher == NULL) {
        return;
    }

    vscr_dealloc_fn self_dealloc_cb = ratchet_cipher->self_dealloc_cb;

    vscr_ratchet_cipher_cleanup(ratchet_cipher);

    if (ratchet_cipher->refcnt == 0 && self_dealloc_cb != NULL) {
        self_dealloc_cb(ratchet_cipher);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscr_ratchet_cipher_new ()'.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_destroy(vscr_ratchet_cipher_t **ratchet_cipher_ref) {

    VSCR_ASSERT_PTR(ratchet_cipher_ref);

    vscr_ratchet_cipher_t *ratchet_cipher = *ratchet_cipher_ref;
    *ratchet_cipher_ref = NULL;

    vscr_ratchet_cipher_delete(ratchet_cipher);
}

//
//  Copy given class context by increasing reference counter.
//
VSCR_PUBLIC vscr_ratchet_cipher_t *
vscr_ratchet_cipher_shallow_copy(vscr_ratchet_cipher_t *ratchet_cipher) {

    VSCR_ASSERT_PTR(ratchet_cipher);

    ++ratchet_cipher->refcnt;

    return ratchet_cipher;
}

//
//  Setup dependency to the implementation 'aes256 gcm' with shared ownership.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_use_aes256_gcm(vscr_ratchet_cipher_t *ratchet_cipher, vscf_aes256_gcm_t *aes256_gcm) {

    VSCR_ASSERT_PTR(ratchet_cipher);
    VSCR_ASSERT_PTR(aes256_gcm);
    VSCR_ASSERT_PTR(ratchet_cipher->aes256_gcm == NULL);

    ratchet_cipher->aes256_gcm = vscf_aes256_gcm_shallow_copy(aes256_gcm);
}

//
//  Setup dependency to the implementation 'aes256 gcm' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_take_aes256_gcm(vscr_ratchet_cipher_t *ratchet_cipher, vscf_aes256_gcm_t *aes256_gcm) {

    VSCR_ASSERT_PTR(ratchet_cipher);
    VSCR_ASSERT_PTR(aes256_gcm);
    VSCR_ASSERT_PTR(ratchet_cipher->aes256_gcm == NULL);

    ratchet_cipher->aes256_gcm = aes256_gcm;
}

//
//  Release dependency to the implementation 'aes256 gcm'.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_release_aes256_gcm(vscr_ratchet_cipher_t *ratchet_cipher) {

    VSCR_ASSERT_PTR(ratchet_cipher);

    vscf_aes256_gcm_destroy(&ratchet_cipher->aes256_gcm);
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
vscr_ratchet_cipher_init_ctx(vscr_ratchet_cipher_t *ratchet_cipher) {

    VSCR_ASSERT_PTR(ratchet_cipher);

    vscr_ratchet_cipher_take_aes256_gcm(ratchet_cipher, vscf_aes256_gcm_new());
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscr_ratchet_cipher_cleanup_ctx(vscr_ratchet_cipher_t *ratchet_cipher) {

    VSCR_ASSERT_PTR(ratchet_cipher);
}

VSCR_PUBLIC size_t
vscr_ratchet_cipher_encrypt_len(vscr_ratchet_cipher_t *ratchet_cipher, size_t plain_text_len) {

    return vscf_aes256_gcm_encrypted_len(ratchet_cipher->aes256_gcm, plain_text_len);
}

VSCR_PUBLIC size_t
vscr_ratchet_cipher_decrypt_len(vscr_ratchet_cipher_t *ratchet_cipher, size_t cipher_text_len) {

    return vscf_aes256_gcm_decrypted_len(ratchet_cipher->aes256_gcm, cipher_text_len);
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_cipher_encrypt(vscr_ratchet_cipher_t *ratchet_cipher, vsc_data_t key, vsc_data_t plain_text,
        vsc_buffer_t *buffer) {

    VSCR_ASSERT_PTR(ratchet_cipher);

    VSCR_ASSERT(vsc_buffer_unused_len(buffer) >= vscr_ratchet_cipher_encrypt_len(ratchet_cipher, plain_text.len));

    vscr_ratchet_cipher_setup_cipher(ratchet_cipher, key);

    vscf_error_t result = vscf_aes256_gcm_encrypt(ratchet_cipher->aes256_gcm, plain_text, buffer);

    if (result != vscf_SUCCESS) {
        return vscr_AES_ERROR;
    }

    return vscr_SUCCESS;
}

VSCR_PUBLIC vscr_error_t
vscr_ratchet_cipher_decrypt(vscr_ratchet_cipher_t *ratchet_cipher, vsc_data_t key, vsc_data_t cipher_text,
        vsc_buffer_t *buffer) {

    VSCR_UNUSED(ratchet_cipher);

    VSCR_ASSERT(vsc_buffer_unused_len(buffer) >= vscr_ratchet_cipher_decrypt_len(ratchet_cipher, cipher_text.len));

    vscr_ratchet_cipher_setup_cipher(ratchet_cipher, key);

    vscf_error_t result = vscf_aes256_gcm_decrypt(ratchet_cipher->aes256_gcm, cipher_text, buffer);

    if (result != vscf_SUCCESS) {
        return vscr_AES_ERROR;
    }

    return vscr_SUCCESS;
}
