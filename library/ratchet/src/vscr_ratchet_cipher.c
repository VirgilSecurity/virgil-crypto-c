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
#include "vscr_ratchet_common_hidden.h"
#include "vscr_error.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_hkdf.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

#if !VSCR_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <virgil/crypto/foundation/vscf_aes256_gcm.h>
#endif

#if VSCR_IMPORT_PROJECT_FOUNDATION_FROM_FRAMEWORK
#   include <VSCFoundation/vscf_aes256_gcm.h>
#endif

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
//  Handle 'ratchet cipher' context.
//
struct vscr_ratchet_cipher_t {
    //
    //  Function do deallocate self context.
    //
    vscr_dealloc_fn self_dealloc_cb;
    //
    //  Reference counter.
    //
    size_t refcnt;
    //
    //  Dependency to the interface 'random'.
    //
    vscf_impl_t *rng;

    vscf_aes256_gcm_t *aes256_gcm;
};

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
vscr_ratchet_cipher_setup_cipher(vscr_ratchet_cipher_t *self, vsc_data_t key);

static size_t
vscr_ratchet_cipher_padded_len(size_t plain_text_len);

static vsc_buffer_t *
vscr_ratchet_cipher_add_padding(vscr_ratchet_cipher_t *self, vsc_data_t plain_text, vscr_error_t *error);

static vscr_status_t
vscr_ratchet_cipher_remove_padding(vsc_data_t decrypted_text, vsc_buffer_t *buffer) VSCR_NODISCARD;

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

        vscr_ratchet_cipher_release_rng(self);

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

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_use_rng(vscr_ratchet_cipher_t *self, vscf_impl_t *rng) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT(self->rng == NULL);

    VSCR_ASSERT(vscf_random_is_implemented(rng));

    self->rng = vscf_impl_shallow_copy(rng);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_take_rng(vscr_ratchet_cipher_t *self, vscf_impl_t *rng) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(rng);
    VSCR_ASSERT_PTR(self->rng == NULL);

    VSCR_ASSERT(vscf_random_is_implemented(rng));

    self->rng = rng;
}

//
//  Release dependency to the interface 'random'.
//
VSCR_PUBLIC void
vscr_ratchet_cipher_release_rng(vscr_ratchet_cipher_t *self) {

    VSCR_ASSERT_PTR(self);

    vscf_impl_destroy(&self->rng);
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

    return vscf_aes256_gcm_encrypted_len(self->aes256_gcm, vscr_ratchet_cipher_padded_len(plain_text_len));
}

VSCR_PUBLIC size_t
vscr_ratchet_cipher_decrypt_len(vscr_ratchet_cipher_t *self, size_t cipher_text_len) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->aes256_gcm);

    return vscf_aes256_gcm_decrypted_len(self->aes256_gcm, cipher_text_len) -
           vscr_ratchet_common_hidden_PADDING_SIZE_LEN;
}

static void
vscr_ratchet_cipher_setup_cipher(vscr_ratchet_cipher_t *self, vsc_data_t key) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->aes256_gcm);

    VSCR_ASSERT(key.len == vscr_ratchet_cipher_KEY_LEN);

    vscf_hkdf_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    byte derived_secret[vscf_aes256_gcm_KEY_LEN + vscf_aes256_gcm_NONCE_LEN];

    vsc_buffer_t buffer;
    vsc_buffer_init(&buffer);
    vsc_buffer_use(&buffer, derived_secret, sizeof(derived_secret));

    vscf_hkdf_set_info(hkdf, vsc_data(ratchet_kdf_cipher_info, sizeof(ratchet_kdf_cipher_info)));
    vscf_hkdf_derive(hkdf, key, sizeof(derived_secret), &buffer);

    vscf_hkdf_destroy(&hkdf);

    vscf_aes256_gcm_set_key(self->aes256_gcm, vsc_data(derived_secret, vscf_aes256_gcm_KEY_LEN));
    vscf_aes256_gcm_set_nonce(
            self->aes256_gcm, vsc_data(derived_secret + vscf_aes256_gcm_KEY_LEN, vscf_aes256_gcm_NONCE_LEN));

    vsc_buffer_delete(&buffer);
    vscr_zeroize(derived_secret, sizeof(derived_secret));
}

static size_t
vscr_ratchet_cipher_padded_len(size_t plain_text_len) {

    size_t full_size = plain_text_len + vscr_ratchet_common_hidden_PADDING_SIZE_LEN;

    size_t factor = full_size / vscr_ratchet_common_hidden_PADDING_FACTOR +
                    (full_size % vscr_ratchet_common_hidden_PADDING_FACTOR == 0 ? 0 : 1);

    return factor * vscr_ratchet_common_hidden_PADDING_FACTOR;
}

static vsc_buffer_t *
vscr_ratchet_cipher_add_padding(vscr_ratchet_cipher_t *self, vsc_data_t plain_text, vscr_error_t *error) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->rng);

    uint32_t padded_len = (uint32_t)vscr_ratchet_cipher_padded_len(plain_text.len);

    vsc_buffer_t *padded_text = vsc_buffer_new_with_capacity(padded_len);
    vsc_buffer_make_secure(padded_text);

    pb_ostream_t stream =
            pb_ostream_from_buffer(vsc_buffer_unused_bytes(padded_text), vscr_ratchet_common_hidden_PADDING_SIZE_LEN);

    bool pb_res = pb_encode_fixed32(&stream, &plain_text.len);

    if (!pb_res) {
        vsc_buffer_destroy(&padded_text);
        return NULL;
    }

    vsc_buffer_inc_used(padded_text, vscr_ratchet_common_hidden_PADDING_SIZE_LEN);

    memcpy(vsc_buffer_unused_bytes(padded_text), plain_text.bytes, plain_text.len);
    vsc_buffer_inc_used(padded_text, plain_text.len);

    size_t rest_len = padded_len - plain_text.len - vscr_ratchet_common_hidden_PADDING_SIZE_LEN;

    if (rest_len != 0) {
        vscf_status_t status = vscf_random(self->rng, rest_len, padded_text);

        if (status != vscf_status_SUCCESS) {
            vsc_buffer_destroy(&padded_text);
            VSCR_ERROR_SAFE_UPDATE(error, vscr_status_ERROR_RNG_FAILED);
            return NULL;
        }
    }

    VSCR_ASSERT(vsc_buffer_unused_len(padded_text) == 0);

    return padded_text;
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_cipher_encrypt(vscr_ratchet_cipher_t *self, vsc_data_t key, vsc_data_t plain_text, vsc_buffer_t *buffer) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->aes256_gcm);

    VSCR_ASSERT(vsc_buffer_unused_len(buffer) >= vscr_ratchet_cipher_encrypt_len(self, plain_text.len));

    vscr_ratchet_cipher_setup_cipher(self, key);

    vscr_error_t error;
    vscr_error_reset(&error);

    vsc_buffer_t *padded_text = vscr_ratchet_cipher_add_padding(self, plain_text, &error);

    if (vscr_error_has_error(&error)) {
        goto err;
    }

    vscf_status_t result = vscf_aes256_gcm_encrypt(self->aes256_gcm, vsc_buffer_data(padded_text), buffer);

    if (result != vscf_status_SUCCESS) {
        error.status = vscr_status_ERROR_AES;
        goto err;
    }

err:
    vsc_buffer_destroy(&padded_text);

    return error.status;
}

static vscr_status_t
vscr_ratchet_cipher_remove_padding(vsc_data_t decrypted_text, vsc_buffer_t *buffer) {

    if (decrypted_text.len < vscr_ratchet_common_hidden_PADDING_SIZE_LEN) {
        return vscr_status_ERROR_INVALID_PADDING;
    }

    uint32_t plain_text_len = 0;

    pb_istream_t stream = pb_istream_from_buffer(decrypted_text.bytes, vscr_ratchet_common_hidden_PADDING_SIZE_LEN);

    bool pb_res = pb_decode_fixed32(&stream, &plain_text_len);

    if (!pb_res) {
        return vscr_status_ERROR_INVALID_PADDING;
    }

    if (vsc_buffer_unused_len(buffer) < plain_text_len) {
        return vscr_status_ERROR_INVALID_PADDING;
    }

    memcpy(vsc_buffer_unused_bytes(buffer), decrypted_text.bytes + vscr_ratchet_common_hidden_PADDING_SIZE_LEN,
            plain_text_len);
    vsc_buffer_inc_used(buffer, plain_text_len);

    return vscr_status_SUCCESS;
}

VSCR_PUBLIC vscr_status_t
vscr_ratchet_cipher_decrypt(vscr_ratchet_cipher_t *self, vsc_data_t key, vsc_data_t cipher_text, vsc_buffer_t *buffer) {

    VSCR_ASSERT_PTR(self);
    VSCR_ASSERT_PTR(self->aes256_gcm);

    VSCR_ASSERT(vsc_buffer_unused_len(buffer) >= vscr_ratchet_cipher_decrypt_len(self, cipher_text.len));

    vscr_status_t result = vscr_status_SUCCESS;

    vscr_ratchet_cipher_setup_cipher(self, key);

    size_t padded_text_len = vscf_aes256_gcm_decrypted_len(self->aes256_gcm, cipher_text.len);
    vsc_buffer_t *padded_text = vsc_buffer_new_with_capacity(padded_text_len);
    vsc_buffer_make_secure(padded_text);

    vscf_status_t f_result = vscf_aes256_gcm_decrypt(self->aes256_gcm, cipher_text, padded_text);

    if (f_result != vscf_status_SUCCESS) {
        result = vscr_status_ERROR_AES;
        goto err;
    }

    result = vscr_ratchet_cipher_remove_padding(vsc_buffer_data(padded_text), buffer);

err:
    vsc_buffer_destroy(&padded_text);

    return result;
}
