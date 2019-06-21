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


//  @description
// --------------------------------------------------------------------------
//  Class for encryption using PHE account key
//  This class is thread-safe.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vsce_phe_cipher.h"
#include "vsce_memory.h"
#include "vsce_assert.h"
#include "vsce_phe_cipher_defs.h"
#include "vsce_const.h"

#include <virgil/crypto/foundation/vscf_random.h>
#include <virgil/crypto/foundation/vscf_ctr_drbg.h>
#include <virgil/crypto/foundation/vscf_sha512.h>
#include <virgil/crypto/foundation/vscf_hkdf.h>
#include <virgil/crypto/foundation/vscf_aes256_gcm.h>
#include <virgil/crypto/common/private/vsc_buffer_defs.h>

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Private integral constants.
//
enum {
    vsce_phe_cipher_SALT_LEN = 32,
    vsce_phe_cipher_KEY_LEN = 32,
    vsce_phe_cipher_NONCE_LEN = 12
};

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_phe_cipher_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_phe_cipher_init_ctx(vsce_phe_cipher_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_cipher_cleanup_ctx(vsce_phe_cipher_t *self);

//
//  Return size of 'vsce_phe_cipher_t'.
//
VSCE_PUBLIC size_t
vsce_phe_cipher_ctx_size(void) {

    return sizeof(vsce_phe_cipher_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCE_PUBLIC void
vsce_phe_cipher_init(vsce_phe_cipher_t *self) {

    VSCE_ASSERT_PTR(self);

    vsce_zeroize(self, sizeof(vsce_phe_cipher_t));

    self->refcnt = 1;

    vsce_phe_cipher_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCE_PUBLIC void
vsce_phe_cipher_cleanup(vsce_phe_cipher_t *self) {

    if (self == NULL) {
        return;
    }

    vsce_phe_cipher_cleanup_ctx(self);

    vsce_phe_cipher_release_random(self);

    vsce_zeroize(self, sizeof(vsce_phe_cipher_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCE_PUBLIC vsce_phe_cipher_t *
vsce_phe_cipher_new(void) {

    vsce_phe_cipher_t *self = (vsce_phe_cipher_t *) vsce_alloc(sizeof (vsce_phe_cipher_t));
    VSCE_ASSERT_ALLOC(self);

    vsce_phe_cipher_init(self);

    self->self_dealloc_cb = vsce_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCE_PUBLIC void
vsce_phe_cipher_delete(vsce_phe_cipher_t *self) {

    if (self == NULL) {
        return;
    }

    size_t old_counter = self->refcnt;
    VSCE_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCE_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCE_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter)) {
        old_counter = self->refcnt;
        VSCE_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vsce_dealloc_fn self_dealloc_cb = self->self_dealloc_cb;

    vsce_phe_cipher_cleanup(self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vsce_phe_cipher_new ()'.
//
VSCE_PUBLIC void
vsce_phe_cipher_destroy(vsce_phe_cipher_t **self_ref) {

    VSCE_ASSERT_PTR(self_ref);

    vsce_phe_cipher_t *self = *self_ref;
    *self_ref = NULL;

    vsce_phe_cipher_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCE_PUBLIC vsce_phe_cipher_t *
vsce_phe_cipher_shallow_copy(vsce_phe_cipher_t *self) {

    VSCE_ASSERT_PTR(self);

    #if defined(VSCE_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    size_t old_counter;
    size_t new_counter;
    do {
        old_counter = self->refcnt;
        new_counter = old_counter + 1;
    } while (!VSCE_ATOMIC_COMPARE_EXCHANGE_WEAK(&self->refcnt, &old_counter, new_counter));
    #else
    ++self->refcnt;
    #endif

    return self;
}

//
//  Random used for salt generation
//
//  Note, ownership is shared.
//
VSCE_PUBLIC void
vsce_phe_cipher_use_random(vsce_phe_cipher_t *self, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT(self->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);
}

//
//  Random used for salt generation
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCE_PUBLIC void
vsce_phe_cipher_take_random(vsce_phe_cipher_t *self, vscf_impl_t *random) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT_PTR(random);
    VSCE_ASSERT(self->random == NULL);

    VSCE_ASSERT(vscf_random_is_implemented(random));

    self->random = random;
}

//
//  Release dependency to the interface 'random'.
//
VSCE_PUBLIC void
vsce_phe_cipher_release_random(vsce_phe_cipher_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vsce_phe_cipher_init() is called.
//  Note, that context is already zeroed.
//
static void
vsce_phe_cipher_init_ctx(vsce_phe_cipher_t *self) {

    VSCE_ASSERT_PTR(self);

    self->aes256_gcm = vscf_aes256_gcm_new();
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vsce_phe_cipher_cleanup_ctx(vsce_phe_cipher_t *self) {

    VSCE_ASSERT_PTR(self);

    vscf_aes256_gcm_destroy(&self->aes256_gcm);
}

//
//  Setups dependencies with default values.
//
VSCE_PUBLIC vsce_status_t
vsce_phe_cipher_setup_defaults(vsce_phe_cipher_t *self) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(self->random == NULL);

    vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
    vscf_status_t status = vscf_ctr_drbg_setup_defaults(random);

    if (status != vscf_status_SUCCESS) {
        vscf_ctr_drbg_destroy(&random);
        return vsce_status_ERROR_RNG_FAILED;
    }

    vsce_phe_cipher_take_random(self, vscf_ctr_drbg_impl(random));

    return vsce_status_SUCCESS;
}

//
//  Returns buffer capacity needed to fit cipher text
//
VSCE_PUBLIC size_t
vsce_phe_cipher_encrypt_len(vsce_phe_cipher_t *self, size_t plain_text_len) {

    VSCE_ASSERT_PTR(self);

    return vscf_aes256_gcm_encrypted_len(self->aes256_gcm, plain_text_len) + vsce_phe_cipher_SALT_LEN;
}

//
//  Returns buffer capacity needed to fit plain text
//
VSCE_PUBLIC size_t
vsce_phe_cipher_decrypt_len(vsce_phe_cipher_t *self, size_t cipher_text_len) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(cipher_text_len >= vsce_phe_cipher_SALT_LEN);

    return vscf_aes256_gcm_decrypted_len(self->aes256_gcm, cipher_text_len - vsce_phe_cipher_SALT_LEN) +
           vsce_phe_cipher_KEY_LEN;
}

//
//  Encrypts data using account key
//
VSCE_PUBLIC vsce_status_t
vsce_phe_cipher_encrypt(
        vsce_phe_cipher_t *self, vsc_data_t plain_text, vsc_data_t account_key, vsc_buffer_t *cipher_text) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(account_key.len == vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);
    VSCE_ASSERT(plain_text.len <= vsce_phe_common_PHE_MAX_ENCRYPT_LEN);
    VSCE_ASSERT(vsc_buffer_capacity(cipher_text) >= vsce_phe_cipher_encrypt_len(self, plain_text.len));

    vsce_status_t status = vsce_status_SUCCESS;

    byte salt[vsce_phe_cipher_SALT_LEN];

    vsc_buffer_t salt_buf;
    vsc_buffer_init(&salt_buf);
    vsc_buffer_use(&salt_buf, salt, sizeof(salt));

    vscf_status_t f_status = vscf_random(self->random, sizeof(salt), &salt_buf);

    if (f_status != vscf_status_SUCCESS) {
        status = vsce_status_ERROR_RNG_FAILED;
        goto rng_err;
    }

    vscf_hkdf_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    byte derived_secret[vsce_phe_cipher_KEY_LEN + vsce_phe_cipher_NONCE_LEN];

    vsc_buffer_t derived_secret_buf;
    vsc_buffer_init(&derived_secret_buf);
    vsc_buffer_use(&derived_secret_buf, derived_secret, sizeof(derived_secret));

    vscf_hkdf_reset(hkdf, vsc_buffer_data(&salt_buf), 0);
    vscf_hkdf_set_info(hkdf, k_encrypt);
    vscf_hkdf_derive(hkdf, account_key, sizeof(derived_secret), &derived_secret_buf);
    vscf_hkdf_destroy(&hkdf);

    vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();

    vscf_aes256_gcm_set_key(
            aes256_gcm, vsc_data_slice_beg(vsc_buffer_data(&derived_secret_buf), 0, vsce_phe_cipher_KEY_LEN));
    vscf_aes256_gcm_set_nonce(
            aes256_gcm, vsc_data_slice_end(vsc_buffer_data(&derived_secret_buf), 0, vsce_phe_cipher_NONCE_LEN));

    memcpy(vsc_buffer_unused_bytes(cipher_text), salt, sizeof(salt));
    vsc_buffer_inc_used(cipher_text, sizeof(salt));

    f_status = vscf_aes256_gcm_encrypt(aes256_gcm, plain_text, cipher_text);

    if (f_status != vscf_status_SUCCESS) {
        status = vsce_status_ERROR_AES_FAILED;
    }

    vscf_aes256_gcm_destroy(&aes256_gcm);

    vsce_zeroize(derived_secret, sizeof(derived_secret));
    vsc_buffer_delete(&derived_secret_buf);

rng_err:
    vsce_zeroize(salt, sizeof(salt));
    vsc_buffer_delete(&salt_buf);

    return status;
}

//
//  Decrypts data using account key
//
VSCE_PUBLIC vsce_status_t
vsce_phe_cipher_decrypt(
        vsce_phe_cipher_t *self, vsc_data_t cipher_text, vsc_data_t account_key, vsc_buffer_t *plain_text) {

    VSCE_ASSERT_PTR(self);
    VSCE_ASSERT(account_key.len == vsce_phe_common_PHE_ACCOUNT_KEY_LENGTH);
    VSCE_ASSERT(cipher_text.len <= vsce_phe_common_PHE_MAX_DECRYPT_LEN);
    VSCE_ASSERT(vsc_buffer_capacity(plain_text) >= vsce_phe_cipher_decrypt_len(self, cipher_text.len));

    vsce_status_t status = vsce_status_SUCCESS;

    vscf_hkdf_t *hkdf = vscf_hkdf_new();
    vscf_hkdf_take_hash(hkdf, vscf_sha512_impl(vscf_sha512_new()));

    byte derived_secret[vsce_phe_cipher_KEY_LEN + vsce_phe_cipher_NONCE_LEN];

    vsc_buffer_t derived_secret_buf;
    vsc_buffer_init(&derived_secret_buf);
    vsc_buffer_use(&derived_secret_buf, derived_secret, sizeof(derived_secret));

    vscf_hkdf_reset(hkdf, vsc_data_slice_beg(cipher_text, 0, vsce_phe_cipher_SALT_LEN), 0);
    vscf_hkdf_set_info(hkdf, k_encrypt);
    vscf_hkdf_derive(hkdf, account_key, sizeof(derived_secret), &derived_secret_buf);
    vscf_hkdf_destroy(&hkdf);

    vscf_aes256_gcm_t *aes256_gcm = vscf_aes256_gcm_new();

    vscf_aes256_gcm_set_key(
            aes256_gcm, vsc_data_slice_beg(vsc_buffer_data(&derived_secret_buf), 0, vsce_phe_cipher_KEY_LEN));
    vscf_aes256_gcm_set_nonce(
            aes256_gcm, vsc_data_slice_end(vsc_buffer_data(&derived_secret_buf), 0, vsce_phe_cipher_NONCE_LEN));

    vscf_status_t f_status = vscf_aes256_gcm_decrypt(aes256_gcm,
            vsc_data_slice_beg(cipher_text, vsce_phe_cipher_SALT_LEN, cipher_text.len - vsce_phe_cipher_SALT_LEN),
            plain_text);

    if (f_status != vscf_status_SUCCESS) {
        status = vsce_status_ERROR_AES_FAILED;
    }

    vscf_aes256_gcm_destroy(&aes256_gcm);

    vsce_zeroize(derived_secret, sizeof(derived_secret));
    vsc_buffer_delete(&derived_secret_buf);

    return status;
}
