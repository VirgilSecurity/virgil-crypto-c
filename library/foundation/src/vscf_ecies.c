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
//  This module contains 'ecies' implementation.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_ecies.h"
#include "vscf_assert.h"
#include "vscf_memory.h"
#include "vscf_alg_factory.h"
#include "vscf_generate_ephemeral_key.h"
#include "vscf_compute_shared_key.h"
#include "vscf_encrypt.h"
#include "vscf_decrypt.h"
#include "vscf_private_key.h"
#include "vscf_kdf2.h"
#include "vscf_sha384.h"
#include "vscf_hmac.h"
#include "vscf_aes256_cbc.h"
#include "vscf_ctr_drbg.h"
#include "vscf_ecies_envelope_defs.h"
#include "vscf_random.h"
#include "vscf_cipher.h"
#include "vscf_mac.h"
#include "vscf_kdf.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_private_key.h"
#include "vscf_ecies_defs.h"
#include "vscf_ecies_internal.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Configure ECIES with default algorithms.
//
static void
vscf_ecies_configure_defaults(vscf_ecies_t *self);


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Provides initialization of the implementation specific context.
//  Note, this method is called automatically when method vscf_ecies_init() is called.
//  Note, that context is already zeroed.
//
VSCF_PRIVATE void
vscf_ecies_init_ctx(vscf_ecies_t *self) {

    VSCF_ASSERT_PTR(self);
    self->envelope = vscf_ecies_envelope_new();
}

//
//  Release resources of the implementation specific context.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
VSCF_PRIVATE void
vscf_ecies_cleanup_ctx(vscf_ecies_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_ecies_envelope_destroy(&self->envelope);
}

//
//  Configure ECIES with default algorithms.
//
static void
vscf_ecies_configure_defaults(vscf_ecies_t *self) {

    VSCF_ASSERT_PTR(self);

    if (NULL == self->cipher) {
        self->cipher = vscf_aes256_cbc_impl(vscf_aes256_cbc_new());
    }

    if (NULL == self->mac) {
        vscf_hmac_t *hmac = vscf_hmac_new();
        vscf_hmac_take_hash(hmac, vscf_sha384_impl(vscf_sha384_new()));
        self->mac = vscf_hmac_impl(hmac);
    }

    if (NULL == self->kdf) {
        vscf_kdf2_t *kdf = vscf_kdf2_new();
        vscf_kdf2_take_hash(kdf, vscf_sha384_impl(vscf_sha384_new()));
        self->kdf = vscf_kdf2_impl(kdf);
    }
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_error_t
vscf_ecies_setup_defaults(vscf_ecies_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_error_t status = vscf_SUCCESS;

    if (NULL == self->random) {
        vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
        status = vscf_ctr_drbg_setup_defaults(random);
        if (status == vscf_SUCCESS) {
            vscf_ecies_take_random(self, vscf_ctr_drbg_impl(random));
        }
    }

    return status;
}

//
//  Encrypt given data.
//
VSCF_PUBLIC vscf_error_t
vscf_ecies_encrypt(vscf_ecies_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(self->encryption_key);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_ecies_encrypted_len(self, data.len));

    vscf_error_ctx_t error;
    vscf_error_ctx_reset(&error);

    //
    // Configure ECIES with default algorithms.
    //
    vscf_ecies_configure_defaults(self);

    //
    // Generate ephemeral keypair, if not defined.
    //
    if (NULL == self->ephemeral_key) {
        VSCF_ASSERT(vscf_generate_ephemeral_key_is_implemented(self->encryption_key));
        self->ephemeral_key = vscf_generate_ephemeral_key(self->encryption_key, &error);
        if (error.error != vscf_SUCCESS) {
            return error.error;
        }
        VSCF_ASSERT(vscf_compute_shared_key_is_implemented(self->ephemeral_key));
    }

    vscf_impl_t *ephemeral_public_key = vscf_private_key_extract_public_key(self->ephemeral_key);
    vscf_ecies_envelope_set_ephemeral_public_key(self->envelope, &ephemeral_public_key);

    vsc_buffer_t *shared_key = NULL;
    vsc_buffer_t *derived_key = NULL;
    vsc_buffer_t *nonce = NULL;

    //
    // Compute shared secret key.
    //
    shared_key = vsc_buffer_new_with_capacity(vscf_compute_shared_key_shared_key_len(self->ephemeral_key));
    vsc_buffer_make_secure(shared_key);
    error.error = vscf_compute_shared_key(self->ephemeral_key, self->encryption_key, shared_key);

    if (error.error != vscf_SUCCESS) {
        goto compute_shared_failed;
    }

    //
    // Derive keys (encryption key and hmac key).
    //
    const size_t mac_key_len = vscf_mac_digest_len(self->mac);
    const size_t cipher_key_len = vscf_cipher_info_key_len(vscf_cipher_cipher_info_api(vscf_cipher_api(self->cipher)));
    const size_t derived_key_len = cipher_key_len + mac_key_len;
    derived_key = vsc_buffer_new_with_capacity(derived_key_len);
    vsc_buffer_make_secure(derived_key);
    vscf_kdf_derive(self->kdf, vsc_buffer_data(shared_key), derived_key_len, derived_key);

    vsc_data_t cipher_key = vsc_data_slice_beg(vsc_buffer_data(derived_key), 0, cipher_key_len);
    vsc_data_t mac_key = vsc_data_slice_beg(vsc_buffer_data(derived_key), cipher_key_len, mac_key_len);

    //
    // Encrypt given message.
    //
    const size_t nonce_len = vscf_cipher_info_nonce_len(vscf_cipher_cipher_info_api(vscf_cipher_api(self->cipher)));
    nonce = vsc_buffer_new_with_capacity(nonce_len);
    error.error = vscf_random(self->random, nonce_len, nonce);

    if (error.error != vscf_SUCCESS) {
        goto random_failed;
    }

    const size_t encrypted_data_len =
            vscf_cipher_encrypted_out_len(self->cipher, data.len) + vscf_cipher_encrypted_out_len(self->cipher, 0);
    vsc_buffer_t *encrypted_data = vsc_buffer_new_with_capacity(encrypted_data_len);
    vscf_cipher_set_nonce(self->cipher, vsc_buffer_data(nonce));
    vscf_cipher_set_key(self->cipher, cipher_key);
    vscf_cipher_start_encryption(self->cipher);
    vscf_cipher_update(self->cipher, data, encrypted_data);
    error.error = vscf_cipher_finish(self->cipher, encrypted_data);

    if (error.error != vscf_SUCCESS) {
        vsc_buffer_destroy(&encrypted_data);
        goto encrypt_failed;
    }

    //
    // Get HMAC for encrypted message.
    //
    vsc_buffer_t *mac_digest = vsc_buffer_new_with_capacity(vscf_mac_digest_len(self->mac));
    vscf_mac_start(self->mac, mac_key);
    vscf_mac_update(self->mac, vsc_buffer_data(encrypted_data));
    vscf_mac_finish(self->mac, mac_digest);

    vscf_ecies_envelope_set_encrypted_content(self->envelope, &encrypted_data);
    vscf_ecies_envelope_set_mac_digest(self->envelope, &mac_digest);

    //
    //  Configure and write envelope.
    //
    vscf_impl_t *cipher = vscf_impl_shallow_copy(self->cipher);
    vscf_ecies_envelope_set_cipher(self->envelope, &cipher);

    vscf_impl_t *kdf = vscf_impl_shallow_copy(self->kdf);
    vscf_ecies_envelope_set_kdf(self->envelope, &kdf);

    vscf_impl_t *mac = vscf_impl_shallow_copy(self->mac);
    vscf_ecies_envelope_set_mac(self->envelope, &mac);

    vscf_ecies_envelope_pack(self->envelope, out);

encrypt_failed:
random_failed:
    vsc_buffer_destroy(&nonce);
    vsc_buffer_destroy(&derived_key);

compute_shared_failed:
    vsc_buffer_destroy(&shared_key);
    vscf_ecies_envelope_cleanup_properties(self->envelope);

    return error.error;
}

//
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_ecies_encrypted_len(vscf_ecies_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);

    //  TODO: Make precise calculation.
    size_t len = 256 + data_len + 48;

    return len;
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_error_t
vscf_ecies_decrypt(vscf_ecies_t *self, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->decryption_key);
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_ecies_decrypted_len(self, data.len));

    vscf_error_ctx_t error;
    vscf_error_ctx_reset(&error);

    vsc_buffer_t *shared_key = NULL;
    vsc_buffer_t *derived_key = NULL;
    vsc_buffer_t *mac_digest = NULL;

    //
    //  Unpack envelope.
    //
    error.error = vscf_ecies_envelope_unpack(self->envelope, data);
    if (error.error != vscf_SUCCESS) {
        goto unpack_envelope_failed;
    }

    //
    //  Compute shared secret key.
    //
    shared_key = vsc_buffer_new_with_capacity(vscf_compute_shared_key_shared_key_len(self->decryption_key));
    vsc_buffer_make_secure(shared_key);
    error.error = vscf_compute_shared_key(self->decryption_key, self->envelope->ephemeral_public_key, shared_key);

    if (error.error != vscf_SUCCESS) {
        goto compute_shared_failed;
    }

    //
    //  Derive keys (decryption key and hmac key).
    //
    const size_t mac_key_len = vscf_mac_digest_len(self->envelope->mac);
    const size_t cipher_key_len =
            vscf_cipher_info_key_len(vscf_cipher_cipher_info_api(vscf_cipher_api(self->envelope->cipher)));
    const size_t derived_key_len = cipher_key_len + mac_key_len;
    derived_key = vsc_buffer_new_with_capacity(derived_key_len);
    vsc_buffer_make_secure(derived_key);
    vscf_kdf_derive(self->envelope->kdf, vsc_buffer_data(shared_key), derived_key_len, derived_key);

    vsc_data_t cipher_key = vsc_data_slice_beg(vsc_buffer_data(derived_key), 0, cipher_key_len);
    vsc_data_t mac_key = vsc_data_slice_beg(vsc_buffer_data(derived_key), cipher_key_len, mac_key_len);

    //
    //  Get HMAC for encrypted message and compare it.
    //
    mac_digest = vsc_buffer_new_with_capacity(vscf_mac_digest_len(self->envelope->mac));
    vscf_mac_start(self->envelope->mac, mac_key);
    vscf_mac_update(self->envelope->mac, vsc_buffer_data(self->envelope->encrypted_content));
    vscf_mac_finish(self->envelope->mac, mac_digest);

    if (!vsc_buffer_equal(self->envelope->mac_digest, mac_digest)) {
        error.error = vscf_error_BAD_ENCRYPTED_DATA;
        goto mac_validation_failed;
    }

    //
    //  Decrypt given message.
    //
    vscf_cipher_set_key(self->envelope->cipher, cipher_key);
    vscf_cipher_start_decryption(self->envelope->cipher);
    vscf_cipher_update(self->envelope->cipher, vsc_buffer_data(self->envelope->encrypted_content), out);
    error.error = vscf_cipher_finish(self->envelope->cipher, out);

    //
    //  Cleanup.
    //
mac_validation_failed:
    vsc_buffer_destroy(&mac_digest);
    vsc_buffer_destroy(&derived_key);

compute_shared_failed:
    vsc_buffer_destroy(&shared_key);

unpack_envelope_failed:
    vscf_ecies_envelope_cleanup_properties(self->envelope);

    return error.error;
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_ecies_decrypted_len(vscf_ecies_t *self, size_t data_len) {

    VSCF_ASSERT_PTR(self);

    return data_len;
}
