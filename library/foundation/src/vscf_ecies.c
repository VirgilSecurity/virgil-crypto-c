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


//  @description
// --------------------------------------------------------------------------
//  Virgil implementation of the ECIES algorithm.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_ecies.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_ecies_defs.h"
#include "vscf_compute_shared_key.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_key_alg.h"
#include "vscf_key_cipher.h"
#include "vscf_kdf2.h"
#include "vscf_sha384.h"
#include "vscf_hmac.h"
#include "vscf_aes256_cbc.h"
#include "vscf_ctr_drbg.h"
#include "vscf_key_alg_factory.h"
#include "vscf_ecies_envelope.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_ecies_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_ecies_init_ctx(vscf_ecies_t *self);

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_ecies_cleanup_ctx(vscf_ecies_t *self);

//
//  Return size of 'vscf_ecies_t'.
//
VSCF_PUBLIC size_t
vscf_ecies_ctx_size(void) {

    return sizeof(vscf_ecies_t);
}

//
//  Perform initialization of pre-allocated context.
//
VSCF_PUBLIC void
vscf_ecies_init(vscf_ecies_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_ecies_t));

    self->refcnt = 1;

    vscf_ecies_init_ctx(self);
}

//
//  Release all inner resources including class dependencies.
//
VSCF_PUBLIC void
vscf_ecies_cleanup(vscf_ecies_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_ecies_release_random(self);
    vscf_ecies_release_cipher(self);
    vscf_ecies_release_mac(self);
    vscf_ecies_release_kdf(self);
    vscf_ecies_release_ephemeral_key(self);

    vscf_ecies_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_ecies_t));
}

//
//  Allocate context and perform it's initialization.
//
VSCF_PUBLIC vscf_ecies_t *
vscf_ecies_new(void) {

    vscf_ecies_t *self = (vscf_ecies_t *) vscf_alloc(sizeof (vscf_ecies_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_ecies_init(self);

    self->self_dealloc_cb = vscf_dealloc;

    return self;
}

//
//  Release all inner resources and deallocate context if needed.
//  It is safe to call this method even if the context was statically allocated.
//
VSCF_PUBLIC void
vscf_ecies_delete(const vscf_ecies_t *self) {

    vscf_ecies_t *local_self = (vscf_ecies_t *)self;

    if (local_self == NULL) {
        return;
    }

    size_t old_counter = local_self->refcnt;
    VSCF_ASSERT(old_counter != 0);
    size_t new_counter = old_counter - 1;

    #if defined(VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK)
    //  CAS loop
    while (!VSCF_ATOMIC_COMPARE_EXCHANGE_WEAK(&local_self->refcnt, &old_counter, new_counter)) {
        old_counter = local_self->refcnt;
        VSCF_ASSERT(old_counter != 0);
        new_counter = old_counter - 1;
    }
    #else
    local_self->refcnt = new_counter;
    #endif

    if (new_counter > 0) {
        return;
    }

    vscf_dealloc_fn self_dealloc_cb = local_self->self_dealloc_cb;

    vscf_ecies_cleanup(local_self);

    if (self_dealloc_cb != NULL) {
        self_dealloc_cb(local_self);
    }
}

//
//  Delete given context and nullifies reference.
//  This is a reverse action of the function 'vscf_ecies_new ()'.
//
VSCF_PUBLIC void
vscf_ecies_destroy(vscf_ecies_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_ecies_t *self = *self_ref;
    *self_ref = NULL;

    vscf_ecies_delete(self);
}

//
//  Copy given class context by increasing reference counter.
//
VSCF_PUBLIC vscf_ecies_t *
vscf_ecies_shallow_copy(vscf_ecies_t *self) {

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

//
//  Copy given class context by increasing reference counter.
//  Reference counter is internally synchronized, so constness is presumed.
//
VSCF_PUBLIC const vscf_ecies_t *
vscf_ecies_shallow_copy_const(const vscf_ecies_t *self) {

    return vscf_ecies_shallow_copy((vscf_ecies_t *)self);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_ecies_use_random(vscf_ecies_t *self, vscf_impl_t *random) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(random);
    VSCF_ASSERT(self->random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(random));

    self->random = vscf_impl_shallow_copy(random);
}

//
//  Setup dependency to the interface 'random' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_ecies_take_random(vscf_ecies_t *self, vscf_impl_t *random) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(random);
    VSCF_ASSERT(self->random == NULL);

    VSCF_ASSERT(vscf_random_is_implemented(random));

    self->random = random;
}

//
//  Release dependency to the interface 'random'.
//
VSCF_PUBLIC void
vscf_ecies_release_random(vscf_ecies_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}

//
//  Setup dependency to the interface 'cipher' with shared ownership.
//
VSCF_PUBLIC void
vscf_ecies_use_cipher(vscf_ecies_t *self, vscf_impl_t *cipher) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(cipher);
    VSCF_ASSERT(self->cipher == NULL);

    VSCF_ASSERT(vscf_cipher_is_implemented(cipher));

    self->cipher = vscf_impl_shallow_copy(cipher);
}

//
//  Setup dependency to the interface 'cipher' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_ecies_take_cipher(vscf_ecies_t *self, vscf_impl_t *cipher) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(cipher);
    VSCF_ASSERT(self->cipher == NULL);

    VSCF_ASSERT(vscf_cipher_is_implemented(cipher));

    self->cipher = cipher;
}

//
//  Release dependency to the interface 'cipher'.
//
VSCF_PUBLIC void
vscf_ecies_release_cipher(vscf_ecies_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->cipher);
}

//
//  Setup dependency to the interface 'mac' with shared ownership.
//
VSCF_PUBLIC void
vscf_ecies_use_mac(vscf_ecies_t *self, vscf_impl_t *mac) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(mac);
    VSCF_ASSERT(self->mac == NULL);

    VSCF_ASSERT(vscf_mac_is_implemented(mac));

    self->mac = vscf_impl_shallow_copy(mac);
}

//
//  Setup dependency to the interface 'mac' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_ecies_take_mac(vscf_ecies_t *self, vscf_impl_t *mac) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(mac);
    VSCF_ASSERT(self->mac == NULL);

    VSCF_ASSERT(vscf_mac_is_implemented(mac));

    self->mac = mac;
}

//
//  Release dependency to the interface 'mac'.
//
VSCF_PUBLIC void
vscf_ecies_release_mac(vscf_ecies_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->mac);
}

//
//  Setup dependency to the interface 'kdf' with shared ownership.
//
VSCF_PUBLIC void
vscf_ecies_use_kdf(vscf_ecies_t *self, vscf_impl_t *kdf) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(kdf);
    VSCF_ASSERT(self->kdf == NULL);

    VSCF_ASSERT(vscf_kdf_is_implemented(kdf));

    self->kdf = vscf_impl_shallow_copy(kdf);
}

//
//  Setup dependency to the interface 'kdf' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_ecies_take_kdf(vscf_ecies_t *self, vscf_impl_t *kdf) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(kdf);
    VSCF_ASSERT(self->kdf == NULL);

    VSCF_ASSERT(vscf_kdf_is_implemented(kdf));

    self->kdf = kdf;
}

//
//  Release dependency to the interface 'kdf'.
//
VSCF_PUBLIC void
vscf_ecies_release_kdf(vscf_ecies_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->kdf);
}

//
//  Set ephemeral key that used for data encryption.
//  Public and ephemeral keys should belong to the same curve.
//  This dependency is optional.
//
//  Note, ownership is shared.
//
VSCF_PUBLIC void
vscf_ecies_use_ephemeral_key(vscf_ecies_t *self, vscf_impl_t *ephemeral_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(ephemeral_key);
    VSCF_ASSERT(self->ephemeral_key == NULL);

    VSCF_ASSERT(vscf_private_key_is_implemented(ephemeral_key));

    self->ephemeral_key = vscf_impl_shallow_copy(ephemeral_key);
}

//
//  Set ephemeral key that used for data encryption.
//  Public and ephemeral keys should belong to the same curve.
//  This dependency is optional.
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_ecies_take_ephemeral_key(vscf_ecies_t *self, vscf_impl_t *ephemeral_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(ephemeral_key);
    VSCF_ASSERT(self->ephemeral_key == NULL);

    VSCF_ASSERT(vscf_private_key_is_implemented(ephemeral_key));

    self->ephemeral_key = ephemeral_key;
}

//
//  Release dependency to the interface 'private key'.
//
VSCF_PUBLIC void
vscf_ecies_release_ephemeral_key(vscf_ecies_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->ephemeral_key);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


//
//  Perform context specific initialization.
//  Note, this method is called automatically when method vscf_ecies_init() is called.
//  Note, that context is already zeroed.
//
static void
vscf_ecies_init_ctx(vscf_ecies_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Release all inner resources.
//  Note, this method is called automatically once when class is completely cleaning up.
//  Note, that context will be zeroed automatically next this method.
//
static void
vscf_ecies_cleanup_ctx(vscf_ecies_t *self) {

    VSCF_ASSERT_PTR(self);
}

//
//  Set weak reference to the key algorithm.
//  Key algorithm MUST support shared key computation as well.
//
VSCF_PUBLIC void
vscf_ecies_set_key_alg(vscf_ecies_t *self, const vscf_impl_t *key_alg) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(key_alg);
    VSCF_ASSERT(vscf_key_alg_is_implemented(key_alg));
    VSCF_ASSERT(vscf_compute_shared_key_is_implemented(key_alg));

    self->key_alg = key_alg;
}

//
//  Release weak reference to the key algorithm.
//
VSCF_PUBLIC void
vscf_ecies_release_key_alg(vscf_ecies_t *self) {

    VSCF_ASSERT_PTR(self);

    self->key_alg = NULL;
}

//
//  Setup predefined values to the uninitialized class dependencies.
//
VSCF_PUBLIC vscf_status_t
vscf_ecies_setup_defaults(vscf_ecies_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_ecies_setup_defaults_no_random(self);

    if (NULL == self->random) {
        vscf_ctr_drbg_t *random = vscf_ctr_drbg_new();
        const vscf_status_t status = vscf_ctr_drbg_setup_defaults(random);
        if (status == vscf_status_SUCCESS) {
            vscf_ecies_take_random(self, vscf_ctr_drbg_impl(random));
        } else {
            return status;
        }
    }

    return vscf_status_SUCCESS;
}

//
//  Setup predefined values to the uninitialized class dependencies
//  except random.
//
VSCF_PUBLIC void
vscf_ecies_setup_defaults_no_random(vscf_ecies_t *self) {

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
//  Calculate required buffer length to hold the encrypted data.
//
VSCF_PUBLIC size_t
vscf_ecies_encrypted_len(const vscf_ecies_t *self, const vscf_impl_t *public_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(public_key);

    //  TODO: Make precise calculation.
    size_t len = 256 + data_len + 48;

    return len;
}

//
//  Encrypt data with a given public key.
//
VSCF_PUBLIC vscf_status_t
vscf_ecies_encrypt(const vscf_ecies_t *self, const vscf_impl_t *public_key, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->random);
    VSCF_ASSERT_PTR(self->key_alg);
    VSCF_ASSERT_PTR(public_key);
    VSCF_ASSERT(vscf_public_key_is_implemented(public_key));
    VSCF_ASSERT_SAFE(vscf_key_is_valid(public_key));
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_ecies_encrypted_len(self, public_key, data.len));

    vscf_error_t error;
    vscf_error_reset(&error);

    //
    // Generate ephemeral keypair, if not defined.
    //
    const vscf_impl_t *ephemeral_key = self->ephemeral_key;

    if (ephemeral_key) {
        ephemeral_key = vscf_impl_shallow_copy_const(self->ephemeral_key);
    } else {
        ephemeral_key = vscf_key_alg_generate_ephemeral_key(self->key_alg, public_key, &error);
        if (vscf_error_has_error(&error)) {
            return vscf_error_status(&error);
        }
    }

    vsc_buffer_t *shared_key = NULL;
    vsc_buffer_t *derived_key = NULL;
    vsc_buffer_t *nonce = NULL;
    vsc_buffer_t *encrypted_data = NULL;
    vsc_buffer_t *mac_digest = NULL;
    vscf_ecies_envelope_t envelope = {NULL, NULL, NULL, NULL, NULL, NULL};

    //
    // Compute shared secret key.
    //
    shared_key = vsc_buffer_new_with_capacity(vscf_compute_shared_key_shared_key_len(self->key_alg, ephemeral_key));
    vsc_buffer_make_secure(shared_key);
    vscf_error_update(&error, vscf_compute_shared_key(self->key_alg, public_key, ephemeral_key, shared_key));

    if (vscf_error_has_error(&error)) {
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
    vscf_error_update(&error, vscf_random(self->random, nonce_len, nonce));

    if (vscf_error_has_error(&error)) {
        goto random_failed;
    }

    const size_t encrypted_data_len =
            vscf_cipher_encrypted_out_len(self->cipher, data.len) + vscf_cipher_encrypted_out_len(self->cipher, 0);
    encrypted_data = vsc_buffer_new_with_capacity(encrypted_data_len);
    vscf_cipher_set_nonce(self->cipher, vsc_buffer_data(nonce));
    vscf_cipher_set_key(self->cipher, cipher_key);
    vscf_cipher_start_encryption(self->cipher);
    vscf_cipher_update(self->cipher, data, encrypted_data);
    vscf_error_update(&error, vscf_cipher_finish(self->cipher, encrypted_data));

    if (vscf_error_has_error(&error)) {
        goto encrypt_failed;
    }

    //
    // Get HMAC for encrypted message.
    //
    mac_digest = vsc_buffer_new_with_capacity(vscf_mac_digest_len(self->mac));
    vscf_mac_start(self->mac, mac_key);
    vscf_mac_update(self->mac, vsc_buffer_data(encrypted_data));
    vscf_mac_finish(self->mac, mac_digest);

    //
    //  Configure and write envelope.
    //
    vscf_impl_t *ephemeral_public_key = vscf_private_key_extract_public_key(ephemeral_key);
    vscf_raw_public_key_t *raw_ephemeral_public_key =
            vscf_key_alg_export_public_key(self->key_alg, ephemeral_public_key, &error);
    vscf_impl_destroy(&ephemeral_public_key);

    if (vscf_error_has_error(&error)) {
        goto pack_envelope_failed;
    }

    envelope.cipher = (vscf_impl_t *)self->cipher;
    envelope.kdf = (vscf_impl_t *)self->kdf;
    envelope.mac = (vscf_impl_t *)self->mac;
    envelope.ephemeral_public_key = raw_ephemeral_public_key;
    envelope.encrypted_content = encrypted_data;
    envelope.mac_digest = mac_digest;

    vscf_error_update(&error, vscf_ecies_envelope_pack(&envelope, out));

    vscf_raw_public_key_destroy(&raw_ephemeral_public_key);

pack_envelope_failed:
encrypt_failed:
    vsc_buffer_destroy(&encrypted_data);
    vsc_buffer_destroy(&mac_digest);

random_failed:
    vsc_buffer_destroy(&nonce);
    vsc_buffer_destroy(&derived_key);

compute_shared_failed:
    vscf_impl_destroy((vscf_impl_t **)&ephemeral_key);
    vsc_buffer_destroy(&shared_key);

    return vscf_error_status(&error);
}

//
//  Calculate required buffer length to hold the decrypted data.
//
VSCF_PUBLIC size_t
vscf_ecies_decrypted_len(const vscf_ecies_t *self, const vscf_impl_t *private_key, size_t data_len) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(private_key);

    return data_len;
}

//
//  Decrypt given data.
//
VSCF_PUBLIC vscf_status_t
vscf_ecies_decrypt(const vscf_ecies_t *self, const vscf_impl_t *private_key, vsc_data_t data, vsc_buffer_t *out) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(self->key_alg);
    VSCF_ASSERT(vscf_private_key_is_implemented(private_key));
    VSCF_ASSERT_SAFE(vscf_key_is_valid(private_key));
    VSCF_ASSERT(vsc_data_is_valid(data));
    VSCF_ASSERT_PTR(out);
    VSCF_ASSERT(vsc_buffer_is_valid(out));
    VSCF_ASSERT(vsc_buffer_unused_len(out) >= vscf_ecies_decrypted_len(self, private_key, data.len));

    vscf_error_t error;
    vscf_error_reset(&error);

    vsc_buffer_t *shared_key = NULL;
    vsc_buffer_t *derived_key = NULL;
    vsc_buffer_t *mac_digest = NULL;
    vscf_ecies_envelope_t envelope = {NULL, NULL, NULL, NULL, NULL, NULL};
    vscf_impl_t *ephemeral_public_key = NULL;

    //
    //  Unpack envelope.
    //
    vscf_error_update(&error, vscf_ecies_envelope_unpack(&envelope, data));
    if (vscf_error_has_error(&error)) {
        goto unpack_envelope_failed;
    }

    ephemeral_public_key = vscf_key_alg_import_public_key(self->key_alg, envelope.ephemeral_public_key, &error);
    if (vscf_error_has_error(&error)) {
        goto unpack_envelope_failed;
    }

    //
    //  Compute shared secret key.
    //
    shared_key = vsc_buffer_new_with_capacity(vscf_compute_shared_key_shared_key_len(self->key_alg, private_key));
    vsc_buffer_make_secure(shared_key);
    vscf_error_update(&error, vscf_compute_shared_key(self->key_alg, ephemeral_public_key, private_key, shared_key));

    if (vscf_error_has_error(&error)) {
        goto compute_shared_failed;
    }

    //
    //  Derive keys (decryption key and hmac key).
    //
    const size_t mac_key_len = vscf_mac_digest_len(envelope.mac);
    const size_t cipher_key_len =
            vscf_cipher_info_key_len(vscf_cipher_cipher_info_api(vscf_cipher_api(envelope.cipher)));
    const size_t derived_key_len = cipher_key_len + mac_key_len;
    derived_key = vsc_buffer_new_with_capacity(derived_key_len);
    vsc_buffer_make_secure(derived_key);
    vscf_kdf_derive(envelope.kdf, vsc_buffer_data(shared_key), derived_key_len, derived_key);

    vsc_data_t cipher_key = vsc_data_slice_beg(vsc_buffer_data(derived_key), 0, cipher_key_len);
    vsc_data_t mac_key = vsc_data_slice_beg(vsc_buffer_data(derived_key), cipher_key_len, mac_key_len);

    //
    //  Get HMAC for encrypted message and compare it.
    //
    mac_digest = vsc_buffer_new_with_capacity(vscf_mac_digest_len(envelope.mac));
    vscf_mac_start(envelope.mac, mac_key);
    vscf_mac_update(envelope.mac, vsc_buffer_data(envelope.encrypted_content));
    vscf_mac_finish(envelope.mac, mac_digest);

    if (!vsc_buffer_secure_equal(envelope.mac_digest, mac_digest)) {
        vscf_error_update(&error, vscf_status_ERROR_BAD_ENCRYPTED_DATA);
        goto mac_validation_failed;
    }

    //
    //  Decrypt given message.
    //
    vscf_cipher_set_key(envelope.cipher, cipher_key);
    vscf_cipher_start_decryption(envelope.cipher);
    vscf_cipher_update(envelope.cipher, vsc_buffer_data(envelope.encrypted_content), out);
    vscf_error_update(&error, vscf_cipher_finish(envelope.cipher, out));

//
//  Cleanup.
//
mac_validation_failed:
    vsc_buffer_destroy(&mac_digest);
    vsc_buffer_destroy(&derived_key);

compute_shared_failed:
    vsc_buffer_destroy(&shared_key);

unpack_envelope_failed:
    vscf_impl_destroy(&ephemeral_public_key);
    vscf_ecies_envelope_cleanup_properties(&envelope);

    return vscf_error_status(&error);
}
