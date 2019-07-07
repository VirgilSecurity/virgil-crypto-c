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
//  This module contains logic for interface/implementation architecture.
//  Do not use this module in any part of the code.
// --------------------------------------------------------------------------


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------

#include "vscf_ecies_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_ecies_defs.h"
#include "vscf_encrypt.h"
#include "vscf_encrypt_api.h"
#include "vscf_decrypt.h"
#include "vscf_decrypt_api.h"
#include "vscf_random.h"
#include "vscf_cipher.h"
#include "vscf_mac.h"
#include "vscf_kdf.h"
#include "vscf_public_key.h"
#include "vscf_private_key.h"
#include "vscf_private_key.h"
#include "vscf_impl.h"
#include "vscf_api.h"

// clang-format on
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

static const vscf_api_t *
vscf_ecies_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'encrypt api'.
//
static const vscf_encrypt_api_t encrypt_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'encrypt' MUST be equal to the 'vscf_api_tag_ENCRYPT'.
    //
    vscf_api_tag_ENCRYPT,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_ECIES,
    //
    //  Encrypt given data.
    //
    (vscf_encrypt_api_encrypt_fn)vscf_ecies_encrypt,
    //
    //  Calculate required buffer length to hold the encrypted data.
    //
    (vscf_encrypt_api_encrypted_len_fn)vscf_ecies_encrypted_len
};

//
//  Configuration of the interface API 'decrypt api'.
//
static const vscf_decrypt_api_t decrypt_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'decrypt' MUST be equal to the 'vscf_api_tag_DECRYPT'.
    //
    vscf_api_tag_DECRYPT,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_ECIES,
    //
    //  Decrypt given data.
    //
    (vscf_decrypt_api_decrypt_fn)vscf_ecies_decrypt,
    //
    //  Calculate required buffer length to hold the decrypted data.
    //
    (vscf_decrypt_api_decrypted_len_fn)vscf_ecies_decrypted_len
};

//
//  Compile-time known information about 'ecies' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_ECIES,
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_ecies_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_ecies_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_ecies_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_ecies_init(vscf_ecies_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_ecies_t));

    self->info = &info;
    self->refcnt = 1;

    vscf_ecies_init_ctx(self);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_ecies_init()'.
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
    vscf_ecies_release_encryption_key(self);
    vscf_ecies_release_decryption_key(self);
    vscf_ecies_release_ephemeral_key(self);

    vscf_ecies_cleanup_ctx(self);

    vscf_zeroize(self, sizeof(vscf_ecies_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_ecies_t *
vscf_ecies_new(void) {

    vscf_ecies_t *self = (vscf_ecies_t *) vscf_alloc(sizeof (vscf_ecies_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_ecies_init(self);

    return self;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_ecies_new()'.
//
VSCF_PUBLIC void
vscf_ecies_delete(vscf_ecies_t *self) {

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

    vscf_ecies_cleanup(self);

    vscf_dealloc(self);
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_ecies_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_ecies_destroy(vscf_ecies_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_ecies_t *self = *self_ref;
    *self_ref = NULL;

    vscf_ecies_delete(self);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_ecies_t *
vscf_ecies_shallow_copy(vscf_ecies_t *self) {

    // Proxy to the parent implementation.
    return (vscf_ecies_t *)vscf_impl_shallow_copy((vscf_impl_t *)self);
}

//
//  Return size of 'vscf_ecies_t' type.
//
VSCF_PUBLIC size_t
vscf_ecies_impl_size(void) {

    return sizeof (vscf_ecies_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ecies_impl(vscf_ecies_t *self) {

    VSCF_ASSERT_PTR(self);
    return (vscf_impl_t *)(self);
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
//  Set public key that is used for data encryption.
//
//  If ephemeral key is not defined, then Public Key, must be conformed
//  to the interface "generate ephemeral key".
//
//  In turn, Ephemeral Key must be conformed to the interface
//  "compute shared key".
//
//  Note, ownership is shared.
//
VSCF_PUBLIC void
vscf_ecies_use_encryption_key(vscf_ecies_t *self, vscf_impl_t *encryption_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(encryption_key);
    VSCF_ASSERT(self->encryption_key == NULL);

    VSCF_ASSERT(vscf_public_key_is_implemented(encryption_key));

    self->encryption_key = vscf_impl_shallow_copy(encryption_key);
}

//
//  Set public key that is used for data encryption.
//
//  If ephemeral key is not defined, then Public Key, must be conformed
//  to the interface "generate ephemeral key".
//
//  In turn, Ephemeral Key must be conformed to the interface
//  "compute shared key".
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_ecies_take_encryption_key(vscf_ecies_t *self, vscf_impl_t *encryption_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(encryption_key);
    VSCF_ASSERT(self->encryption_key == NULL);

    VSCF_ASSERT(vscf_public_key_is_implemented(encryption_key));

    self->encryption_key = encryption_key;
}

//
//  Release dependency to the interface 'public key'.
//
VSCF_PUBLIC void
vscf_ecies_release_encryption_key(vscf_ecies_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->encryption_key);
}

//
//  Set private key that used for data decryption.
//
//  Private Key must be conformed to the interface "compute shared key".
//
//  Note, ownership is shared.
//
VSCF_PUBLIC void
vscf_ecies_use_decryption_key(vscf_ecies_t *self, vscf_impl_t *decryption_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(decryption_key);
    VSCF_ASSERT(self->decryption_key == NULL);

    VSCF_ASSERT(vscf_private_key_is_implemented(decryption_key));

    self->decryption_key = vscf_impl_shallow_copy(decryption_key);
}

//
//  Set private key that used for data decryption.
//
//  Private Key must be conformed to the interface "compute shared key".
//
//  Note, ownership is transfered.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_ecies_take_decryption_key(vscf_ecies_t *self, vscf_impl_t *decryption_key) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(decryption_key);
    VSCF_ASSERT(self->decryption_key == NULL);

    VSCF_ASSERT(vscf_private_key_is_implemented(decryption_key));

    self->decryption_key = decryption_key;
}

//
//  Release dependency to the interface 'private key'.
//
VSCF_PUBLIC void
vscf_ecies_release_decryption_key(vscf_ecies_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->decryption_key);
}

//
//  Set private key that used for data decryption.
//
//  Ephemeral Key must be conformed to the interface "compute shared key".
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
//  Set private key that used for data decryption.
//
//  Ephemeral Key must be conformed to the interface "compute shared key".
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

static const vscf_api_t *
vscf_ecies_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_DECRYPT:
            return (const vscf_api_t *) &decrypt_api;
        case vscf_api_tag_ENCRYPT:
            return (const vscf_api_t *) &encrypt_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
