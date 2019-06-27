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

#include "vscf_ed25519_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_ed25519_defs.h"
#include "vscf_alg.h"
#include "vscf_alg_api.h"
#include "vscf_key_alg.h"
#include "vscf_key_alg_api.h"
#include "vscf_key_cipher.h"
#include "vscf_key_cipher_api.h"
#include "vscf_key_signer.h"
#include "vscf_key_signer_api.h"
#include "vscf_compute_shared_key.h"
#include "vscf_compute_shared_key_api.h"
#include "vscf_random.h"
#include "vscf_ecies.h"
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
vscf_ed25519_find_api(vscf_api_tag_t api_tag);

//
//  Configuration of the interface API 'alg api'.
//
static const vscf_alg_api_t alg_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'alg' MUST be equal to the 'vscf_api_tag_ALG'.
    //
    vscf_api_tag_ALG,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_ED25519,
    //
    //  Provide algorithm identificator.
    //
    (vscf_alg_api_alg_id_fn)vscf_ed25519_alg_id,
    //
    //  Produce object with algorithm information and configuration parameters.
    //
    (vscf_alg_api_produce_alg_info_fn)vscf_ed25519_produce_alg_info,
    //
    //  Restore algorithm configuration from the given object.
    //
    (vscf_alg_api_restore_alg_info_fn)vscf_ed25519_restore_alg_info
};

//
//  Configuration of the interface API 'key alg api'.
//
static const vscf_key_alg_api_t key_alg_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'key_alg' MUST be equal to the 'vscf_api_tag_KEY_ALG'.
    //
    vscf_api_tag_KEY_ALG,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_ED25519,
    //
    //  Link to the inherited interface API 'alg'.
    //
    &alg_api,
    //
    //  Generate ephemeral private key of the same type.
    //  Note, this operation might be slow.
    //
    (vscf_key_alg_api_generate_ephemeral_key_fn)vscf_ed25519_generate_ephemeral_key,
    //
    //  Import public key from the raw binary format.
    //
    //  Return public key that is adopted and optimized to be used
    //  with this particular algorithm.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA public key must be imported from the format defined in
    //  RFC 3447 Appendix A.1.1.
    //
    (vscf_key_alg_api_import_public_key_fn)vscf_ed25519_import_public_key,
    //
    //  Export public key to the raw binary format.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA public key must be exported in format defined in
    //  RFC 3447 Appendix A.1.1.
    //
    (vscf_key_alg_api_export_public_key_fn)vscf_ed25519_export_public_key,
    //
    //  Import private key from the raw binary format.
    //
    //  Return private key that is adopted and optimized to be used
    //  with this particular algorithm.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA private key must be imported from the format defined in
    //  RFC 3447 Appendix A.1.2.
    //
    (vscf_key_alg_api_import_private_key_fn)vscf_ed25519_import_private_key,
    //
    //  Export private key in the raw binary format.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA private key must be exported in format defined in
    //  RFC 3447 Appendix A.1.2.
    //
    (vscf_key_alg_api_export_private_key_fn)vscf_ed25519_export_private_key,
    //
    //  Defines whether a public key can be imported or not.
    //
    vscf_ed25519_CAN_IMPORT_PUBLIC_KEY,
    //
    //  Define whether a public key can be exported or not.
    //
    vscf_ed25519_CAN_EXPORT_PUBLIC_KEY,
    //
    //  Define whether a private key can be imported or not.
    //
    vscf_ed25519_CAN_IMPORT_PRIVATE_KEY,
    //
    //  Define whether a private key can be exported or not.
    //
    vscf_ed25519_CAN_EXPORT_PRIVATE_KEY
};

//
//  Configuration of the interface API 'key cipher api'.
//
static const vscf_key_cipher_api_t key_cipher_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'key_cipher' MUST be equal to the 'vscf_api_tag_KEY_CIPHER'.
    //
    vscf_api_tag_KEY_CIPHER,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_ED25519,
    //
    //  Link to the inherited interface API 'key alg'.
    //
    &key_alg_api,
    //
    //  Check if algorithm can encrypt data with a given key.
    //
    (vscf_key_cipher_api_can_encrypt_fn)vscf_ed25519_can_encrypt,
    //
    //  Calculate required buffer length to hold the encrypted data.
    //
    (vscf_key_cipher_api_encrypted_len_fn)vscf_ed25519_encrypted_len,
    //
    //  Encrypt data with a given public key.
    //
    (vscf_key_cipher_api_encrypt_fn)vscf_ed25519_encrypt,
    //
    //  Check if algorithm can decrypt data with a given key.
    //  However, success result of decryption is not guaranteed.
    //
    (vscf_key_cipher_api_can_decrypt_fn)vscf_ed25519_can_decrypt,
    //
    //  Calculate required buffer length to hold the decrypted data.
    //
    (vscf_key_cipher_api_decrypted_len_fn)vscf_ed25519_decrypted_len,
    //
    //  Decrypt given data.
    //
    (vscf_key_cipher_api_decrypt_fn)vscf_ed25519_decrypt
};

//
//  Configuration of the interface API 'key signer api'.
//
static const vscf_key_signer_api_t key_signer_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'key_signer' MUST be equal to the 'vscf_api_tag_KEY_SIGNER'.
    //
    vscf_api_tag_KEY_SIGNER,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_ED25519,
    //
    //  Link to the inherited interface API 'key alg'.
    //
    &key_alg_api,
    //
    //  Check if algorithm can sign data digest with a given key.
    //
    (vscf_key_signer_api_can_sign_fn)vscf_ed25519_can_sign,
    //
    //  Return length in bytes required to hold signature.
    //  Return zero if a given private key can not produce signatures.
    //
    (vscf_key_signer_api_signature_len_fn)vscf_ed25519_signature_len,
    //
    //  Sign data digest with a given private key.
    //
    (vscf_key_signer_api_sign_hash_fn)vscf_ed25519_sign_hash,
    //
    //  Check if algorithm can verify data digest with a given key.
    //
    (vscf_key_signer_api_can_verify_fn)vscf_ed25519_can_verify,
    //
    //  Verify data digest with a given public key and signature.
    //
    (vscf_key_signer_api_verify_hash_fn)vscf_ed25519_verify_hash
};

//
//  Configuration of the interface API 'compute shared key api'.
//
static const vscf_compute_shared_key_api_t compute_shared_key_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'compute_shared_key' MUST be equal to the 'vscf_api_tag_COMPUTE_SHARED_KEY'.
    //
    vscf_api_tag_COMPUTE_SHARED_KEY,
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_ED25519,
    //
    //  Link to the inherited interface API 'key alg'.
    //
    &key_alg_api,
    //
    //  Compute shared key for 2 asymmetric keys.
    //  Note, computed shared key can be used only within symmetric cryptography.
    //
    (vscf_compute_shared_key_api_compute_shared_key_fn)vscf_ed25519_compute_shared_key,
    //
    //  Return number of bytes required to hold shared key.
    //  Expect Public Key or Private Key.
    //
    (vscf_compute_shared_key_api_shared_key_len_fn)vscf_ed25519_shared_key_len
};

//
//  Compile-time known information about 'ed25519' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_ED25519,
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_ed25519_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_ed25519_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_ed25519_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_ed25519_init(vscf_ed25519_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_ed25519_t));

    self->info = &info;
    self->refcnt = 1;
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_ed25519_init()'.
//
VSCF_PUBLIC void
vscf_ed25519_cleanup(vscf_ed25519_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_ed25519_release_random(self);
    vscf_ed25519_release_ecies(self);

    vscf_zeroize(self, sizeof(vscf_ed25519_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_ed25519_t *
vscf_ed25519_new(void) {

    vscf_ed25519_t *self = (vscf_ed25519_t *) vscf_alloc(sizeof (vscf_ed25519_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_ed25519_init(self);

    return self;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_ed25519_new()'.
//
VSCF_PUBLIC void
vscf_ed25519_delete(vscf_ed25519_t *self) {

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

    vscf_ed25519_cleanup(self);

    vscf_dealloc(self);
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_ed25519_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_ed25519_destroy(vscf_ed25519_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_ed25519_t *self = *self_ref;
    *self_ref = NULL;

    vscf_ed25519_delete(self);
}

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_ed25519_t *
vscf_ed25519_shallow_copy(vscf_ed25519_t *self) {

    // Proxy to the parent implementation.
    return (vscf_ed25519_t *)vscf_impl_shallow_copy((vscf_impl_t *)self);
}

//
//  Return size of 'vscf_ed25519_t' type.
//
VSCF_PUBLIC size_t
vscf_ed25519_impl_size(void) {

    return sizeof (vscf_ed25519_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_ed25519_impl(vscf_ed25519_t *self) {

    VSCF_ASSERT_PTR(self);
    return (vscf_impl_t *)(self);
}

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_ed25519_impl_const(const vscf_ed25519_t *self) {

    VSCF_ASSERT_PTR(self);
    return (const vscf_impl_t *)(self);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_ed25519_use_random(vscf_ed25519_t *self, vscf_impl_t *random) {

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
vscf_ed25519_take_random(vscf_ed25519_t *self, vscf_impl_t *random) {

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
vscf_ed25519_release_random(vscf_ed25519_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}

//
//  Setup dependency to the class 'ecies' with shared ownership.
//
VSCF_PUBLIC void
vscf_ed25519_use_ecies(vscf_ed25519_t *self, vscf_ecies_t *ecies) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(ecies);
    VSCF_ASSERT(self->ecies == NULL);

    self->ecies = vscf_ecies_shallow_copy(ecies);
}

//
//  Setup dependency to the class 'ecies' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_ed25519_take_ecies(vscf_ed25519_t *self, vscf_ecies_t *ecies) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(ecies);
    VSCF_ASSERT(self->ecies == NULL);

    self->ecies = ecies;
}

//
//  Release dependency to the class 'ecies'.
//
VSCF_PUBLIC void
vscf_ed25519_release_ecies(vscf_ed25519_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_ecies_destroy(&self->ecies);
}

static const vscf_api_t *
vscf_ed25519_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_ALG:
            return (const vscf_api_t *) &alg_api;
        case vscf_api_tag_COMPUTE_SHARED_KEY:
            return (const vscf_api_t *) &compute_shared_key_api;
        case vscf_api_tag_KEY_ALG:
            return (const vscf_api_t *) &key_alg_api;
        case vscf_api_tag_KEY_CIPHER:
            return (const vscf_api_t *) &key_cipher_api;
        case vscf_api_tag_KEY_SIGNER:
            return (const vscf_api_t *) &key_signer_api;
        default:
            return NULL;
    }
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
