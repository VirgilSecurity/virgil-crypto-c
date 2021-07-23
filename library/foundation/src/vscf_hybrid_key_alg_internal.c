//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2021 Virgil Security, Inc.
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

#include "vscf_hybrid_key_alg_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_hybrid_key_alg_defs.h"
#include "vscf_key_alg.h"
#include "vscf_key_alg_api.h"
#include "vscf_key_cipher.h"
#include "vscf_key_cipher_api.h"
#include "vscf_key_signer.h"
#include "vscf_key_signer_api.h"
#include "vscf_random.h"
#include "vscf_cipher_auth.h"
#include "vscf_hash.h"
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
vscf_hybrid_key_alg_find_api(vscf_api_tag_t api_tag);

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
    vscf_impl_tag_HYBRID_KEY_ALG,
    //
    //  Generate ephemeral private key of the same type.
    //  Note, this operation might be slow.
    //
    (vscf_key_alg_api_generate_ephemeral_key_fn)vscf_hybrid_key_alg_generate_ephemeral_key,
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
    (vscf_key_alg_api_import_public_key_fn)vscf_hybrid_key_alg_import_public_key,
    //
    //  Import public key from the raw binary format.
    //
    (vscf_key_alg_api_import_public_key_data_fn)vscf_hybrid_key_alg_import_public_key_data,
    //
    //  Export public key to the raw binary format.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA public key must be exported in format defined in
    //  RFC 3447 Appendix A.1.1.
    //
    (vscf_key_alg_api_export_public_key_fn)vscf_hybrid_key_alg_export_public_key,
    //
    //  Return length in bytes required to hold exported public key.
    //
    (vscf_key_alg_api_exported_public_key_data_len_fn)vscf_hybrid_key_alg_exported_public_key_data_len,
    //
    //  Export public key to the raw binary format without algorithm information.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA public key must be exported in format defined in
    //  RFC 3447 Appendix A.1.1.
    //
    (vscf_key_alg_api_export_public_key_data_fn)vscf_hybrid_key_alg_export_public_key_data,
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
    (vscf_key_alg_api_import_private_key_fn)vscf_hybrid_key_alg_import_private_key,
    //
    //  Import private key from the raw binary format.
    //
    (vscf_key_alg_api_import_private_key_data_fn)vscf_hybrid_key_alg_import_private_key_data,
    //
    //  Export private key in the raw binary format.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA private key must be exported in format defined in
    //  RFC 3447 Appendix A.1.2.
    //
    (vscf_key_alg_api_export_private_key_fn)vscf_hybrid_key_alg_export_private_key,
    //
    //  Return length in bytes required to hold exported private key.
    //
    (vscf_key_alg_api_exported_private_key_data_len_fn)vscf_hybrid_key_alg_exported_private_key_data_len,
    //
    //  Export private key to the raw binary format without algorithm information.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA private key must be exported in format defined in
    //  RFC 3447 Appendix A.1.2.
    //
    (vscf_key_alg_api_export_private_key_data_fn)vscf_hybrid_key_alg_export_private_key_data,
    //
    //  Defines whether a public key can be imported or not.
    //
    vscf_hybrid_key_alg_CAN_IMPORT_PUBLIC_KEY,
    //
    //  Define whether a public key can be exported or not.
    //
    vscf_hybrid_key_alg_CAN_EXPORT_PUBLIC_KEY,
    //
    //  Define whether a private key can be imported or not.
    //
    vscf_hybrid_key_alg_CAN_IMPORT_PRIVATE_KEY,
    //
    //  Define whether a private key can be exported or not.
    //
    vscf_hybrid_key_alg_CAN_EXPORT_PRIVATE_KEY
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
    vscf_impl_tag_HYBRID_KEY_ALG,
    //
    //  Link to the inherited interface API 'key alg'.
    //
    &key_alg_api,
    //
    //  Check if algorithm can encrypt data with a given key.
    //
    (vscf_key_cipher_api_can_encrypt_fn)vscf_hybrid_key_alg_can_encrypt,
    //
    //  Calculate required buffer length to hold the encrypted data.
    //
    (vscf_key_cipher_api_encrypted_len_fn)vscf_hybrid_key_alg_encrypted_len,
    //
    //  Encrypt data with a given public key.
    //
    (vscf_key_cipher_api_encrypt_fn)vscf_hybrid_key_alg_encrypt,
    //
    //  Check if algorithm can decrypt data with a given key.
    //  However, success result of decryption is not guaranteed.
    //
    (vscf_key_cipher_api_can_decrypt_fn)vscf_hybrid_key_alg_can_decrypt,
    //
    //  Calculate required buffer length to hold the decrypted data.
    //
    (vscf_key_cipher_api_decrypted_len_fn)vscf_hybrid_key_alg_decrypted_len,
    //
    //  Decrypt given data.
    //
    (vscf_key_cipher_api_decrypt_fn)vscf_hybrid_key_alg_decrypt
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
    vscf_impl_tag_HYBRID_KEY_ALG,
    //
    //  Link to the inherited interface API 'key alg'.
    //
    &key_alg_api,
    //
    //  Check if algorithm can sign data digest with a given key.
    //
    (vscf_key_signer_api_can_sign_fn)vscf_hybrid_key_alg_can_sign,
    //
    //  Return length in bytes required to hold signature.
    //  Return zero if a given private key can not produce signatures.
    //
    (vscf_key_signer_api_signature_len_fn)vscf_hybrid_key_alg_signature_len,
    //
    //  Sign data digest with a given private key.
    //
    (vscf_key_signer_api_sign_hash_fn)vscf_hybrid_key_alg_sign_hash,
    //
    //  Check if algorithm can verify data digest with a given key.
    //
    (vscf_key_signer_api_can_verify_fn)vscf_hybrid_key_alg_can_verify,
    //
    //  Verify data digest with a given public key and signature.
    //
    (vscf_key_signer_api_verify_hash_fn)vscf_hybrid_key_alg_verify_hash
};

//
//  Compile-time known information about 'hybrid key alg' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vscf_impl_tag_HYBRID_KEY_ALG,
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_hybrid_key_alg_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_hybrid_key_alg_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_hybrid_key_alg_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_hybrid_key_alg_init(vscf_hybrid_key_alg_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_zeroize(self, sizeof(vscf_hybrid_key_alg_t));

    self->info = &info;
    self->refcnt = 1;
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_hybrid_key_alg_init()'.
//
VSCF_PUBLIC void
vscf_hybrid_key_alg_cleanup(vscf_hybrid_key_alg_t *self) {

    if (self == NULL) {
        return;
    }

    vscf_hybrid_key_alg_release_random(self);
    vscf_hybrid_key_alg_release_cipher(self);
    vscf_hybrid_key_alg_release_hash(self);

    vscf_zeroize(self, sizeof(vscf_hybrid_key_alg_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_hybrid_key_alg_t *
vscf_hybrid_key_alg_new(void) {

    vscf_hybrid_key_alg_t *self = (vscf_hybrid_key_alg_t *) vscf_alloc(sizeof (vscf_hybrid_key_alg_t));
    VSCF_ASSERT_ALLOC(self);

    vscf_hybrid_key_alg_init(self);

    return self;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_hybrid_key_alg_new()'.
//
VSCF_PUBLIC void
vscf_hybrid_key_alg_delete(vscf_hybrid_key_alg_t *self) {

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

    vscf_hybrid_key_alg_cleanup(self);

    vscf_dealloc(self);
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_hybrid_key_alg_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_hybrid_key_alg_destroy(vscf_hybrid_key_alg_t **self_ref) {

    VSCF_ASSERT_PTR(self_ref);

    vscf_hybrid_key_alg_t *self = *self_ref;
    *self_ref = NULL;

    vscf_hybrid_key_alg_delete(self);
}

//
//  Copy given implementation context by increasing reference counter.
//
VSCF_PUBLIC vscf_hybrid_key_alg_t *
vscf_hybrid_key_alg_shallow_copy(vscf_hybrid_key_alg_t *self) {

    // Proxy to the parent implementation.
    return (vscf_hybrid_key_alg_t *)vscf_impl_shallow_copy((vscf_impl_t *)self);
}

//
//  Return size of 'vscf_hybrid_key_alg_t' type.
//
VSCF_PUBLIC size_t
vscf_hybrid_key_alg_impl_size(void) {

    return sizeof (vscf_hybrid_key_alg_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_hybrid_key_alg_impl(vscf_hybrid_key_alg_t *self) {

    VSCF_ASSERT_PTR(self);
    return (vscf_impl_t *)(self);
}

//
//  Cast to the const 'vscf_impl_t' type.
//
VSCF_PUBLIC const vscf_impl_t *
vscf_hybrid_key_alg_impl_const(const vscf_hybrid_key_alg_t *self) {

    VSCF_ASSERT_PTR(self);
    return (const vscf_impl_t *)(self);
}

//
//  Setup dependency to the interface 'random' with shared ownership.
//
VSCF_PUBLIC void
vscf_hybrid_key_alg_use_random(vscf_hybrid_key_alg_t *self, vscf_impl_t *random) {

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
vscf_hybrid_key_alg_take_random(vscf_hybrid_key_alg_t *self, vscf_impl_t *random) {

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
vscf_hybrid_key_alg_release_random(vscf_hybrid_key_alg_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->random);
}

//
//  Setup dependency to the interface 'cipher auth' with shared ownership.
//
VSCF_PUBLIC void
vscf_hybrid_key_alg_use_cipher(vscf_hybrid_key_alg_t *self, vscf_impl_t *cipher) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(cipher);
    VSCF_ASSERT(self->cipher == NULL);

    VSCF_ASSERT(vscf_cipher_auth_is_implemented(cipher));

    self->cipher = vscf_impl_shallow_copy(cipher);
}

//
//  Setup dependency to the interface 'cipher auth' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_hybrid_key_alg_take_cipher(vscf_hybrid_key_alg_t *self, vscf_impl_t *cipher) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(cipher);
    VSCF_ASSERT(self->cipher == NULL);

    VSCF_ASSERT(vscf_cipher_auth_is_implemented(cipher));

    self->cipher = cipher;
}

//
//  Release dependency to the interface 'cipher auth'.
//
VSCF_PUBLIC void
vscf_hybrid_key_alg_release_cipher(vscf_hybrid_key_alg_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->cipher);
}

//
//  Setup dependency to the interface 'hash' with shared ownership.
//
VSCF_PUBLIC void
vscf_hybrid_key_alg_use_hash(vscf_hybrid_key_alg_t *self, vscf_impl_t *hash) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(hash);
    VSCF_ASSERT(self->hash == NULL);

    VSCF_ASSERT(vscf_hash_is_implemented(hash));

    self->hash = vscf_impl_shallow_copy(hash);
}

//
//  Setup dependency to the interface 'hash' and transfer ownership.
//  Note, transfer ownership does not mean that object is uniquely owned by the target object.
//
VSCF_PUBLIC void
vscf_hybrid_key_alg_take_hash(vscf_hybrid_key_alg_t *self, vscf_impl_t *hash) {

    VSCF_ASSERT_PTR(self);
    VSCF_ASSERT_PTR(hash);
    VSCF_ASSERT(self->hash == NULL);

    VSCF_ASSERT(vscf_hash_is_implemented(hash));

    self->hash = hash;
}

//
//  Release dependency to the interface 'hash'.
//
VSCF_PUBLIC void
vscf_hybrid_key_alg_release_hash(vscf_hybrid_key_alg_t *self) {

    VSCF_ASSERT_PTR(self);

    vscf_impl_destroy(&self->hash);
}

static const vscf_api_t *
vscf_hybrid_key_alg_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
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
