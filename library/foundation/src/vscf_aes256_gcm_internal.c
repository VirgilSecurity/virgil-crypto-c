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

#include "vscf_aes256_gcm_internal.h"
#include "vscf_memory.h"
#include "vscf_assert.h"
#include "vscf_aes256_gcm_defs.h"
#include "vscf_encrypt.h"
#include "vscf_encrypt_api.h"
#include "vscf_decrypt.h"
#include "vscf_decrypt_api.h"
#include "vscf_cipher_info.h"
#include "vscf_cipher_info_api.h"
#include "vscf_cipher.h"
#include "vscf_cipher_api.h"
#include "vscf_cipher_auth_info.h"
#include "vscf_cipher_auth_info_api.h"
#include "vscf_auth_encrypt.h"
#include "vscf_auth_encrypt_api.h"
#include "vscf_auth_decrypt.h"
#include "vscf_auth_decrypt_api.h"
#include "vscf_cipher_auth.h"
#include "vscf_cipher_auth_api.h"
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
vscf_aes256_gcm_find_api(vscf_api_tag_t api_tag);

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
    //  Encrypt given data.
    //
    (vscf_encrypt_api_encrypt_fn)vscf_aes256_gcm_encrypt,
    //
    //  Calculate required buffer length to hold the encrypted data.
    //
    (vscf_encrypt_api_encrypted_len_fn)vscf_aes256_gcm_encrypted_len
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
    //  Decrypt given data.
    //
    (vscf_decrypt_api_decrypt_fn)vscf_aes256_gcm_decrypt,
    //
    //  Calculate required buffer length to hold the decrypted data.
    //
    (vscf_decrypt_api_decrypted_len_fn)vscf_aes256_gcm_decrypted_len
};

//
//  Configuration of the interface API 'cipher info api'.
//
static const vscf_cipher_info_api_t cipher_info_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'cipher_info' MUST be equal to the 'vscf_api_tag_CIPHER_INFO'.
    //
    vscf_api_tag_CIPHER_INFO,
    //
    //  Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
    //
    vscf_aes256_gcm_NONCE_LEN,
    //
    //  Cipher key length in bytes.
    //
    vscf_aes256_gcm_KEY_LEN,
    //
    //  Cipher key length in bits.
    //
    vscf_aes256_gcm_KEY_BITLEN,
    //
    //  Cipher block length in bytes.
    //
    vscf_aes256_gcm_BLOCK_LEN
};

//
//  Configuration of the interface API 'cipher api'.
//
static const vscf_cipher_api_t cipher_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'cipher' MUST be equal to the 'vscf_api_tag_CIPHER'.
    //
    vscf_api_tag_CIPHER,
    //
    //  Link to the inherited interface API 'encrypt'.
    //
    &encrypt_api,
    //
    //  Link to the inherited interface API 'decrypt'.
    //
    &decrypt_api,
    //
    //  Link to the inherited interface API 'cipher info'.
    //
    &cipher_info_api,
    //
    //  Setup IV or nonce.
    //
    (vscf_cipher_api_set_nonce_fn)vscf_aes256_gcm_set_nonce,
    //
    //  Set cipher encryption / decryption key.
    //
    (vscf_cipher_api_set_key_fn)vscf_aes256_gcm_set_key
};

//
//  Configuration of the interface API 'cipher auth info api'.
//
static const vscf_cipher_auth_info_api_t cipher_auth_info_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'cipher_auth_info' MUST be equal to the 'vscf_api_tag_CIPHER_AUTH_INFO'.
    //
    vscf_api_tag_CIPHER_AUTH_INFO,
    //
    //  Defines authentication tag length in bytes.
    //
    vscf_aes256_gcm_AUTH_TAG_LEN
};

//
//  Configuration of the interface API 'auth encrypt api'.
//
static const vscf_auth_encrypt_api_t auth_encrypt_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'auth_encrypt' MUST be equal to the 'vscf_api_tag_AUTH_ENCRYPT'.
    //
    vscf_api_tag_AUTH_ENCRYPT,
    //
    //  Link to the inherited interface API 'cipher auth info'.
    //
    &cipher_auth_info_api,
    //
    //  Encrypt given data.
    //  If 'tag' is not give, then it will written to the 'enc'.
    //
    (vscf_auth_encrypt_api_auth_encrypt_fn)vscf_aes256_gcm_auth_encrypt,
    //
    //  Calculate required buffer length to hold the authenticated encrypted data.
    //
    (vscf_auth_encrypt_api_auth_encrypted_len_fn)vscf_aes256_gcm_auth_encrypted_len
};

//
//  Configuration of the interface API 'auth decrypt api'.
//
static const vscf_auth_decrypt_api_t auth_decrypt_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'auth_decrypt' MUST be equal to the 'vscf_api_tag_AUTH_DECRYPT'.
    //
    vscf_api_tag_AUTH_DECRYPT,
    //
    //  Link to the inherited interface API 'cipher auth info'.
    //
    &cipher_auth_info_api,
    //
    //  Decrypt given data.
    //  If 'tag' is not give, then it will be taken from the 'enc'.
    //
    (vscf_auth_decrypt_api_auth_decrypt_fn)vscf_aes256_gcm_auth_decrypt,
    //
    //  Calculate required buffer length to hold the authenticated decrypted data.
    //
    (vscf_auth_decrypt_api_auth_decrypted_len_fn)vscf_aes256_gcm_auth_decrypted_len
};

//
//  Configuration of the interface API 'cipher auth api'.
//
static const vscf_cipher_auth_api_t cipher_auth_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'cipher_auth' MUST be equal to the 'vscf_api_tag_CIPHER_AUTH'.
    //
    vscf_api_tag_CIPHER_AUTH,
    //
    //  Link to the inherited interface API 'auth encrypt'.
    //
    &auth_encrypt_api,
    //
    //  Link to the inherited interface API 'auth decrypt'.
    //
    &auth_decrypt_api
};

//
//  Compile-time known information about 'aes256 gcm' implementation.
//
static const vscf_impl_info_t info = {
    //
    //  Callback that returns API of the requested interface if implemented, otherwise - NULL.
    //  MUST be second in the structure.
    //
    vscf_aes256_gcm_find_api,
    //
    //  Release acquired inner resources.
    //
    (vscf_impl_cleanup_fn)vscf_aes256_gcm_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vscf_impl_delete_fn)vscf_aes256_gcm_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSCF_PUBLIC void
vscf_aes256_gcm_init(vscf_aes256_gcm_t *aes256_gcm) {

    VSCF_ASSERT_PTR(aes256_gcm);

    vscf_zeroize(aes256_gcm, sizeof(vscf_aes256_gcm_t));

    aes256_gcm->info = &info;
    aes256_gcm->refcnt = 1;

    vscf_aes256_gcm_init_ctx(aes256_gcm);
}

//
//  Cleanup implementation context and release dependencies.
//  This is a reverse action of the function 'vscf_aes256_gcm_init()'.
//
VSCF_PUBLIC void
vscf_aes256_gcm_cleanup(vscf_aes256_gcm_t *aes256_gcm) {

    if (aes256_gcm == NULL || aes256_gcm->info == NULL) {
        return;
    }

    if (aes256_gcm->refcnt == 0) {
        return;
    }

    if (--aes256_gcm->refcnt > 0) {
        return;
    }

    vscf_aes256_gcm_cleanup_ctx(aes256_gcm);

    vscf_zeroize(aes256_gcm, sizeof(vscf_aes256_gcm_t));
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSCF_PUBLIC vscf_aes256_gcm_t *
vscf_aes256_gcm_new(void) {

    vscf_aes256_gcm_t *aes256_gcm = (vscf_aes256_gcm_t *) vscf_alloc(sizeof (vscf_aes256_gcm_t));
    VSCF_ASSERT_ALLOC(aes256_gcm);

    vscf_aes256_gcm_init(aes256_gcm);

    return aes256_gcm;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_aes256_gcm_new()'.
//
VSCF_PUBLIC void
vscf_aes256_gcm_delete(vscf_aes256_gcm_t *aes256_gcm) {

    vscf_aes256_gcm_cleanup(aes256_gcm);

    if (aes256_gcm && (aes256_gcm->refcnt == 0)) {
        vscf_dealloc(aes256_gcm);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vscf_aes256_gcm_new()'.
//  Given reference is nullified.
//
VSCF_PUBLIC void
vscf_aes256_gcm_destroy(vscf_aes256_gcm_t **aes256_gcm_ref) {

    VSCF_ASSERT_PTR(aes256_gcm_ref);

    vscf_aes256_gcm_t *aes256_gcm = *aes256_gcm_ref;
    *aes256_gcm_ref = NULL;

    vscf_aes256_gcm_delete(aes256_gcm);
}

//
//  Copy given implementation context by increasing reference counter.
//  If deep copy is required interface 'clonable' can be used.
//
VSCF_PUBLIC vscf_aes256_gcm_t *
vscf_aes256_gcm_shallow_copy(vscf_aes256_gcm_t *aes256_gcm) {

    // Proxy to the parent implementation.
    return (vscf_aes256_gcm_t *)vscf_impl_shallow_copy((vscf_impl_t *)aes256_gcm);
}

//
//  Returns instance of the implemented interface 'cipher info'.
//
VSCF_PUBLIC const vscf_cipher_info_api_t *
vscf_aes256_gcm_cipher_info_api(void) {

    return &cipher_info_api;
}

//
//  Returns instance of the implemented interface 'cipher auth info'.
//
VSCF_PUBLIC const vscf_cipher_auth_info_api_t *
vscf_aes256_gcm_cipher_auth_info_api(void) {

    return &cipher_auth_info_api;
}

//
//  Returns instance of the implemented interface 'cipher auth'.
//
VSCF_PUBLIC const vscf_cipher_auth_api_t *
vscf_aes256_gcm_cipher_auth_api(void) {

    return &cipher_auth_api;
}

//
//  Return size of 'vscf_aes256_gcm_t' type.
//
VSCF_PUBLIC size_t
vscf_aes256_gcm_impl_size(void) {

    return sizeof (vscf_aes256_gcm_t);
}

//
//  Cast to the 'vscf_impl_t' type.
//
VSCF_PUBLIC vscf_impl_t *
vscf_aes256_gcm_impl(vscf_aes256_gcm_t *aes256_gcm) {

    VSCF_ASSERT_PTR(aes256_gcm);
    return (vscf_impl_t *)(aes256_gcm);
}

static const vscf_api_t *
vscf_aes256_gcm_find_api(vscf_api_tag_t api_tag) {

    switch(api_tag) {
        case vscf_api_tag_AUTH_DECRYPT:
            return (const vscf_api_t *) &auth_decrypt_api;
        case vscf_api_tag_AUTH_ENCRYPT:
            return (const vscf_api_t *) &auth_encrypt_api;
        case vscf_api_tag_CIPHER:
            return (const vscf_api_t *) &cipher_api;
        case vscf_api_tag_CIPHER_AUTH:
            return (const vscf_api_t *) &cipher_auth_api;
        case vscf_api_tag_CIPHER_AUTH_INFO:
            return (const vscf_api_t *) &cipher_auth_info_api;
        case vscf_api_tag_CIPHER_INFO:
            return (const vscf_api_t *) &cipher_info_api;
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
