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

#include "vsf_aes256_gcm_internal.h"
#include "vsf_memory.h"
#include "vsf_assert.h"
#include "vsf_aes256_gcm.h"
#include "vsf_aes256_gcm_impl.h"
#include "vsf_encrypt_api.h"
#include "vsf_decrypt_api.h"
#include "vsf_cipher_info_api.h"
#include "vsf_cipher_api.h"
#include "vsf_cipher_auth_info_api.h"
#include "vsf_auth_encrypt_api.h"
#include "vsf_auth_decrypt_api.h"
#include "vsf_cipher_auth_api.h"
//  @end


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Configuration of the interface API 'encrypt api'.
//
static const vsf_encrypt_api_t encrypt_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'encrypt' MUST be equal to the 'vsf_api_tag_ENCRYPT'.
    //
    vsf_api_tag_ENCRYPT,
    //
    //  Encrypt given data.
    //
    (vsf_encrypt_api_encrypt_fn) vsf_aes256_gcm_encrypt,
    //
    //  Calculate required buffer length to hold the encrypted data.
    //  If argument 'auth tag len' is 0, then returned length
    //  adjusted to hold auth tag as well.
    //
    (vsf_encrypt_api_required_enc_len_fn) vsf_aes256_gcm_required_enc_len
};

//
//  Configuration of the interface API 'decrypt api'.
//
static const vsf_decrypt_api_t decrypt_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'decrypt' MUST be equal to the 'vsf_api_tag_DECRYPT'.
    //
    vsf_api_tag_DECRYPT,
    //
    //  Decrypt given data.
    //
    (vsf_decrypt_api_decrypt_fn) vsf_aes256_gcm_decrypt,
    //
    //  Calculate required buffer length to hold the decrypted data.
    //  If argument 'auth tag len' is 0, then returned length
    //  adjusted to cut of auth tag length.
    //
    (vsf_decrypt_api_required_dec_len_fn) vsf_aes256_gcm_required_dec_len
};

//
//  Configuration of the interface API 'cipher info api'.
//
static const vsf_cipher_info_api_t cipher_info_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'cipher_info' MUST be equal to the 'vsf_api_tag_CIPHER_INFO'.
    //
    vsf_api_tag_CIPHER_INFO,
    //
    //  Cipher nfonce length or IV length in bytes, or 0 if nonce is not required.
    //
    vsf_aes256_gcm_NONCE_LEN,
    //
    //  Cipher key length in bytes.
    //
    vsf_aes256_gcm_KEY_LEN,
    //
    //  Cipher key length in bits.
    //
    vsf_aes256_gcm_KEY_BITLEN,
    //
    //  Cipher block length in bytes.
    //
    vsf_aes256_gcm_BLOCK_LEN
};

//
//  Configuration of the interface API 'cipher api'.
//
static const vsf_cipher_api_t cipher_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'cipher' MUST be equal to the 'vsf_api_tag_CIPHER'.
    //
    vsf_api_tag_CIPHER,
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
    (vsf_cipher_api_set_nonce_fn) vsf_aes256_gcm_set_nonce,
    //
    //  Set cipher encryption / decryption key.
    //
    (vsf_cipher_api_set_key_fn) vsf_aes256_gcm_set_key
};

//
//  Configuration of the interface API 'cipher auth info api'.
//
static const vsf_cipher_auth_info_api_t cipher_auth_info_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'cipher_auth_info' MUST be equal to the 'vsf_api_tag_CIPHER_AUTH_INFO'.
    //
    vsf_api_tag_CIPHER_AUTH_INFO,
    //
    //  Defines authentication tag length in bytes.
    //
    vsf_aes256_gcm_AUTH_TAG_LEN
};

//
//  Configuration of the interface API 'auth encrypt api'.
//
static const vsf_auth_encrypt_api_t auth_encrypt_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'auth_encrypt' MUST be equal to the 'vsf_api_tag_AUTH_ENCRYPT'.
    //
    vsf_api_tag_AUTH_ENCRYPT,
    //
    //  Encrypt given data.
    //  If 'tag' is not give, then it will written to the 'enc'.
    //
    (vsf_auth_encrypt_api_auth_encrypt_fn) vsf_aes256_gcm_auth_encrypt
};

//
//  Configuration of the interface API 'auth decrypt api'.
//
static const vsf_auth_decrypt_api_t auth_decrypt_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'auth_decrypt' MUST be equal to the 'vsf_api_tag_AUTH_DECRYPT'.
    //
    vsf_api_tag_AUTH_DECRYPT,
    //
    //  Decrypt given data.
    //  If 'tag' is not give, then it will be taken from the 'enc'.
    //
    (vsf_auth_decrypt_api_auth_decrypt_fn) vsf_aes256_gcm_auth_decrypt
};

//
//  Configuration of the interface API 'cipher auth api'.
//
static const vsf_cipher_auth_api_t cipher_auth_api = {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'cipher_auth' MUST be equal to the 'vsf_api_tag_CIPHER_AUTH'.
    //
    vsf_api_tag_CIPHER_AUTH,
    //
    //  Link to the inherited interface API 'cipher auth info'.
    //
    &cipher_auth_info_api,
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
//  Null-terminated array of the implemented 'Interface API' instances.
//
static const vsf_api_t* api_array[] = {
    (const vsf_api_t*) &encrypt_api,
    (const vsf_api_t*) &decrypt_api,
    (const vsf_api_t*) &cipher_info_api,
    (const vsf_api_t*) &cipher_api,
    (const vsf_api_t*) &cipher_auth_info_api,
    (const vsf_api_t*) &auth_encrypt_api,
    (const vsf_api_t*) &auth_decrypt_api,
    (const vsf_api_t*) &cipher_auth_api,
    NULL
};

//
//  Compile-time known information about 'aes256 gcm' implementation.
//
static const vsf_impl_info_t info = {
    //
    //  Implementation unique identifier, MUST be first in the structure.
    //
    vsf_impl_tag_AES256_GCM,
    //
    //  NULL terminated array of the implemented interfaces.
    //  MUST be second in the structure.
    //
    api_array,
    //
    //  Erase inner state in a secure manner.
    //
    (vsf_impl_cleanup_fn) vsf_aes256_gcm_cleanup,
    //
    //  Self destruction, according to destruction policy.
    //
    (vsf_impl_delete_fn) vsf_aes256_gcm_delete
};

//
//  Perform initialization of preallocated implementation context.
//
VSF_PUBLIC vsf_error_t
vsf_aes256_gcm_init(vsf_aes256_gcm_impl_t* aes256_gcm_impl) {

    VSF_ASSERT_PTR (aes256_gcm_impl);
    VSF_ASSERT_PTR (aes256_gcm_impl->info == NULL);

    aes256_gcm_impl->info = &info;

    return vsf_aes256_gcm_init_ctx (aes256_gcm_impl);
}

//
//  Cleanup implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_aes256_gcm_init ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSF_PUBLIC void
vsf_aes256_gcm_cleanup(vsf_aes256_gcm_impl_t* aes256_gcm_impl) {

    VSF_ASSERT_PTR (aes256_gcm_impl);

    if (aes256_gcm_impl->info == NULL) {
        return;
    }

    vsf_aes256_gcm_cleanup_ctx (aes256_gcm_impl);

    aes256_gcm_impl->info = NULL;
}

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSF_PUBLIC vsf_aes256_gcm_impl_t*
vsf_aes256_gcm_new(void) {

    vsf_aes256_gcm_impl_t *aes256_gcm_impl = (vsf_aes256_gcm_impl_t *) vsf_alloc (sizeof (vsf_aes256_gcm_impl_t));
    VSF_ASSERT_PTR (aes256_gcm_impl);

    vsf_aes256_gcm_init (aes256_gcm_impl);

    return aes256_gcm_impl;
}

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_aes256_gcm_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSF_PUBLIC void
vsf_aes256_gcm_delete(vsf_aes256_gcm_impl_t* aes256_gcm_impl) {

    if (aes256_gcm_impl) {
        vsf_aes256_gcm_cleanup (aes256_gcm_impl);
        vsf_dealloc (aes256_gcm_impl);
    }
}

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_aes256_gcm_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//  Given reference is nullified.
//
VSF_PUBLIC void
vsf_aes256_gcm_destroy(vsf_aes256_gcm_impl_t** aes256_gcm_impl_ref) {

    VSF_ASSERT_PTR (aes256_gcm_impl_ref);

    vsf_aes256_gcm_impl_t *aes256_gcm_impl = *aes256_gcm_impl_ref;
    *aes256_gcm_impl_ref = NULL;

    vsf_aes256_gcm_delete (aes256_gcm_impl);
}

//
//  Returns instance of the implemented interface 'cipher info'.
//
VSF_PUBLIC const vsf_cipher_info_api_t*
vsf_aes256_gcm_cipher_info_api(void) {

    return &cipher_info_api;
}

//
//  Returns instance of the implemented interface 'cipher auth info'.
//
VSF_PUBLIC const vsf_cipher_auth_info_api_t*
vsf_aes256_gcm_cipher_auth_info_api(void) {

    return &cipher_auth_info_api;
}

//
//  Returns instance of the implemented interface 'cipher auth'.
//
VSF_PUBLIC const vsf_cipher_auth_api_t*
vsf_aes256_gcm_cipher_auth_api(void) {

    return &cipher_auth_api;
}

//
//  Return size of 'vsf_aes256_gcm_impl_t' type.
//
VSF_PUBLIC size_t
vsf_aes256_gcm_impl_size(void) {

    return sizeof (vsf_aes256_gcm_impl_t);
}

//
//  Cast to the 'vsf_impl_t' type.
//
VSF_PUBLIC vsf_impl_t*
vsf_aes256_gcm_impl(vsf_aes256_gcm_impl_t* aes256_gcm_impl) {

    VSF_ASSERT_PTR (aes256_gcm_impl);
    return (vsf_impl_t *) (aes256_gcm_impl);
}


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end
