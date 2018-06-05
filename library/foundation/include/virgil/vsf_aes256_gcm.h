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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  This module contains 'aes256 gcm' implementation.
// --------------------------------------------------------------------------

#ifndef VSF_AES256_GCM_H_INCLUDED
#define VSF_AES256_GCM_H_INCLUDED

#include "vsf_library.h"
#include "vsf_error.h"
#include "vsf_impl.h"
#include "vsf_encrypt.h"
#include "vsf_decrypt.h"
#include "vsf_cipher_info.h"
#include "vsf_cipher.h"
#include "vsf_cipher_auth_info.h"
#include "vsf_auth_encrypt.h"
#include "vsf_auth_decrypt.h"
#include "vsf_cipher_auth.h"
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Public integral constants.
//
enum {
    vsf_aes256_gcm_NONCE_LEN = 12,
    vsf_aes256_gcm_KEY_LEN = 32,
    vsf_aes256_gcm_KEY_BITLEN = 256,
    vsf_aes256_gcm_BLOCK_LEN = 16,
    vsf_aes256_gcm_AUTH_TAG_LEN = 16
};

//
//  Handles implementation details.
//
typedef struct vsf_aes256_gcm_impl_t vsf_aes256_gcm_impl_t;

//
//  Return size of 'vsf_aes256_gcm_impl_t' type.
//
VSF_PUBLIC size_t
vsf_aes256_gcm_impl_size(void);

//
//  Cast to the 'vsf_impl_t' type.
//
VSF_PUBLIC vsf_impl_t*
vsf_aes256_gcm_impl(vsf_aes256_gcm_impl_t* aes256_gcm_impl);

//
//  Perform initialization of preallocated implementation context.
//
VSF_PUBLIC vsf_error_t
vsf_aes256_gcm_init(vsf_aes256_gcm_impl_t* aes256_gcm_impl);

//
//  Cleanup implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_aes256_gcm_init ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSF_PUBLIC void
vsf_aes256_gcm_cleanup(vsf_aes256_gcm_impl_t* aes256_gcm_impl);

//
//  Allocate implementation context and perform it's initialization.
//  Postcondition: check memory allocation result.
//
VSF_PUBLIC vsf_aes256_gcm_impl_t*
vsf_aes256_gcm_new(void);

//
//  Delete given implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_aes256_gcm_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//
VSF_PUBLIC void
vsf_aes256_gcm_delete(vsf_aes256_gcm_impl_t* aes256_gcm_impl);

//
//  Destroy given implementation context and it's dependencies.
//  This is a reverse action of the function 'vsf_aes256_gcm_new ()'.
//  All dependencies that is not under ownership will be cleaned up.
//  All dependencies that is under ownership will be destroyed.
//  Given reference is nullified.
//
VSF_PUBLIC void
vsf_aes256_gcm_destroy(vsf_aes256_gcm_impl_t** aes256_gcm_impl_ref);

//
//  Returns instance of the implemented interface 'cipher info'.
//
VSF_PUBLIC const vsf_cipher_info_api_t*
vsf_aes256_gcm_cipher_info_api(void);

//
//  Returns instance of the implemented interface 'cipher auth info'.
//
VSF_PUBLIC const vsf_cipher_auth_info_api_t*
vsf_aes256_gcm_cipher_auth_info_api(void);

//
//  Returns instance of the implemented interface 'cipher auth'.
//
VSF_PUBLIC const vsf_cipher_auth_api_t*
vsf_aes256_gcm_cipher_auth_api(void);

//
//  Encrypt given data.
//
VSF_PUBLIC vsf_error_t
vsf_aes256_gcm_encrypt(vsf_aes256_gcm_impl_t* aes256_gcm_impl, const byte* data, size_t data_len,
        byte* enc, size_t enc_len, size_t* out_len);

//
//  Calculate required buffer length to hold the encrypted data.
//  If argument 'auth tag len' is 0, then returned length
//  adjusted to hold auth tag as well.
//
VSF_PUBLIC size_t
vsf_aes256_gcm_required_enc_len(vsf_aes256_gcm_impl_t* aes256_gcm_impl, size_t data_len,
        size_t auth_tag_len);

//
//  Decrypt given data.
//
VSF_PUBLIC vsf_error_t
vsf_aes256_gcm_decrypt(vsf_aes256_gcm_impl_t* aes256_gcm_impl, const byte* enc, size_t enc_len,
        byte* plain, size_t plain_len, size_t* out_len);

//
//  Calculate required buffer length to hold the decrypted data.
//  If argument 'auth tag len' is 0, then returned length
//  adjusted to cut of auth tag length.
//
VSF_PUBLIC size_t
vsf_aes256_gcm_required_dec_len(vsf_aes256_gcm_impl_t* aes256_gcm_impl, size_t enc_len,
        size_t auth_tag_len);

//
//  Setup IV or nonce.
//
VSF_PUBLIC void
vsf_aes256_gcm_set_nonce(vsf_aes256_gcm_impl_t* aes256_gcm_impl, const byte* nonce,
        size_t nonce_len);

//
//  Set cipher encryption / decryption key.
//
VSF_PUBLIC void
vsf_aes256_gcm_set_key(vsf_aes256_gcm_impl_t* aes256_gcm_impl, const byte* key, size_t key_len);

//
//  Encrypt given data.
//  If 'tag' is not give, then it will written to the 'enc'.
//
VSF_PUBLIC vsf_error_t
vsf_aes256_gcm_auth_encrypt(vsf_aes256_gcm_impl_t* aes256_gcm_impl, const byte* data,
        size_t data_len, const byte* auth_data, size_t auth_data_len, byte* enc, size_t enc_len,
        size_t* out_len, byte* tag, size_t tag_len);

//
//  Decrypt given data.
//  If 'tag' is not give, then it will be taken from the 'enc'.
//
VSF_PUBLIC vsf_error_t
vsf_aes256_gcm_auth_decrypt(vsf_aes256_gcm_impl_t* aes256_gcm_impl, const byte* enc, size_t enc_len,
        const byte* auth_data, size_t auth_data_len, const byte* tag, size_t tag_len, byte* dec,
        size_t dec_len, size_t* out_len);


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSF_AES256_GCM_H_INCLUDED
//  @end
