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
//  Interface 'cipher' API.
// --------------------------------------------------------------------------

#ifndef VSF_CIPHER_API_H_INCLUDED
#define VSF_CIPHER_API_H_INCLUDED

#include "vsf_library.h"
#include "vsf_error.h"
#include "vsf_api.h"
#include "vsf_impl.h"
#include "vsf_encrypt.h"
#include "vsf_decrypt.h"
#include "vsf_cipher_info.h"
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Callback. Setup IV or nonce.
//
typedef void (*vsf_cipher_api_set_nonce_fn)(vsf_impl_t* impl, const byte* nonce, size_t nonce_len);

//
//  Callback. Set cipher encryption / decryption key.
//
typedef void (*vsf_cipher_api_set_key_fn)(vsf_impl_t* impl, const byte* key, size_t key_len);

//
//  Contains API requirements of the interface 'cipher'.
//
struct vsf_cipher_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'cipher' MUST be equal to the 'vsf_api_tag_CIPHER'.
    //
    vsf_api_tag_t api_tag;
    //
    //  Link to the inherited interface API 'encrypt'.
    //
    const vsf_encrypt_api_t* encrypt_api;
    //
    //  Link to the inherited interface API 'decrypt'.
    //
    const vsf_decrypt_api_t* decrypt_api;
    //
    //  Link to the inherited interface API 'cipher info'.
    //
    const vsf_cipher_info_api_t* cipher_info_api;
    //
    //  Setup IV or nonce.
    //
    vsf_cipher_api_set_nonce_fn set_nonce_cb;
    //
    //  Set cipher encryption / decryption key.
    //
    vsf_cipher_api_set_key_fn set_key_cb;
};


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSF_CIPHER_API_H_INCLUDED
//  @end
