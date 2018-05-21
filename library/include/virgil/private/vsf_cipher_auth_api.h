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
//  Interface 'cipher auth' API.
// --------------------------------------------------------------------------

#ifndef VSF_CIPHER_AUTH_API_H_INCLUDED
#define VSF_CIPHER_AUTH_API_H_INCLUDED

#include "vsf_library.h"
#include "vsf_api.h"
#include "vsf_impl.h"
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Callback. Setup additional data.
//          Must be called before encryption / decryption operation.
//
typedef void (*vsf_cipher_auth_api_set_data_fn) (vsf_impl_t* impl, const byte* data,
        size_t data_len);

//
//  Callback. Write authentication tag.
//          Must be called after encryption is finished.
//
typedef void (*vsf_cipher_auth_api_write_tag_fn) (vsf_impl_t* impl, byte* tag, size_t tag_len);

//
//  Callback. Validate authentication tag.
//          Must be called after decryption is finished.
//
typedef void (*vsf_cipher_auth_api_check_tag_fn) (vsf_impl_t* impl, const byte* tag,
        size_t tag_len);

//
//  Contains API requirements of the interface 'cipher auth'.
//
struct vsf_cipher_auth_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'cipher_auth' MUST be equal to the 'vsf_api_tag_CIPHER_AUTH'.
    //
    vsf_api_tag_t api_tag;
    //
    //  Setup additional data.
    //  Must be called before encryption / decryption operation.
    //
    vsf_cipher_auth_api_set_data_fn set_data_cb;
    //
    //  Write authentication tag.
    //  Must be called after encryption is finished.
    //
    vsf_cipher_auth_api_write_tag_fn write_tag_cb;
    //
    //  Validate authentication tag.
    //  Must be called after decryption is finished.
    //
    vsf_cipher_auth_api_check_tag_fn check_tag_cb;
    //
    //  Defines authentication tag length in bytes.
    //
    size_t tag_len;
};


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSF_CIPHER_AUTH_API_H_INCLUDED
//  @end
