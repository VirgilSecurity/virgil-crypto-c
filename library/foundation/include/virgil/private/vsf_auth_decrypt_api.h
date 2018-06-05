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
//  Interface 'auth decrypt' API.
// --------------------------------------------------------------------------

#ifndef VSF_AUTH_DECRYPT_API_H_INCLUDED
#define VSF_AUTH_DECRYPT_API_H_INCLUDED

#include "vsf_library.h"
#include "vsf_error.h"
#include "vsf_api.h"
#include "vsf_impl.h"
//  @end


#ifdef __cplusplus
extern "C" {
#endif


//  @generated
// --------------------------------------------------------------------------
// clang-format off
//  Generated section start.
// --------------------------------------------------------------------------

//
//  Callback. Decrypt given data.
//          If 'tag' is not give, then it will be taken from the 'enc'.
//
typedef vsf_error_t (*vsf_auth_decrypt_api_auth_decrypt_fn)(vsf_impl_t* impl, const byte* enc, size_t enc_len,
        const byte* auth_data, size_t auth_data_len, const byte* tag, size_t tag_len, byte* dec, size_t dec_len,
        size_t* out_len);

//
//  Contains API requirements of the interface 'auth decrypt'.
//
struct vsf_auth_decrypt_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'auth_decrypt' MUST be equal to the 'vsf_api_tag_AUTH_DECRYPT'.
    //
    vsf_api_tag_t api_tag;
    //
    //  Decrypt given data.
    //  If 'tag' is not give, then it will be taken from the 'enc'.
    //
    vsf_auth_decrypt_api_auth_decrypt_fn auth_decrypt_cb;
};


// --------------------------------------------------------------------------
//  Generated section end.
// clang-format on
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSF_AUTH_DECRYPT_API_H_INCLUDED
//  @end
