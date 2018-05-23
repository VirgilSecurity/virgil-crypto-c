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
//  Provide interface for authenticated data encryption.
// --------------------------------------------------------------------------

#ifndef VSF_AUTH_ENCRYPT_H_INCLUDED
#define VSF_AUTH_ENCRYPT_H_INCLUDED

#include "vsf_library.h"
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
//  Contains API requirements of the interface 'auth encrypt'.
//
typedef struct vsf_auth_encrypt_api_t vsf_auth_encrypt_api_t;

//
//  Encrypt given data.
//
VSF_PUBLIC int
vsf_auth_encrypt (vsf_impl_t* impl, const byte* data, size_t data_len, const byte* auth_data,
        size_t auth_data_len, byte* enc, size_t enc_len, size_t* out_len, byte* tag,
        size_t tag_len);

//
//  Return auth encrypt API, or NULL if it is not implemented.
//
VSF_PUBLIC const vsf_auth_encrypt_api_t*
vsf_auth_encrypt_api (vsf_impl_t* impl);

//
//  Return size of 'vsf_auth_encrypt_api_t' type.
//
VSF_PUBLIC size_t
vsf_auth_encrypt_api_size (void);

//
//  Check if given object implements interface 'auth encrypt'.
//
VSF_PUBLIC bool
vsf_auth_encrypt_is_implemented (vsf_impl_t* impl);


// --------------------------------------------------------------------------
//  Generated section end.
// --------------------------------------------------------------------------
//  @end


#ifdef __cplusplus
}
#endif


//  @footer
#endif // VSF_AUTH_ENCRYPT_H_INCLUDED
//  @end
