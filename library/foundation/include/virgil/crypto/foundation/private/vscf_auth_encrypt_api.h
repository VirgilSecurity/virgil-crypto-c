//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2022 Virgil Security, Inc.
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


//  @warning
// --------------------------------------------------------------------------
//  This file is partially generated.
//  Generated blocks are enclosed between tags [@<tag>, @end].
//  User's code can be added between tags [@end, @<tag>].
// --------------------------------------------------------------------------


//  @description
// --------------------------------------------------------------------------
//  Interface 'auth encrypt' API.
// --------------------------------------------------------------------------

#ifndef VSCF_AUTH_ENCRYPT_API_H_INCLUDED
#define VSCF_AUTH_ENCRYPT_API_H_INCLUDED

#include "vscf_library.h"
#include "vscf_api.h"
#include "vscf_impl.h"
#include "vscf_cipher_auth_info.h"
#include "vscf_status.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_data.h>
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_data.h>
#   include <VSCCommon/vsc_buffer.h>
#endif

// clang-format on
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
//  Callback. Encrypt given data.
//          If 'tag' is not given, then it will written to the 'enc'.
//
typedef vscf_status_t (*vscf_auth_encrypt_api_auth_encrypt_fn)(vscf_impl_t *impl, vsc_data_t data, vsc_data_t auth_data,
        vsc_buffer_t *out, vsc_buffer_t *tag);

//
//  Callback. Calculate required buffer length to hold the authenticated encrypted data.
//
typedef size_t (*vscf_auth_encrypt_api_auth_encrypted_len_fn)(const vscf_impl_t *impl, size_t data_len);

//
//  Contains API requirements of the interface 'auth encrypt'.
//
struct vscf_auth_encrypt_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'auth_encrypt' MUST be equal to the 'vscf_api_tag_AUTH_ENCRYPT'.
    //
    vscf_api_tag_t api_tag;
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_t impl_tag;
    //
    //  Link to the inherited interface API 'cipher auth info'.
    //
    const vscf_cipher_auth_info_api_t *cipher_auth_info_api;
    //
    //  Encrypt given data.
    //  If 'tag' is not given, then it will written to the 'enc'.
    //
    vscf_auth_encrypt_api_auth_encrypt_fn auth_encrypt_cb;
    //
    //  Calculate required buffer length to hold the authenticated encrypted data.
    //
    vscf_auth_encrypt_api_auth_encrypted_len_fn auth_encrypted_len_cb;
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
#endif // VSCF_AUTH_ENCRYPT_API_H_INCLUDED
//  @end
