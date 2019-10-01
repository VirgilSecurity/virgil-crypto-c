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

#ifndef VSCF_CIPHER_AUTH_API_H_INCLUDED
#define VSCF_CIPHER_AUTH_API_H_INCLUDED

#include "vscf_library.h"
#include "vscf_api.h"
#include "vscf_impl.h"
#include "vscf_cipher.h"
#include "vscf_auth_encrypt.h"
#include "vscf_auth_decrypt.h"
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
//  Callback. Set additional data for for AEAD ciphers.
//
typedef void (*vscf_cipher_auth_api_set_auth_data_fn)(vscf_impl_t *impl, vsc_data_t auth_data);

//
//  Callback. Accomplish an authenticated encryption and place tag separately.
//
//          Note, if authentication tag should be added to an encrypted data,
//          method "finish" can be used.
//
typedef vscf_status_t (*vscf_cipher_auth_api_finish_auth_encryption_fn)(vscf_impl_t *impl, vsc_buffer_t *out,
        vsc_buffer_t *tag);

//
//  Callback. Accomplish an authenticated decryption with explicitly given tag.
//
//          Note, if authentication tag is a part of an encrypted data then,
//          method "finish" can be used for simplicity.
//
typedef vscf_status_t (*vscf_cipher_auth_api_finish_auth_decryption_fn)(vscf_impl_t *impl, vsc_data_t tag,
        vsc_buffer_t *out);

//
//  Contains API requirements of the interface 'cipher auth'.
//
struct vscf_cipher_auth_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'cipher_auth' MUST be equal to the 'vscf_api_tag_CIPHER_AUTH'.
    //
    vscf_api_tag_t api_tag;
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_t impl_tag;
    //
    //  Link to the inherited interface API 'cipher'.
    //
    const vscf_cipher_api_t *cipher_api;
    //
    //  Link to the inherited interface API 'auth encrypt'.
    //
    const vscf_auth_encrypt_api_t *auth_encrypt_api;
    //
    //  Link to the inherited interface API 'auth decrypt'.
    //
    const vscf_auth_decrypt_api_t *auth_decrypt_api;
    //
    //  Set additional data for for AEAD ciphers.
    //
    vscf_cipher_auth_api_set_auth_data_fn set_auth_data_cb;
    //
    //  Accomplish an authenticated encryption and place tag separately.
    //
    //  Note, if authentication tag should be added to an encrypted data,
    //  method "finish" can be used.
    //
    vscf_cipher_auth_api_finish_auth_encryption_fn finish_auth_encryption_cb;
    //
    //  Accomplish an authenticated decryption with explicitly given tag.
    //
    //  Note, if authentication tag is a part of an encrypted data then,
    //  method "finish" can be used for simplicity.
    //
    vscf_cipher_auth_api_finish_auth_decryption_fn finish_auth_decryption_cb;
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
#endif // VSCF_CIPHER_AUTH_API_H_INCLUDED
//  @end
