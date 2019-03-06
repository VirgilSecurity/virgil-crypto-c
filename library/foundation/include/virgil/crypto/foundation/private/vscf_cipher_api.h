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
//  Interface 'cipher' API.
// --------------------------------------------------------------------------

#ifndef VSCF_CIPHER_API_H_INCLUDED
#define VSCF_CIPHER_API_H_INCLUDED

#include "vscf_library.h"
#include "vscf_api.h"
#include "vscf_impl.h"
#include "vscf_encrypt.h"
#include "vscf_decrypt.h"
#include "vscf_cipher_info.h"
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
//  Callback. Setup IV or nonce.
//
typedef void (*vscf_cipher_api_set_nonce_fn)(vscf_impl_t *impl, vsc_data_t nonce);

//
//  Callback. Set cipher encryption / decryption key.
//
typedef void (*vscf_cipher_api_set_key_fn)(vscf_impl_t *impl, vsc_data_t key);

//
//  Callback. Start sequential encryption.
//
typedef void (*vscf_cipher_api_start_encryption_fn)(vscf_impl_t *impl);

//
//  Callback. Start sequential decryption.
//
typedef void (*vscf_cipher_api_start_decryption_fn)(vscf_impl_t *impl);

//
//  Callback. Process encryption or decryption of the given data chunk.
//
typedef void (*vscf_cipher_api_update_fn)(vscf_impl_t *impl, vsc_data_t data, vsc_buffer_t *out);

//
//  Callback. Return buffer length required to hold an output of the methods
//          "update" or "finish" in an current mode.
//          Pass zero length to define buffer length of the method "finish".
//
typedef size_t (*vscf_cipher_api_out_len_fn)(vscf_impl_t *impl, size_t data_len);

//
//  Callback. Return buffer length required to hold an output of the methods
//          "update" or "finish" in an encryption mode.
//          Pass zero length to define buffer length of the method "finish".
//
typedef size_t (*vscf_cipher_api_encrypted_out_len_fn)(vscf_impl_t *impl, size_t data_len);

//
//  Callback. Return buffer length required to hold an output of the methods
//          "update" or "finish" in an decryption mode.
//          Pass zero length to define buffer length of the method "finish".
//
typedef size_t (*vscf_cipher_api_decrypted_out_len_fn)(vscf_impl_t *impl, size_t data_len);

//
//  Callback. Accomplish encryption or decryption process.
//
typedef vscf_status_t (*vscf_cipher_api_finish_fn)(vscf_impl_t *impl, vsc_buffer_t *out);

//
//  Contains API requirements of the interface 'cipher'.
//
struct vscf_cipher_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'cipher' MUST be equal to the 'vscf_api_tag_CIPHER'.
    //
    vscf_api_tag_t api_tag;
    //
    //  Link to the inherited interface API 'encrypt'.
    //
    const vscf_encrypt_api_t *encrypt_api;
    //
    //  Link to the inherited interface API 'decrypt'.
    //
    const vscf_decrypt_api_t *decrypt_api;
    //
    //  Link to the inherited interface API 'cipher info'.
    //
    const vscf_cipher_info_api_t *cipher_info_api;
    //
    //  Setup IV or nonce.
    //
    vscf_cipher_api_set_nonce_fn set_nonce_cb;
    //
    //  Set cipher encryption / decryption key.
    //
    vscf_cipher_api_set_key_fn set_key_cb;
    //
    //  Start sequential encryption.
    //
    vscf_cipher_api_start_encryption_fn start_encryption_cb;
    //
    //  Start sequential decryption.
    //
    vscf_cipher_api_start_decryption_fn start_decryption_cb;
    //
    //  Process encryption or decryption of the given data chunk.
    //
    vscf_cipher_api_update_fn update_cb;
    //
    //  Return buffer length required to hold an output of the methods
    //  "update" or "finish" in an current mode.
    //  Pass zero length to define buffer length of the method "finish".
    //
    vscf_cipher_api_out_len_fn out_len_cb;
    //
    //  Return buffer length required to hold an output of the methods
    //  "update" or "finish" in an encryption mode.
    //  Pass zero length to define buffer length of the method "finish".
    //
    vscf_cipher_api_encrypted_out_len_fn encrypted_out_len_cb;
    //
    //  Return buffer length required to hold an output of the methods
    //  "update" or "finish" in an decryption mode.
    //  Pass zero length to define buffer length of the method "finish".
    //
    vscf_cipher_api_decrypted_out_len_fn decrypted_out_len_cb;
    //
    //  Accomplish encryption or decryption process.
    //
    vscf_cipher_api_finish_fn finish_cb;
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
#endif // VSCF_CIPHER_API_H_INCLUDED
//  @end
