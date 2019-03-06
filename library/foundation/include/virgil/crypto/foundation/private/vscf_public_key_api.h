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
//  Interface 'public key' API.
// --------------------------------------------------------------------------

#ifndef VSCF_PUBLIC_KEY_API_H_INCLUDED
#define VSCF_PUBLIC_KEY_API_H_INCLUDED

#include "vscf_library.h"
#include "vscf_api.h"
#include "vscf_impl.h"
#include "vscf_key.h"
#include "vscf_status.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#   include <virgil/crypto/common/vsc_data.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <VSCCommon/vsc_buffer.h>
#   include <VSCCommon/vsc_data.h>
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
//  Callback. Export public key in the binary format.
//
//          Binary format must be defined in the key specification.
//          For instance, RSA public key must be exported in format defined in
//          RFC 3447 Appendix A.1.1.
//
typedef vscf_status_t (*vscf_public_key_api_export_public_key_fn)(const vscf_impl_t *impl, vsc_buffer_t *out);

//
//  Callback. Return length in bytes required to hold exported public key.
//
typedef size_t (*vscf_public_key_api_exported_public_key_len_fn)(const vscf_impl_t *impl);

//
//  Callback. Import public key from the binary format.
//
//          Binary format must be defined in the key specification.
//          For instance, RSA public key must be imported from the format defined in
//          RFC 3447 Appendix A.1.1.
//
typedef vscf_status_t (*vscf_public_key_api_import_public_key_fn)(vscf_impl_t *impl, vsc_data_t data);

//
//  Contains API requirements of the interface 'public key'.
//
struct vscf_public_key_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'public_key' MUST be equal to the 'vscf_api_tag_PUBLIC_KEY'.
    //
    vscf_api_tag_t api_tag;
    //
    //  Link to the inherited interface API 'key'.
    //
    const vscf_key_api_t *key_api;
    //
    //  Export public key in the binary format.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA public key must be exported in format defined in
    //  RFC 3447 Appendix A.1.1.
    //
    vscf_public_key_api_export_public_key_fn export_public_key_cb;
    //
    //  Return length in bytes required to hold exported public key.
    //
    vscf_public_key_api_exported_public_key_len_fn exported_public_key_len_cb;
    //
    //  Import public key from the binary format.
    //
    //  Binary format must be defined in the key specification.
    //  For instance, RSA public key must be imported from the format defined in
    //  RFC 3447 Appendix A.1.1.
    //
    vscf_public_key_api_import_public_key_fn import_public_key_cb;
    //
    //  Define whether a public key can be exported or not.
    //
    bool can_export_public_key;
    //
    //  Defines whether a public key can be imported or not.
    //
    bool can_import_public_key;
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
#endif // VSCF_PUBLIC_KEY_API_H_INCLUDED
//  @end
