//  @license
// --------------------------------------------------------------------------
//  Copyright (C) 2015-2020 Virgil Security, Inc.
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
//  Interface 'kem' API.
// --------------------------------------------------------------------------

#ifndef VSCF_KEM_API_H_INCLUDED
#define VSCF_KEM_API_H_INCLUDED

#include "vscf_library.h"
#include "vscf_api.h"
#include "vscf_impl.h"
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
//  Callback. Return length in bytes required to hold encapsulated shared key.
//
typedef size_t (*vscf_kem_api_kem_shared_key_len_fn)(const vscf_impl_t *impl, const vscf_impl_t *key);

//
//  Callback. Return length in bytes required to hold encapsulated key.
//
typedef size_t (*vscf_kem_api_kem_encapsulated_key_len_fn)(const vscf_impl_t *impl, const vscf_impl_t *public_key);

//
//  Callback. Generate a shared key and a key encapsulated message.
//
typedef vscf_status_t (*vscf_kem_api_kem_encapsulate_fn)(const vscf_impl_t *impl, const vscf_impl_t *public_key,
        vsc_buffer_t *shared_key, vsc_buffer_t *encapsulated_key);

//
//  Callback. Decapsulate the shared key.
//
typedef vscf_status_t (*vscf_kem_api_kem_decapsulate_fn)(const vscf_impl_t *impl, vsc_data_t encapsulated_key,
        const vscf_impl_t *private_key, vsc_buffer_t *shared_key);

//
//  Contains API requirements of the interface 'kem'.
//
struct vscf_kem_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'kem' MUST be equal to the 'vscf_api_tag_KEM'.
    //
    vscf_api_tag_t api_tag;
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_t impl_tag;
    //
    //  Return length in bytes required to hold encapsulated shared key.
    //
    vscf_kem_api_kem_shared_key_len_fn kem_shared_key_len_cb;
    //
    //  Return length in bytes required to hold encapsulated key.
    //
    vscf_kem_api_kem_encapsulated_key_len_fn kem_encapsulated_key_len_cb;
    //
    //  Generate a shared key and a key encapsulated message.
    //
    vscf_kem_api_kem_encapsulate_fn kem_encapsulate_cb;
    //
    //  Decapsulate the shared key.
    //
    vscf_kem_api_kem_decapsulate_fn kem_decapsulate_cb;
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
#endif // VSCF_KEM_API_H_INCLUDED
//  @end
