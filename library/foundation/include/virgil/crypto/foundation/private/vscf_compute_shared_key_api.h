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
//  Interface 'compute shared key' API.
// --------------------------------------------------------------------------

#ifndef VSCF_COMPUTE_SHARED_KEY_API_H_INCLUDED
#define VSCF_COMPUTE_SHARED_KEY_API_H_INCLUDED

#include "vscf_library.h"
#include "vscf_api.h"
#include "vscf_impl.h"
#include "vscf_key_alg.h"
#include "vscf_status.h"

#if !VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
#   include <virgil/crypto/common/vsc_buffer.h>
#endif

#if VSCF_IMPORT_PROJECT_COMMON_FROM_FRAMEWORK
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
//  Callback. Compute shared key for 2 asymmetric keys.
//          Note, computed shared key can be used only within symmetric cryptography.
//
typedef vscf_status_t (*vscf_compute_shared_key_api_compute_shared_key_fn)(const vscf_impl_t *impl,
        vscf_impl_t *public_key, vscf_impl_t *private_key, vsc_buffer_t *shared_key);

//
//  Callback. Return number of bytes required to hold shared key.
//          Expect Public Key or Private Key.
//
typedef size_t (*vscf_compute_shared_key_api_shared_key_len_fn)(const vscf_impl_t *impl, const vscf_impl_t *key);

//
//  Contains API requirements of the interface 'compute shared key'.
//
struct vscf_compute_shared_key_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'compute_shared_key' MUST be equal to the 'vscf_api_tag_COMPUTE_SHARED_KEY'.
    //
    vscf_api_tag_t api_tag;
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_t impl_tag;
    //
    //  Link to the inherited interface API 'key alg'.
    //
    const vscf_key_alg_api_t *key_alg_api;
    //
    //  Compute shared key for 2 asymmetric keys.
    //  Note, computed shared key can be used only within symmetric cryptography.
    //
    vscf_compute_shared_key_api_compute_shared_key_fn compute_shared_key_cb;
    //
    //  Return number of bytes required to hold shared key.
    //  Expect Public Key or Private Key.
    //
    vscf_compute_shared_key_api_shared_key_len_fn shared_key_len_cb;
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
#endif // VSCF_COMPUTE_SHARED_KEY_API_H_INCLUDED
//  @end
