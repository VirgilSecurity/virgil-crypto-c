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
//  Interface 'key' API.
// --------------------------------------------------------------------------

#ifndef VSCF_KEY_API_H_INCLUDED
#define VSCF_KEY_API_H_INCLUDED

#include "vscf_library.h"
#include "vscf_api.h"
#include "vscf_impl.h"
#include "vscf_alg_id.h"

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
//  Callback. Algorithm identifier the key belongs to.
//
typedef vscf_alg_id_t (*vscf_key_api_alg_id_fn)(const vscf_impl_t *impl);

//
//  Callback. Return algorithm information that can be used for serialization.
//
typedef const vscf_impl_t * (*vscf_key_api_alg_info_fn)(const vscf_impl_t *impl);

//
//  Callback. Length of the key in bytes.
//
typedef size_t (*vscf_key_api_len_fn)(const vscf_impl_t *impl);

//
//  Callback. Length of the key in bits.
//
typedef size_t (*vscf_key_api_bitlen_fn)(const vscf_impl_t *impl);

//
//  Callback. Return tag of an associated algorithm that can handle this key.
//
typedef vscf_impl_tag_t (*vscf_key_api_impl_tag_fn)(const vscf_impl_t *impl);

//
//  Callback. Check that key is valid.
//          Note, this operation can be slow.
//
typedef bool (*vscf_key_api_is_valid_fn)(const vscf_impl_t *impl);

//
//  Contains API requirements of the interface 'key'.
//
struct vscf_key_api_t {
    //
    //  API's unique identifier, MUST be first in the structure.
    //  For interface 'key' MUST be equal to the 'vscf_api_tag_KEY'.
    //
    vscf_api_tag_t api_tag;
    //
    //  Implementation unique identifier, MUST be second in the structure.
    //
    vscf_impl_tag_t impl_tag;
    //
    //  Algorithm identifier the key belongs to.
    //
    vscf_key_api_alg_id_fn alg_id_cb;
    //
    //  Return algorithm information that can be used for serialization.
    //
    vscf_key_api_alg_info_fn alg_info_cb;
    //
    //  Length of the key in bytes.
    //
    vscf_key_api_len_fn len_cb;
    //
    //  Length of the key in bits.
    //
    vscf_key_api_bitlen_fn bitlen_cb;
    //
    //  Return tag of an associated algorithm that can handle this key.
    //
    vscf_key_api_impl_tag_fn impl_tag_cb;
    //
    //  Check that key is valid.
    //  Note, this operation can be slow.
    //
    vscf_key_api_is_valid_fn is_valid_cb;
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
#endif // VSCF_KEY_API_H_INCLUDED
//  @end
